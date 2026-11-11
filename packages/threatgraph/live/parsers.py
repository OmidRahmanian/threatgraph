"""Parsers for the log formats the collector supports. Standard library only.

Every parser returns `None` for a line it does not recognise (counted as `unparsed`, never
guessed) or a `Parsed(kind, ts, attrs, message)` with normalized fields. Parsing does not apply
privacy filters; the agent applies them right after (see `agent.normalize`).

Supported:
- nginx access log: `combined`, and `combined` followed by `$request_time` and
  `$upstream_response_time` (format name `timed`; see docs/live/collector.md for the
  `log_format` line).
- nginx error log.
- syslog-style auth logs (Debian/Ubuntu `/var/log/auth.log`, RHEL `/var/log/secure`) with
  either the traditional `Mon DD HH:MM:SS` or the RFC 3339 timestamp: sshd, sudo, su,
  useradd/usermod/userdel/groupadd/gpasswd/passwd.
- syslog/kern logs: OOM kills, segfaults, systemd unit failures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "adm", "root", "docker", "lxd", "disk"})


@dataclass
class Parsed:
    kind: str
    ts: float
    attrs: dict[str, Any] = field(default_factory=dict)
    message: str | None = None
    service: str | None = None


# --------------------------------------------------------------------------- nginx
_NGINX_ACCESS = re.compile(
    r"^(?P<addr>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
    r"(?: (?P<rt>[\d.]+|-)(?: (?P<urt>[\d.,: -]+|-))?)?\s*$"
)
_NGINX_TIME = "%d/%b/%Y:%H:%M:%S %z"


def _float(v: str | None) -> float | None:
    if v is None or v in ("-", ""):
        return None
    try:
        # upstream times can be "0.010, 0.020" when nginx retried upstreams: take the last one.
        return float(re.split(r"[,:]\s*", v.strip())[-1])
    except ValueError:
        return None


def parse_nginx_access(line: str) -> Parsed | None:
    m = _NGINX_ACCESS.match(line.rstrip("\n"))
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], _NGINX_TIME).timestamp()
    except ValueError:
        return None
    request = m["request"]
    parts = request.split(" ")
    if len(parts) == 3 and parts[2].startswith("HTTP/"):
        method, target, proto = parts
        well_formed = True
    else:  # e.g. "-" for an empty request, or binary garbage from a TLS probe on port 80
        method, target, proto, well_formed = None, None, None, False
    rt = _float(m["rt"])
    urt = _float(m["urt"])
    return Parsed(
        kind="http.access",
        ts=ts,
        attrs={
            "client": m["addr"],
            "method": method,
            "path": target,
            "protocol": proto,
            "status": int(m["status"]),
            "bytes": None if m["bytes"] == "-" else int(m["bytes"]),
            "referer": None if m["referer"] in (None, "-") else m["referer"],
            "user_agent": None if m["ua"] in (None, "-") else m["ua"],
            "request_time_ms": None if rt is None else round(rt * 1000, 1),
            "upstream_time_ms": None if urt is None else round(urt * 1000, 1),
            "well_formed": well_formed,
            "remote_user": None if m["user"] == "-" else m["user"],
        },
        message=None if well_formed else request[:200],
    )


_NGINX_ERROR = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#\d+: "
    r"(?:\*\d+ )?(?P<msg>.*)$"
)
_KV_CLIENT = re.compile(r", client: (?P<client>[^,]+)")
_KV_REQUEST = re.compile(r', request: "(?P<request>(?:[^"\\]|\\.)*)"')


def parse_nginx_error(line: str, tz: tzinfo) -> Parsed | None:
    m = _NGINX_ERROR.match(line.rstrip("\n"))
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz).timestamp()
    except ValueError:
        return None
    msg = m["msg"]
    client = _KV_CLIENT.search(msg)
    req = _KV_REQUEST.search(msg)
    path = None
    if req:
        parts = req["request"].split(" ")
        path = parts[1] if len(parts) == 3 else None
    head = msg.split(", client: ")[0]
    return Parsed(
        kind="http.error",
        ts=ts,
        attrs={
            "level": m["level"],
            "pid": int(m["pid"]),
            "client": client["client"].strip() if client else None,
            "path": path,
            "category": _error_category(head),
            "worker_crash": bool(re.search(r"worker process \d+ exited on signal", head)),
        },
        message=head,
    )


def _error_category(msg: str) -> str:
    rules = [
        ("upstream", r"upstream|connect\(\) failed|no live upstreams"),
        ("not_found", r"No such file or directory|is not found"),
        ("forbidden", r"forbidden|access forbidden|denied"),
        ("limit", r"limiting requests|limiting connections"),
        ("ssl", r"SSL_|ssl"),
        ("crash", r"exited on signal|core dumped"),
        ("config", r"emerg|invalid|unknown directive"),
    ]
    for name, rx in rules:
        if re.search(rx, msg, re.I):
            return name
    return "other"


# --------------------------------------------------------------------------- syslog header
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)


@dataclass
class SyslogLine:
    ts: float
    host: str
    program: str
    pid: int | None
    msg: str


def parse_syslog_header(line: str, tz: tzinfo, now: datetime | None = None) -> SyslogLine | None:
    line = line.rstrip("\n")
    m = _RFC3339.match(line)
    if m:
        raw = m["ts"].replace("Z", "+00:00")
        try:
            ts = datetime.fromisoformat(raw).timestamp()
        except ValueError:
            return None
    else:
        m = _RFC3164.match(line)
        if not m or m["mon"] not in MONTHS:
            return None
        now = now or datetime.now(UTC)
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        try:
            dt = datetime(now.year, MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=tz)
        except ValueError:
            return None
        # No year in RFC 3164: a time more than a day ahead belongs to last year (Dec -> Jan).
        if dt - now.astimezone(tz) > timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        ts = dt.timestamp()
    return SyslogLine(
        ts=ts,
        host=m["host"],
        program=m["prog"],
        pid=int(m["pid"]) if m["pid"] else None,
        msg=m["msg"],
    )


# --------------------------------------------------------------------------- sshd
# The user name is attacker-chosen, so it is matched greedily and the *last* "from IP port N"
# (which sshd appends itself) is taken as the source: a name like "x from 9.9.9.9 port 1"
# cannot spoof the address.
_FROM = r"(?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)(?:\s.*)?$"
_SSH_RULES: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (
        re.compile(rf"^Accepted (?P<method>\S+) for (?P<user>.*) from {_FROM}"),
        {"outcome": "success"},
    ),
    (
        re.compile(
            rf"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) from {_FROM}"
        ),
        {"outcome": "failure"},
    ),
    (
        re.compile(rf"^Invalid user (?P<user>.*) from {_FROM}"),
        {"outcome": "failure", "invalid_user": True, "method": "none"},
    ),
    (
        re.compile(
            rf"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?(?P<user>.*) from {_FROM}"
        ),
        {"outcome": "failure", "method": "max_attempts"},
    ),
]
_SSH_PROBE = [
    (
        re.compile(r"^Did not receive identification string from (?P<ip>[0-9A-Fa-f:.]+)"),
        "no_identification",
    ),
    (
        re.compile(
            r"^banner exchange: Connection from (?P<ip>[0-9A-Fa-f:.]+) port \d+: (?P<why>.*)"
        ),
        "bad_banner",
    ),
    (
        re.compile(r"^Unable to negotiate with (?P<ip>[0-9A-Fa-f:.]+) port \d+"),
        "negotiation_failed",
    ),
]


def _ssh(s: SyslogLine) -> Parsed | None:
    for rx, base in _SSH_RULES:
        m = rx.match(s.msg)
        if m:
            g = m.groupdict()
            invalid = bool(g.get("invalid")) or bool(base.get("invalid_user"))
            return Parsed(
                kind="ssh.auth",
                ts=s.ts,
                service="sshd",
                attrs={
                    "outcome": base["outcome"],
                    "user": g["user"],
                    "invalid_user": invalid,
                    "method": g.get("method") or base.get("method"),
                    "src_ip": g["ip"],
                    "src_port": int(g["port"]),
                },
                message=s.msg,
            )
    for rx, reason in _SSH_PROBE:
        m = rx.match(s.msg)
        if m:
            return Parsed(
                kind="ssh.probe",
                ts=s.ts,
                service="sshd",
                attrs={"src_ip": m["ip"], "reason": reason},
                message=s.msg,
            )
    return None


# --------------------------------------------------------------------------- sudo / su / accounts
_SUDO_CMD = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<fail>\d+ incorrect password attempts?|user NOT in sudoers|"
    r"command not allowed|a password is required) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ;(?: COMMAND=(?P<cmd>.*))?$"
)
_SU = [
    (re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"), "success"),
    (re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)"), "failure"),
    (
        re.compile(
            r"^pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(?P<user>\S*).*?user=(?P<target>\S+)"
        ),
        "failure",
    ),
]
_ACCOUNT: list[tuple[str, re.Pattern[str]]] = [
    ("new_user", re.compile(r"^new user: name=(?P<target>[^,]+)")),
    ("new_group", re.compile(r"^new group: name=(?P<target>[^,]+)")),
    ("delete_user", re.compile(r"^delete user '(?P<target>[^']+)'")),
    (
        "group_add_member",
        re.compile(r"^add '(?P<target>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'"),
    ),
    ("group_add_member", re.compile(r"^user (?P<target>\S+) added by \S+ to group (?P<group>\S+)")),
    (
        "password_change",
        re.compile(r"^pam_unix\(passwd:chauthtok\): password changed for (?P<target>\S+)"),
    ),
    ("password_change", re.compile(r"^password for '(?P<target>[^']+)' changed")),
]
_ACCOUNT_PROGRAMS = {
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "gpasswd",
    "passwd",
    "chpasswd",
    "groupmod",
}


def _admin(s: SyslogLine) -> Parsed | None:
    if s.program == "sudo":
        m = _SUDO_CMD.match(s.msg)
        if not m:
            return None
        return Parsed(
            kind="admin.sudo",
            ts=s.ts,
            service="sudo",
            attrs={
                "user": m["user"],
                "target_user": m["target"],
                "outcome": "failure" if m["fail"] else "success",
                "failure_reason": m["fail"],
                "tty": m["tty"],
                "command": m["cmd"],
            },
            message=s.msg,
        )
    if s.program == "su":
        for rx, outcome in _SU:
            m = rx.match(s.msg)
            if m:
                return Parsed(
                    kind="admin.su",
                    ts=s.ts,
                    service="su",
                    attrs={
                        "user": m["user"] or None,
                        "target_user": m["target"],
                        "outcome": outcome,
                    },
                    message=s.msg,
                )
        return None
    if s.program in _ACCOUNT_PROGRAMS:
        for action, rx in _ACCOUNT:
            m = rx.match(s.msg)
            if m:
                group = m.groupdict().get("group")
                return Parsed(
                    kind="admin.account",
                    ts=s.ts,
                    service=s.program,
                    attrs={
                        "action": action,
                        "target": m["target"],
                        "group": group,
                        "privileged": group in PRIVILEGED_GROUPS if group else False,
                    },
                    message=s.msg,
                )
    return None


def parse_auth_log(line: str, tz: tzinfo, now: datetime | None = None) -> Parsed | None:
    s = parse_syslog_header(line, tz, now)
    if s is None:
        return None
    if s.program in ("sshd", "sshd-session") or s.program.startswith("sshd"):
        return _ssh(s)
    return _admin(s)


# --------------------------------------------------------------------------- syslog / kernel
_OOM = re.compile(r"Out of memory: Killed process (?P<pid>\d+) \((?P<proc>[^)]+)\)")
_SEGV = re.compile(r"^(?P<proc>[^\[\s]+)\[(?P<pid>\d+)\]: segfault at")
_UNIT_FAIL = [
    re.compile(
        r"^(?P<unit>\S+\.(?:service|socket|timer|mount)): Failed with result '(?P<why>[^']+)'"
    ),
    re.compile(
        r"^(?P<unit>\S+\.(?:service|socket|timer|mount)): Main process exited, code=(?P<why>\S+), status=(?P<status>\S+)"
    ),
    re.compile(r"^Failed to start (?P<unit>.+?)\.?$"),
]


def parse_syslog(line: str, tz: tzinfo, now: datetime | None = None) -> Parsed | None:
    s = parse_syslog_header(line, tz, now)
    if s is None:
        return None
    if s.program == "kernel":
        msg = re.sub(r"^\[\s*\d+\.\d+\]\s*", "", s.msg)
        m = _OOM.search(msg)
        if m:
            return Parsed(
                kind="system.kernel",
                ts=s.ts,
                service="kernel",
                attrs={"event": "oom_kill", "process": m["proc"], "pid": int(m["pid"])},
                message=msg,
            )
        m = _SEGV.match(msg)
        if m:
            return Parsed(
                kind="system.kernel",
                ts=s.ts,
                service="kernel",
                attrs={"event": "segfault", "process": m["proc"], "pid": int(m["pid"])},
                message=msg,
            )
        return None
    if s.program == "systemd":
        for rx in _UNIT_FAIL:
            m = rx.match(s.msg)
            if m:
                g = m.groupdict()
                if g.get("status") in ("0/SUCCESS",):
                    return None
                return Parsed(
                    kind="system.service",
                    ts=s.ts,
                    service="systemd",
                    attrs={
                        "unit": g["unit"],
                        "state": "failed",
                        "detail": g.get("why") or g.get("status"),
                        "source": "journal_line",
                    },
                    message=s.msg,
                )
    return None
