"""Deterministic detection rules for Live Monitoring Mode.

Rules run every `detection.interval_seconds` over recent events and return `Finding`s. The
incident manager (`incidents.py`) turns findings into deduplicated incidents. Each rule
documents what it counts, its threshold (configs/live.yaml), its default severity and its
blind spots (docs/live/incidents.md).

Two kinds of rule:
- **event rules** (brute force, reconnaissance, file changes...) report something that
  happened. Their incidents stay open until a person acknowledges and resolves them.
- **condition rules** (website down, disk full, agent offline...) report a state that holds
  *now*. Their incidents resolve automatically when the condition clears, which also sends a
  recovery notification.

Real and simulated (test-fixture) events are evaluated separately and never mixed.
Assessment vocabulary: `unusual` (deviation, no claim of intent), `suspected_malicious`
(pattern typical of an attack, not confirmed). Only a person can mark an incident confirmed.
"""

from __future__ import annotations

import ipaddress
import re
import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from threatgraph.live.config import LiveConfig, Severity
from threatgraph.live.store import LiveStore

Category = Literal["security", "operational", "availability"]
Assessment = Literal["unusual", "suspected_malicious"]


@dataclass
class Finding:
    rule_id: str
    category: Category
    title: str
    severity: Severity
    assessment: Assessment
    entity: str
    first_seen: float
    last_seen: float
    evidence: list[str]
    event_rowids: list[int]
    confidence: str
    limitations: str
    recommended_action: str
    service: str | None = None
    source_id: str | None = None
    condition: bool = False  # True: auto-resolves when it stops being reported
    detector: str = "rule"
    simulated: bool = False
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        return f"{self.rule_id}|{self.source_id or '-'}|{self.service or '-'}|{self.entity}"


def _mins(seconds: float) -> str:
    return f"{seconds / 60:g} min" if seconds < 3600 else f"{seconds / 3600:g} h"


def robust_z(value: float, history: Sequence[float]) -> tuple[float, float, float]:
    """(z, median, scale) of `value` against `history` using median and MAD (floor 1.0)."""
    med = statistics.median(history)
    mad = statistics.median([abs(h - med) for h in history]) * 1.4826
    scale = max(mad, 1.0, 0.1 * med)
    return (value - med) / scale, med, scale


class RuleEngine:
    def __init__(self, store: LiveStore, cfg: LiveConfig) -> None:
        self.store = store
        self.cfg = cfg
        self.det = cfg.detection
        self.sensitive = [re.compile(p) for p in self.det.sensitive_paths]
        self.allow = set(self.det.allowlist_sources)
        self._simulated = False

    # ------------------------------------------------------------------ helpers
    def p(self, rule: str, key: str, default: Any) -> Any:
        return self.det.rule(rule).params.get(key, default)

    def on(self, rule: str) -> bool:
        return self.det.rule(rule).enabled and rule in self.det.rules

    def sev(self, rule: str) -> Severity:
        return self.det.rule(rule).severity

    def _allowed(self, ip: str | None) -> bool:
        if not ip:
            return False
        if ip in self.allow:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for a in self.allow:
            try:
                if addr in ipaddress.ip_network(a, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def is_sensitive(self, path: str | None) -> bool:
        return bool(path) and any(rx.search(path) for rx in self.sensitive)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ entry point
    def run(self, now: float) -> list[Finding]:
        findings: list[Finding] = []
        lookback = max(
            self.det.lookback_seconds,
            *(int(r.params.get("window_seconds", 0)) for r in self.det.rules.values()),
        )
        for simulated in (False, True):
            self._simulated = simulated
            ev = self.store.events(
                since=now - lookback, until=now + 1, simulated=simulated, limit=500_000
            )
            by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for e in ev:
                by_kind[e["kind"]].append(e)
            batch: list[Finding] = []
            for rule in (
                self.ssh_rules,
                self.admin_rules,
                self.http_rules,
                self.host_event_rules,
                self.deviation_rules,
            ):
                batch += rule(by_kind, now)
            batch += self.availability(now, simulated) + self.host_state(now, simulated)
            for f in batch:
                f.simulated = simulated
            findings += batch
        if self.on("agent_offline"):
            findings += self.agent_offline(now)
        return findings

    # ================================================================== SSH
    def ssh_rules(self, ev: dict[str, list[dict[str, Any]]], now: float) -> list[Finding]:
        out: list[Finding] = []
        auth = ev.get("ssh.auth", [])
        fails: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for e in auth:
            a = e["attrs"]
            if a.get("outcome") == "failure" and a.get("src_ip") and not self._allowed(a["src_ip"]):
                fails[(e["source_id"], a["src_ip"])].append(e)

        if self.on("ssh_bruteforce"):
            w = self.p("ssh_bruteforce", "window_seconds", 300)
            n = self.p("ssh_bruteforce", "min_failures", 10)
            for (src, ip), rows in fails.items():
                recent = [r for r in rows if r["ts"] >= now - w]
                if len(recent) < n:
                    continue
                users = {r["attrs"].get("user") for r in recent}
                invalid = sum(bool(r["attrs"].get("invalid_user")) for r in recent)
                out.append(
                    Finding(
                        rule_id="ssh_bruteforce",
                        category="security",
                        title="Repeated SSH authentication failures",
                        severity=self.sev("ssh_bruteforce"),
                        assessment="suspected_malicious",
                        entity=ip,
                        source_id=src,
                        service="sshd",
                        first_seen=recent[0]["ts"],
                        last_seen=recent[-1]["ts"],
                        evidence=[
                            f"{len(recent)} failed SSH logins from {ip} within {_mins(w)} "
                            f"(threshold {n})",
                            f"{len(users)} distinct user names tried; {invalid} were not valid "
                            "accounts on this host",
                        ],
                        event_rowids=[r["rowid"] for r in recent],
                        confidence="High that the failures occurred (counted from sshd logs).",
                        limitations="Failures alone do not show a compromise. Behind NAT many "
                        "users may share one address.",
                        recommended_action="Check whether any login from this address "
                        "succeeded; confirm password authentication is disabled; consider a "
                        "rate limiter such as fail2ban. ThreatGraph does not block addresses.",
                        facts={"failures": len(recent), "distinct_users": len(users)},
                    )
                )

        if self.on("ssh_password_spray"):
            w = self.p("ssh_password_spray", "window_seconds", 600)
            k = self.p("ssh_password_spray", "min_distinct_users", 5)
            for (src, ip), rows in fails.items():
                recent = [r for r in rows if r["ts"] >= now - w]
                names = sorted({str(r["attrs"].get("user")) for r in recent})
                if len(names) < k:
                    continue
                out.append(
                    Finding(
                        rule_id="ssh_password_spray",
                        category="security",
                        title="SSH user-name enumeration or password spraying",
                        severity=self.sev("ssh_password_spray"),
                        assessment="suspected_malicious",
                        entity=ip,
                        source_id=src,
                        service="sshd",
                        first_seen=recent[0]["ts"],
                        last_seen=recent[-1]["ts"],
                        evidence=[
                            f"{len(names)} different user names tried from {ip} within "
                            f"{_mins(w)} (threshold {k})",
                            "Examples: " + ", ".join(u[:32] for u in names[:5]),
                        ],
                        event_rowids=[r["rowid"] for r in recent],
                        confidence="High that the attempts occurred.",
                        limitations="Typical of automated internet-wide scanning; it is rarely "
                        "targeted at this server specifically.",
                        recommended_action="Ensure only key-based authentication is allowed "
                        "and that no listed account name exists with a weak password.",
                        facts={"distinct_users": len(names)},
                    )
                )

        if self.on("ssh_success_after_failures"):
            w = self.p("ssh_success_after_failures", "window_seconds", 3600)
            n = self.p("ssh_success_after_failures", "min_failures", 5)
            for e in auth:
                a = e["attrs"]
                if a.get("outcome") != "success" or self._allowed(a.get("src_ip")):
                    continue
                prior = [
                    r
                    for r in fails.get((e["source_id"], a.get("src_ip", "")), [])
                    if e["ts"] - w <= r["ts"] < e["ts"]
                ]
                if len(prior) < n:
                    continue
                out.append(
                    Finding(
                        rule_id="ssh_success_after_failures",
                        category="security",
                        title="Successful SSH login after repeated failures",
                        severity=self.sev("ssh_success_after_failures"),
                        assessment="suspected_malicious",
                        entity=f"{a.get('src_ip')}:{a.get('user')}",
                        source_id=e["source_id"],
                        service="sshd",
                        first_seen=prior[0]["ts"],
                        last_seen=e["ts"],
                        evidence=[
                            f"{len(prior)} failed logins from {a.get('src_ip')} in the "
                            f"{_mins(w)} before a successful login",
                            f"Successful login as '{a.get('user')}' using {a.get('method')}",
                        ],
                        event_rowids=[r["rowid"] for r in prior[-20:]] + [e["rowid"]],
                        confidence="High that the sequence occurred; whether the success was "
                        "the attacker is unknown.",
                        limitations="A legitimate user who mistyped a password several times "
                        "produces the same pattern.",
                        recommended_action="Confirm with the account owner that this login was "
                        "theirs. If not: treat the host as compromised, review the session and "
                        "rotate credentials.",
                    )
                )
        return out

    # ================================================================== admin / integrity
    def admin_rules(self, ev: dict[str, list[dict[str, Any]]], now: float) -> list[Finding]:
        out: list[Finding] = []
        if self.on("privileged_account_change"):
            for e in ev.get("admin.account", []):
                a = e["attrs"]
                privileged = bool(a.get("privileged"))
                sev: Severity = self.sev("privileged_account_change") if privileged else "low"
                what = {
                    "new_user": f"New user account '{a.get('target')}' created",
                    "new_group": f"New group '{a.get('target')}' created",
                    "delete_user": f"User account '{a.get('target')}' deleted",
                    "group_add_member": f"'{a.get('target')}' added to group '{a.get('group')}'",
                    "password_change": f"Password changed for '{a.get('target')}'",
                }.get(a.get("action"), f"Account change: {a.get('action')}")
                out.append(
                    Finding(
                        rule_id="privileged_account_change",
                        category="security",
                        title="Privileged group membership changed"
                        if privileged
                        else "User account changed",
                        severity=sev,
                        assessment="unusual",
                        entity=f"{a.get('action')}:{a.get('target')}:{a.get('group')}",
                        source_id=e["source_id"],
                        service=e["service"],
                        first_seen=e["ts"],
                        last_seen=e["ts"],
                        evidence=[what + (" (an administrator group)" if privileged else "")],
                        event_rowids=[e["rowid"]],
                        confidence="High that the change was logged.",
                        limitations="Whether the change was authorized is not visible in logs.",
                        recommended_action="Confirm the change was made intentionally by an "
                        "administrator.",
                    )
                )
        if self.on("sudo_failure"):
            w = self.p("sudo_failure", "window_seconds", 600)
            n = self.p("sudo_failure", "min_failures", 3)
            by_user: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
            for e in ev.get("admin.sudo", []):
                if e["attrs"].get("outcome") == "failure" and e["ts"] >= now - w:
                    by_user[(e["source_id"], str(e["attrs"].get("user")))].append(e)
            for (src, user), rows in by_user.items():
                attempts = sum(
                    int(m.group(1))
                    if (m := re.match(r"(\d+)", str(r["attrs"].get("failure_reason") or "")))
                    else 1
                    for r in rows
                )
                if attempts < n:
                    continue
                out.append(
                    Finding(
                        rule_id="sudo_failure",
                        category="security",
                        title="Repeated failed sudo attempts",
                        severity=self.sev("sudo_failure"),
                        assessment="unusual",
                        entity=user,
                        source_id=src,
                        service="sudo",
                        first_seen=rows[0]["ts"],
                        last_seen=rows[-1]["ts"],
                        evidence=[f"{attempts} failed sudo attempts by '{user}' within {_mins(w)}"],
                        event_rowids=[r["rowid"] for r in rows],
                        confidence="High that the attempts were logged.",
                        limitations="Mistyped passwords look the same.",
                        recommended_action="Ask the user; if unexpected, review that account's "
                        "recent logins.",
                    )
                )
        allowed = set(self.p("unexpected_admin", "allowed_sudo_users", []))
        if self.on("unexpected_admin") and allowed:
            for e in ev.get("admin.sudo", []):
                user = str(e["attrs"].get("user"))
                if e["attrs"].get("outcome") == "success" and user not in allowed:
                    out.append(
                        Finding(
                            rule_id="unexpected_admin",
                            category="security",
                            title="Administrative command by an unexpected user",
                            severity=self.sev("unexpected_admin"),
                            assessment="unusual",
                            entity=user,
                            source_id=e["source_id"],
                            service="sudo",
                            first_seen=e["ts"],
                            last_seen=e["ts"],
                            evidence=[
                                f"'{user}' ran sudo as {e['attrs'].get('target_user')}; this user "
                                "is not in allowed_sudo_users"
                            ],
                            event_rowids=[e["rowid"]],
                            confidence="High that the command was logged.",
                            limitations="The allowlist may simply be out of date.",
                            recommended_action="Confirm the user is meant to administer this "
                            "host; update the allowlist if so.",
                        )
                    )
        if self.on("file_integrity"):
            high = set(self.p("file_integrity", "high_paths", []))
            for e in ev.get("fim.change", []):
                path = str(e["attrs"].get("path"))
                out.append(
                    Finding(
                        rule_id="file_integrity",
                        category="security",
                        title="Monitored file changed",
                        severity="high" if path in high else self.sev("file_integrity"),
                        assessment="unusual",
                        entity=f"{path}:{e['attrs'].get('sha256_after')}",
                        source_id=e["source_id"],
                        service="fim",
                        first_seen=e["ts"],
                        last_seen=e["ts"],
                        evidence=[f"{path} was {e['attrs'].get('change')}"],
                        event_rowids=[e["rowid"]],
                        confidence="High: the content hash differs from the recorded baseline.",
                        limitations="Package updates and deliberate edits also change files.",
                        recommended_action="Confirm the change matches planned maintenance; "
                        "compare with your configuration repository or backup.",
                    )
                )
        return out

    # ================================================================== web
    def http_rules(self, ev: dict[str, list[dict[str, Any]]], now: float) -> list[Finding]:
        out: list[Finding] = []
        access = ev.get("http.access", [])
        by_client: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for e in access:
            c = e["attrs"].get("client")
            if c and not self._allowed(c):
                by_client[(e["source_id"], e["service"] or "web", c)].append(e)

        if self.on("http_recon"):
            w = self.p("http_recon", "window_seconds", 300)
            n_sens = self.p("http_recon", "min_sensitive_hits", 3)
            n_404 = self.p("http_recon", "min_distinct_404_paths", 25)
            for (src, svc, client), rows in by_client.items():
                recent = [r for r in rows if r["ts"] >= now - w]
                sens = [r for r in recent if self.is_sensitive(r["attrs"].get("path"))]
                served = [r for r in sens if 200 <= int(r["attrs"].get("status") or 0) < 300]
                nf = {r["attrs"].get("path") for r in recent if r["attrs"].get("status") == 404}
                if len(sens) < n_sens and len(nf) < n_404 and not served:
                    continue
                ev_lines = [
                    f"{len(recent)} requests from {client} within {_mins(w)}",
                    f"{len(sens)} requests for sensitive-looking paths (threshold {n_sens}), "
                    "e.g. " + ", ".join(sorted({str(r["attrs"].get("path")) for r in sens})[:4])
                    if sens
                    else f"{len(nf)} distinct paths returned 404 (threshold {n_404})",
                ]
                severity: Severity = self.sev("http_recon")
                title = "Suspected automated reconnaissance"
                action = (
                    "Review the request logs for this source. No action is taken automatically."
                )
                if served:
                    severity = "high"
                    title = "Sensitive-looking path served successfully"
                    ev_lines.append(
                        "Returned 2xx for: "
                        + ", ".join(sorted({str(r["attrs"].get("path")) for r in served})[:4])
                    )
                    action = (
                        "Check immediately whether the file is publicly readable (for example "
                        "an .env or .git directory) and rotate any secrets it contains."
                    )
                out.append(
                    Finding(
                        rule_id="http_recon",
                        category="security",
                        title=title,
                        severity=severity,
                        assessment="suspected_malicious",
                        entity=client,
                        source_id=src,
                        service=svc,
                        first_seen=recent[0]["ts"],
                        last_seen=recent[-1]["ts"],
                        evidence=ev_lines,
                        event_rowids=[r["rowid"] for r in (sens + served or recent)][:100],
                        confidence="High that the requests occurred; intent is inferred from "
                        "the paths requested.",
                        limitations="Automated scanners probe every public site; most of this "
                        "traffic is not targeted. No compromise is implied.",
                        recommended_action=action,
                    )
                )

        if self.on("http_request_burst"):
            w = self.p("http_request_burst", "window_seconds", 60)
            n = self.p("http_request_burst", "min_requests", 600)
            for (src, svc, client), rows in by_client.items():
                recent = [r for r in rows if r["ts"] >= now - w]
                if len(recent) < n:
                    continue
                out.append(
                    Finding(
                        rule_id="http_request_burst",
                        category="security",
                        title="Request burst from one source",
                        severity=self.sev("http_request_burst"),
                        assessment="unusual",
                        entity=client,
                        source_id=src,
                        service=svc,
                        first_seen=recent[0]["ts"],
                        last_seen=recent[-1]["ts"],
                        evidence=[
                            f"{len(recent)} requests from {client} within {_mins(w)} (threshold {n})"
                        ],
                        event_rowids=[r["rowid"] for r in recent[-50:]],
                        confidence="High that the requests occurred.",
                        limitations="Crawlers, load tests and users behind a shared proxy can "
                        "produce bursts.",
                        recommended_action="Identify the client; consider rate limiting at the "
                        "web server.",
                    )
                )

        if self.on("http_error_spike"):
            w = self.p("http_error_spike", "window_seconds", 300)
            n = self.p("http_error_spike", "min_requests", 30)
            ratio_min = self.p("http_error_spike", "min_5xx_ratio", 0.25)
            by_svc: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
            for e in access:
                if e["ts"] >= now - w:
                    by_svc[(e["source_id"], e["service"] or "web")].append(e)
            for (src, svc), rows in by_svc.items():
                errs = [r for r in rows if int(r["attrs"].get("status") or 0) >= 500]
                if len(rows) < n or len(errs) / len(rows) < ratio_min:
                    continue
                ratio = len(errs) / len(rows)
                out.append(
                    Finding(
                        rule_id="http_error_spike",
                        category="operational",
                        title="High rate of server errors (5xx)",
                        severity="high" if ratio >= 0.5 else self.sev("http_error_spike"),
                        assessment="unusual",
                        entity="5xx",
                        source_id=src,
                        service=svc,
                        first_seen=rows[0]["ts"],
                        last_seen=rows[-1]["ts"],
                        evidence=[
                            f"{len(errs)} of {len(rows)} requests ({ratio:.0%}) returned 5xx "
                            f"within {_mins(w)} (threshold {ratio_min:.0%})",
                            "Status codes: "
                            + ", ".join(
                                f"{k}×{v}"
                                for k, v in sorted(
                                    _count(str(r["attrs"].get("status")) for r in errs).items()
                                )
                            ),
                        ],
                        event_rowids=[r["rowid"] for r in errs[-50:]],
                        confidence="High: computed from access logs.",
                        limitations="Covers only requests that reached the web server.",
                        recommended_action="Check the application and upstream service logs.",
                        condition=True,
                    )
                )
        return out

    def deviation_rules(self, ev: dict[str, list[dict[str, Any]]], now: float) -> list[Finding]:
        """Volume deviations against the service's own recent history (robust z-score)."""
        out: list[Finding] = []
        for rule, kind, title in (
            ("request_volume_deviation", "http.access", "Unusual request volume"),
            ("error_rate_deviation", "http.error", "Unusual change in web-server error rate"),
        ):
            if not self.on(rule):
                continue
            b = int(self.p(rule, "bucket_seconds", 300))
            hours = float(self.p(rule, "history_hours", 24))
            need = int(self.p(rule, "min_history_buckets", 48))
            zmin = float(self.p(rule, "robust_z", 8.0))
            minimum = int(self.p(rule, "min_requests", 200 if kind == "http.access" else 20))
            cur_start = (int(now) // b - 1) * b  # last complete bucket
            rows = self.store.query(
                "SELECT source_id, COALESCE(service, '-') svc, CAST(ts / ? AS INTEGER) * ? bucket, "
                "count(*) n FROM events WHERE kind = ? AND ts >= ? AND ts < ? AND simulated = ? "
                "GROUP BY 1, 2, 3",
                (b, b, kind, cur_start - hours * 3600, cur_start + b, int(self._simulated)),
            )
            series: dict[tuple[str, str], dict[int, int]] = defaultdict(dict)
            for r in rows:
                series[(r["source_id"], r["svc"])][int(r["bucket"])] = int(r["n"])
            for (src, svc), counts in series.items():
                first = min(counts)
                hist = [counts.get(t, 0) for t in range(first, cur_start, b)]
                cur = counts.get(cur_start, 0)
                if len(hist) < need or cur < minimum:
                    continue
                z, med, _ = robust_z(cur, hist)
                if z < zmin:
                    continue
                out.append(
                    Finding(
                        rule_id=rule,
                        detector="baseline",
                        category="operational" if kind == "http.error" else "security",
                        title=title,
                        severity=self.sev(rule),
                        assessment="unusual",
                        entity=f"bucket:{cur_start}",
                        source_id=src,
                        service=None if svc == "-" else svc,
                        first_seen=cur_start,
                        last_seen=cur_start + b,
                        evidence=[
                            f"{cur} events in the last {_mins(b)} versus a median of {med:g} over "
                            f"the previous {len(hist)} intervals (robust z = {z:.1f}, "
                            f"threshold {zmin:g})"
                        ],
                        event_rowids=[],
                        confidence="Statistical: a large deviation from this service's own "
                        "recent history.",
                        limitations="Launches, campaigns, crawlers and seasonality cause "
                        "legitimate spikes; the baseline covers only recent hours.",
                        recommended_action="Compare with expected traffic; check the top "
                        "clients and paths in the event timeline.",
                    )
                )
        return out

    def host_event_rules(self, ev: dict[str, list[dict[str, Any]]], now: float) -> list[Finding]:
        out: list[Finding] = []
        if self.on("kernel_oom"):
            for e in ev.get("system.kernel", []):
                a = e["attrs"]
                out.append(
                    Finding(
                        rule_id="kernel_oom",
                        category="operational",
                        title="Process killed by the kernel"
                        if a.get("event") == "oom_kill"
                        else "Process crashed",
                        severity=self.sev("kernel_oom"),
                        assessment="unusual",
                        entity=f"{a.get('event')}:{a.get('process')}",
                        source_id=e["source_id"],
                        service=str(a.get("process")),
                        first_seen=e["ts"],
                        last_seen=e["ts"],
                        evidence=[
                            f"{a.get('event')} of process '{a.get('process')}' (pid {a.get('pid')})"
                        ],
                        event_rowids=[e["rowid"]],
                        confidence="High: reported by the kernel.",
                        limitations="The kernel log does not say why memory ran out.",
                        recommended_action="Check memory use and limits of the affected service.",
                    )
                )
        if self.on("nginx_worker_crash"):
            for e in ev.get("http.error", []):
                if e["attrs"].get("worker_crash"):
                    out.append(
                        Finding(
                            rule_id="nginx_worker_crash",
                            category="operational",
                            title="Web server worker process crashed",
                            severity=self.sev("nginx_worker_crash"),
                            assessment="unusual",
                            entity="worker",
                            source_id=e["source_id"],
                            service=e["service"],
                            first_seen=e["ts"],
                            last_seen=e["ts"],
                            evidence=[str(e["message"] or "worker exited on signal")[:200]],
                            event_rowids=[e["rowid"]],
                            confidence="High: reported by nginx.",
                            limitations="Crashes can come from modules, memory or malformed input.",
                            recommended_action="Check the nginx error log around this time.",
                        )
                    )
        if self.on("service_failure"):
            for e in ev.get("system.service", []):
                a = e["attrs"]
                if a.get("source") == "journal_line" and a.get("state") == "failed":
                    out.append(
                        Finding(
                            rule_id="service_failure",
                            category="operational",
                            title="Service failure logged",
                            severity=self.sev("service_failure"),
                            assessment="unusual",
                            entity=f"log:{a.get('unit')}",
                            source_id=e["source_id"],
                            service=str(a.get("unit")),
                            first_seen=e["ts"],
                            last_seen=e["ts"],
                            evidence=[f"systemd: {a.get('unit')} failed ({a.get('detail')})"],
                            event_rowids=[e["rowid"]],
                            confidence="High: logged by systemd.",
                            limitations="A unit that restarts successfully still logs a failure.",
                            recommended_action="Check `systemctl status` and the unit's journal.",
                        )
                    )
        return out

    # ================================================================== state (condition) rules
    def _latest(self, kind: str, simulated: bool, since: float, group: str) -> list[dict[str, Any]]:
        """Most recent event per (source_id, json attr `group`) of a kind."""
        rows = self.store.query(
            "SELECT e.rowid, e.source_id, e.kind, e.ts, e.service, e.attrs, e.message, e.simulated "
            "FROM events e JOIN (SELECT source_id, json_extract(attrs, ?) g, max(ts) mts FROM events "
            "WHERE kind = ? AND simulated = ? AND ts >= ? GROUP BY 1, 2) m "
            "ON e.source_id = m.source_id AND json_extract(e.attrs, ?) IS m.g AND e.ts = m.mts "
            "WHERE e.kind = ? AND e.simulated = ?",
            (f"$.{group}", kind, int(simulated), since, f"$.{group}", kind, int(simulated)),
        )
        return rows

    def availability(self, now: float, simulated: bool) -> list[Finding]:
        out: list[Finding] = []
        if not (self.on("availability") or self.on("tls_expiry")):
            return out
        need = int(self.p("availability", "consecutive_failures", 2))
        crit_after = float(self.p("availability", "critical_after_seconds", 900))
        since = now - max(3 * 3600, crit_after * 4)
        rows = self.store.events(
            kinds=["probe.http"], since=since, simulated=simulated, limit=100_000
        )
        by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            by_target[str(r["attrs"].get("target"))].append(r)
        for target, rs in by_target.items():
            rs.sort(key=lambda r: r["ts"])
            last = rs[-1]
            # Results from every probe location are pooled per target: an outage is reported
            # when the most recent `need` results all failed.
            tail = rs[-need:]
            if (
                self.on("availability")
                and len(tail) >= need
                and not any(r["attrs"].get("ok") for r in tail)
            ):
                down_since = tail[0]["ts"]
                for r in reversed(rs):
                    if r["attrs"].get("ok"):
                        break
                    down_since = r["ts"]
                duration = now - down_since
                errors = sorted(
                    {str(r["attrs"].get("error") or r["attrs"].get("status")) for r in tail}
                )
                out.append(
                    Finding(
                        rule_id="availability",
                        category="availability",
                        title="Website unavailable",
                        severity="critical" if duration >= crit_after else self.sev("availability"),
                        assessment="unusual",
                        entity=target,
                        source_id=None,
                        service=last["service"] or target,
                        first_seen=down_since,
                        last_seen=last["ts"],
                        evidence=[
                            f"{len(tail)} consecutive failed checks of {last['attrs'].get('url')}",
                            f"Failing for {_mins(duration)}; last error: {', '.join(errors)[:160]}",
                            "Checked from: " + ", ".join(sorted({r["source_id"] for r in tail})),
                        ],
                        event_rowids=[r["rowid"] for r in tail],
                        confidence="High when checks from more than one location agree.",
                        limitations="A check from a single location can fail because of that "
                        "location's own network.",
                        recommended_action="Open the site yourself; check the web server, the "
                        "VPS provider status and DNS.",
                        condition=True,
                    )
                )
            days = last["attrs"].get("cert_days_left")
            if self.on("tls_expiry") and last["attrs"].get("ok") and days is not None:
                warn = float(self.p("tls_expiry", "warn_days", 14))
                hi = float(self.p("tls_expiry", "high_days", 3))
                if days <= warn:
                    out.append(
                        Finding(
                            rule_id="tls_expiry",
                            category="availability",
                            title="TLS certificate expires soon",
                            severity="high" if days <= hi else self.sev("tls_expiry"),
                            assessment="unusual",
                            entity=target,
                            service=last["service"] or target,
                            first_seen=last["ts"],
                            last_seen=last["ts"],
                            evidence=[
                                f"Certificate for {last['attrs'].get('url')} expires in {days:.1f} days"
                            ],
                            event_rowids=[last["rowid"]],
                            confidence="High: read from the served certificate.",
                            limitations="Automatic renewal may still succeed before expiry.",
                            recommended_action="Check the certificate renewal job (for example certbot).",
                            condition=True,
                        )
                    )
        return out

    def host_state(self, now: float, simulated: bool) -> list[Finding]:
        out: list[Finding] = []
        since = now - 3 * 86_400
        if self.on("service_failure"):
            for r in self._latest("system.service", simulated, since, "unit"):
                a = r["attrs"]
                if a.get("source") == "systemctl" and a.get("state") == "failed":
                    out.append(
                        Finding(
                            rule_id="service_failure",
                            category="operational",
                            title="Service in failed state",
                            severity=self.sev("service_failure"),
                            assessment="unusual",
                            entity=str(a.get("unit")),
                            source_id=r["source_id"],
                            service=str(a.get("unit")),
                            first_seen=r["ts"],
                            last_seen=now,
                            evidence=[f"systemd reports {a.get('unit')} as failed"],
                            event_rowids=[r["rowid"]],
                            confidence="High: reported by systemctl.",
                            limitations="Units that are expected to fail (one-shot jobs) also appear.",
                            recommended_action="Run `systemctl status` for the unit and check its journal.",
                            condition=True,
                        )
                    )
        if self.on("container_unhealthy"):
            for r in self._latest("container.health", simulated, since, "name"):
                a = r["attrs"]
                bad = a.get("health") == "unhealthy" or a.get("state") in (
                    "exited",
                    "dead",
                    "restarting",
                )
                if bad:
                    out.append(
                        Finding(
                            rule_id="container_unhealthy",
                            category="operational",
                            title="Container unhealthy or stopped",
                            severity=self.sev("container_unhealthy"),
                            assessment="unusual",
                            entity=str(a.get("name")),
                            source_id=r["source_id"],
                            service=str(a.get("name")),
                            first_seen=r["ts"],
                            last_seen=now,
                            evidence=[
                                f"Container {a.get('name')}: state {a.get('state')}, health "
                                f"{a.get('health') or 'not reported'}, restarts {a.get('restart_count')}"
                            ],
                            event_rowids=[r["rowid"]],
                            confidence="High: reported by Docker.",
                            limitations="Containers stopped on purpose also appear.",
                            recommended_action="Check `docker logs` for the container.",
                            condition=True,
                        )
                    )
        if self.on("disk_usage") or self.on("memory_pressure"):
            samples = self.store.events(
                kinds=["system.metrics"], since=now - 1800, simulated=simulated, limit=50_000
            )
            by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for s in samples:
                by_src[s["source_id"]].append(s)
            hi = float(self.p("disk_usage", "high_percent", 90))
            crit = float(self.p("disk_usage", "critical_percent", 97))
            mem_pct = float(self.p("memory_pressure", "percent", 95))
            need = int(self.p("memory_pressure", "sustained_samples", 5))
            for src, rs in by_src.items():
                last = rs[-1]
                if self.on("disk_usage"):
                    for d in last["attrs"].get("disks") or []:
                        used = d.get("used_percent")
                        if used is None or used < hi:
                            continue
                        out.append(
                            Finding(
                                rule_id="disk_usage",
                                category="operational",
                                title="Disk nearly full",
                                severity="critical" if used >= crit else self.sev("disk_usage"),
                                assessment="unusual",
                                entity=str(d.get("path")),
                                source_id=src,
                                service="host",
                                first_seen=last["ts"],
                                last_seen=last["ts"],
                                evidence=[
                                    f"{d.get('path')} is {used:.1f}% full ({d.get('free_gb')} GB free; "
                                    f"thresholds {hi:g}% / {crit:g}%)"
                                ],
                                event_rowids=[last["rowid"]],
                                confidence="High: measured on the host.",
                                limitations="Reserved blocks mean writes can fail slightly before 100%.",
                                recommended_action="Free space (old logs, Docker images, backups) "
                                "or enlarge the disk.",
                                condition=True,
                            )
                        )
                tail = [s["attrs"].get("mem_percent") for s in rs[-need:]]
                if (
                    self.on("memory_pressure")
                    and len(tail) >= need
                    and all(v is not None and v >= mem_pct for v in tail)
                ):
                    out.append(
                        Finding(
                            rule_id="memory_pressure",
                            category="operational",
                            title="Sustained memory pressure",
                            severity=self.sev("memory_pressure"),
                            assessment="unusual",
                            entity="memory",
                            source_id=src,
                            service="host",
                            first_seen=rs[-need]["ts"],
                            last_seen=last["ts"],
                            evidence=[
                                f"Memory use ≥ {mem_pct:g}% in the last {need} samples (latest {tail[-1]}%)"
                            ],
                            event_rowids=[s["rowid"] for s in rs[-need:]],
                            confidence="High: measured on the host.",
                            limitations="Page cache is excluded; this is memory applications hold.",
                            recommended_action="Check the largest processes; the kernel may start "
                            "killing processes.",
                            condition=True,
                        )
                    )
        return out

    def agent_offline(self, now: float) -> list[Finding]:
        out = []
        limit = self.det.agent_offline_after_seconds
        for a in self.store.agents():
            if a["disabled"] or a["last_seen"] is None:
                continue  # never connected: shown in the dashboard, not alerted
            silent = now - a["last_seen"]
            if silent < limit:
                continue
            out.append(
                Finding(
                    rule_id="agent_offline",
                    category="availability",
                    title="Monitoring agent stopped reporting",
                    severity=self.sev("agent_offline"),
                    assessment="unusual",
                    entity=a["source_id"],
                    source_id=a["source_id"],
                    service="agent",
                    first_seen=a["last_seen"],
                    last_seen=now,
                    evidence=[
                        f"No data from {a['source_id']} for {_mins(silent)} (threshold {_mins(limit)})"
                    ],
                    event_rowids=[],
                    confidence="High that no data arrived; the cause is unknown.",
                    limitations="The host may be down, the agent stopped, or the network "
                    "between them broken. Telemetry from this host is missing meanwhile, "
                    "so other detections for it are blind.",
                    recommended_action="Check the host and `systemctl status threatgraph-agent`.",
                    condition=True,
                )
            )
        return out


def _count(items: Any) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for i in items:
        out[i] += 1
    return dict(out)
