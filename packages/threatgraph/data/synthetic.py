"""Deterministic synthetic fixture in the exact LANL `auth.txt`, `redteam.txt` and `proc.txt`
text formats.

Everything here is invented. The fixture exists so the full pipeline (parser, features,
models, API, website) can run without the real LANL download, and it is labeled
"Synthetic demo" everywhere downstream. It deliberately includes things that make
evaluation non-trivial:

* benign confounders that look anomalous (admin maintenance sweeps, failure storms,
  new hires with no history, users moving to a new workstation, high-volume service accounts);
* attacker events that are *not* in the red-team file (failed attempts and ~15% of
  successful hops), so "unlabeled" never means "benign";
* data-quality problems the parser must survive: malformed rows, `?` fields, duplicate
  auth lines, a duplicate red-team record, and a red-team record with no matching event.

Process starts (`proc.txt.gz`) are drawn after the authentication events from their own
random stream, so adding them leaves the auth file byte-identical. Users start habitual
programs after their logons; admins carry admin tools to every host they touch (including
maintenance sweeps); a software rollout puts a brand-new program on many workstations in one
day; most red-team hops start tools, some reused across campaigns, while the stealth campaign
starts only the victim's usual programs. Benign novelty therefore exists on purpose, and the
process features are not a perfect separator.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from threatgraph.config import DAY_SECONDS

HOUR = 3600
Row = tuple[int, str, str, str, str, str, str, str, str]


@dataclass(frozen=True)
class CampaignSpec:
    campaign_id: str
    start_day: float
    style: str  # "burst" | "slow" | "stealth"
    n_hops: int


@dataclass(frozen=True)
class SyntheticSpec:
    seed: int = 42
    n_days: int = 14
    n_users: int = 220
    n_admins: int = 8
    n_service_users: int = 3
    n_workstations: int = 240
    n_servers: int = 24
    n_domain_controllers: int = 3
    domain: str = "DOM1"
    new_hire_days: tuple[float, ...] = (5.0, 9.0, 10.0, 11.0, 12.0, 13.0)
    workstation_moves: tuple[float, ...] = (4.3, 7.4, 9.4, 12.5)
    failure_storm_days: tuple[float, ...] = (3.6, 5.4, 7.5, 8.4, 9.6, 10.5, 11.4, 12.6, 13.5)
    admin_sweep_days: tuple[float, ...] = (4.4, 9.5, 12.4)
    campaigns: tuple[CampaignSpec, ...] = (
        CampaignSpec("rt-01", 3.45, "burst", 8),
        CampaignSpec("rt-02", 6.40, "slow", 6),
        CampaignSpec("rt-03", 8.55, "slow", 5),
        CampaignSpec("rt-04", 10.40, "burst", 10),
        CampaignSpec("rt-05", 11.50, "burst", 12),
        CampaignSpec("rt-06", 12.35, "slow", 7),
        CampaignSpec("rt-07", 13.30, "stealth", 3),
    )
    label_keep_probability: float = 0.85
    n_random_duplicate_lines: int = 40
    software_rollout_day: float = 9.3


@dataclass
class UserProfile:
    principal: str
    role: str  # normal | admin | service | new_hire
    home: str  # workstation (or server, for service accounts)
    usual: list[str]
    rate: float
    start_seconds: int = 0
    moves: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class FixtureResult:
    auth_path: Path
    redteam_path: Path
    manifest_path: Path
    manifest: dict[str, Any]


class _Generator:
    def __init__(self, spec: SyntheticSpec) -> None:
        self.spec = spec
        self.rng = np.random.default_rng(spec.seed)
        self.end = spec.n_days * DAY_SECONDS
        self.rows: list[Row] = []
        self.labeled: list[tuple[int, str, str, str]] = []
        self.campaign_log: list[dict[str, Any]] = []
        self.benign_log: list[dict[str, Any]] = []
        self.hops: list[tuple[int, str, str, str]] = []  # (time, principal, dst, style)
        self._build_entities()

    # ------------------------------------------------------------------ entities
    def _build_entities(self) -> None:
        s, rng = self.spec, self.rng
        n_comp = s.n_workstations + s.n_servers + s.n_domain_controllers
        comp_ids = rng.choice(np.arange(1, 25_000), size=n_comp, replace=False)
        comps = [f"C{i}" for i in comp_ids]
        self.dcs = comps[: s.n_domain_controllers]
        self.servers = comps[s.n_domain_controllers : s.n_domain_controllers + s.n_servers]
        self.workstations = comps[s.n_domain_controllers + s.n_servers :]

        user_ids = rng.choice(np.arange(1, 15_000), size=s.n_users, replace=False)
        principals = [f"U{i}@{s.domain}" for i in user_ids]
        n_new = len(s.new_hire_days)
        roles = (
            ["admin"] * s.n_admins
            + ["service"] * s.n_service_users
            + ["new_hire"] * n_new
            + ["normal"] * (s.n_users - s.n_admins - s.n_service_users - n_new)
        )
        free_ws = list(self.workstations)
        rng.shuffle(free_ws)
        self.spare_ws = free_ws[s.n_users :]  # workstations nobody owns at the start
        self.users: list[UserProfile] = []
        new_idx = 0
        for i, (p, role) in enumerate(zip(principals, roles, strict=True)):
            ws = free_ws[i % len(free_ws)]
            if role == "admin":
                pool = self.servers + self.workstations
                usual = list(rng.choice(pool, size=int(rng.integers(20, 41)), replace=False))
                prof = UserProfile(p, role, ws, usual, rate=float(rng.uniform(2.0, 3.5)))
            elif role == "service":
                home = str(rng.choice(self.servers))
                usual = list(rng.choice(self.servers, size=int(rng.integers(6, 13)), replace=False))
                prof = UserProfile(p, role, home, usual, rate=float(rng.uniform(20, 35)))
            else:
                usual = list(rng.choice(self.servers, size=int(rng.integers(2, 6)), replace=False))
                rate = float(np.exp(rng.normal(np.log(1.5), 0.5)))
                prof = UserProfile(p, role, ws, usual, rate=rate)
                if role == "new_hire":
                    prof.start_seconds = int(s.new_hire_days[new_idx] * DAY_SECONDS)
                    new_idx += 1
            self.users.append(prof)
        self.normal_users = [u for u in self.users if u.role == "normal"]
        self.admins = [u for u in self.users if u.role == "admin"]
        # Users reserved for scripted scenarios so they do not overlap.
        order = rng.permutation(len(self.normal_users))
        self._scenario_pool = [self.normal_users[i] for i in order]

    def _take_normal_user(self) -> UserProfile:
        return self._scenario_pool.pop()

    # ------------------------------------------------------------------ emit
    def emit(
        self,
        t: int,
        user: str,
        src: str,
        dst: str,
        auth_type: str,
        logon_type: str,
        orientation: str,
        outcome: str,
        dst_user: str | None = None,
    ) -> Row | None:
        if not 0 <= t < self.end:
            return None
        row: Row = (
            t,
            user,
            dst_user or user,
            src,
            dst,
            auth_type,
            logon_type,
            orientation,
            outcome,
        )
        self.rows.append(row)
        return row

    @staticmethod
    def _cycle_activity(t: int, role: str) -> float:
        # Synthetic activity cycle. This is a property of the fixture only; the pipeline
        # never uses clock-of-day features (LANL time is relative with an unknown epoch).
        hour = (t // HOUR) % 24
        day = t // DAY_SECONDS
        p = 0.7 if 8 <= hour < 18 else (0.1 if role == "admin" else 0.05)
        return p * (0.25 if day % 7 in (5, 6) else 1.0)

    def _home_at(self, u: UserProfile, t: int) -> str:
        home = u.home
        for when, ws in u.moves:
            if t >= when:
                home = ws
        return home

    # ------------------------------------------------------------------ background
    def background(self) -> None:
        rng = self.rng
        n_hours = self.end // HOUR
        for h in range(n_hours):
            t0 = h * HOUR
            for u in self.users:
                if t0 < u.start_seconds:
                    continue
                if u.role == "service":
                    self._service_hour(u, t0)
                elif rng.random() < self._cycle_activity(t0, u.role):
                    if u.role == "admin":
                        self._admin_hour(u, t0)
                    else:
                        self._user_hour(u, t0)
            for ws in self.workstations:
                for _ in range(rng.poisson(0.8)):
                    t = t0 + int(rng.integers(0, HOUR))
                    machine = f"{ws}$@{self.spec.domain}"
                    logon = "Network" if rng.random() > 0.1 else "?"
                    orient = "TGT" if rng.random() < 0.5 else "TGS"
                    self.emit(
                        t,
                        machine,
                        ws,
                        str(rng.choice(self.dcs)),
                        "Kerberos",
                        logon,
                        orient,
                        "Success",
                    )

    def _logon(self, u: UserProfile, t: int, src: str, dst: str, auth: str, logon: str) -> None:
        rng = self.rng
        dc = str(rng.choice(self.dcs))
        self.emit(t, u.principal, src, dc, "Kerberos", "Network", "TGS", "Success")
        if rng.random() < 0.02:
            self.emit(t + 1, u.principal, src, dst, auth, logon, "LogOn", "Fail")
            if rng.random() > 0.8:
                return
            t += int(rng.integers(3, 30))
        self.emit(t + 2, u.principal, src, dst, auth, logon, "LogOn", "Success")
        self.emit(
            t + int(rng.integers(30, 2400)), u.principal, dst, dst, "?", logon, "LogOff", "Success"
        )

    def _user_hour(self, u: UserProfile, t0: int) -> None:
        rng = self.rng
        src = self._home_at(u, t0)
        for _ in range(1 + rng.poisson(u.rate)):
            t = t0 + int(rng.integers(0, HOUR))
            if rng.random() < 0.25:
                auth = "Kerberos" if rng.random() < 0.7 else "Negotiate"
                self.emit(t, u.principal, src, src, auth, "Interactive", "LogOn", "Success")
            if rng.random() < 0.01:  # benign exploration of a new server
                dst = str(rng.choice(self.servers))
                if rng.random() < 0.5 and dst not in u.usual:
                    u.usual.append(dst)
            else:
                dst = str(rng.choice(u.usual))
            auth = "Kerberos" if rng.random() < 0.92 else "NTLM"
            self._logon(u, t + 1, src, dst, auth, "Network")

    def _admin_hour(self, u: UserProfile, t0: int) -> None:
        rng = self.rng
        for _ in range(1 + rng.poisson(u.rate)):
            t = t0 + int(rng.integers(0, HOUR))
            pool = self.servers + self.workstations
            dst = str(rng.choice(pool)) if rng.random() < 0.05 else str(rng.choice(u.usual))
            auth = "NTLM" if rng.random() < 0.3 else "Kerberos"
            logon = "RemoteInteractive" if rng.random() < 0.2 else "Network"
            self._logon(u, t, u.home, dst, auth, logon)

    def _service_hour(self, u: UserProfile, t0: int) -> None:
        rng = self.rng
        for _ in range(int(u.rate) + rng.poisson(5)):
            t = t0 + int(rng.integers(0, HOUR))
            outcome = "Fail" if rng.random() < 0.005 else "Success"
            dst = str(rng.choice(u.usual))
            self.emit(t, u.principal, u.home, dst, "Kerberos", "Network", "LogOn", outcome)

    # ------------------------------------------------------------------ benign scenarios
    def benign_scenarios(self) -> None:
        rng, s = self.rng, self.spec
        for day in s.failure_storm_days:
            u = self._take_normal_user()
            t = int(day * DAY_SECONDS)
            dst = str(rng.choice(u.usual))
            n = int(rng.integers(15, 51))
            times = np.sort(rng.integers(0, int(rng.integers(1200, 3600)), size=n)) + t
            for ti in times:
                self.emit(int(ti), u.principal, u.home, dst, "Kerberos", "Network", "LogOn", "Fail")
            self.emit(
                int(times[-1]) + 5,
                u.principal,
                u.home,
                dst,
                "Kerberos",
                "Network",
                "LogOn",
                "Success",
            )
            self.benign_log.append(
                {
                    "kind": "failure_storm",
                    "principal": u.principal,
                    "start_seconds": t,
                    "end_seconds": int(times[-1]) + 5,
                    "n_failures": n,
                }
            )
        for day in s.admin_sweep_days:
            u = self.admins[int(rng.integers(0, len(self.admins)))]
            t = int(day * DAY_SECONDS)
            targets = [w for w in self.workstations if w not in u.usual]
            n = int(rng.integers(25, 46))
            hosts = rng.choice(targets, size=n, replace=False)
            for h in hosts:
                t += int(rng.integers(30, 300))
                auth = "NTLM" if rng.random() < 0.6 else "Kerberos"
                self._logon(u, t, u.home, str(h), auth, "Network")
            self.benign_log.append(
                {
                    "kind": "admin_maintenance_sweep",
                    "principal": u.principal,
                    "start_seconds": int(day * DAY_SECONDS),
                    "end_seconds": t,
                    "n_hosts": n,
                }
            )
        for day in s.workstation_moves:
            u = self._take_normal_user()
            new_ws = self.spare_ws.pop()
            when = int(day * DAY_SECONDS)
            u.moves.append((when, new_ws))
            self.benign_log.append(
                {
                    "kind": "workstation_move",
                    "principal": u.principal,
                    "start_seconds": when,
                    "new_workstation": new_ws,
                }
            )
        for u in self.users:
            if u.role == "new_hire":
                self.benign_log.append(
                    {"kind": "new_hire", "principal": u.principal, "start_seconds": u.start_seconds}
                )

    # ------------------------------------------------------------------ red team
    def campaigns(self) -> None:
        rng, s = self.rng, self.spec
        for c in s.campaigns:
            victim = self._take_normal_user()
            t = int(c.start_day * DAY_SECONDS)
            compromised = [victim.home]
            candidates = [h for h in self.workstations + self.servers if h not in victim.usual]
            labeled_n = unlabeled_success = failures = 0
            for _ in range(c.n_hops):
                src = compromised[-1] if c.style != "burst" else str(rng.choice(compromised))
                known = c.style == "stealth" and rng.random() < 0.5
                pool = [h for h in (victim.usual if known else candidates) if h not in compromised]
                dst = str(rng.choice(pool))
                auth = "NTLM" if (c.style == "burst" or rng.random() < 0.3) else "Kerberos"
                if c.style == "burst" and rng.random() < 0.4:
                    for _ in range(int(rng.integers(1, 4))):
                        t += int(rng.integers(2, 20))
                        self.emit(t, victim.principal, src, dst, auth, "Network", "LogOn", "Fail")
                        failures += 1
                t += int(rng.integers(1, 10))
                self.emit(
                    t,
                    victim.principal,
                    src,
                    str(rng.choice(self.dcs)),
                    "Kerberos",
                    "Network",
                    "TGS",
                    "Success",
                )
                t += 1
                row = self.emit(t, victim.principal, src, dst, auth, "Network", "LogOn", "Success")
                if row is not None:
                    self.hops.append((t, victim.principal, dst, c.style))
                    if rng.random() < s.label_keep_probability:
                        self.labeled.append((t, victim.principal, src, dst))
                        labeled_n += 1
                    else:
                        unlabeled_success += 1
                compromised.append(dst)
                gap = {"burst": (60, 600), "slow": (1800, 5400), "stealth": (7200, 14400)}[c.style]
                t += int(rng.integers(*gap))
            self.campaign_log.append(
                {
                    "campaign_id": c.campaign_id,
                    "style": c.style,
                    "principal": victim.principal,
                    "start_seconds": int(c.start_day * DAY_SECONDS),
                    "end_seconds": t,
                    "hosts": compromised,
                    "labeled_events": labeled_n,
                    "unlabeled_successful_hops": unlabeled_success,
                    "unlabeled_failures": failures,
                }
            )

    # ------------------------------------------------------------------ processes
    def processes(self, rows: list[Row]) -> list[str]:
        """Process start/end lines (LANL proc.txt format) derived from the auth events."""
        prng = np.random.default_rng(self.spec.seed + 1)  # separate stream: auth unchanged
        common = [f"P{i}" for i in range(1, 61)]
        weights = 1.0 / np.arange(1, 61) ** 1.1
        weights /= weights.sum()
        system = [f"P{i}" for i in range(1, 13)]
        admin_tools = [f"P{i}" for i in range(70, 80)]
        attacker_tools = [f"P{i}" for i in range(4401, 4407)]
        habits: dict[str, list[str]] = {}
        for u in self.users:
            k = int(prng.integers(3, 8))
            h = list(prng.choice(common, size=k, replace=False, p=weights))
            if u.role == "admin":
                h += list(prng.choice(admin_tools, size=4, replace=False))
            habits[u.principal] = h
        roles = {u.principal: u.role for u in self.users}
        out: list[tuple[int, str, str, str, str]] = []

        def start(t: int, user: str, comp: str, proc: str) -> None:
            if not 0 <= t < self.end:
                return
            out.append((t, user, comp, proc, "Start"))
            if prng.random() < 0.6:
                t_end = t + int(prng.integers(5, 3600))
                if t_end < self.end:
                    out.append((t_end, user, comp, proc, "End"))

        for t, user, _, src, dst, _a, _l, orient, outcome in rows:
            if "$@" in user:
                if prng.random() < 0.3:
                    start(t + int(prng.integers(1, 60)), user, src, str(prng.choice(system)))
                continue
            if orient != "LogOn" or outcome != "Success" or user not in habits:
                continue
            if prng.random() < (0.5 if roles.get(user) == "admin" else 0.35):
                for _ in range(1 + prng.poisson(0.5)):
                    start(t + int(prng.integers(1, 120)), user, dst, str(prng.choice(habits[user])))

        # Benign look-alike: a software rollout puts a new program on many workstations.
        t0 = int(self.spec.software_rollout_day * DAY_SECONDS)
        rolled = [u for u in self.normal_users if prng.random() < 0.4]
        for u in rolled:
            start(t0 + int(prng.integers(0, 3 * HOUR)), u.principal, self._home_at(u, t0), "P900")
        self.benign_log.append(
            {
                "kind": "software_rollout",
                "process": "P900",
                "start_seconds": t0,
                "n_users": len(rolled),
            }
        )

        # Red-team hops: tools started shortly after the lateral logon (stealth: usual ones).
        for t, user, dst, style in self.hops:
            if style == "stealth":
                if prng.random() < 0.5:
                    start(t + int(prng.integers(5, 90)), user, dst, str(prng.choice(habits[user])))
            elif prng.random() < 0.75:
                for _ in range(int(prng.integers(1, 4))):
                    start(
                        t + int(prng.integers(5, 90)), user, dst, str(prng.choice(attacker_tools))
                    )

        out.sort(key=lambda r: (r[0], r[1], r[2], r[3], r[4]))
        lines = [",".join(str(x) for x in r) for r in out]
        malformed = [
            "{t},?,C1,P1,Start",  # missing principal
            "{t},U1@DOM1,C1,P1,Restart",  # invalid action
            "{t},U1@DOM1,C1,P1",  # too few columns
        ]
        for k, line in enumerate(malformed):
            pos = (k + 1) * len(lines) // (len(malformed) + 1)
            lines.insert(pos, line.format(t=lines[pos].split(",")[0]))
        return lines


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_gz(path: Path, lines: list[str]) -> None:
    # mtime=0 and an empty embedded filename make the compressed bytes reproducible.
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        gz.write(("\n".join(lines) + "\n").encode())


def generate_fixture(out_dir: Path, spec: SyntheticSpec | None = None) -> FixtureResult:
    spec = spec or SyntheticSpec()
    gen = _Generator(spec)
    gen.benign_scenarios()  # assigns workstation moves before background traffic is drawn
    gen.background()
    gen.campaigns()
    rng = gen.rng

    rows = sorted(gen.rows, key=lambda r: r[0])  # stable: ties keep generation order
    labeled_set = set(gen.labeled)
    # Exact duplicate auth lines (LANL contains repeated lines); one is a labeled event,
    # which makes that red-team record match two auth events.
    dup_idx = sorted(rng.choice(len(rows), size=spec.n_random_duplicate_lines, replace=False))
    first_label = min(gen.labeled)
    label_row = next(i for i, r in enumerate(rows) if (r[0], r[1], r[3], r[4]) == first_label)
    out: list[str] = []
    dup_set = {*map(int, dup_idx), label_row}
    for i, r in enumerate(rows):
        line = ",".join(str(x) for x in r)
        out.append(line)
        if i in dup_set:
            out.append(line)

    # Malformed rows at fixed relative positions.
    malformed = {
        "too_few_columns": "1000,U1@DOM1,U1@DOM1,C1,C1,Kerberos,Network",
        "too_many_columns": "1000,U1@DOM1,U1@DOM1,C1,C1,Kerberos,Network,LogOn,Success,EXTRA",
        "non_integer_time": "abc,U1@DOM1,U1@DOM1,C1,C1,Kerberos,Network,LogOn,Success",
        "invalid_outcome": "1000,U1@DOM1,U1@DOM1,C1,C1,Kerberos,Network,LogOn,Maybe",
        "free_text": "this line is not a csv record",
    }
    for k, (_, line) in enumerate(malformed.items()):
        pos = (k + 1) * len(out) // (len(malformed) + 1)
        # Keep timestamps monotone in the file by reusing the neighbour's time where numeric.
        neighbour_t = out[pos].split(",")[0]
        out.insert(pos, line.replace("1000", neighbour_t, 1))

    rt_rows = sorted(labeled_set)
    rt_lines = [f"{t},{u},{s},{d}" for t, u, s, d in rt_rows]
    rt_lines.append(rt_lines[len(rt_lines) // 2])  # duplicate red-team record
    t_u, u_u, s_u, d_u = rt_rows[-1]
    rt_lines.append(f"{t_u + 7},{u_u},{s_u},{d_u}")  # record with no matching auth event
    rt_lines.sort(key=lambda line: int(line.split(",")[0]))

    proc_lines = gen.processes(rows)

    out_dir.mkdir(parents=True, exist_ok=True)
    auth_path, rt_path = out_dir / "auth.txt.gz", out_dir / "redteam.txt.gz"
    proc_path = out_dir / "proc.txt.gz"
    _write_gz(auth_path, out)
    _write_gz(rt_path, rt_lines)
    _write_gz(proc_path, proc_lines)

    manifest = {
        "synthetic": True,
        "notice": "Synthetic demonstration data. Not real network activity.",
        "generator": "threatgraph.data.synthetic.generate_fixture",
        "spec": asdict(spec),
        "files": {
            "auth.txt.gz": {"lines": len(out), "sha256": _sha256(auth_path)},
            "redteam.txt.gz": {"lines": len(rt_lines), "sha256": _sha256(rt_path)},
            "proc.txt.gz": {"lines": len(proc_lines), "sha256": _sha256(proc_path)},
        },
        "entities": {
            "users": len(gen.users),
            "admins": len(gen.admins),
            "workstations": len(gen.workstations),
            "servers": len(gen.servers),
            "domain_controllers": len(gen.dcs),
        },
        "injected_quality_issues": {
            "malformed_rows": list(malformed),
            "duplicate_auth_lines": len(dup_set),
            "duplicate_redteam_records": 1,
            "unmatched_redteam_records": 1,
            "malformed_proc_rows": 3,
        },
        "campaigns": gen.campaign_log,
        "benign_scenarios": gen.benign_log,
    }
    manifest_path = out_dir / "fixture_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return FixtureResult(auth_path, rt_path, manifest_path, manifest)
