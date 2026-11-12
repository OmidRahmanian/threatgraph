"""Operator commands for Live Monitoring Mode.

threatgraph-live init-db
threatgraph-live agent add web1            # prints the agent token once
threatgraph-live agent add probe-home --role probe
threatgraph-live agent list | rotate web1 | disable web1 | enable web1
threatgraph-live hash-password             # for TG_LIVE_ADMIN_PASSWORD_HASH
threatgraph-live worker [--once]
threatgraph-live train-model
threatgraph-live notify-test               # labeled test message to configured channels
threatgraph-live simulate ssh_bruteforce   # SIMULATED events into the local database
threatgraph-live backup /backups/live-$(date +%F).db
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
import time

from threatgraph.live import behavior, scenarios
from threatgraph.live.notify import channels_from_env, send_test
from threatgraph.live.store import LiveStore
from threatgraph_live.auth import hash_password
from threatgraph_live.settings import LiveSettings
from threatgraph_live.worker import Worker


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="threatgraph-live", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    ag = sub.add_parser("agent")
    ag.add_argument("action", choices=["add", "list", "rotate", "disable", "enable"])
    ag.add_argument("source_id", nargs="?")
    ag.add_argument("--role", choices=["agent", "probe"], default="agent")
    sub.add_parser("hash-password")
    w = sub.add_parser("worker")
    w.add_argument("--once", action="store_true")
    sub.add_parser("train-model")
    sub.add_parser("health", help="exit 1 unless the worker completed a cycle recently")
    sub.add_parser("notify-test")
    s = sub.add_parser("simulate", help="insert SIMULATED events (local testing only)")
    s.add_argument("scenario", choices=sorted(scenarios.SCENARIOS))
    b = sub.add_parser("backup")
    b.add_argument("dest")
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    settings = LiveSettings()
    if args.cmd == "hash-password":
        pw = getpass.getpass("New dashboard password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords differ")
        print(hash_password(pw))
        return
    if args.cmd == "notify-test":
        chans = channels_from_env()
        if not chans:
            sys.exit(
                "no channel configured (TG_TELEGRAM_BOT_TOKEN/TG_TELEGRAM_CHAT_ID or TG_SMTP_*)"
            )
        print(json.dumps(send_test(chans), indent=2))
        return

    store = LiveStore(settings.db_path)
    cfg = settings.live_config()
    if args.cmd == "init-db":
        print(f"database ready: {settings.db_path}")
    elif args.cmd == "agent":
        if args.action == "list":
            for a in store.agents():
                seen = (
                    "never"
                    if a["last_seen"] is None
                    else time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(a["last_seen"]))
                )
                print(
                    f"{a['source_id']:<24} {a['role']:<6} {'disabled' if a['disabled'] else 'enabled':<9} last seen {seen}"
                )
            return
        if not args.source_id:
            sys.exit("source_id required")
        if args.action == "add":
            token = store.add_agent(args.source_id, args.role)
        elif args.action == "rotate":
            token = store.rotate_agent_token(args.source_id)
        else:
            store.set_agent_disabled(args.source_id, args.action == "disable")
            print(f"{args.source_id}: {args.action}d")
            return
        print(f"token for {args.source_id} (shown once; store it in the agent's token file):")
        print(token)
    elif args.cmd == "worker":
        wk = Worker(store, cfg, settings.db_path)
        if args.once:
            print(json.dumps(wk.cycle(), indent=2, default=str))
        else:
            wk.run()
    elif args.cmd == "health":
        st = store.kv_get("worker_status")
        age = None if not st else time.time() - st["last_run"]
        limit = 3 * cfg.detection.interval_seconds + 60
        print(json.dumps({"last_run_age_seconds": age, "errors": (st or {}).get("errors")}))
        if age is None or age > limit:
            sys.exit(1)
    elif args.cmd == "train-model":
        print(json.dumps(behavior.train(store, cfg, settings.db_path), indent=2, default=str))
    elif args.cmd == "simulate":
        events = scenarios.SCENARIOS[args.scenario](time.time())
        res = store.insert_events(events, received_at=time.time())
        print(
            f"inserted {res.accepted} SIMULATED events ({args.scenario}); view them with "
            "'Show simulated test data' in the dashboard"
        )
    elif args.cmd == "backup":
        store.backup(args.dest)
        print(f"backup written: {args.dest}")


if __name__ == "__main__":
    main()
