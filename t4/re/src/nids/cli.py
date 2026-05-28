from __future__ import annotations

import argparse
import json
from pathlib import Path

from .monitor import AlertMonitor, MonitorConfig
from .responder import Responder, ResponsePolicy
from .storage import AlertStore


SAMPLE_ALERTS = Path(__file__).resolve().parents[2] / "sample_alerts" / "eve.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nids", description="Suricata-based intrusion detection starter")
    subcommands = parser.add_subparsers(dest="command", required=True)

    monitor = subcommands.add_parser("monitor", help="Watch a Suricata eve.json file")
    monitor.add_argument("--eve-log", required=True, help="Path to Suricata eve.json")
    monitor.add_argument("--db-path", default="data/nids.db", help="SQLite database path")
    monitor.add_argument("--poll-interval", type=float, default=1.0, help="Polling interval in seconds")
    monitor.add_argument("--response-window-seconds", type=int, default=300, help="Window used to count repeated alerts")
    monitor.add_argument("--escalation-threshold", type=int, default=5, help="Repeated alerts required before escalation")
    monitor.add_argument("--block-command", nargs="*", default=[], help="Command prefix used to block a source IP")
    monitor.add_argument("--quarantine-log", default="data/quarantine.log", help="Write escalation notes here when blocking is not configured")

    seed = subcommands.add_parser("seed-sample", help="Load sample alerts into the database")
    seed.add_argument("--db-path", default="data/nids.db", help="SQLite database path")

    return parser


def run_monitor(args: argparse.Namespace) -> int:
    store = AlertStore(args.db_path)
    responder = Responder(
        ResponsePolicy(
            escalation_threshold=args.escalation_threshold,
            block_command=args.block_command,
            quarantine_log=Path(args.quarantine_log),
        )
    )
    monitor = AlertMonitor(
        store=store,
        responder=responder,
        config=MonitorConfig(eve_log=Path(args.eve_log), poll_interval=args.poll_interval),
    )
    monitor.run_forever()
    return 0


def run_seed_sample(args: argparse.Namespace) -> int:
    store = AlertStore(args.db_path)
    if not SAMPLE_ALERTS.exists():
        raise FileNotFoundError(f"Sample alerts file not found: {SAMPLE_ALERTS}")

    responder = Responder(ResponsePolicy())
    monitor = AlertMonitor(store=store, responder=responder, config=MonitorConfig(eve_log=SAMPLE_ALERTS))
    with SAMPLE_ALERTS.open("r", encoding="utf-8") as handle:
        processed = monitor.process_stream(handle)

    print(json.dumps({"processed": processed, "db_path": str(Path(args.db_path).resolve())}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "monitor":
        return run_monitor(args)
    if args.command == "seed-sample":
        return run_seed_sample(args)

    parser.error("Unknown command")
    return 2
