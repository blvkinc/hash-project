"""
core.__main__ — headless CLI for the Hash Monitor.

Lets the evaluation harness, cron jobs, and red-team scripts drive the
pipeline without spinning up the FastAPI server.

Subcommands:
  scan <path>        run scan_and_baseline + compare_and_log on a directory
  analyze [--limit]  drain the pending-analysis queue once
  watch <path>       block-and-watch a directory in real time (Ctrl+C to exit)
  stats              print FileRecord / FileLog counts and priority breakdown

Examples:
  python -m core scan /etc
  python -m core analyze --limit 50
  python -m core watch ./Desktop
  python -m core stats
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from typing import Sequence

from core.database import init_db, SessionLocal
from core.models import FileLog, FileRecord


def _setup_logging(verbose: bool) -> None:
    from core.logging_config import configure_logging
    configure_logging()
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


def cmd_scan(args: argparse.Namespace) -> int:
    from core.scanner import scan_and_baseline, compare_and_log

    print(f"Scanning: {args.path}")
    baseline = scan_and_baseline(
        args.path,
        reanalyze_existing=args.reanalyze,
        reanalyze_limit=args.reanalyze_limit,
    )
    print(f"  baseline: {baseline}")
    changes = compare_and_log(args.path)
    print(f"  changes:  {changes}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from core.background_analysis import process_pending_analysis

    total = 0
    while True:
        processed = process_pending_analysis(batch_size=args.batch)
        total += processed
        if processed == 0 or (args.limit and total >= args.limit):
            break
    print(f"Processed {total} pending event(s).")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from core.watcher import FileWatcher

    watcher = FileWatcher(args.path)
    watcher.start()
    print(f"Watching {args.path} (Ctrl+C to stop).")

    stopped = {"flag": False}

    def _handle_signal(signum, frame):
        stopped["flag"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stopped["flag"]:
            time.sleep(0.5)
    finally:
        watcher.stop()
        print("Watcher stopped.")
    return 0


def cmd_stats(_args: argparse.Namespace) -> int:
    session = SessionLocal()
    try:
        record_count = session.query(FileRecord).count()
        log_count = session.query(FileLog).count()
        print(f"FileRecord rows: {record_count}")
        print(f"FileLog rows:    {log_count}")
        print("Priority breakdown:")
        for priority in ("critical", "high", "medium", "low", "info", "pending"):
            n = session.query(FileLog).filter(FileLog.priority == priority).count()
            print(f"  {priority:<10} {n}")
    finally:
        session.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m core", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Baseline + change-detect a directory")
    p_scan.add_argument("path")
    p_scan.add_argument("--reanalyze", action="store_true",
                        help="Force re-analysis of files already baselined")
    p_scan.add_argument("--reanalyze-limit", type=int, default=200)
    p_scan.set_defaults(func=cmd_scan)

    p_analyze = sub.add_parser("analyze", help="Drain pending-analysis queue once")
    p_analyze.add_argument("--batch", type=int, default=50,
                           help="Batch size per inner pass")
    p_analyze.add_argument("--limit", type=int, default=0,
                           help="Stop after N total events (0 = drain fully)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_watch = sub.add_parser("watch", help="Real-time watch a directory")
    p_watch.add_argument("path")
    p_watch.set_defaults(func=cmd_watch)

    p_stats = sub.add_parser("stats", help="Print DB stats")
    p_stats.set_defaults(func=cmd_stats)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    init_db()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
