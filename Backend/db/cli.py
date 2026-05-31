"""Admin CLI for DB tasks: init-db, migrate, list-predictions, show-stats

Usage examples:
  python Backend/db/cli.py init-db
  python Backend/db/cli.py migrate
  python Backend/db/cli.py list-predictions --limit 10
  python Backend/db/cli.py show-stats --limit 5
"""
import argparse
import subprocess
import sys
from typing import Any

from Backend.db.database import SessionLocal, create_tables
from Backend.db.models import Prediction, TrafficStats


def cmd_init_db(args: Any) -> None:
    create_tables()
    print("Tables ensured (create_tables executed).")


def cmd_migrate(args: Any) -> None:
    # Run alembic upgrade head using repo-level alembic.ini
    try:
        subprocess.check_call([sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"])
    except Exception as exc:
        print("alembic migrate failed:", exc)


def cmd_list_predictions(args: Any) -> None:
    session = SessionLocal()
    try:
        q = session.query(Prediction).order_by(Prediction.id.desc()).limit(args.limit)
        for row in q:
            print(row.id, row.timestamp, row.source_ip, row.destination_ip, row.predicted_label, row.confidence)
    finally:
        session.close()


def cmd_show_stats(args: Any) -> None:
    session = SessionLocal()
    try:
        q = session.query(TrafficStats).order_by(TrafficStats.id.desc()).limit(args.limit)
        for row in q:
            print(row.id, row.timestamp, row.total_predictions, row.attacks_detected, row.normal_traffic, row.uncertain, row.uptime_seconds)
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(prog="dbcli")
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init-db")
    p_init.set_defaults(func=cmd_init_db)

    p_mig = sub.add_parser("migrate")
    p_mig.set_defaults(func=cmd_migrate)

    p_list = sub.add_parser("list-predictions")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.set_defaults(func=cmd_list_predictions)

    p_stats = sub.add_parser("show-stats")
    p_stats.add_argument("--limit", type=int, default=10)
    p_stats.set_defaults(func=cmd_show_stats)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
