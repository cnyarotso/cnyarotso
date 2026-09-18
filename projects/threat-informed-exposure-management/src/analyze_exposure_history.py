#!/usr/bin/env python3
"""Measure remediation performance from synthetic dated exposure snapshots."""

from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path

VALID_STATUSES = {"open", "in_progress", "exception", "remediated"}

SCHEMA = """
CREATE TABLE exposure_history (
    snapshot_date TEXT NOT NULL,
    exposure_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open','in_progress','exception','remediated')),
    exception_review_date TEXT,
    PRIMARY KEY(snapshot_date, exposure_id)
);
"""

QUERIES = {
    "time_to_remediation": """
        SELECT exposure_id,
               CAST(julianday(MIN(CASE WHEN status='remediated' THEN snapshot_date END))
                    - julianday(MIN(snapshot_date)) AS INTEGER) AS days_to_remediation
        FROM exposure_history
        GROUP BY exposure_id
        HAVING MIN(CASE WHEN status='remediated' THEN snapshot_date END) IS NOT NULL
        ORDER BY days_to_remediation DESC, exposure_id
    """,
    "reopened_exposures": """
        WITH sequenced AS (
          SELECT exposure_id, snapshot_date, status,
                 LAG(status) OVER (PARTITION BY exposure_id ORDER BY snapshot_date) AS prior_status
          FROM exposure_history
        )
        SELECT exposure_id, snapshot_date AS reopened_on, status
        FROM sequenced
        WHERE prior_status='remediated' AND status<>'remediated'
        ORDER BY reopened_on, exposure_id
    """,
    "recurring_exposures": """
        SELECT exposure_id, COUNT(*) AS snapshots_observed,
               SUM(status<>'remediated') AS active_snapshots
        FROM exposure_history
        GROUP BY exposure_id
        HAVING COUNT(*) >= 3
        ORDER BY active_snapshots DESC, snapshots_observed DESC, exposure_id
    """,
    "exceptions_due_within_30_days": """
        WITH latest AS (
          SELECT *, ROW_NUMBER() OVER (PARTITION BY exposure_id ORDER BY snapshot_date DESC) AS rn
          FROM exposure_history
        )
        SELECT exposure_id, snapshot_date, exception_review_date,
               CAST(julianday(exception_review_date)-julianday(snapshot_date) AS INTEGER) AS days_until_review
        FROM latest
        WHERE rn=1 AND status='exception' AND exception_review_date IS NOT NULL
          AND julianday(exception_review_date)-julianday(snapshot_date) BETWEEN 0 AND 30
        ORDER BY exception_review_date, exposure_id
    """,
}


def load_history(connection: sqlite3.Connection, csv_path: Path) -> None:
    connection.executescript(SCHEMA)
    with csv_path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    seen: set[tuple[str, str]] = set()
    values = []
    for row in rows:
        key = (row["snapshot_date"], row["exposure_id"])
        if key in seen:
            raise ValueError(f"duplicate snapshot/exposure pair: {key}")
        seen.add(key)
        if row["status"] not in VALID_STATUSES:
            raise ValueError(f"unsupported status: {row['status']!r}")
        values.append((*key, row["status"], row["exception_review_date"] or None))
    connection.executemany("INSERT INTO exposure_history VALUES (?, ?, ?, ?)", values)


def analyze(csv_path: Path) -> dict[str, list[tuple[object, ...]]]:
    with sqlite3.connect(":memory:") as connection:
        load_history(connection, csv_path)
        return {name: connection.execute(sql).fetchall() for name, sql in QUERIES.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("history_csv", type=Path)
    args = parser.parse_args()
    for name, rows in analyze(args.history_csv).items():
        print(f"\n[{name}]")
        for row in rows:
            print("\t".join(str(value) for value in row))
        if not rows:
            print("(no rows)")


if __name__ == "__main__":
    main()
