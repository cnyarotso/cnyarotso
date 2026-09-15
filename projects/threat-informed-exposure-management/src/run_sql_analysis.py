#!/usr/bin/env python3
"""Load prioritized exposure data into SQLite and run named analysis queries."""

from __future__ import annotations

import argparse
import csv
import re
import sqlite3
from pathlib import Path

QUERY_NAME = re.compile(r"^-- name:\s*([a-z][a-z0-9_]*)\s*$")

SCHEMA = """
CREATE TABLE exposures (
    exposure_id TEXT PRIMARY KEY,
    asset_name TEXT NOT NULL,
    business_service TEXT NOT NULL,
    cve TEXT NOT NULL,
    cvss REAL NOT NULL CHECK (cvss BETWEEN 0 AND 10),
    asset_criticality INTEGER NOT NULL CHECK (asset_criticality BETWEEN 1 AND 5),
    known_exploited INTEGER NOT NULL CHECK (known_exploited IN (0, 1)),
    active_exploitation INTEGER NOT NULL CHECK (active_exploitation IN (0, 1)),
    externally_reachable INTEGER NOT NULL CHECK (externally_reachable IN (0, 1)),
    identity_privileged INTEGER NOT NULL CHECK (identity_privileged IN (0, 1)),
    control_coverage INTEGER NOT NULL CHECK (control_coverage BETWEEN 0 AND 100),
    days_open INTEGER NOT NULL CHECK (days_open >= 0),
    intelligence_confidence TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL,
    priority_score REAL NOT NULL,
    priority_band TEXT NOT NULL,
    remediation_sla_days INTEGER NOT NULL,
    sla_breached INTEGER NOT NULL CHECK (sla_breached IN (0, 1)),
    score_reasons TEXT NOT NULL,
    recommended_action TEXT NOT NULL
);
"""

FIELDS = (
    "exposure_id", "asset_name", "business_service", "cve", "cvss",
    "asset_criticality", "known_exploited", "active_exploitation",
    "externally_reachable", "identity_privileged", "control_coverage",
    "days_open", "intelligence_confidence", "owner", "status",
    "priority_score", "priority_band", "remediation_sla_days",
    "sla_breached", "score_reasons", "recommended_action",
)


def as_bool(value: str) -> int:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"expected true or false; received {value!r}")
    return int(normalized == "true")


def load_exposures(connection: sqlite3.Connection, csv_path: Path) -> None:
    connection.executescript(SCHEMA)
    with csv_path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))

    placeholders = ", ".join("?" for _ in FIELDS)
    statement = f"INSERT INTO exposures ({', '.join(FIELDS)}) VALUES ({placeholders})"
    values = []
    for row in rows:
        values.append((
            row["exposure_id"], row["asset_name"], row["business_service"], row["cve"],
            float(row["cvss"]), int(row["asset_criticality"]), as_bool(row["known_exploited"]),
            as_bool(row["active_exploitation"]), as_bool(row["externally_reachable"]),
            as_bool(row["identity_privileged"]), int(row["control_coverage"]),
            int(row["days_open"]), row["intelligence_confidence"], row["owner"], row["status"],
            float(row["priority_score"]), row["priority_band"], int(row["remediation_sla_days"]),
            as_bool(row["sla_breached"]), row["score_reasons"], row["recommended_action"],
        ))
    connection.executemany(statement, values)


def load_named_queries(sql_path: Path) -> dict[str, str]:
    queries: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    for line in sql_path.read_text(encoding="utf-8").splitlines():
        match = QUERY_NAME.match(line)
        if match:
            if current_name:
                queries[current_name] = "\n".join(current_lines).strip()
            current_name = match.group(1)
            current_lines = []
        elif current_name:
            current_lines.append(line)
    if current_name:
        queries[current_name] = "\n".join(current_lines).strip()
    if not queries:
        raise ValueError(f"no named queries found in {sql_path}")
    return queries


def execute_queries(
    connection: sqlite3.Connection, queries: dict[str, str]
) -> dict[str, tuple[list[str], list[tuple[object, ...]]]]:
    results = {}
    for name, statement in queries.items():
        cursor = connection.execute(statement)
        columns = [item[0] for item in cursor.description or []]
        results[name] = (columns, cursor.fetchall())
    return results


def print_results(results: dict[str, tuple[list[str], list[tuple[object, ...]]]]) -> None:
    for name, (columns, rows) in results.items():
        print(f"\n[{name}]")
        print("\t".join(columns))
        for row in rows:
            print("\t".join(str(value) for value in row))
        if not rows:
            print("(no rows)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prioritized_csv", type=Path)
    parser.add_argument("query_file", type=Path)
    args = parser.parse_args()

    with sqlite3.connect(":memory:") as connection:
        load_exposures(connection, args.prioritized_csv)
        results = execute_queries(connection, load_named_queries(args.query_file))
    print_results(results)


if __name__ == "__main__":
    main()
