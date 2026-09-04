#!/usr/bin/env python3
"""Rank synthetic cyber exposures with a transparent, threat-informed model."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable

REQUIRED_FIELDS = {
    "exposure_id",
    "asset_name",
    "business_service",
    "cve",
    "cvss",
    "asset_criticality",
    "known_exploited",
    "active_exploitation",
    "externally_reachable",
    "identity_privileged",
    "control_coverage",
    "days_open",
    "intelligence_confidence",
    "owner",
    "status",
}
BOOLEAN_VALUES = {"true": True, "false": False}
CONFIDENCE_POINTS = {"low": 1.0, "moderate": 3.0, "high": 5.0}
VALID_STATUSES = {"open", "in_progress", "exception", "remediated"}
OUTPUT_FIELDS = [
    "priority_score",
    "priority_band",
    "remediation_sla_days",
    "sla_breached",
    "score_reasons",
    "recommended_action",
]


def parse_bool(value: str, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in BOOLEAN_VALUES:
        raise ValueError(f"{field} must be true or false; received {value!r}")
    return BOOLEAN_VALUES[normalized]


def parse_number(value: str, field: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be numeric; received {value!r}") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}; received {number}")
    return number


def validate_record(record: dict[str, str]) -> dict[str, object]:
    missing = sorted(field for field in REQUIRED_FIELDS if not record.get(field, "").strip())
    if missing:
        raise ValueError(f"missing required values: {', '.join(missing)}")

    confidence = record["intelligence_confidence"].strip().lower()
    if confidence not in CONFIDENCE_POINTS:
        raise ValueError(f"unsupported intelligence_confidence: {confidence!r}")
    status = record["status"].strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(f"unsupported status: {status!r}")

    return {
        **record,
        "cvss": parse_number(record["cvss"], "cvss", 0, 10),
        "asset_criticality": int(parse_number(record["asset_criticality"], "asset_criticality", 1, 5)),
        "known_exploited": parse_bool(record["known_exploited"], "known_exploited"),
        "active_exploitation": parse_bool(record["active_exploitation"], "active_exploitation"),
        "externally_reachable": parse_bool(record["externally_reachable"], "externally_reachable"),
        "identity_privileged": parse_bool(record["identity_privileged"], "identity_privileged"),
        "control_coverage": int(parse_number(record["control_coverage"], "control_coverage", 0, 100)),
        "days_open": int(parse_number(record["days_open"], "days_open", 0, 10000)),
        "intelligence_confidence": confidence,
        "status": status,
    }


def priority_band(score: float) -> tuple[str, int]:
    if score >= 75:
        return "Critical", 7
    if score >= 55:
        return "High", 15
    if score >= 35:
        return "Medium", 30
    return "Low", 90


def score_exposure(raw_record: dict[str, str]) -> dict[str, str]:
    record = validate_record(raw_record)
    score = (record["cvss"] / 10) * 15
    score += (record["asset_criticality"] / 5) * 15
    score += 20 if record["known_exploited"] else 0
    score += 15 if record["active_exploitation"] else 0
    score += 10 if record["externally_reachable"] else 0
    score += 5 if record["identity_privileged"] else 0
    score += ((100 - record["control_coverage"]) / 100) * 10
    score += min(record["days_open"] / 90, 1) * 5
    has_threat_signal = record["known_exploited"] or record["active_exploitation"]
    score += CONFIDENCE_POINTS[record["intelligence_confidence"]] if has_threat_signal else 0
    score = round(score, 1)

    band, sla_days = priority_band(score)
    breached = record["status"] != "remediated" and record["days_open"] > sla_days

    reasons: list[str] = []
    if record["known_exploited"]:
        reasons.append("known exploited")
    if record["active_exploitation"]:
        reasons.append("active exploitation")
    if record["externally_reachable"]:
        reasons.append("externally reachable")
    if record["identity_privileged"]:
        reasons.append("privileged system")
    if record["asset_criticality"] >= 4:
        reasons.append("critical business asset")
    if record["control_coverage"] < 60:
        reasons.append("weak control coverage")
    if breached:
        reasons.append("SLA breached")
    if not reasons:
        reasons.append("severity and baseline context")

    if record["status"] == "remediated":
        action = "Validate closure with a rescan or control check"
    elif record["active_exploitation"] and band in {"Critical", "High"}:
        action = "Hunt immediately; contain if activity is corroborated; remediate within SLA"
    elif band in {"Critical", "High"}:
        action = "Assign owner and remediate within SLA; apply compensating controls"
    elif band == "Medium":
        action = "Schedule remediation and monitor for threat activity"
    else:
        action = "Track, review intelligence, and validate during routine remediation"

    return {
        **{key: str(value).lower() if isinstance(value, bool) else str(value) for key, value in record.items()},
        "priority_score": f"{score:.1f}",
        "priority_band": band,
        "remediation_sla_days": str(sla_days),
        "sla_breached": str(breached).lower(),
        "score_reasons": "; ".join(reasons),
        "recommended_action": action,
    }


def prioritize(records: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    scored = [score_exposure(record) for record in records]
    identifiers = [record["exposure_id"] for record in scored]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("exposure_id values must be unique")
    return sorted(scored, key=lambda record: float(record["priority_score"]), reverse=True)


def run(input_path: Path, output_path: Path) -> None:
    with input_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        missing_columns = sorted(REQUIRED_FIELDS - set(reader.fieldnames or []))
        if missing_columns:
            raise ValueError(f"missing required columns: {', '.join(missing_columns)}")
        rows = prioritize(reader)
        input_fields = list(reader.fieldnames or [])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=input_fields + OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    args = parser.parse_args()
    run(args.input_csv, args.output_csv)
    print(f"Prioritized exposures written to {args.output_csv}")


if __name__ == "__main__":
    main()
