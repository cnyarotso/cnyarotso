import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from prioritize_exposures import prioritize, score_exposure  # noqa: E402


def record(**overrides: str) -> dict[str, str]:
    baseline = {
        "exposure_id": "EXP-TEST",
        "asset_name": "synthetic-host",
        "business_service": "Test Service",
        "cve": "CVE-2026-19999",
        "cvss": "5.0",
        "asset_criticality": "3",
        "known_exploited": "false",
        "active_exploitation": "false",
        "externally_reachable": "false",
        "identity_privileged": "false",
        "control_coverage": "80",
        "days_open": "5",
        "intelligence_confidence": "low",
        "owner": "Test Owner",
        "status": "open",
    }
    baseline.update(overrides)
    return baseline


class ExposureScoringTests(unittest.TestCase):
    def test_combined_threat_and_asset_context_produces_critical_priority(self) -> None:
        result = score_exposure(
            record(
                cvss="8.0",
                asset_criticality="5",
                known_exploited="true",
                active_exploitation="true",
                externally_reachable="true",
                control_coverage="40",
                intelligence_confidence="high",
            )
        )
        self.assertEqual(result["priority_band"], "Critical")
        self.assertIn("active exploitation", result["score_reasons"])

    def test_context_can_outrank_cvss_alone(self) -> None:
        high_cvss = record(exposure_id="EXP-A", cvss="9.8")
        threat_informed = record(
            exposure_id="EXP-B",
            cvss="6.5",
            asset_criticality="5",
            known_exploited="true",
            active_exploitation="true",
            externally_reachable="true",
            intelligence_confidence="high",
        )
        ranked = prioritize([high_cvss, threat_informed])
        self.assertEqual(ranked[0]["exposure_id"], "EXP-B")

    def test_open_record_beyond_sla_is_flagged(self) -> None:
        result = score_exposure(record(days_open="120"))
        self.assertEqual(result["sla_breached"], "true")

    def test_confidence_does_not_add_points_without_threat_evidence(self) -> None:
        low = score_exposure(record(intelligence_confidence="low"))
        high = score_exposure(record(intelligence_confidence="high"))
        self.assertEqual(low["priority_score"], high["priority_score"])

    def test_remediated_record_requires_validation_not_sla_breach(self) -> None:
        result = score_exposure(record(days_open="120", status="remediated"))
        self.assertEqual(result["sla_breached"], "false")
        self.assertTrue(result["recommended_action"].startswith("Validate closure"))

    def test_duplicate_exposure_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be unique"):
            prioritize([record(), record()])

    def test_fractional_integer_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a whole number"):
            score_exposure(record(asset_criticality="3.9"))

    def test_out_of_range_value_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be between 0 and 100"):
            score_exposure(record(control_coverage="101"))


if __name__ == "__main__":
    unittest.main()
