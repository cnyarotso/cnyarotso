import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analyze_exposure_history import analyze  # noqa: E402


class ExposureHistoryTests(unittest.TestCase):
    def test_history_metrics_find_remediation_reopen_and_expiring_exception(self) -> None:
        results = analyze(PROJECT_ROOT / "data" / "exposure_history.csv")
        self.assertIn(("EXP-001", 62), results["time_to_remediation"])
        self.assertEqual(results["reopened_exposures"], [("EXP-002", "2026-08-31", "open")])
        self.assertTrue(any(row[0] == "EXP-003" for row in results["recurring_exposures"]))
        self.assertEqual(results["exceptions_due_within_30_days"][0][0], "EXP-003")

    def test_duplicate_snapshot_exposure_pair_fails_closed(self) -> None:
        content = "snapshot_date,exposure_id,status,exception_review_date\n2026-09-01,X,open,\n2026-09-01,X,open,\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "duplicate.csv"
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                analyze(path)


if __name__ == "__main__":
    unittest.main()
