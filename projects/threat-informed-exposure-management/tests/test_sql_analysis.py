import sqlite3
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from run_sql_analysis import execute_queries, load_exposures, load_named_queries  # noqa: E402


class SqlAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        load_exposures(self.connection, PROJECT_ROOT / "output" / "prioritized_exposures.csv")
        self.queries = load_named_queries(PROJECT_ROOT / "sql" / "security_exposure_analysis.sql")

    def tearDown(self) -> None:
        self.connection.close()

    def test_all_named_queries_execute(self) -> None:
        results = execute_queries(self.connection, self.queries)
        self.assertEqual(
            set(results),
            {"urgent_action_queue", "overdue_by_owner", "top_exposure_per_service", "duplicate_identifier_check"},
        )

    def test_urgent_queue_is_ranked_and_excludes_remediated_items(self) -> None:
        _, rows = execute_queries(
            self.connection, {"urgent_action_queue": self.queries["urgent_action_queue"]}
        )["urgent_action_queue"]
        self.assertEqual(rows[0][0], "EXP-001")
        self.assertNotIn("EXP-006", {row[0] for row in rows})

    def test_duplicate_identifier_check_returns_no_rows(self) -> None:
        _, rows = execute_queries(
            self.connection,
            {"duplicate_identifier_check": self.queries["duplicate_identifier_check"]},
        )["duplicate_identifier_check"]
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
