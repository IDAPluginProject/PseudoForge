from __future__ import annotations

import unittest

from ida_pseudoforge.core.rule_diagnostics import (
    format_rule_report_summary,
    summarize_rule_report,
)


class RuleDiagnosticsTests(unittest.TestCase):
    def test_rule_report_diagnostics_counts_statuses_and_details(self) -> None:
        report = {
            "matched_rules": [{"rule_id": "one"}],
            "rewrite_emissions": [
                {"kind": "call_arg_rewrite", "status": "applied"},
                {"kind": "text_rewrite", "status": "shadowed"},
                {"kind": "text_rewrite", "status": "rejected"},
            ],
            "rejected_emissions": [{"rule_id": "bad"}],
            "load_errors": [{"path": "project/broken.json", "error": "invalid json"}],
            "validation_errors": [{"path": "project/invalid.json", "error": "bad phase"}],
        }

        diagnostics = summarize_rule_report(report)

        self.assertEqual(1, diagnostics["matched_rules"])
        self.assertEqual(3, diagnostics["rewrite_emissions"]["total"])
        self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["applied"])
        self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["shadowed"])
        self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["rejected"])
        self.assertEqual(1, diagnostics["rewrite_emissions"]["by_kind"]["call_arg_rewrite"])
        self.assertEqual(2, diagnostics["rewrite_emissions"]["by_kind"]["text_rewrite"])
        self.assertEqual(1, diagnostics["rejected_emissions"])
        self.assertEqual(1, diagnostics["load_errors"])
        self.assertEqual(1, diagnostics["validation_errors"])

    def test_rule_report_summary_is_malformed_report_safe(self) -> None:
        summary = format_rule_report_summary(
            {
                "matched_rules": [{"rule_id": "one"}],
                "rewrite_emissions": None,
                "load_errors": [{"path": "bad.json", "error": "bad"}],
            },
            include_error_details=True,
        )

        self.assertIn("Rules: 1 matched, 0 rewrite(s) applied", summary)
        self.assertIn("Rule load errors:", summary)
        self.assertIn("- bad.json: bad", summary)


if __name__ == "__main__":
    unittest.main()
