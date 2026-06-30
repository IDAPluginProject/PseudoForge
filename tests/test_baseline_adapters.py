from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.baseline_adapters import (
    corpus_baseline_records_from_adapter_reports,
    load_baseline_adapter_report,
)


class BaselineAdapterTests(unittest.TestCase):
    def test_baseline_adapter_report_normalizes_comparison_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_report(Path(temp_dir), "ghidra")
            report = load_baseline_adapter_report(path)
            records = corpus_baseline_records_from_adapter_reports([report])

        self.assertEqual("ghidra", report["tool"])
        self.assertEqual(2, report["summary"]["comparison_count"])
        self.assertEqual(1, report["summary"]["qualified_comparison_count"])
        self.assertEqual("ghidra", records[0]["tool"])
        self.assertEqual("passed", records[0]["status"])

    def test_baseline_adapter_tool_writes_records(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = _write_report(root, "angr")
            out_path = root / "baseline-records.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_baseline_adapter.py"),
                    str(report_path),
                    "--json-out",
                    str(out_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            payload = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(2, len(payload["baseline_comparisons"]))
        self.assertEqual("angr", payload["baseline_comparisons"][0]["tool"])


def _write_report(root: Path, tool: str) -> Path:
    path = root / ("%s.json" % tool)
    path.write_text(
        json.dumps(
            {
                "schema": "pseudoforge_baseline_adapter_report_v1",
                "tool": tool,
                "comparisons": [
                    {
                        "reference": "baseline://%s/pass" % tool,
                        "metric": "semantic_contract_recall",
                        "pseudoforge_value": "1.0",
                        "baseline_value": "0.5",
                        "status": "passed",
                    },
                    {
                        "reference": "baseline://%s/blocked" % tool,
                        "metric": "semantic_contract_recall",
                        "pseudoforge_value": "0.0",
                        "baseline_value": "0.0",
                        "status": "blocked",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    unittest.main()
