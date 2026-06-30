from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.agentic_benchmark import (
    apply_agentic_report_to_corpus_evidence,
    load_agentic_task_suite,
    run_agentic_benchmark,
)
from tests.test_claim_gate import _strong_report


class AgenticBenchmarkTests(unittest.TestCase):
    def test_agentic_task_suite_scores_report_assertions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            suite_path = _write_suite(Path(temp_dir), pass_count=1, fail_count=1)
            suite = load_agentic_task_suite(suite_path)
            report = _strong_report()
            report["claim_gate"] = {
                "metrics": {
                    "target_family_count": 2,
                    "false_positives": 0,
                }
            }

            agentic = run_agentic_benchmark(suite, report)
            evidence = apply_agentic_report_to_corpus_evidence({}, agentic)

        self.assertEqual(2, agentic["task_count"])
        self.assertEqual(1, agentic["passed"])
        self.assertEqual(1, agentic["failed"])
        self.assertEqual(0.5, agentic["precision"])
        self.assertEqual(2, evidence["agentic_task_count"])
        self.assertEqual(1, evidence["qualified_agentic_task_count"])
        self.assertEqual(0.5, evidence["agentic_task_precision"])

    def test_agentic_benchmark_tool_writes_report(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            suite_path = _write_suite(root, pass_count=1, fail_count=0)
            report_path = root / "benchmark.json"
            out_path = root / "agentic.json"
            report = _strong_report()
            report["claim_gate"] = {
                "metrics": {
                    "target_family_count": 2,
                    "false_positives": 0,
                }
            }
            report_path.write_text(json.dumps(report), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_agentic_benchmark.py"),
                    str(suite_path),
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

        self.assertEqual(1, payload["passed"])
        self.assertEqual(0, payload["failed"])


def _write_suite(root: Path, pass_count: int, fail_count: int) -> Path:
    tasks = []
    for index in range(pass_count):
        tasks.append(
            {
                "id": "pass-%02d" % index,
                "reference": "agentic://pass-%02d" % index,
                "objective": "verify report target-family and false-positive gates",
                "assertions": [
                    {
                        "path": "claim_gate.metrics.target_family_count",
                        "operator": "min",
                        "value": 2,
                    },
                    {
                        "path": "claim_gate.metrics.false_positives",
                        "operator": "max",
                        "value": 0,
                    },
                ],
            }
        )
    for index in range(fail_count):
        tasks.append(
            {
                "id": "fail-%02d" % index,
                "reference": "agentic://fail-%02d" % index,
                "objective": "negative control for impossible target-family count",
                "assertions": [
                    {
                        "path": "claim_gate.metrics.target_family_count",
                        "operator": "min",
                        "value": 99,
                    }
                ],
            }
        )
    path = root / "tasks.json"
    path.write_text(
        json.dumps(
            {
                "schema": "pseudoforge_agentic_task_suite_v1",
                "tasks": tasks,
            }
        ),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    unittest.main()
