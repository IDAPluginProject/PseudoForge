from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.baseline_adapters import (
    corpus_baseline_records_from_adapter_reports,
    external_baseline_ledger_from_adapter_reports,
    load_baseline_adapter_report,
)
from ida_pseudoforge.core.corpus_evidence import summarize_corpus_manifests
from ida_pseudoforge.core.evidence_pack import apply_evidence_ledgers, load_external_baseline_ledger


class BaselineAdapterTests(unittest.TestCase):
    def test_baseline_adapter_report_normalizes_comparison_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_report(Path(temp_dir), "ghidra")
            report = load_baseline_adapter_report(path)
            records = corpus_baseline_records_from_adapter_reports([report])
            ledger = external_baseline_ledger_from_adapter_reports(
                [report],
                default_corpus_name="corpus-a",
                default_target_family="windows_user_pe",
            )

        self.assertEqual("ghidra", report["tool"])
        self.assertEqual(2, report["summary"]["comparison_count"])
        self.assertEqual(1, report["summary"]["qualified_comparison_count"])
        self.assertEqual("ghidra", records[0]["tool"])
        self.assertEqual("passed", records[0]["status"])
        self.assertEqual("pseudoforge_external_baseline_ledger_v1", ledger["schema"])
        self.assertEqual(2, len(ledger["baselines"]))
        self.assertEqual("corpus-a", ledger["baselines"][0]["corpus_name"])

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

    def test_baseline_adapter_tool_writes_claim_gate_ledger(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = _write_report(root, "binary-ninja")
            ledger_path = root / "external-baseline-ledger.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_baseline_adapter.py"),
                    str(report_path),
                    "--ledger-out",
                    str(ledger_path),
                    "--corpus-name",
                    "corpus-a",
                    "--target-family",
                    "windows_user_pe",
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            ledger = load_external_baseline_ledger(ledger_path)
            merged = apply_evidence_ledgers(_manifest(), external_baseline_ledgers=[ledger])
            evidence = summarize_corpus_manifests([merged])

        self.assertEqual(2, len(ledger["baselines"]))
        self.assertEqual(1, evidence["qualified_external_baseline_count"])
        self.assertEqual(["binary-ninja"], evidence["qualified_external_baselines"])

    def test_baseline_adapter_ledger_requires_corpus_metadata(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = _write_report(root, "ghidra")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_baseline_adapter.py"),
                    str(report_path),
                    "--ledger-out",
                    str(root / "external-baseline-ledger.json"),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(2, completed.returncode)
        self.assertIn("corpus_name is required", completed.stderr)


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


def _manifest() -> dict[str, object]:
    return {
        "schema": "pseudoforge_general_corpus_manifest_v1",
        "corpora": [
            {
                "name": "corpus-a",
                "target_family": "windows_user_pe",
                "origin": "unit",
                "claim_eligible": True,
                "source_reference": "unit://corpus-a",
                "function_count": 10,
                "ground_truth_pair_count": 1,
                "ground_truth_pairs": [
                    {
                        "id": "gt-a",
                        "reference": "unit://corpus-a/gt-a",
                        "expectation": "Baseline comparison attaches to this corpus.",
                    }
                ],
                "ir_evidence_function_count": 10,
                "ir_total_function_count": 10,
                "cross_function_contract_count": 0,
                "external_baselines": [],
                "analyst_audit_count": 0,
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
