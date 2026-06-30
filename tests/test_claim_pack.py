from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ClaimPackTests(unittest.TestCase):
    def test_claim_pack_tool_writes_benchmark_gap_and_summary(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        corpus_root = repo_root / "tests" / "fixtures" / "general_corpus"
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "claim-pack"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_claim_pack.py"),
                    str(fixture_root),
                    "--corpus-manifest",
                    str(corpus_root / "claim_useful_manifest.json"),
                    "--external-baseline-ledger",
                    str(corpus_root / "external_baseline_ledger.json"),
                    "--analyst-audit-ledger",
                    str(corpus_root / "analyst_audit_ledger.json"),
                    "--cross-function-contract-ledger",
                    str(corpus_root / "cross_function_contract_ledger.json"),
                    "--no-runtime",
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            benchmark = json.loads((out_dir / "benchmark.json").read_text(encoding="utf-8"))
            gap = json.loads((out_dir / "claim-gap.json").read_text(encoding="utf-8"))
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            markdown = (out_dir / "claim-gap.md").read_text(encoding="utf-8")

        self.assertEqual("useful general assistant", summary["claim_level"])
        self.assertEqual("useful general assistant", benchmark["claim_level"])
        self.assertGreater(gap["gap_count"], 0)
        self.assertFalse(summary["world_class_claim_allowed"])
        self.assertIn("PseudoForge World-Class Claim Gap", markdown)

    def test_claim_pack_can_attach_agentic_tasks_for_external_world_class(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            out_dir = root / "claim-pack"
            manifest_path = root / "external-world-class.json"
            task_suite_path = root / "agentic-tasks.json"
            manifest_path.write_text(json.dumps(_external_manifest()), encoding="utf-8")
            task_suite_path.write_text(json.dumps(_agentic_suite()), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_claim_pack.py"),
                    str(fixture_root),
                    "--corpus-manifest",
                    str(manifest_path),
                    "--agentic-task-suite",
                    str(task_suite_path),
                    "--no-runtime",
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            benchmark = json.loads((out_dir / "benchmark.json").read_text(encoding="utf-8"))

        self.assertEqual("external-world-class candidate", summary["claim_level"])
        self.assertTrue(summary["world_class_claim_allowed"])
        self.assertTrue(summary["external_world_class_claim_allowed"])
        self.assertEqual(0, summary["external_gap_count"])
        self.assertEqual(5, benchmark["claim_gate"]["corpus_evidence"]["qualified_agentic_task_count"])


def _external_manifest() -> dict[str, object]:
    main = {
        "name": "external_world_class_linux_semantic",
        "target_family": "linux_elf_user",
        "origin": "open_source_build_summary",
        "claim_eligible": True,
        "source_reference": "local-summary://external_world_class_linux_semantic",
        "function_count": 600,
        "ground_truth_pair_count": 300,
        "ground_truth_pairs": [
            {
                "id": "gt-%03d" % index,
                "reference": "local-gt://gt-%03d" % index,
                "expectation": "semantic source mapping %03d is preserved" % index,
            }
            for index in range(300)
        ],
        "ir_evidence_function_count": 560,
        "ir_total_function_count": 600,
        "cross_function_contract_count": 50,
        "cross_function_contracts": [
            {
                "id": "cross-%03d" % index,
                "reference": "local-cross://cross-%03d" % index,
                "source_function": "source_%03d" % index,
                "sink_function": "sink_%03d" % index,
                "contract": "cross-function API contract %03d" % index,
            }
            for index in range(50)
        ],
        "external_baselines": [
            {
                "name": "ghidra",
                "reference": "baseline://ghidra",
                "metric": "accepted_observation_delta",
            },
            {
                "name": "binary-ninja",
                "reference": "baseline://binary-ninja",
                "metric": "accepted_observation_delta",
            },
            {
                "name": "angr",
                "reference": "baseline://angr",
                "metric": "accepted_observation_delta",
            },
        ],
        "analyst_audits": [
            {
                "id": "audit-external-world-class",
                "reviewer": "local-review",
                "reference": "audit://external-world-class",
            }
        ],
        "semantic_ground_truth_pairs": [
            {
                "id": "semantic-%03d" % index,
                "reference": "semantic://semantic-%03d" % index,
                "function": "function_%03d" % index,
                "semantic_kind": "source_behavior_equivalence",
                "oracle": "source map plus deterministic runtime expectation",
                "validation": "source-level fixture and expected observation",
                "status": "validated",
            }
            for index in range(100)
        ],
        "real_replay_targets": [
            {
                "family": "windows_user_pe",
                "tool": "ida",
                "reference": "replay://windows-user",
                "function_count": 300,
                "status": "passed",
            },
            {
                "family": "windows_kernel",
                "tool": "ida",
                "reference": "replay://windows-kernel",
                "function_count": 250,
                "status": "passed",
            },
            {
                "family": "linux_elf_user",
                "tool": "ghidra",
                "reference": "replay://linux",
                "function_count": 200,
                "status": "passed",
            },
            {
                "family": "macos_macho_user",
                "tool": "ghidra",
                "reference": "replay://macos",
                "function_count": 150,
                "status": "passed",
            },
        ],
        "multi_ir_records": [
            {
                "function": "function_%03d" % index,
                "views": ["ida_hexrays", "ghidra_pcode", "angr_ail", "binaryninja_hlil"],
                "reference": "multi-ir://function-%03d" % index,
                "status": "validated",
            }
            for index in range(60)
        ],
        "dataflow_contracts": [
            {
                "id": "dataflow-%03d" % index,
                "reference": "dataflow://contract-%03d" % index,
                "source_function": "open_%03d" % index,
                "sink_function": "close_%03d" % index,
                "contract": "resource lifetime source reaches sink",
                "proof": "def-use path and source oracle",
                "status": "validated",
            }
            for index in range(30)
        ],
        "baseline_comparisons": [
            {
                "tool": tool,
                "reference": "baseline-comparison://%s/%d" % (tool, index),
                "metric": "semantic_contract_recall",
                "pseudoforge_value": "1.0",
                "baseline_value": "0.7",
                "status": "passed",
            }
            for index, tool in enumerate(
                [
                    "ghidra",
                    "ghidra",
                    "ghidra",
                    "binary-ninja",
                    "binary-ninja",
                    "binary-ninja",
                    "angr",
                    "angr",
                    "angr",
                ]
            )
        ],
    }
    return {
        "schema": "pseudoforge_general_corpus_manifest_v1",
        "corpora": [
            main,
            _small_corpus("external_world_class_windows_user", "windows_user_pe", 300),
            _small_corpus("external_world_class_windows_kernel", "windows_kernel", 250),
            _small_corpus("external_world_class_macos", "macos_macho_user", 200),
        ],
    }


def _small_corpus(name: str, target_family: str, function_count: int) -> dict[str, object]:
    return {
        "name": name,
        "target_family": target_family,
        "origin": "open_source_build_summary",
        "claim_eligible": True,
        "source_reference": "local-summary://%s" % name,
        "function_count": function_count,
        "ir_evidence_function_count": function_count,
        "ir_total_function_count": function_count,
        "ground_truth_pair_count": 0,
        "ground_truth_pairs": [],
        "cross_function_contract_count": 0,
        "external_baselines": [],
        "analyst_audit_count": 0,
    }


def _agentic_suite() -> dict[str, object]:
    return {
        "schema": "pseudoforge_agentic_task_suite_v1",
        "tasks": [
            {
                "id": "agentic-task-%02d" % index,
                "reference": "agentic://task-%02d" % index,
                "objective": "verify general-analysis evidence gate %02d" % index,
                "assertions": [
                    {
                        "path": "claim_gate.metrics.target_family_count",
                        "operator": "min",
                        "value": 5,
                    },
                    {
                        "path": "claim_gate.metrics.false_positives",
                        "operator": "max",
                        "value": 0,
                    },
                ],
            }
            for index in range(5)
        ],
    }


if __name__ == "__main__":
    unittest.main()
