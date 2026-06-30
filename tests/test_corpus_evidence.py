from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, load_corpus_manifest


class CorpusEvidenceTests(unittest.TestCase):
    def test_corpus_manifest_summarizes_claim_eligible_real_corpora(self) -> None:
        manifest_path = Path(__file__).resolve().parent / "fixtures" / "general_corpus" / "claim_useful_manifest.json"

        evidence = load_corpus_evidence([manifest_path])

        self.assertEqual("pseudoforge_general_corpus_evidence_v1", evidence["schema"])
        self.assertEqual(1, evidence["manifest_count"])
        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertEqual(1, evidence["synthetic_or_unqualified_corpus_count"])
        self.assertEqual(85, evidence["real_corpus_function_count"])
        self.assertEqual(2, evidence["ground_truth_pair_count"])
        self.assertEqual(2, evidence["qualified_ground_truth_pair_count"])
        self.assertEqual(0.0, evidence["ir_evidence_coverage"])
        self.assertEqual(["linux_elf_user", "windows_user_pe"], evidence["target_families"])

    def test_synthetic_entries_do_not_raise_claim_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "toy",
                                "target_family": "windows_user_pe",
                                "origin": "synthetic",
                                "claim_eligible": True,
                                "function_count": 10000,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_corpus_evidence([manifest_path])

            self.assertEqual(0, evidence["real_corpus_count"])
            self.assertEqual(0, evidence["real_corpus_function_count"])
            self.assertEqual(1, evidence["synthetic_or_unqualified_corpus_count"])

    def test_corpus_manifest_reports_missing_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "target_family": "windows_user_pe",
                                "origin": "open_source_build_summary",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "name is required"):
                load_corpus_manifest(manifest_path)

    def test_claim_eligible_real_corpus_requires_source_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "real_without_reference",
                                "target_family": "windows_user_pe",
                                "origin": "open_source_build_summary",
                                "claim_eligible": True,
                                "function_count": 10,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "source_reference is required"):
                load_corpus_manifest(manifest_path)

    def test_ir_evidence_counts_must_be_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "bad_ir_counts",
                                "target_family": "windows_user_pe",
                                "origin": "synthetic",
                                "claim_eligible": False,
                                "function_count": 5,
                                "ir_evidence_function_count": 6,
                                "ir_total_function_count": 5,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "ir_evidence_function_count exceeds"):
                load_corpus_manifest(manifest_path)

    def test_count_fields_must_be_numeric(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "bad_count",
                                "target_family": "windows_user_pe",
                                "origin": "synthetic",
                                "function_count": "many",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "function_count must be an integer"):
                load_corpus_manifest(manifest_path)

    def test_external_baseline_strings_are_not_qualified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "raw_baseline_names",
                                "target_family": "windows_user_pe",
                                "origin": "open_source_build_summary",
                                "claim_eligible": True,
                                "source_reference": "local-summary://raw_baseline_names",
                                "function_count": 10,
                                "ground_truth_pair_count": 1,
                                "ground_truth_pairs": [
                                    {
                                        "id": "pair",
                                        "reference": "local-summary://raw_baseline_names/pair",
                                        "expectation": "one qualified pair",
                                    }
                                ],
                                "external_baselines": ["ghidra", "binary-ninja"],
                                "analyst_audit_count": 1,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_corpus_evidence([manifest_path])

            self.assertEqual(2, evidence["external_baseline_count"])
            self.assertEqual(0, evidence["qualified_external_baseline_count"])
            self.assertEqual(1, evidence["analyst_audit_count"])
            self.assertEqual(0, evidence["qualified_analyst_audit_count"])

    def test_structured_baselines_and_audits_are_qualified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "qualified_evidence",
                                "target_family": "windows_user_pe",
                                "origin": "open_source_build_summary",
                                "claim_eligible": True,
                                "source_reference": "local-summary://qualified_evidence",
                                "function_count": 10,
                                "ground_truth_pair_count": 1,
                                "ground_truth_pairs": [
                                    {
                                        "id": "pair",
                                        "reference": "local-summary://qualified_evidence/pair",
                                        "expectation": "one qualified pair",
                                    }
                                ],
                                "external_baselines": [
                                    {
                                        "name": "ghidra",
                                        "reference": "local-summary://qualified_evidence/ghidra",
                                        "metric": "accepted_observation_delta",
                                    }
                                ],
                                "analyst_audits": [
                                    {
                                        "id": "audit",
                                        "reviewer": "local-review",
                                        "reference": "local-summary://qualified_evidence/audit",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_corpus_evidence([manifest_path])

            self.assertEqual(1, evidence["qualified_external_baseline_count"])
            self.assertEqual(1, evidence["qualified_analyst_audit_count"])

    def test_structured_cross_function_contracts_are_qualified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "contract_evidence",
                                "target_family": "windows_user_pe",
                                "origin": "open_source_build_summary",
                                "claim_eligible": True,
                                "source_reference": "local-summary://contract_evidence",
                                "function_count": 10,
                                "cross_function_contract_count": 99,
                                "cross_function_contracts": [
                                    {
                                        "id": "contract",
                                        "reference": "local-summary://contract_evidence/contract",
                                        "source_function": "OpenThing",
                                        "sink_function": "CloseThing",
                                        "contract": "open result reaches close",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_corpus_evidence([manifest_path])

            self.assertEqual(99, evidence["cross_function_contract_count"])
            self.assertEqual(1, evidence["qualified_cross_function_contract_count"])

    def test_external_world_class_evidence_axes_are_counted_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_corpus_manifest_v1",
                        "corpora": [
                            {
                                "name": "external_axes",
                                "target_family": "linux_elf_user",
                                "origin": "open_source_build_summary",
                                "claim_eligible": True,
                                "source_reference": "local-summary://external_axes",
                                "function_count": 10,
                                "semantic_ground_truth_pairs": [
                                    {
                                        "id": "semantic-open-close",
                                        "reference": "local-summary://external_axes/semantic",
                                        "function": "open_and_close",
                                        "semantic_kind": "resource_lifetime",
                                        "oracle": "source-level expected close on every success path",
                                        "validation": "source-map + runtime check",
                                        "status": "validated",
                                    },
                                    {
                                        "id": "semantic-blocked",
                                        "reference": "local-summary://external_axes/blocked",
                                        "function": "unknown",
                                        "semantic_kind": "symbol_identity",
                                        "oracle": "symbol-only",
                                        "validation": "not semantic",
                                        "status": "blocked",
                                    },
                                ],
                                "real_replay_targets": [
                                    {
                                        "family": "linux_elf_user",
                                        "tool": "ida",
                                        "reference": "ida-replay://linux",
                                        "function_count": 10,
                                        "status": "passed",
                                    }
                                ],
                                "multi_ir_records": [
                                    {
                                        "function": "open_and_close",
                                        "views": ["ida_hexrays", "ghidra_pcode", "angr_ail"],
                                        "reference": "multi-ir://open_and_close",
                                        "status": "validated",
                                    }
                                ],
                                "dataflow_contracts": [
                                    {
                                        "id": "fd-open-close",
                                        "reference": "dataflow://fd-open-close",
                                        "source_function": "open",
                                        "sink_function": "close",
                                        "contract": "file descriptor reaches close",
                                        "proof": "def-use source-to-sink path",
                                        "status": "validated",
                                    }
                                ],
                                "baseline_comparisons": [
                                    {
                                        "tool": "ghidra",
                                        "reference": "baseline://ghidra/open_and_close",
                                        "metric": "semantic_contract_recall",
                                        "pseudoforge_value": "1.0",
                                        "baseline_value": "0.5",
                                        "status": "passed",
                                    }
                                ],
                                "agentic_tasks": [
                                    {
                                        "id": "task-resource-lifetime",
                                        "reference": "agentic://task-resource-lifetime",
                                        "objective": "recover fd lifetime",
                                        "score": "1.0",
                                        "status": "passed",
                                    },
                                    {
                                        "id": "task-failed",
                                        "reference": "agentic://task-failed",
                                        "objective": "negative task",
                                        "score": "0.0",
                                        "status": "failed",
                                    },
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_corpus_evidence([manifest_path])

        self.assertEqual(2, evidence["semantic_ground_truth_pair_count"])
        self.assertEqual(1, evidence["qualified_semantic_ground_truth_pair_count"])
        self.assertEqual(1, evidence["qualified_non_windows_real_replay_family_count"])
        self.assertEqual(["linux_elf_user"], evidence["qualified_real_replay_families"])
        self.assertEqual(1, evidence["qualified_multi_ir_record_count"])
        self.assertEqual(3, evidence["qualified_multi_ir_view_count"])
        self.assertEqual(1, evidence["qualified_dataflow_contract_count"])
        self.assertEqual(1, evidence["qualified_baseline_tool_count"])
        self.assertEqual(2, evidence["agentic_task_count"])
        self.assertEqual(1, evidence["qualified_agentic_task_count"])
        self.assertEqual(0.5, evidence["agentic_task_precision"])


if __name__ == "__main__":
    unittest.main()
