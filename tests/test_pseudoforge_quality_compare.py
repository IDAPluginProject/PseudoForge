from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_quality_compare import compare_quality_reports, main, render_compare_markdown


class PseudoForgeQualityCompareTests(unittest.TestCase):
    def test_compare_quality_reports_marks_directional_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.json"
            new_path = Path(temp_dir) / "new.json"
            old_path.write_text(
                json.dumps(
                    {
                        "corpus_root": "old",
                        "totals": {
                            "summaries": 2,
                            "warnings": 10,
                            "applied_renames": 3,
                        },
                        "structure_quality_score": {
                            "score": 5.5,
                            "components": {
                                "prototype_correctness": {"score": 4.0},
                                "call_argument_cleanup": {"score": 5.0},
                                "structure_identity_evidence": {"score": 3.0},
                                "offset_residue": {"score": 4.5},
                                "pointer_indexed_residue": {"score": 4.0},
                                "generic_identifier_residue": {"score": 6.0},
                                "rewrite_safety_blockers": {"score": 7.0},
                                "ida_plugin_packaging_boundary": {"score": 10.0},
                            },
                        },
                        "rename_stats": {"apply_rate": 30.0},
                        "body_text_stats": {
                            "generic_identifier_tokens": 100,
                            "pointer_indexed_offset_deref_patterns": 9,
                        },
                        "text_stats": {"inferred_offset_rewrite_blockers": 1},
                        "layout_rewrite_ready_stats": {
                            "source_provenance": {"none": 2, "domain_identity": 1}
                        },
                        "layout_rewrite_preview_stats": {
                            "source_provenance": {"none": 2, "domain_identity": 1}
                        },
                        "body_offset_residue_review_stats": {
                            "totals": {
                                "functions_with_offset_residue": 4,
                                "offset_deref_survivors": 40,
                                "generic_parameter_survivors": 6,
                                "functions_with_rewrite_blockers": 1,
                                "functions_with_rewrite_ready": 2,
                            },
                            "review_classes": {
                                "hot_cluster_missing_identity": 2,
                                "unclassified_offset_residue": 3,
                                "report_only_blocked_residue": 1,
                            },
                        },
                        "pointer_indexed_offset_stats": {
                            "totals": {
                                "pointer_indexed_layout_rewrite_candidates": 2,
                                "pointer_indexed_rewrite_applied": 1,
                            }
                        },
                        "prototype_correction_stats": {
                            "totals": {
                                "function_identity_candidates": 1,
                                "applied_parameter_type_corrections": 1,
                                "blocked_parameter_type_corrections": 0,
                                "generic_parameter_survivors": 5,
                                "offset_deref_survivors": 7,
                                "body_rewrite_ready": 1,
                                "negative_control_functions": 1,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            new_path.write_text(
                json.dumps(
                    {
                        "corpus_root": "new",
                        "totals": {
                            "summaries": 2,
                            "warnings": 4,
                            "applied_renames": 8,
                        },
                        "structure_quality_score": {
                            "score": 7.25,
                            "components": {
                                "prototype_correctness": {"score": 7.0},
                                "call_argument_cleanup": {"score": 8.0},
                                "structure_identity_evidence": {"score": 7.5},
                                "offset_residue": {"score": 8.5},
                                "pointer_indexed_residue": {"score": 8.0},
                                "generic_identifier_residue": {"score": 5.0},
                                "rewrite_safety_blockers": {"score": 8.0},
                                "ida_plugin_packaging_boundary": {"score": 10.0},
                            },
                        },
                        "rename_stats": {"apply_rate": 80.0},
                        "body_text_stats": {
                            "generic_identifier_tokens": 120,
                            "pointer_indexed_offset_deref_patterns": 3,
                        },
                        "text_stats": {"inferred_offset_rewrite_blockers": 4},
                        "layout_rewrite_ready_stats": {
                            "source_provenance": {"domain_identity": 3}
                        },
                        "layout_rewrite_preview_stats": {
                            "source_provenance": {"domain_identity": 3}
                        },
                        "body_offset_residue_review_stats": {
                            "totals": {
                                "functions_with_offset_residue": 2,
                                "offset_deref_survivors": 15,
                                "generic_parameter_survivors": 2,
                                "functions_with_rewrite_blockers": 4,
                                "functions_with_rewrite_ready": 1,
                            },
                            "review_classes": {
                                "hot_cluster_missing_identity": 1,
                                "unclassified_offset_residue": 1,
                                "report_only_blocked_residue": 4,
                            },
                        },
                        "pointer_indexed_offset_stats": {
                            "totals": {
                                "pointer_indexed_layout_rewrite_candidates": 5,
                                "pointer_indexed_rewrite_applied": 4,
                            }
                        },
                        "prototype_correction_stats": {
                            "totals": {
                                "function_identity_candidates": 4,
                                "applied_parameter_type_corrections": 3,
                                "blocked_parameter_type_corrections": 2,
                                "generic_parameter_survivors": 2,
                                "offset_deref_survivors": 3,
                                "body_rewrite_ready": 4,
                                "negative_control_functions": 1,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = compare_quality_reports(old_path, new_path)
            metrics = {item["name"]: item for item in report["metrics"]}

            self.assertTrue(report["same_function_count"])
            self.assertEqual(1.75, metrics["structure_quality_score"]["delta"])
            self.assertEqual("improved", metrics["structure_quality_score"]["status"])
            self.assertEqual(4.0, metrics["structure_quality_offset_residue"]["delta"])
            self.assertEqual("improved", metrics["structure_quality_offset_residue"]["status"])
            self.assertEqual(-1.0, metrics["structure_quality_generic_identifier_residue"]["delta"])
            self.assertEqual("regressed", metrics["structure_quality_generic_identifier_residue"]["status"])
            self.assertEqual(-6, metrics["warnings"]["delta"])
            self.assertEqual("improved", metrics["warnings"]["status"])
            self.assertEqual(5, metrics["applied_renames"]["delta"])
            self.assertEqual("improved", metrics["applied_renames"]["status"])
            self.assertEqual(20, metrics["body_generic_identifier_tokens"]["delta"])
            self.assertEqual("regressed", metrics["body_generic_identifier_tokens"]["status"])
            self.assertEqual(-6, metrics["body_pointer_indexed_offset_deref_patterns"]["delta"])
            self.assertEqual("improved", metrics["body_pointer_indexed_offset_deref_patterns"]["status"])
            self.assertEqual(3, metrics["inferred_offset_rewrite_blockers"]["delta"])
            self.assertEqual("info", metrics["inferred_offset_rewrite_blockers"]["status"])
            self.assertEqual(-2, metrics["layout_rewrite_ready_source_none"]["delta"])
            self.assertEqual("improved", metrics["layout_rewrite_ready_source_none"]["status"])
            self.assertEqual(-2, metrics["layout_rewrite_preview_source_none"]["delta"])
            self.assertEqual("improved", metrics["layout_rewrite_preview_source_none"]["status"])
            self.assertEqual(-2, metrics["body_offset_residue_functions"]["delta"])
            self.assertEqual("improved", metrics["body_offset_residue_functions"]["status"])
            self.assertEqual(-25, metrics["body_offset_deref_survivors"]["delta"])
            self.assertEqual("improved", metrics["body_offset_deref_survivors"]["status"])
            self.assertEqual(-4, metrics["body_offset_generic_parameter_survivors"]["delta"])
            self.assertEqual("improved", metrics["body_offset_generic_parameter_survivors"]["status"])
            self.assertEqual(-1, metrics["body_offset_hot_cluster_missing_identity_functions"]["delta"])
            self.assertEqual("improved", metrics["body_offset_hot_cluster_missing_identity_functions"]["status"])
            self.assertEqual(-2, metrics["body_offset_unclassified_residue_functions"]["delta"])
            self.assertEqual("improved", metrics["body_offset_unclassified_residue_functions"]["status"])
            self.assertEqual(3, metrics["body_offset_report_only_blocked_functions"]["delta"])
            self.assertEqual("info", metrics["body_offset_report_only_blocked_functions"]["status"])
            self.assertEqual(3, metrics["body_offset_rewrite_blocker_functions"]["delta"])
            self.assertEqual("info", metrics["body_offset_rewrite_blocker_functions"]["status"])
            self.assertEqual(-1, metrics["body_offset_rewrite_ready_functions"]["delta"])
            self.assertEqual("info", metrics["body_offset_rewrite_ready_functions"]["status"])
            self.assertEqual(3, metrics["pointer_indexed_layout_rewrite_candidates"]["delta"])
            self.assertEqual("info", metrics["pointer_indexed_layout_rewrite_candidates"]["status"])
            self.assertEqual(3, metrics["pointer_indexed_rewrite_applied"]["delta"])
            self.assertEqual("improved", metrics["pointer_indexed_rewrite_applied"]["status"])
            self.assertEqual(2, metrics["prototype_parameter_type_corrections_applied"]["delta"])
            self.assertEqual("improved", metrics["prototype_parameter_type_corrections_applied"]["status"])
            self.assertEqual(-3, metrics["prototype_generic_parameter_survivors"]["delta"])
            self.assertEqual("improved", metrics["prototype_generic_parameter_survivors"]["status"])
            self.assertEqual(-4, metrics["prototype_offset_deref_survivors"]["delta"])
            self.assertEqual("improved", metrics["prototype_offset_deref_survivors"]["status"])
            self.assertEqual("info", metrics["prototype_parameter_type_corrections_blocked"]["status"])
            self.assertIn("warnings", render_compare_markdown(report))
            self.assertIn("prototype_parameter_type_corrections_applied", render_compare_markdown(report))

    def test_quality_compare_cli_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.json"
            new_path = Path(temp_dir) / "new.json"
            out_dir = Path(temp_dir) / "compare"
            payload = {
                "corpus_root": "sample",
                "totals": {"summaries": 1, "warnings": 1, "applied_renames": 1},
                "rename_stats": {"apply_rate": 100.0},
            }
            old_path.write_text(json.dumps(payload), encoding="utf-8")
            new_path.write_text(json.dumps(payload), encoding="utf-8")

            exit_code = main(
                [
                    "--old",
                    str(old_path),
                    "--new",
                    str(new_path),
                    "--out",
                    str(out_dir),
                    "--format",
                    "both",
                ]
            )

            self.assertEqual(0, exit_code)
            self.assertTrue((out_dir / "quality-compare.json").exists())
            self.assertTrue((out_dir / "quality-compare.md").exists())


if __name__ == "__main__":
    unittest.main()
