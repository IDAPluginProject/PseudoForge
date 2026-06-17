from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_corpus_quality import (
    DECIMAL_STATUS_RE,
    _base_stability_review_profile,
    _decimal_status_like_literals,
    _layout_rewrite_blocker_review_profiles,
    analyze_corpus,
    main,
)


CLEANED = r"""
/*
    Kernel insights:
      - inferred_offset_layout: Offset layout hint: sessionSpace has 6 typed dereference(s) across 3 offset(s) +0x10, +0x18, +0x20; observed types: _DWORD, _QWORD. Review as an inferred structure base. confidence=0.83
      - inferred_offset_field_preview: Preview fields for sessionSpace: +0x10 _DWORD field_10; +0x18 _QWORD field_18; +0x20 _BYTE field_20; +0x28 _DWORD field_28; +0x30 _WORD field_30. Preview only; no IDB type or pseudocode rewrite was applied. confidence=0.81
      - inferred_offset_field_aliases: Alias map for sessionSpace: field_10=+0x10 _DWORD; field_18=+0x18 _QWORD; field_20=+0x20 _BYTE; field_28=+0x28 _DWORD; field_30=+0x30 _WORD. Use as review-only shorthand for repeated offset dereferences. confidence=0.73
      - inferred_offset_subfield_overlays: Subfield overlay evidence for sessionSpace: +0x20 field_20 uses 1/2-byte accesses (_BYTE/_WORD) [bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]. Review-only; field rewrite remains blocked for mixed-width offsets. confidence=0.72
      - inferred_offset_narrow_subfields: Narrow subfield candidates for sessionSpace: +0x20 field_20 uses 1/2-byte accesses (_BYTE/_WORD) [bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]. Audit-only; body rewrite remains disabled until the parent structure is trusted. confidence=0.72
      - inferred_offset_bitfield_aliases: Bitfield aliases for sessionSpace: field_20=+0x20 bitfield_low_nibble/bitfield_preserve_outer_nibbles/bitfield_clear_low_nibble masks=0xF,0xF00F,0xFFF0. Review-only names; body rewrite remains disabled until the parent structure is trusted. confidence=0.73
      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for sessionSpace: rewrite offset threshold requires at least 8 offsets; rewrite access threshold requires at least 12 accesses. Review-only aliases remain available. confidence=0.73
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for readySession: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Audit only; body rewrite was not applied. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for readySession: 12 dereference(s) can map to 8 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Preview artifact only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_near_ready: Offset field rewrite near-ready for nearlySession: 12 typed dereference(s) across 6 offset(s), missing offset threshold only. Audit only; body rewrite was not applied. confidence=0.75
      - inferred_offset_layout: Offset layout hint: v14 has 13 typed dereference(s) across 8 offset(s) +0x8, +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40; observed types: _BYTE, _DWORD, .... Review as a high-evidence temporary base before inferring a structure. confidence=0.74
      - inferred_offset_stable_base_source: Stable base source for v14: argument2 (argument source), 13 typed dereference(s) across 8 offset(s). Review-only; temp/generic base keeps rewrite blocked until source identity is trusted. confidence=0.68
      - inferred_offset_base_stability: Base stability evidence for v14: 2 initializer(s) before first layout access across 2 distinct RHS (argument2; argument3); 1 post-access assignment(s), 1 followed by later layout access. Review initializer dominance before enabling canonical rewrite. confidence=0.70
      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v14: base is a decompiler temporary. Review-only aliases remain available. confidence=0.73
      - inferred_offset_generic_base_evidence: Generic base evidence for context: 20 typed dereference(s) across 10 offset(s), blocker profile generic_only. Review-only; rewrite remains blocked until the base identity is trusted. confidence=0.74
      - inferred_offset_generic_base_trust_candidate: Generic base trust candidate for context: parameter source, generic-only blockers, 20 typed dereference(s) across 10 offset(s). Promotion eligible only when no other rewrite blocker is present; canonical rewrite still requires explicit validation-gated export. confidence=0.76
*/
__int64 __fastcall Sample(__int64 a1)
{
  __int64 v1;
  __int64 v14;

  v14 = argument2;
  v1 = *(_DWORD *)(a1 + 24LL);
  if ( v1 )
    goto LABEL_1;
  if ( v1 == -1073740748 )
    return v1;
  if ( -1073741675 != v1 )
    return v1;
  if ( v1 == -1073532109 )
    return v1;
  if ( v1 >= -1073740748 )
    return v1;
  SetFailureLocation(a1, SomeHelper(1, 2), 34, -1073741492, 96);
  SetFailureLocation(a1, 1, 34, 1073741833, 32);
  SetFailureLocation(a1, 1, 34, status, 96);
  TraceFailureLocation(a1, 1, 34, -1073741492, 96);
  return -1073741811;
LABEL_1:
  return 0xC000000D;
}
"""


class PseudoForgeCorpusQualityTests(unittest.TestCase):
    def test_decimal_status_pattern_counts_integer_suffixes(self) -> None:
        self.assertEqual(1, len(DECIMAL_STATUS_RE.findall("status = 3221226238LL;")))

    def test_decimal_status_residue_review_classes_separate_magic_and_bitmasks(self) -> None:
        literals = _decimal_status_like_literals(
            "unsigned __int64 tick;\n"
            "status = 3221226238LL;\n"
            "tick = 3221226238LL;\n"
            "if ( result == -1073532109 )\n"
            "if ( (flags & 0x4200000) == 69206016 )\n"
            "if ( ok || *BinAddress != 1852400232 )\n"
            "*BinAddress = 1852400232;\n"
        )

        self.assertEqual(
            [
                "profiled_status_literal_candidate",
                "profiled_status_literal_weak_target",
                "unprofiled_ntstatus_error_candidate",
                "bitmask_comparison_candidate",
                "ascii_magic_candidate",
                "ascii_magic_candidate",
            ],
            [item["review_class"] for item in literals],
        )
        self.assertEqual("status_identifier_target", literals[0]["target_evidence"])
        self.assertEqual("wide_or_nonstatus_target", literals[1]["target_evidence"])
        self.assertEqual("unsigned __int64", literals[1]["target_type"])

    def test_layout_rewrite_blocker_profiles_split_base_identity(self) -> None:
        self.assertEqual(
            ["base_identity_candidates", "temp_base_identity_candidates"],
            _layout_rewrite_blocker_review_profiles(["base is a decompiler temporary"]),
        )
        self.assertEqual(
            ["base_identity_candidates", "generic_base_identity_candidates"],
            _layout_rewrite_blocker_review_profiles(["base name is generic"]),
        )
        self.assertEqual(
            ["base_stability_blockers", "multiple_initializer_base_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["base has multiple initializers before layout access"]
            ),
        )
        self.assertEqual(
            ["base_stability_blockers", "reassigned_base_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["base is reassigned after layout access"]
            ),
        )
        self.assertEqual(
            ["threshold_gap_candidates", "offset_threshold_gap_candidates"],
            _layout_rewrite_blocker_review_profiles(
                ["rewrite offset threshold requires at least 8 offsets"]
            ),
        )
        self.assertEqual(
            ["threshold_gap_candidates", "access_threshold_gap_candidates"],
            _layout_rewrite_blocker_review_profiles(
                ["rewrite access threshold requires at least 12 accesses"]
            ),
        )
        self.assertEqual(
            ["type_evidence_blockers", "narrow_subfield_type_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["one or more offsets mix narrow subfield access widths"]
            ),
        )
        self.assertEqual(
            ["type_evidence_blockers", "wide_overlay_type_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["one or more offsets mix wide overlay access widths"]
            ),
        )
        self.assertEqual(
            ["type_evidence_blockers", "alignment_type_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["one or more typed offsets are not naturally aligned"]
            ),
        )

    def test_base_stability_profiles_split_initializer_and_reassignment_risk(self) -> None:
        self.assertEqual(
            "initializer_dominance_review",
            _base_stability_review_profile(
                {
                    "distinct_pre_access_rhs_count": 2,
                    "risky_post_access_assignment_count": 0,
                }
            ),
        )
        self.assertEqual(
            "initializer_and_reassignment_risk",
            _base_stability_review_profile(
                {
                    "distinct_pre_access_rhs_count": 2,
                    "risky_post_access_assignment_count": 1,
                }
            ),
        )
        self.assertEqual(
            "post_access_reassignment_risk",
            _base_stability_review_profile(
                {
                    "distinct_pre_access_rhs_count": 1,
                    "risky_post_access_assignment_count": 1,
                }
            ),
        )

    def test_analyze_corpus_reports_layout_rewrite_partial_opportunities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140002000_Partial"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "Partial.cleaned.cpp"
            summary_path = function_dir / "Partial.ida-batch-summary.json"
            cleaned_path.write_text(
                r"""
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for sessionSpace: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Safe offsets +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40, +0x48; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.75
*/
__int64 __fastcall Partial(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 0x10);
}
""",
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "Partial",
                        "function_ea": "0x140002000",
                        "artifacts": {
                            "cleaned_pseudocode": "Partial.cleaned.cpp",
                            "summary": "Partial.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            stats = report["layout_rewrite_partial_opportunity_stats"]
            self.assertEqual(1, stats["totals"]["partial_opportunities"])
            self.assertEqual(1, stats["totals"]["functions_with_partial_opportunities"])
            self.assertEqual(8, stats["totals"]["safe_offset_observations"])
            self.assertEqual(12, stats["totals"]["safe_access_observations"])
            self.assertEqual(1, stats["totals"]["excluded_offset_observations"])
            self.assertEqual(2, stats["totals"]["excluded_access_observations"])
            self.assertEqual(1, stats["top_bases"]["sessionSpace"])
            self.assertEqual(1, stats["source_provenance"]["none"])
            self.assertEqual(
                1,
                stats["reasons"]["one or more offsets mix narrow subfield access widths"],
            )
            self.assertEqual("Partial", stats["top_functions"][0]["name"])
            self.assertEqual(8, stats["top_functions"][0]["max_safe_offsets"])
            self.assertEqual(12, stats["top_functions"][0]["max_safe_access_count"])
            self.assertEqual(1, stats["top_functions"][0]["max_excluded_offsets"])
            self.assertEqual(2, stats["top_functions"][0]["max_excluded_access_count"])
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_rewrite_partial_opportunities"],
            )

    def test_analyze_corpus_counts_expression_source_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140002500_ExpressionSource"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "ExpressionSource.cleaned.cpp"
            summary_path = function_dir / "ExpressionSource.ida-batch-summary.json"
            cleaned_path.write_text(
                r"""
/*
    Kernel insights:
      - inferred_offset_stable_base_source: Stable base source for v8: MakeObject(v7) (call_result source, direct_call_result_alias), 14 typed dereference(s) across 9 offset(s). Review-only source identity evidence for temp/generic base promotion. confidence=0.68
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for v8: 14 typed dereference(s) across 9 offset(s), no rewrite blockers found. Source provenance direct_call_result_alias from MakeObject(v7). Threshold policy named_threshold_grace. Validated layout rewrite applied to canonical cleaned output. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v8: 14 dereference(s) can map to 9 field alias(es) field_8, field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Source provenance direct_call_result_alias from MakeObject(v7). Validated layout rewrite applied to canonical cleaned output. confidence=0.78
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for v8: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_8, field_10, field_18, field_20, field_28, field_30, field_38, field_40. Safe offsets +0x8, +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40; excluded offsets +0x48. Excluded reasons one or more typed offsets are not naturally aligned. Source provenance direct_call_result_alias from MakeObject(v7). Validated partial layout rewrite applied to canonical cleaned output. confidence=0.77
*/
__int64 __fastcall ExpressionSource(__int64 context)
{
  return *(_QWORD *)(context + 0x10);
}
""",
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "ExpressionSource",
                        "function_ea": "0x140002500",
                        "artifacts": {
                            "cleaned_pseudocode": "ExpressionSource.cleaned.cpp",
                            "summary": "ExpressionSource.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["source_provenance"][
                    "direct_call_result_alias"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_ready_stats"]["source_provenance"][
                    "direct_call_result_alias"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_stats"]["source_provenance"][
                    "direct_call_result_alias"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_partial_opportunity_stats"]["source_provenance"][
                    "direct_call_result_alias"
                ],
            )
            self.assertEqual(
                {"direct_call_result_alias": 1},
                report["layout_rewrite_ready_stats"]["top_functions"][0]["source_provenance"],
            )
            self.assertEqual(
                {"named_threshold_grace": 1},
                report["layout_rewrite_ready_stats"]["top_functions"][0]["threshold_policies"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_ready_stats"]["threshold_policies"][
                    "named_threshold_grace"
                ],
            )
            self.assertEqual(
                {"direct_call_result_alias": 1},
                report["layout_rewrite_preview_stats"]["top_functions"][0]["source_provenance"],
            )

    def test_analyze_corpus_splits_canonical_rewrite_plan_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            functions_root = root / "functions"
            full_dir = functions_root / "0000000140003000_Full"
            partial_dir = functions_root / "0000000140004000_Partial"
            full_dir.mkdir(parents=True)
            partial_dir.mkdir(parents=True)
            _write_preview_artifact_function(
                full_dir,
                "Full",
                "0x140003000",
                {
                    "schema": "layout_rewrite_preview_v2",
                    "artifact": "layout_rewrite_preview",
                    "canonical_rewrite_requested": True,
                    "canonical_cleaned_output_modified": True,
                    "canonical_rewrite_status": "applied",
                    "canonical_rewrite_errors": [],
                    "preview_plans": [
                        {
                            "base": "fullBase",
                            "plan_kind": "full",
                            "advertised_access_count": 12,
                            "advertised_field_count": 8,
                        }
                    ],
                    "rewritten_accesses": 12,
                    "rewritten_fields": 8,
                    "rewritten_bases": ["fullBase"],
                    "validation": {"status": "passed", "checks": {}, "errors": []},
                },
            )
            _write_preview_artifact_function(
                partial_dir,
                "Partial",
                "0x140004000",
                {
                    "schema": "layout_rewrite_preview_v2",
                    "artifact": "layout_rewrite_preview",
                    "canonical_rewrite_requested": True,
                    "canonical_cleaned_output_modified": True,
                    "canonical_rewrite_status": "applied_partial",
                    "canonical_rewrite_errors": [],
                    "preview_plans": [
                        {
                            "base": "partialBase",
                            "plan_kind": "partial",
                            "advertised_access_count": 23,
                            "advertised_field_count": 10,
                            "allowed_offsets": [0x20, 0x40],
                            "excluded_offsets": [0x206],
                        }
                    ],
                    "rewritten_accesses": 23,
                    "rewritten_fields": 10,
                    "rewritten_bases": ["partialBase"],
                    "validation": {"status": "passed", "checks": {}, "errors": []},
                },
            )

            report = analyze_corpus(root)

            stats = report["layout_rewrite_preview_artifact_stats"]
            self.assertEqual(2, stats["totals"]["preview_artifacts"])
            self.assertEqual(2, stats["totals"]["canonical_rewrite_requested"])
            self.assertEqual(2, stats["totals"]["canonical_rewrite_applied"])
            self.assertEqual(1, stats["totals"]["canonical_rewrite_applied_full"])
            self.assertEqual(1, stats["totals"]["canonical_rewrite_applied_partial"])
            self.assertEqual(1, stats["totals"]["full_preview_plans"])
            self.assertEqual(1, stats["totals"]["partial_preview_plans"])
            self.assertEqual(1, stats["canonical_rewrite_statuses"]["applied"])
            self.assertEqual(1, stats["canonical_rewrite_statuses"]["applied_partial"])
            self.assertEqual({"full": 1, "partial": 1}, stats["preview_plan_kinds"])

    def test_analyze_corpus_counts_warning_rename_rule_and_text_residue_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_quality_fixture(root)

            report = analyze_corpus(root)

            self.assertEqual("pseudoforge_corpus_quality_v1", report["schema"])
            self.assertEqual(1, report["totals"]["summaries"])
            self.assertEqual(1, report["totals"]["cleaned_files"])
            self.assertEqual(2, report["totals"]["warnings"])
            self.assertEqual(2, report["totals"]["applied_renames"])
            self.assertEqual(66.67, report["rename_stats"]["apply_rate"])
            self.assertEqual(2, report["rename_stats"]["by_source"]["llm"])
            self.assertEqual(1, report["rename_stats"]["applied_by_source"]["llm"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["llm_pascal_case"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["llm_pointer_bound"])
            self.assertEqual(2, report["rule_stats"]["rewrite_emissions"])
            self.assertEqual(1, report["rule_stats"]["rejected_emissions"])
            self.assertEqual(2, report["api_semantic_stats"]["diagnostics"])
            self.assertEqual(2, report["api_semantic_stats"]["rejections"])
            self.assertEqual(1, report["api_semantic_stats"]["functions_with_diagnostics"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_reason"]["large_dispatcher"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_reason"]["conflict_old"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_stage"]["api-argument"])
            self.assertEqual(1, report["api_semantic_stats"]["rejections_by_stage"]["api-out-param"])
            self.assertEqual(
                {
                    "reason": "large_dispatcher",
                    "stage": "api-argument",
                    "new": "object",
                    "callee": "ObfDereferenceObject",
                    "parameter": "Object",
                    "parameter_type": "PVOID",
                    "argument_index": "0",
                    "count": 1,
                },
                report["api_semantic_stats"]["top_rejection_profiles"][0],
            )
            self.assertEqual("Sample", report["api_semantic_stats"]["top_functions"][0]["name"])
            self.assertEqual(2, report["api_semantic_stats"]["top_functions"][0]["rejection_count"])
            self.assertEqual(
                1,
                report["api_semantic_stats"]["top_functions"][0]["rejections_by_target"]["object"],
            )
            self.assertEqual(2, report["layout_hint_stats"]["totals"]["hints"])
            self.assertEqual(1, report["layout_hint_stats"]["totals"]["functions_with_hints"])
            self.assertEqual(1, report["layout_hint_stats"]["totals"]["named_base_hints"])
            self.assertEqual(1, report["layout_hint_stats"]["totals"]["temp_base_hints"])
            self.assertEqual(11, report["layout_hint_stats"]["totals"]["offset_observations"])
            self.assertEqual(19, report["layout_hint_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_hint_stats"]["totals"]["large_offset_hints"])
            self.assertEqual(1, report["layout_hint_stats"]["top_bases"]["sessionSpace"])
            self.assertEqual(1, report["layout_hint_stats"]["top_bases"]["v14"])
            self.assertEqual(2, report["layout_hint_stats"]["observed_types"]["_DWORD"])
            self.assertEqual("Sample", report["layout_hint_stats"]["top_functions"][0]["name"])
            self.assertEqual(8, report["layout_hint_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(1, report["layout_stable_base_source_stats"]["totals"]["source_comments"])
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["totals"]["functions_with_source_comments"],
            )
            self.assertEqual(8, report["layout_stable_base_source_stats"]["totals"]["offset_observations"])
            self.assertEqual(13, report["layout_stable_base_source_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_stable_base_source_stats"]["top_bases"]["v14"])
            self.assertEqual(1, report["layout_stable_base_source_stats"]["sources"]["argument2"])
            self.assertEqual(1, report["layout_stable_base_source_stats"]["source_kinds"]["argument"])
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["source_provenance"][
                    "direct_argument_alias"
                ],
            )
            self.assertEqual("Sample", report["layout_stable_base_source_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["top_functions"][0]["top_sources"]["argument2"],
            )
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["top_functions"][0]["top_source_kinds"]["argument"],
            )
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["top_functions"][0]["top_source_provenance"][
                    "direct_argument_alias"
                ],
            )
            self.assertEqual(1, report["layout_base_stability_stats"]["totals"]["stability_comments"])
            self.assertEqual(
                1,
                report["layout_base_stability_stats"]["totals"]["functions_with_stability_comments"],
            )
            self.assertEqual(2, report["layout_base_stability_stats"]["totals"]["pre_access_assignments"])
            self.assertEqual(
                2,
                report["layout_base_stability_stats"]["totals"]["distinct_pre_access_rhs_observations"],
            )
            self.assertEqual(1, report["layout_base_stability_stats"]["totals"]["post_access_assignments"])
            self.assertEqual(
                1,
                report["layout_base_stability_stats"]["totals"]["risky_post_access_assignments"],
            )
            self.assertEqual(1, report["layout_base_stability_stats"]["top_bases"]["v14"])
            self.assertEqual(1, report["layout_base_stability_stats"]["rhs_samples"]["argument2"])
            self.assertEqual(1, report["layout_base_stability_stats"]["rhs_samples"]["argument3"])
            self.assertEqual(
                1,
                report["layout_base_stability_stats"]["profiles"]["initializer_and_reassignment_risk"],
            )
            base_stability_queue = report["layout_base_stability_stats"]["review_queues"][
                "initializer_and_reassignment_risk"
            ]
            self.assertEqual(1, base_stability_queue["comments"])
            self.assertEqual(1, base_stability_queue["functions"])
            self.assertEqual(2, base_stability_queue["max_distinct_pre_access_rhs"])
            self.assertEqual(1, base_stability_queue["max_risky_post_access_assignments"])
            self.assertEqual("Sample", base_stability_queue["items"][0]["name"])
            self.assertEqual("v14", base_stability_queue["items"][0]["base"])
            self.assertEqual("Sample", report["layout_base_stability_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                2,
                report["layout_base_stability_stats"]["top_functions"][0]["max_distinct_pre_access_rhs"],
            )
            self.assertEqual(
                1,
                report["layout_base_stability_stats"]["top_functions"][0][
                    "max_risky_post_access_assignments"
                ],
            )
            self.assertEqual(
                1,
                report["layout_base_stability_stats"]["top_functions"][0]["profiles"][
                    "initializer_and_reassignment_risk"
                ],
            )
            self.assertEqual(1, report["layout_generic_base_evidence_stats"]["totals"]["evidence_comments"])
            self.assertEqual(
                1,
                report["layout_generic_base_evidence_stats"]["totals"]["functions_with_evidence_comments"],
            )
            self.assertEqual(10, report["layout_generic_base_evidence_stats"]["totals"]["offset_observations"])
            self.assertEqual(20, report["layout_generic_base_evidence_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_generic_base_evidence_stats"]["top_bases"]["context"])
            self.assertEqual(1, report["layout_generic_base_evidence_stats"]["blocker_profiles"]["generic_only"])
            self.assertEqual("Sample", report["layout_generic_base_evidence_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                1,
                report["layout_generic_base_evidence_stats"]["top_functions"][0]["blocker_profiles"][
                    "generic_only"
                ],
            )
            self.assertEqual(10, report["layout_generic_base_evidence_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(
                20,
                report["layout_generic_base_evidence_stats"]["top_functions"][0]["max_access_count"],
            )
            self.assertEqual(
                1,
                report["layout_generic_base_trust_candidate_stats"]["totals"]["trust_candidates"],
            )
            self.assertEqual(
                1,
                report["layout_generic_base_trust_candidate_stats"]["totals"][
                    "functions_with_trust_candidates"
                ],
            )
            self.assertEqual(
                10,
                report["layout_generic_base_trust_candidate_stats"]["totals"]["offset_observations"],
            )
            self.assertEqual(
                20,
                report["layout_generic_base_trust_candidate_stats"]["totals"]["access_observations"],
            )
            self.assertEqual(1, report["layout_generic_base_trust_candidate_stats"]["top_bases"]["context"])
            self.assertEqual(1, report["layout_generic_base_trust_candidate_stats"]["source_kinds"]["parameter"])
            self.assertEqual(
                1,
                report["layout_generic_base_trust_candidate_stats"]["blocker_profiles"]["generic_only"],
            )
            self.assertEqual(
                "Sample",
                report["layout_generic_base_trust_candidate_stats"]["top_functions"][0]["name"],
            )
            self.assertEqual(
                1,
                report["layout_generic_base_trust_candidate_stats"]["top_functions"][0]["source_kinds"][
                    "parameter"
                ],
            )
            self.assertEqual(
                1,
                report["layout_generic_base_trust_candidate_stats"]["top_functions"][0]["blocker_profiles"][
                    "generic_only"
                ],
            )
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["totals"]["overlay_comments"])
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["totals"]["functions_with_overlay_comments"],
            )
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["totals"]["field_observations"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["top_bases"]["sessionSpace"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["size_classes"]["byte_word"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["policy_classes"]["narrow_subfield"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["interpretations"]["bitfield_candidate"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["bit_masks"]["0xF"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["bit_masks"]["0xF00F"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["bit_masks"]["0xFFF0"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["bit_operations"]["test_mask"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["bit_operations"]["clear_mask"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["mask_families"]["low_nibble"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["mask_families"]["preserve_outer_nibbles"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["mask_families"]["clear_low_nibble"])
            self.assertEqual("Sample", report["layout_subfield_overlay_stats"]["top_functions"][0]["name"])
            self.assertEqual(1, report["layout_subfield_overlay_stats"]["top_functions"][0]["field_count"])
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_size_classes"]["byte_word"],
            )
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_policy_classes"][
                    "narrow_subfield"
                ],
            )
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_interpretations"][
                    "bitfield_candidate"
                ],
            )
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_bit_masks"]["0xF"],
            )
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_bit_operations"]["test_mask"],
            )
            self.assertEqual(
                1,
                report["layout_subfield_overlay_stats"]["top_functions"][0]["top_mask_families"]["low_nibble"],
            )
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["totals"]["candidate_comments"])
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["totals"]["functions_with_candidate_comments"],
            )
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["totals"]["field_observations"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["top_bases"]["sessionSpace"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["size_classes"]["byte_word"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["interpretations"]["bitfield_candidate"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["bit_masks"]["0xF"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["bit_masks"]["0xF00F"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["bit_masks"]["0xFFF0"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["bit_operations"]["test_mask"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["bit_operations"]["clear_mask"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["mask_families"]["low_nibble"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["mask_families"]["preserve_outer_nibbles"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["mask_families"]["clear_low_nibble"])
            self.assertEqual("Sample", report["layout_narrow_subfield_stats"]["top_functions"][0]["name"])
            self.assertEqual(1, report["layout_narrow_subfield_stats"]["top_functions"][0]["field_count"])
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["top_functions"][0]["top_size_classes"]["byte_word"],
            )
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["top_functions"][0]["top_interpretations"][
                    "bitfield_candidate"
                ],
            )
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["top_functions"][0]["top_bit_masks"]["0xF"],
            )
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["top_functions"][0]["top_bit_operations"]["test_mask"],
            )
            self.assertEqual(
                1,
                report["layout_narrow_subfield_stats"]["top_functions"][0]["top_mask_families"]["low_nibble"],
            )
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["totals"]["alias_comments"])
            self.assertEqual(
                1,
                report["layout_bitfield_alias_stats"]["totals"]["functions_with_alias_comments"],
            )
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["totals"]["field_observations"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["top_bases"]["sessionSpace"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["aliases"]["bitfield_low_nibble"])
            self.assertEqual(
                1,
                report["layout_bitfield_alias_stats"]["aliases"]["bitfield_preserve_outer_nibbles"],
            )
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["aliases"]["bitfield_clear_low_nibble"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["masks"]["0xF"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["masks"]["0xF00F"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["masks"]["0xFFF0"])
            self.assertEqual("Sample", report["layout_bitfield_alias_stats"]["top_functions"][0]["name"])
            self.assertEqual(1, report["layout_bitfield_alias_stats"]["top_functions"][0]["field_count"])
            self.assertEqual(
                1,
                report["layout_bitfield_alias_stats"]["top_functions"][0]["top_aliases"]["bitfield_low_nibble"],
            )
            self.assertEqual(
                1,
                report["layout_bitfield_alias_stats"]["top_functions"][0]["top_masks"]["0xF"],
            )
            self.assertEqual(1, report["layout_rewrite_ready_stats"]["totals"]["ready_candidates"])
            self.assertEqual(1, report["layout_rewrite_ready_stats"]["totals"]["functions_with_ready_candidates"])
            self.assertEqual(8, report["layout_rewrite_ready_stats"]["totals"]["offset_observations"])
            self.assertEqual(12, report["layout_rewrite_ready_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_rewrite_ready_stats"]["top_bases"]["readySession"])
            self.assertEqual(1, report["layout_rewrite_ready_stats"]["source_provenance"]["none"])
            self.assertEqual("Sample", report["layout_rewrite_ready_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                {"none": 1},
                report["layout_rewrite_ready_stats"]["top_functions"][0]["source_provenance"],
            )
            self.assertEqual(8, report["layout_rewrite_ready_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(12, report["layout_rewrite_ready_stats"]["top_functions"][0]["max_access_count"])
            self.assertEqual(1, report["layout_rewrite_preview_stats"]["totals"]["preview_plans"])
            self.assertEqual(1, report["layout_rewrite_preview_stats"]["totals"]["functions_with_preview_plans"])
            self.assertEqual(8, report["layout_rewrite_preview_stats"]["totals"]["field_observations"])
            self.assertEqual(12, report["layout_rewrite_preview_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_rewrite_preview_stats"]["top_bases"]["readySession"])
            self.assertEqual(1, report["layout_rewrite_preview_stats"]["source_provenance"]["none"])
            self.assertEqual("Sample", report["layout_rewrite_preview_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                {"none": 1},
                report["layout_rewrite_preview_stats"]["top_functions"][0]["source_provenance"],
            )
            self.assertEqual(8, report["layout_rewrite_preview_stats"]["top_functions"][0]["max_fields"])
            self.assertEqual(12, report["layout_rewrite_preview_stats"]["top_functions"][0]["max_access_count"])
            self.assertEqual(1, report["layout_rewrite_preview_artifact_stats"]["totals"]["preview_artifacts"])
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["totals"]["functions_with_preview_artifacts"],
            )
            self.assertEqual(12, report["layout_rewrite_preview_artifact_stats"]["totals"]["rewritten_accesses"])
            self.assertEqual(8, report["layout_rewrite_preview_artifact_stats"]["totals"]["rewritten_fields"])
            self.assertEqual(0, report["layout_rewrite_preview_artifact_stats"]["totals"]["validation_errors"])
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["totals"]["advertisement_normalizations"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["totals"]["normalized_access_delta"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["totals"]["normalized_field_delta"],
            )
            self.assertEqual(
                0,
                report["layout_rewrite_preview_artifact_stats"]["totals"].get("canonical_rewrite_requested", 0),
            )
            self.assertEqual(
                0,
                report["layout_rewrite_preview_artifact_stats"]["totals"].get("canonical_rewrite_applied", 0),
            )
            self.assertEqual(
                0,
                report["layout_rewrite_preview_artifact_stats"]["totals"].get("canonical_rewrite_applied_full", 0),
            )
            self.assertEqual(
                0,
                report["layout_rewrite_preview_artifact_stats"]["totals"].get("canonical_rewrite_applied_partial", 0),
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["totals"].get("full_preview_plans", 0),
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["validation_statuses"]["passed"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["canonical_rewrite_statuses"]["not_requested"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_preview_artifact_stats"]["preview_plan_kinds"]["full"],
            )
            self.assertEqual({}, report["layout_rewrite_preview_artifact_stats"]["failed_checks"])
            self.assertEqual(
                "Sample",
                report["layout_rewrite_preview_artifact_stats"]["top_functions"][0]["name"],
            )
            self.assertEqual(
                "passed",
                report["layout_rewrite_preview_artifact_stats"]["top_functions"][0]["validation_status"],
            )
            self.assertEqual(
                "not_requested",
                report["layout_rewrite_preview_artifact_stats"]["top_functions"][0]["canonical_rewrite_status"],
            )
            self.assertEqual(
                1,
                len(
                    report["layout_rewrite_preview_artifact_stats"]["top_functions"][0][
                        "advertisement_normalizations"
                    ]
                ),
            )
            self.assertEqual(
                {"full": 1},
                report["layout_rewrite_preview_artifact_stats"]["top_functions"][0][
                    "preview_plan_kinds"
                ],
            )
            self.assertEqual(1, report["layout_rewrite_near_ready_stats"]["totals"]["near_ready_candidates"])
            self.assertEqual(
                1,
                report["layout_rewrite_near_ready_stats"]["totals"]["functions_with_near_ready_candidates"],
            )
            self.assertEqual(6, report["layout_rewrite_near_ready_stats"]["totals"]["offset_observations"])
            self.assertEqual(12, report["layout_rewrite_near_ready_stats"]["totals"]["access_observations"])
            self.assertEqual(1, report["layout_rewrite_near_ready_stats"]["top_bases"]["nearlySession"])
            self.assertEqual(1, report["layout_rewrite_near_ready_stats"]["missing_thresholds"]["offset"])
            self.assertEqual("Sample", report["layout_rewrite_near_ready_stats"]["top_functions"][0]["name"])
            self.assertEqual(6, report["layout_rewrite_near_ready_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(12, report["layout_rewrite_near_ready_stats"]["top_functions"][0]["max_access_count"])
            self.assertEqual(2, report["layout_rewrite_blocker_stats"]["totals"]["blockers"])
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["totals"]["functions_with_blockers"])
            self.assertEqual(3, report["layout_rewrite_blocker_stats"]["totals"]["reason_observations"])
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["top_bases"]["sessionSpace"])
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["top_bases"]["v14"])
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["reasons"][
                    "rewrite offset threshold requires at least 8 offsets"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["reasons"][
                    "rewrite access threshold requires at least 12 accesses"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["reasons"][
                    "base is a decompiler temporary"
                ],
            )
            self.assertEqual("Sample", report["layout_rewrite_blocker_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_profiles"][
                    "base_identity_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_profiles"][
                    "temp_base_identity_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_profiles"][
                    "threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_profiles"][
                    "offset_threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_profiles"][
                    "access_threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["blockers"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["functions"],
            )
            self.assertEqual(
                3,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["max_offsets"],
            )
            self.assertEqual(
                6,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["max_access_count"],
            )
            self.assertEqual(
                "Sample",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["items"][0]["name"],
            )
            self.assertEqual(
                3,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["items"][0]["offset_count"],
            )
            self.assertEqual(
                6,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["items"][0]["access_count"],
            )
            self.assertEqual(
                {"none": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["identity_evidence"],
            )
            self.assertEqual(
                {"missing_identity_evidence": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["promotion_review_classes"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["blockers"],
            )
            self.assertEqual(
                {"stable_argument_source": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["identity_evidence"],
            )
            self.assertEqual(
                {"direct_argument_alias": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["identity_source_provenance"],
            )
            self.assertEqual(
                {"stable_source_promotion_review": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["promotion_review_classes"],
            )
            self.assertEqual(
                "v14",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["base"],
            )
            self.assertEqual(
                "stable_argument_source",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["identity_evidence"],
            )
            self.assertEqual(
                "argument2",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["identity_source"],
            )
            self.assertEqual(
                "argument",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["identity_source_kind"],
            )
            self.assertEqual(
                "direct_argument_alias",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["identity_source_provenance"],
            )
            self.assertEqual(
                "none",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["identity_source_rhs_kind"],
            )
            self.assertEqual(
                "stable_source_promotion_review",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["promotion_review_class"],
            )
            self.assertEqual(
                ["identity_only"],
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["promotion_risk_factors"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "offset_threshold_gap_candidates"
                ]["blockers"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "access_threshold_gap_candidates"
                ]["blockers"],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["top_functions"][0]["review_profiles"][
                    "threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["top_functions"][0]["review_profiles"][
                    "offset_threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_blocker_stats"]["top_functions"][0]["review_profiles"][
                    "access_threshold_gap_candidates"
                ],
            )
            self.assertEqual(
                {"stable_argument_source": 1, "none": 1},
                report["layout_rewrite_blocker_stats"]["top_functions"][0]["identity_evidence"],
            )
            self.assertEqual(
                {"direct_argument_alias": 1, "none": 1},
                report["layout_rewrite_blocker_stats"]["top_functions"][0][
                    "identity_source_provenance"
                ],
            )
            self.assertEqual(
                {"stable_source_promotion_review": 1, "missing_identity_evidence": 1},
                report["layout_rewrite_blocker_stats"]["top_functions"][0][
                    "promotion_review_classes"
                ],
            )
            self.assertEqual(8, report["layout_rewrite_blocker_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(13, report["layout_rewrite_blocker_stats"]["top_functions"][0]["max_access_count"])
            self.assertEqual(1, report["text_stats"]["offset_deref_patterns"])
            self.assertEqual(2, report["text_stats"]["label_tokens"])
            self.assertEqual(4, report["text_stats"]["decimal_status_like_literals"])
            self.assertEqual(1, report["text_stats"]["hex_status_like_literals"])
            self.assertEqual(2, report["text_stats"]["profiled_status_argument_literals"])
            self.assertEqual(1, report["text_stats"]["functions_with_profiled_status_argument_literals"])
            self.assertEqual(7, report["text_stats"]["ntstatus_family_literals"])
            self.assertEqual(6, report["text_stats"]["ntstatus_profiled_family_literals"])
            self.assertEqual(1, report["text_stats"]["ntstatus_unprofiled_family_literals"])
            self.assertEqual(1, report["text_stats"]["functions_with_ntstatus_unprofiled_family_literals"])
            self.assertEqual(6, report["text_stats"]["ntstatus_error_family_literals"])
            self.assertEqual(1, report["text_stats"]["ntstatus_informational_family_literals"])
            self.assertEqual(1, report["text_stats"]["ntstatus_unprofiled_error_family_literals"])
            self.assertEqual(2, report["text_stats"]["inferred_offset_layout_hints"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_field_previews"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_field_aliases"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_subfield_overlays"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_narrow_subfields"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_bitfield_aliases"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_stable_base_sources"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_base_stability"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_generic_base_evidence"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_generic_base_trust_candidates"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_ready"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_previews"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_near_ready"])
            self.assertEqual(2, report["text_stats"]["inferred_offset_rewrite_blockers"])
            self.assertEqual(1, report["body_text_stats"]["offset_deref_patterns"])
            self.assertEqual(2, report["body_text_stats"]["label_tokens"])
            self.assertEqual(4, report["body_text_stats"]["decimal_status_like_literals"])
            self.assertEqual(1, report["body_text_stats"]["hex_status_like_literals"])
            self.assertEqual(2, report["body_text_stats"]["profiled_status_argument_literals"])
            self.assertEqual(7, report["body_text_stats"]["ntstatus_family_literals"])
            self.assertEqual(6, report["body_text_stats"]["ntstatus_profiled_family_literals"])
            self.assertEqual(1, report["body_text_stats"]["ntstatus_unprofiled_family_literals"])
            self.assertEqual(1, report["body_text_stats"]["functions_with_ntstatus_unprofiled_family_literals"])
            self.assertEqual(6, report["body_text_stats"]["ntstatus_error_family_literals"])
            self.assertEqual(1, report["body_text_stats"]["ntstatus_informational_family_literals"])
            self.assertEqual(1, report["body_text_stats"]["ntstatus_unprofiled_error_family_literals"])
            decimal_stats = report["decimal_status_residue_stats"]
            self.assertEqual(
                {"comparison": 3, "return": 1},
                decimal_stats["context_kinds"],
            )
            self.assertEqual(
                {
                    "STATUS_PTE_CHANGED": 1,
                    "STATUS_INTEGER_OVERFLOW": 1,
                    "unprofiled": 1,
                    "STATUS_INVALID_PARAMETER": 1,
                },
                decimal_stats["profile_names"],
            )
            self.assertEqual(
                {
                    "profiled_status_literal_candidate": 3,
                    "unprofiled_ntstatus_error_candidate": 1,
                },
                decimal_stats["review_classes"],
            )
            self.assertEqual(
                {"complex_or_memory_target": 4},
                decimal_stats["target_evidence"],
            )
            self.assertEqual(
                3,
                decimal_stats["review_queues"]["strong_profiled_status_literals"]["literals"],
            )
            self.assertEqual(
                1,
                decimal_stats["review_queues"]["strong_profiled_status_literals"]["functions"],
            )
            self.assertEqual(
                {"profiled_status_literal_candidate": 3},
                decimal_stats["review_queues"]["strong_profiled_status_literals"][
                    "review_classes"
                ],
            )
            self.assertEqual(
                {"complex_or_memory_target": 3},
                decimal_stats["review_queues"]["strong_profiled_status_literals"][
                    "target_evidence"
                ],
            )
            self.assertEqual(
                "Sample",
                decimal_stats["review_queues"]["strong_profiled_status_literals"]["items"][0][
                    "name"
                ],
            )
            self.assertEqual(
                0,
                decimal_stats["review_queues"]["weak_target_profiled_status_literals"][
                    "literals"
                ],
            )
            self.assertEqual(
                1,
                decimal_stats["review_queues"]["unprofiled_ntstatus_error_literals"][
                    "literals"
                ],
            )
            self.assertEqual(
                0,
                decimal_stats["review_queues"]["nonstatus_ascii_magic_literals"]["literals"],
            )
            self.assertEqual(
                0,
                decimal_stats["review_queues"]["nonstatus_bitmask_comparisons"]["literals"],
            )
            self.assertEqual("Sample", decimal_stats["top_functions"][0]["name"])
            self.assertEqual(4, decimal_stats["top_functions"][0]["literal_count"])
            self.assertEqual(3, decimal_stats["top_functions"][0]["profiled_count"])
            self.assertEqual(1, decimal_stats["top_functions"][0]["unprofiled_count"])
            self.assertEqual(
                {
                    "profiled_status_literal_candidate": 3,
                    "unprofiled_ntstatus_error_candidate": 1,
                },
                decimal_stats["top_functions"][0]["review_classes"],
            )
            self.assertEqual(
                {"complex_or_memory_target": 4},
                decimal_stats["top_functions"][0]["target_evidence"],
            )
            self.assertEqual(
                "if ( v1 == -1073740748 )",
                decimal_stats["top_functions"][0]["contexts"][0]["source"],
            )
            self.assertEqual(
                "profiled_status_literal_candidate",
                decimal_stats["top_functions"][0]["contexts"][0]["review_class"],
            )
            self.assertEqual(
                "complex_or_memory_target",
                decimal_stats["top_functions"][0]["contexts"][0]["target_evidence"],
            )
            ntstatus_stats = report["ntstatus_body_residue_stats"]
            self.assertEqual(
                "0xC0033333",
                ntstatus_stats["top_unprofiled_error_values"][0]["hex_value"],
            )
            self.assertEqual(
                -1073532109,
                ntstatus_stats["top_unprofiled_error_values"][0]["signed_value"],
            )
            self.assertEqual(0x003, ntstatus_stats["top_unprofiled_error_values"][0]["facility"])
            self.assertEqual("0x003", ntstatus_stats["top_unprofiled_error_values"][0]["facility_hex"])
            self.assertEqual(0x3333, ntstatus_stats["top_unprofiled_error_values"][0]["code"])
            self.assertEqual("0x3333", ntstatus_stats["top_unprofiled_error_values"][0]["code_hex"])
            self.assertFalse(ntstatus_stats["top_unprofiled_error_values"][0]["customer"])
            self.assertEqual(
                {"comparison": 1},
                ntstatus_stats["top_unprofiled_error_values"][0]["context_kinds"],
            )
            self.assertEqual(
                "comparison_sentinel_candidate",
                ntstatus_stats["top_unprofiled_error_values"][0]["review_hint"],
            )
            self.assertEqual(1, ntstatus_stats["top_unprofiled_error_values"][0]["count"])
            self.assertEqual(1, ntstatus_stats["top_unprofiled_error_values"][0]["function_count"])
            self.assertEqual(
                {"comparison": 1},
                ntstatus_stats["unprofiled_error_context_kinds"],
            )
            self.assertEqual(
                {"comparison_sentinel_candidate": 1},
                ntstatus_stats["unprofiled_error_review_hints"],
            )
            self.assertEqual(
                [],
                ntstatus_stats["review_queues"]["status_profile_candidates"]["values"],
            )
            self.assertEqual(
                "0xC0033333",
                ntstatus_stats["review_queues"]["comparison_sentinel_candidates"]["values"][0][
                    "hex_value"
                ],
            )
            self.assertEqual(
                "Sample",
                ntstatus_stats["review_queues"]["comparison_sentinel_candidates"]["functions"][0][
                    "name"
                ],
            )
            self.assertEqual(
                "Sample",
                ntstatus_stats["top_unprofiled_error_functions"][0]["name"],
            )
            self.assertEqual(
                "comparison_sentinel_candidate",
                ntstatus_stats["top_unprofiled_error_functions"][0]["review_hint"],
            )
            self.assertEqual(
                {"comparison": 1},
                ntstatus_stats["top_unprofiled_error_functions"][0]["context_kinds"],
            )
            self.assertEqual(
                {"0xC0033333": 1},
                ntstatus_stats["top_unprofiled_error_functions"][0]["values"],
            )
            self.assertEqual(
                {"-1073532109": 1},
                ntstatus_stats["top_unprofiled_error_functions"][0]["raw_literals"],
            )
            self.assertEqual(
                "if ( v1 == -1073532109 )",
                ntstatus_stats["top_unprofiled_error_functions"][0]["contexts"][0]["source"],
            )
            self.assertEqual(
                "comparison",
                ntstatus_stats["top_unprofiled_error_functions"][0]["contexts"][0]["kind"],
            )
            self.assertGreater(
                ntstatus_stats["top_unprofiled_error_functions"][0]["contexts"][0]["line"],
                0,
            )
            self.assertNotIn("inferred_offset_layout_hints", report["body_text_stats"])
            self.assertNotIn("inferred_offset_field_aliases", report["body_text_stats"])
            self.assertNotIn("inferred_offset_subfield_overlays", report["body_text_stats"])
            self.assertNotIn("inferred_offset_narrow_subfields", report["body_text_stats"])
            self.assertNotIn("inferred_offset_bitfield_aliases", report["body_text_stats"])
            self.assertNotIn("inferred_offset_stable_base_sources", report["body_text_stats"])
            self.assertNotIn("inferred_offset_generic_base_evidence", report["body_text_stats"])
            self.assertNotIn("inferred_offset_generic_base_trust_candidates", report["body_text_stats"])
            self.assertNotIn("inferred_offset_rewrite_ready", report["body_text_stats"])
            self.assertNotIn("inferred_offset_rewrite_previews", report["body_text_stats"])
            self.assertNotIn("inferred_offset_rewrite_near_ready", report["body_text_stats"])
            self.assertNotIn("inferred_offset_rewrite_blockers", report["body_text_stats"])
            self.assertLess(
                report["body_text_stats"]["generic_identifier_tokens"],
                report["text_stats"]["generic_identifier_tokens"],
            )

    def test_cli_writes_json_and_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            output_dir = Path(temp_dir) / "quality"
            _write_quality_fixture(root)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--corpus-root",
                        str(root),
                        "--out",
                        str(output_dir),
                        "--format",
                        "both",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertTrue((output_dir / "corpus-quality.json").exists())
            self.assertTrue((output_dir / "corpus-quality.md").exists())
            self.assertIn("Wrote corpus quality report", stdout.getvalue())
            self.assertIn(
                "PseudoForge Corpus Quality Report",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "API Semantic Diagnostics",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Inferred Layout Hints",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Stable Base Sources",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Base Stability Evidence",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Base Stability Review Profiles",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Base Stability Review Queues",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `initializer_and_reassignment_risk` | 1 | 1 | 2 | 1 | v14=1 | argument2=1, argument3=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Base Stability Queue Top Items",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "#### `initializer_and_reassignment_risk`",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | `v14` | 2 | 1 | argument2; argument3 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | 1 | 2 | 1 | initializer_and_reassignment_risk=1 | `v14` | argument2=1, argument3=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Stable Base Source Kinds",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Generic Base Evidence",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Generic Base Evidence Profiles",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Generic Base Trust Candidates",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Generic Base Trust Source Kinds",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Subfield Overlays",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Subfield Overlay Policy Classes",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Subfield Overlay Interpretations",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Subfield Overlay Bit Masks",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Subfield Overlay Bit Operations",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Subfield Overlay Mask Families",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Narrow Subfields",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Narrow Subfield Interpretations",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Narrow Subfield Bit Masks",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Narrow Subfield Bit Operations",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Narrow Subfield Mask Families",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Bitfield Aliases",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Bitfield Alias Names",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Readiness",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Preview Plans",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite Preview Source Provenance",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Preview Artifact Validation",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Preview Artifact Canonical Rewrite Statuses",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite-Ready Source Provenance",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite-Ready Threshold Policies",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Near-Ready",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Blockers",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite Blocker Review Profiles",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite Blocker Review Queues",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Rewrite Blocker Queue Top Items",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "#### `base_identity_candidates`",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `base_identity_candidates` | 1 | 1 | 8 | 13 | v14=1 | stable_argument_source=1 | direct_argument_alias=1 | stable_source_promotion_review=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | `v14` | 8 | 13 | stable_argument_source | direct_argument_alias, argument, argument2 | stable_source_promotion_review | identity_only | base is a decompiler temporary |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `offset_threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `access_threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Code Body Residue",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Unprofiled NTSTATUS Error Values",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Decimal Status-Like Residue",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Decimal Status-Like Review Queues",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `strong_profiled_status_literals` | 3 | 1 | profiled_status_literal_candidate=3 | complex_or_memory_target=3 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | 4 | 3 | 1 | profiled_status_literal_candidate=3, unprofiled_ntstatus_error_candidate=1 | complex_or_memory_target=4 | comparison=3, return=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| Value | Signed | Facility | Code | Hint | Kinds | Count | Functions |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Unprofiled NTSTATUS Error Context Kinds",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Unprofiled NTSTATUS Error Review Hints",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Unprofiled NTSTATUS Review Queues",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `comparison_sentinel_candidates` | 1 | 1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| Function | EA | Literals | Hint | Kinds | Values | Lines | Context | Raw literals |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "comparison_sentinel_candidate",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "if ( v1 == -1073532109 )",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )

    def test_analyze_corpus_filters_by_ea_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            _write_quality_fixture(root)
            other_dir = root / "functions" / "0000000140002000_Other"
            other_dir.mkdir(parents=True)
            (other_dir / "Other.ida-batch-summary.json").write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "Other",
                        "function_ea": "0x140002000",
                        "rename_candidates": 9,
                        "renames": 1,
                        "warnings": 7,
                        "artifacts": {},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root, ea_filter={0x140001000})

            self.assertEqual(1, report["totals"]["summaries"])
            self.assertEqual(2, report["totals"]["warnings"])
            self.assertEqual(1, report["ea_filter_count"])

    def test_cli_filters_by_ea_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            output_dir = Path(temp_dir) / "quality"
            ea_file = Path(temp_dir) / "eas.txt"
            _write_quality_fixture(root)
            ea_file.write_text("0x140001000\n0x1400BAD0\n", encoding="utf-8")

            exit_code = main(
                [
                    "--corpus-root",
                    str(root),
                    "--out",
                    str(output_dir),
                    "--format",
                    "json",
                    "--ea-file",
                    str(ea_file),
                ]
            )

            self.assertEqual(0, exit_code)
            report = json.loads((output_dir / "corpus-quality.json").read_text(encoding="utf-8"))
            self.assertEqual(1, report["totals"]["summaries"])
            self.assertEqual(2, report["ea_filter_count"])


def _write_quality_fixture(root: Path) -> None:
    function_dir = root / "functions" / "0000000140001000_Sample"
    function_dir.mkdir(parents=True)
    cleaned_path = function_dir / "Sample.cleaned.cpp"
    warnings_path = function_dir / "Sample.warnings.json"
    rename_map_path = function_dir / "Sample.rename-map.json"
    buffer_contracts_path = function_dir / "Sample.buffer-contracts.json"
    rule_report_path = function_dir / "Sample.rule-report.json"
    preview_metadata_path = function_dir / "Sample.layout-rewrite-preview.json"
    summary_path = function_dir / "Sample.ida-batch-summary.json"
    cleaned_path.write_text(CLEANED, encoding="utf-8")
    warnings_path.write_text(
        json.dumps(
            [
                "Skipped PascalCase LLM rename a1->PageTableBase",
                "Skipped pointer-bound rename v4->targetBuffer",
            ]
        ),
        encoding="utf-8",
    )
    rename_map_path.write_text(
        json.dumps(
            {
                "renames": [
                    {"old": "a1", "new": "PageTableBase", "source": "llm", "apply": False},
                    {"old": "v1", "new": "status", "source": "llm", "apply": True},
                    {"old": "v2", "new": "statusCode", "source": "kernel-status", "apply": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    buffer_contracts_path.write_text(json.dumps([{"command_value": 0x90000000}]), encoding="utf-8")
    rule_report_path.write_text(
        json.dumps(
            {
                "matched_rules": [{"rule_id": "sample.rename"}, {"rule_id": "sample.flow"}],
                "rewrite_emissions": [{"kind": "flow"}, {"kind": "text_rewrite"}],
                "rejected_emissions": [{"reason": "conflict"}],
                "api_semantic_diagnostics": [
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "large_dispatcher",
                        "old": "v7",
                        "new": "object",
                        "callee": "ObfDereferenceObject",
                        "argument_index": 0,
                        "argument": "v7",
                        "parameter": "Object",
                        "parameter_type": "PVOID",
                    },
                    {
                        "stage": "api-out-param",
                        "status": "rejected",
                        "reason": "conflict_old",
                        "old": "v8",
                        "new": "process",
                    },
                ],
                "validation_errors": [{"path": "rules.json", "error": "bad operator"}],
            }
        ),
        encoding="utf-8",
    )
    preview_metadata_path.write_text(
        json.dumps(
            {
                "schema": "layout_rewrite_preview_v2",
                "artifact": "layout_rewrite_preview",
                "canonical_rewrite_requested": False,
                "canonical_cleaned_output_modified": False,
                "canonical_rewrite_status": "not_requested",
                "canonical_rewrite_errors": [],
                "preview_plans": [
                    {
                        "base": "readySession",
                        "plan_kind": "full",
                        "source": "",
                        "source_provenance": "none",
                        "advertised_access_count": 12,
                        "advertised_field_count": 8,
                        "confidence": 0.78,
                    }
                ],
                "rewritten_accesses": 12,
                "rewritten_fields": 8,
                "rewritten_bases": ["readySession"],
                "advertisement_normalizations": [
                    {
                        "base": "readySession",
                        "original_accesses": 13,
                        "original_fields": 9,
                        "normalized_accesses": 12,
                        "normalized_fields": 8,
                    }
                ],
                "rewrite_results": {
                    "readySession": {
                        "rewritten_accesses": 12,
                        "rewritten_fields": 8,
                        "field_aliases": ["field_10", "field_18"],
                    }
                },
                "validation": {
                    "status": "passed",
                    "checks": {
                        "canonical_cleaned_output_preserved": True,
                        "all_plans_rewritten": True,
                        "advertised_access_counts_match": True,
                        "advertised_field_counts_match": True,
                        "preview_contains_field_rewrites": True,
                        "preview_has_no_raw_offset_derefs_for_rewritten_bases": True,
                    },
                    "errors": [],
                },
            }
        ),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": "Sample",
                "function_ea": "0x140001000",
                "rename_candidates": 3,
                "renames": 2,
                "flow_rewrites": 1,
                "buffer_contracts": 1,
                "warnings": 2,
                "rule_diagnostics": {"matched_rules": 2},
                "llm_status": "ok",
                "artifacts": {
                    "cleaned_pseudocode": "old/Sample.cleaned.cpp",
                    "warnings": "old/Sample.warnings.json",
                    "rename_map": "old/Sample.rename-map.json",
                    "buffer_contracts": "old/Sample.buffer-contracts.json",
                    "rule_report": "old/Sample.rule-report.json",
                    "layout_rewrite_preview_metadata": "old/Sample.layout-rewrite-preview.json",
                    "summary": "old/Sample.ida-batch-summary.json",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_preview_artifact_function(
    function_dir: Path,
    name: str,
    ea: str,
    metadata: dict[str, object],
) -> None:
    metadata_path = function_dir / f"{name}.layout-rewrite-preview.json"
    summary_path = function_dir / f"{name}.ida-batch-summary.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    summary_path.write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": name,
                "function_ea": ea,
                "artifacts": {
                    "layout_rewrite_preview_metadata": metadata_path.name,
                    "summary": summary_path.name,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
