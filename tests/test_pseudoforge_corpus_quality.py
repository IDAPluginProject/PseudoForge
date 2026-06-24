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
    _body_offset_fail_closed_family,
    _body_offset_named_goal_target_group,
    _body_offset_residue_item_matches_queue,
    _body_offset_residue_promotion_hints,
    _body_offset_residue_next_action_details,
    _body_offset_residue_review_evidence,
    _body_offset_rewrite_safety_policy,
    _decimal_status_like_literals,
    _decimal_status_target_review_queues,
    _extract_layout_rewrite_blockers,
    _layout_promotion_next_action_details,
    _layout_promotion_next_action,
    _layout_rewrite_blocker_review_profiles,
    _nested_status_pointer_store_literals,
    _ntstatus_family_literals,
    _offset_deref_shape_profile,
    _prototype_correction_review_queues,
    analyze_corpus,
    main,
    render_quality_markdown,
)


CLEANED = r"""
/*
    Kernel insights:
      - inferred_offset_layout: Offset layout hint: sessionSpace has 6 typed dereference(s) across 3 offset(s) +0x10, +0x18, +0x20; observed types: _DWORD, _QWORD. Review as an inferred structure base. confidence=0.83
      - inferred_offset_field_preview: Preview fields for sessionSpace: +0x10 _DWORD field_10; +0x18 _QWORD field_18; +0x20 _BYTE field_20; +0x28 _DWORD field_28; +0x30 _WORD field_30. Preview only; no IDB type or pseudocode rewrite was applied. confidence=0.81
      - inferred_offset_field_aliases: Alias map for sessionSpace: field_10=+0x10 _DWORD; field_18=+0x18 _QWORD; field_20=+0x20 _BYTE; field_28=+0x28 _DWORD; field_30=+0x30 _WORD. Use as review-only shorthand for repeated offset dereferences. confidence=0.73
      - inferred_offset_field_hot_cluster: Hot field cluster for context (generic base): 27 typed dereference(s) concentrated in 6 offset(s); top fields field_20=+0x20 _DWORD x10; field_18=+0x18 _QWORD x8; field_28=+0x28 _QWORD * x4. Review-only access-pressure evidence; no structure type or body rewrite was inferred. confidence=0.72
      - inferred_offset_indexed_callback_table_evidence: Indexed layout evidence for argument0 (argument identity base): 8 indexed/callback access(es) across 8 slot(s); scalar indexes index_513, index_524, index_593, index_630; callback slots slot_32, slot_70, slot_71, slot_72. Alias bases v4. Review-only; indexed table access is not used for canonical field rewrite. confidence=0.72
      - inferred_offset_subfield_overlays: Subfield overlay evidence for sessionSpace: +0x20 field_20 uses 1/2-byte accesses (_BYTE/_WORD) [bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]. Review-only; field rewrite remains blocked for mixed-width offsets. confidence=0.72
      - inferred_offset_narrow_subfields: Narrow subfield candidates for sessionSpace: +0x20 field_20 uses 1/2-byte accesses (_BYTE/_WORD) [bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]. Audit-only; body rewrite remains disabled until the parent structure is trusted. confidence=0.72
      - inferred_offset_bitfield_aliases: Bitfield aliases for sessionSpace: field_20=+0x20 bitfield_low_nibble/bitfield_preserve_outer_nibbles/bitfield_clear_low_nibble masks=0xF,0xF00F,0xFFF0. Review-only names; body rewrite remains disabled until the parent structure is trusted. confidence=0.73
      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for sessionSpace: rewrite offset threshold requires at least 8 offsets; rewrite access threshold requires at least 12 accesses. Review-only aliases remain available. confidence=0.73
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for readySession: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Audit only; body rewrite was not applied. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for readySession: 12 dereference(s) can map to 8 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Preview artifact only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_near_ready: Offset field rewrite near-ready for nearlySession: 12 typed dereference(s) across 6 offset(s), missing offset threshold only. Audit only; body rewrite was not applied. confidence=0.75
      - inferred_offset_layout: Offset layout hint: v14 has 13 typed dereference(s) across 8 offset(s) +0x8, +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40; observed types: _BYTE, _DWORD, .... Review as a high-evidence temporary base before inferring a structure. confidence=0.74
      - inferred_offset_stable_base_source: Stable base source for v14: argument2 (argument source), 13 typed dereference(s) across 8 offset(s). Review-only; temp/generic base keeps rewrite blocked until source identity is trusted. confidence=0.68
      - inferred_offset_base_stability: Base stability evidence for v14: 2 initializer(s) before first layout access across 2 distinct RHS (argument2; argument3); 1 post-access assignment(s), 1 followed by later layout access. Post-access assignment samples: relocation-sensitive RHS argument3. Review initializer dominance before enabling canonical rewrite. confidence=0.70
      - inferred_offset_base_merge_evidence: Base merge evidence for v14: 2 initializer(s) before first layout access across 2 source candidate(s): argument2; argument3. Candidate classes identifier=2. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.70
      - inferred_offset_call_result_merge_equivalence: Call-result merge equivalence for v18: 3 call-result initializer(s), 2 direct call(s), 1 indirect dispatch call(s), 0 opaque call(s). Call families RtlpInterlockedPopEntrySList=2, guard_dispatch_icall_no_overrides=1; equivalence class direct_call_with_indirect_fallback. Keep canonical rewrite blocked until call-result object equivalence is validated. confidence=0.64
      - inferred_offset_allocation_null_merge_dominance: Allocation/null merge dominance for newProviderRecord2: 2 allocation initializer(s), 1 null initializer(s), first layout access is dominated by a base truthiness guard. Guard condition newProviderRecord2. Keep canonical rewrite blocked until allocation object equivalence and guard dominance are validated. confidence=0.67
      - inferred_offset_call_result_parameter_merge_provenance: Call-result/parameter merge provenance for v15: 1 call-result initializer(s), 1 parameter-root candidate(s), 0 temporary-root candidate(s). Call families LookupLayoutObject=1. Parameter roots argument2. Parameter candidates *argument2 [pointer_deref]. Temporary roots none. 1 call-result initializer(s) mention parameter root(s). First layout access is not dominated by a base truthiness guard. Provenance class call_result_with_parameter_root_linked_arguments_pointer_deref. Keep canonical rewrite blocked until parameter/call-result path dominance is validated. confidence=0.65
      - inferred_offset_call_result_temporary_merge_provenance: Call-result/temporary merge provenance for v17: 1 call-result initializer(s), 1 temporary-root candidate(s). Call families ExAllocateFromLookasideListEx=1. Temporary roots v29 stable=deref(_QWORD,referencedObject@0x28). Provenance class allocation_call_with_temporary. Keep canonical rewrite blocked until temporary source dominance is validated. confidence=0.64
      - inferred_offset_bugcheck_parameter_merge_identity: Bugcheck-parameter merge identity for v16: 2 bugcheck-root candidate(s), 0 temporary-root candidate(s). Bugcheck roots BugCheckParameter3, BugCheckParameter2. Bugcheck candidates BugCheckParameter3 [direct_root 0x0]; BugCheckParameter2 [direct_root 0x0]. Temporary roots none. First layout access is not dominated by a base truthiness guard. Identity class multiple_bugcheck_roots. Treat BugCheckParameter names as unresolved decompiler identity; keep canonical rewrite blocked until domain-specific pointer meaning is validated. confidence=0.61
      - inferred_offset_same_source_family_merge_dominance: Same-source-family merge dominance for v14: 2 initializer candidate(s) share argument root argument2. Branch shapes direct_root=2; source offsets 0x0; first layout access is not dominated by a base truthiness guard. Candidate sources argument2 [direct_root 0x0]; argument3 [direct_root 0x0]. Dominance class argument_root_direct_branch. Keep canonical rewrite blocked until path-specific initializer dominance is validated. confidence=0.63
      - inferred_offset_same_family_merge_provenance: Same-family merge provenance for v14: root argument2 (argument), candidate count 2, branch shapes direct_root=2, guard dominance missing, trust class same_family_merge_review. Review-only until path-specific initializer dominance is validated. confidence=0.64
      - inferred_offset_call_result_parameter_dominance: Call-result parameter dominance for v15: linked call-result initializers 1, parameter roots argument2, guard dominance missing, trust class call_result_parameter_review. Review-only until parameter/call-result path dominance is validated. confidence=0.65
      - inferred_offset_base_relocation_evidence: Base relocation evidence for v14: trusted source argument2 (direct_argument_alias), 1 post-access assignment(s), 0 stable reload(s), 1 relocation-sensitive assignment(s). relocation-sensitive RHS argument3. Treat as a moving logical layout; keep canonical rewrite blocked until segment or relocation validation is available. confidence=0.70
      - inferred_offset_post_access_mutation_blocker: Post-access mutation blocker for v14: post-access assignments 1, risky 1, stable reloads 0, reasons base is reassigned after layout access, trust class reassignment_blocked. Canonical rewrite remains blocked until later layout accesses are proven to use the same base object. confidence=0.66
      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v14: base is a decompiler temporary. Review-only aliases remain available. confidence=0.73
      - inferred_offset_temp_provenance_trace: Temp-base provenance trace for v8: trust class trusted_stable_temp, source MakeObject(v7) (call_result/direct_call_result_alias), origin call_result, first layout access line 12, pre-access initializers 1/1, post-access assignments 0 risky 0, pointer mutation no, address-taken no, array-indexed no, call-mutation-risk no, branch merge none, guard dominance missing. confidence=0.72
      - inferred_offset_trusted_temp_source: Trusted temp-base source for v8: source MakeObject(v7) (call_result/direct_call_result_alias), origin call_result, promotion ready yes, first layout access line 12. Single-source lifetime, blocker-free mutation, and threshold gates are satisfied. confidence=0.74
      - inferred_offset_temp_provenance_trace: Temp-base provenance trace for v14: trust class reassignment_blocked, source argument2 (argument/direct_argument_alias), origin function_parameter, first layout access line 16, pre-access initializers 2/2, post-access assignments 1 risky 1, pointer mutation no, address-taken no, array-indexed no, call-mutation-risk no, branch merge same_source_family, guard dominance missing. confidence=0.66
      - inferred_offset_temp_promotion_blocked: Temp-base promotion blocked for v14: trust class reassignment_blocked, reasons branch_merge, post_access_reassignment, same_source_family. Rewrite blockers base is a decompiler temporary; base has multiple initializers before layout access; base is reassigned after layout access. Canonical rewrite remains disabled until provenance, dominance, and mutation gates are clear. confidence=0.66
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

    def test_status_residue_classifies_known_magic_constants_as_nonstatus(self) -> None:
        text = (
            "result = 3285377520LL;\n"
            "*(_DWORD *)v10 = -857879331;\n"
            "status = -1073532109;\n"
        )

        literals = _decimal_status_like_literals(text)

        self.assertEqual(
            [
                "nonstatus_magic_candidate",
                "nonstatus_magic_candidate",
                "unprofiled_ntstatus_error_candidate",
            ],
            [item["review_class"] for item in literals],
        )
        self.assertEqual(["0xC0033333"], [item["hex_value"] for item in _ntstatus_family_literals(text)])

    def test_decimal_status_target_review_hints_split_four_byte_scalars(self) -> None:
        literals = _decimal_status_like_literals(
            "int callResult;\n"
            "int plainValue;\n"
            "int magicValue;\n"
            "int literalValue;\n"
            "int enumValue;\n"
            "int directEnumValue;\n"
            "int mixedDebugValue;\n"
            "int plainDebugValue;\n"
            "callResult = SomeStatusCall();\n"
            "if ( callResult == -1073741789 )\n"
            "if ( plainValue == -1073741789 )\n"
            "magicValue = 1231315286;\n"
            "literalValue = -2147483643;\n"
            "if ( enumValue == 4 || (unsigned int)(enumValue - 1) <= 1 || enumValue == -2147483647 )\n"
            "if ( directEnumValue != -1073741789 || 7u == directEnumValue )\n"
            "mixedDebugValue = -1744830460;\n"
            "mixedDebugValue = -2147483644;\n"
            "plainDebugValue = -2147483645;\n"
        )

        self.assertEqual(
            [
                "four_byte_scalar_call_result_review",
                "four_byte_scalar_comparison_review",
                "four_byte_scalar_ascii_magic_review",
                "four_byte_scalar_status_literal_assignment_review",
                "four_byte_scalar_small_enum_comparison_review",
                "four_byte_scalar_small_enum_comparison_review",
                "four_byte_scalar_debug_exception_assignment_review",
                "four_byte_scalar_debug_exception_assignment_review",
                "four_byte_scalar_status_literal_assignment_review",
            ],
            [item["target_review_hint"] for item in literals],
        )
        self.assertEqual("small_enum_comparison_candidate", literals[4]["review_class"])
        self.assertEqual("small_enum_comparison_candidate", literals[5]["review_class"])
        self.assertEqual("manual_review", literals[6]["review_class"])
        self.assertEqual("debug_exception_assignment_candidate", literals[7]["review_class"])
        self.assertEqual("profiled_status_literal_weak_target", literals[8]["review_class"])

    def test_decimal_status_target_review_queues_split_weak_evidence(self) -> None:
        queues = _decimal_status_target_review_queues(
            [
                {
                    "name": "Sample",
                    "ea": "0x140001000",
                    "summary_path": "Sample.ida-batch-summary.json",
                    "target_evidence": {
                        "complex_or_memory_target": 3,
                        "four_byte_scalar_target": 1,
                        "wide_or_nonstatus_target": 1,
                        "unknown_target": 1,
                    },
                    "target_review_classes": {
                        "complex_or_memory_target": {
                            "profiled_status_literal_candidate": 1,
                            "manual_review": 2,
                        },
                        "four_byte_scalar_target": {
                            "unprofiled_ntstatus_error_candidate": 1,
                        },
                        "wide_or_nonstatus_target": {
                            "profiled_status_literal_weak_target": 1,
                        },
                        "unknown_target": {
                            "manual_review": 1,
                        },
                    },
                    "target_review_hints_by_evidence": {
                        "complex_or_memory_target": {
                            "complex_or_memory_review": 3,
                        },
                        "four_byte_scalar_target": {
                            "four_byte_scalar_call_result_review": 1,
                        },
                        "wide_or_nonstatus_target": {
                            "wide_or_nonstatus_review": 1,
                        },
                        "unknown_target": {
                            "unknown_target_review": 1,
                        },
                    },
                    "contexts": [
                        {
                            "review_class": "profiled_status_literal_candidate",
                            "target_evidence": "complex_or_memory_target",
                        },
                        {
                            "review_class": "unprofiled_ntstatus_error_candidate",
                            "target_evidence": "four_byte_scalar_target",
                        },
                        {
                            "review_class": "profiled_status_literal_weak_target",
                            "target_evidence": "wide_or_nonstatus_target",
                        },
                        {
                            "review_class": "manual_review",
                            "target_evidence": "unknown_target",
                        },
                    ],
                }
            ],
            10,
        )

        self.assertEqual(3, queues["complex_or_memory_targets"]["literals"])
        self.assertEqual(1, queues["four_byte_scalar_targets"]["literals"])
        self.assertEqual(1, queues["wide_or_nonstatus_targets"]["literals"])
        self.assertEqual(1, queues["unknown_targets"]["literals"])
        self.assertEqual(
            {"manual_review": 2, "profiled_status_literal_candidate": 1},
            queues["complex_or_memory_targets"]["review_classes"],
        )
        self.assertEqual(
            {"four_byte_scalar_target": 1},
            queues["four_byte_scalar_targets"]["target_evidence"],
        )
        self.assertEqual(
            {"four_byte_scalar_call_result_review": 1},
            queues["four_byte_scalar_targets"]["target_review_hints"],
        )

    def test_nested_status_pointer_store_literals_split_dword_and_wide_review(self) -> None:
        stores = _nested_status_pointer_store_literals(
            "**(_DWORD **)(argument3 + 16) = -1073741790;\n"
            "**(_QWORD **)(v22 + 1224) = 3221225626LL;\n"
            "*(_DWORD *)(argument0 + 8) = -1073741790;\n"
        )

        self.assertEqual(2, len(stores))
        self.assertEqual("dword", stores[0]["store_width"])
        self.assertEqual("STATUS_ACCESS_DENIED", stores[0]["profile_name"])
        self.assertEqual(
            "dword_nested_pointer_status_store_candidate",
            stores[0]["review_class"],
        )
        self.assertEqual("wide", stores[1]["store_width"])
        self.assertEqual("STATUS_INSUFFICIENT_RESOURCES", stores[1]["profile_name"])
        self.assertEqual(
            "wide_nested_pointer_status_store_review",
            stores[1]["review_class"],
        )

    def test_analyze_corpus_reports_nested_status_pointer_store_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140003000_NestedStatusStore"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "NestedStatusStore.cleaned.cpp"
            summary_path = function_dir / "NestedStatusStore.ida-batch-summary.json"
            cleaned_path.write_text(
                r"""
__int64 __fastcall NestedStatusStore(__int64 argument0, __int64 argument1)
{
  **(_DWORD **)(argument0 + 16) = -1073741790;
  **(_DWORD **)(argument0 + 16) = -1073741811;
  **(_QWORD **)(argument1 + 1224) = 3221225626LL;
  *(_DWORD *)(argument0 + 24) = -1073741790;
  return 0;
}
""",
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "NestedStatusStore",
                        "function_ea": "0x140003000",
                        "artifacts": {
                            "cleaned_pseudocode": "NestedStatusStore.cleaned.cpp",
                            "summary": "NestedStatusStore.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            stats = report["status_store_residue_stats"]

            self.assertEqual({"0xC0000022": 1, "0xC000000D": 1, "0xC000009A": 1}, stats["nested_pointer_store_values"])
            self.assertEqual({"dword": 2, "wide": 1}, stats["nested_pointer_store_widths"])
            self.assertEqual(
                {
                    "dword_nested_pointer_status_store_candidate": 2,
                    "wide_nested_pointer_status_store_review": 1,
                },
                stats["nested_pointer_store_review_classes"],
            )
            self.assertEqual(2, stats["review_queues"]["dword_nested_pointer_status_stores"]["stores"])
            self.assertEqual(
                {"dword": 2},
                stats["review_queues"]["dword_nested_pointer_status_stores"]["store_widths"],
            )
            self.assertEqual(1, stats["review_queues"]["wide_nested_pointer_status_stores"]["stores"])
            self.assertEqual(
                {"wide": 1},
                stats["review_queues"]["wide_nested_pointer_status_stores"]["store_widths"],
            )
            self.assertEqual(
                "NestedStatusStore",
                stats["top_nested_pointer_store_functions"][0]["name"],
            )
            self.assertEqual(3, stats["top_nested_pointer_store_functions"][0]["store_count"])
            self.assertEqual(2, stats["top_nested_pointer_store_functions"][0]["dword_store_count"])
            self.assertEqual(1, stats["top_nested_pointer_store_functions"][0]["wide_store_count"])

            markdown = render_quality_markdown(report)
            self.assertIn("### Nested Pointer Status Store Residue", markdown)
            self.assertIn("`dword_nested_pointer_status_stores`", markdown)
            self.assertIn("NestedStatusStore", markdown)

    def test_analyze_corpus_reports_pointer_indexed_offset_rewrite_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140004000_PointerIndexedRewrite"
            function_dir.mkdir(parents=True)
            raw_path = function_dir / "PointerIndexedRewrite.raw.cpp"
            cleaned_path = function_dir / "PointerIndexedRewrite.cleaned.cpp"
            preview_metadata_path = function_dir / "PointerIndexedRewrite.layout-rewrite-preview.json"
            summary_path = function_dir / "PointerIndexedRewrite.ida-batch-summary.json"
            raw_path.write_text(
                r"""
__int64 __fastcall PointerIndexedRewrite(__int64 token)
{
  return *((_QWORD *)token + 2)
       + *((_DWORD *)token + 30)
       + *((_QWORD *)token + 98);
}
""",
                encoding="utf-8",
            )
            cleaned_path.write_text(
                r"""
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for token: 3 typed dereference(s) across 3 offset(s), no rewrite blockers found. Audit only; body rewrite was not applied. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for token: 3 dereference(s) can map to 3 field alias(es) field_10, field_78, field_310. Validated layout rewrite applied to canonical cleaned output. confidence=0.78
*/
__int64 __fastcall PointerIndexedRewrite(__int64 token)
{
  return token->field_10 /* _QWORD +0x10 */
       + token->field_78 /* _DWORD +0x78 */
       + *((_QWORD *)token + 98);
}
""",
                encoding="utf-8",
            )
            preview_metadata_path.write_text(
                json.dumps(
                    {
                        "canonical_cleaned_output_modified": True,
                        "preview_plans": [
                            {
                                "base": "token",
                                "advertised_offsets": [16, 120, 784],
                            }
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "PointerIndexedRewrite",
                        "function_ea": "0x140004000",
                        "artifacts": {
                            "raw_pseudocode": "PointerIndexedRewrite.raw.cpp",
                            "cleaned_pseudocode": "PointerIndexedRewrite.cleaned.cpp",
                            "layout_rewrite_preview_metadata": "PointerIndexedRewrite.layout-rewrite-preview.json",
                            "summary": "PointerIndexedRewrite.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            stats = report["pointer_indexed_offset_stats"]
            totals = stats["totals"]

            self.assertEqual(3, totals["raw_pointer_indexed_offset_deref_patterns"])
            self.assertEqual(1, totals["pointer_indexed_offset_deref_patterns"])
            self.assertEqual(3, totals["pointer_indexed_layout_rewrite_candidates"])
            self.assertEqual(2, totals["pointer_indexed_rewrite_applied"])
            self.assertEqual(1, report["body_text_stats"]["pointer_indexed_offset_deref_patterns"])
            self.assertEqual(1, report["body_text_stats"]["functions_with_pointer_indexed_offset_derefs"])
            self.assertEqual({"token": 1}, stats["top_bases"])
            self.assertEqual({"token": 2}, stats["rewritten_bases"])
            self.assertEqual("PointerIndexedRewrite", stats["top_functions"][0]["name"])
            self.assertEqual(2, stats["top_functions"][0]["pointer_indexed_rewrite_applied"])

            markdown = render_quality_markdown(report)
            self.assertIn("## Pointer-Indexed Offset Residue", markdown)
            self.assertIn("PointerIndexedRewrite", markdown)

    def test_pointer_indexed_rewrite_inventory_handles_renamed_bases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140005000_RenamedPointerIndexedRewrite"
            function_dir.mkdir(parents=True)
            raw_path = function_dir / "RenamedPointerIndexedRewrite.raw.cpp"
            cleaned_path = function_dir / "RenamedPointerIndexedRewrite.cleaned.cpp"
            preview_metadata_path = function_dir / "RenamedPointerIndexedRewrite.layout-rewrite-preview.json"
            summary_path = function_dir / "RenamedPointerIndexedRewrite.ida-batch-summary.json"
            raw_path.write_text(
                r"""
__int64 __fastcall RenamedPointerIndexedRewrite(__int64 argument0)
{
  __int64 v9;

  v9 = argument0;
  *((_QWORD *)v9 + 2) = argument0;
  *((_DWORD *)v9 + 8) = 1;
  return v9;
}
""",
                encoding="utf-8",
            )
            cleaned_path.write_text(
                r"""
__int64 __fastcall RenamedPointerIndexedRewrite(__int64 argument0)
{
  __int64 pool;

  pool = argument0;
  pool->field_10 /* _QWORD +0x10 */ = argument0;
  pool->field_20 /* _DWORD +0x20 */ = 1;
  return pool;
}
""",
                encoding="utf-8",
            )
            preview_metadata_path.write_text(
                json.dumps(
                    {
                        "canonical_cleaned_output_modified": True,
                        "rewritten_bases": ["pool"],
                        "preview_plans": [
                            {
                                "base": "pool",
                                "advertised_offsets": [16, 32],
                            }
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "RenamedPointerIndexedRewrite",
                        "function_ea": "0x140005000",
                        "artifacts": {
                            "raw_pseudocode": "RenamedPointerIndexedRewrite.raw.cpp",
                            "cleaned_pseudocode": "RenamedPointerIndexedRewrite.cleaned.cpp",
                            "layout_rewrite_preview_metadata": "RenamedPointerIndexedRewrite.layout-rewrite-preview.json",
                            "summary": "RenamedPointerIndexedRewrite.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            stats = report["pointer_indexed_offset_stats"]
            totals = stats["totals"]

            self.assertEqual(2, totals["raw_pointer_indexed_offset_deref_patterns"])
            self.assertEqual(0, totals["pointer_indexed_offset_deref_patterns"])
            self.assertEqual(2, totals["pointer_indexed_layout_rewrite_candidates"])
            self.assertEqual(2, totals["pointer_indexed_rewrite_applied"])
            self.assertEqual({"pool": 2}, stats["rewritten_bases"])

    def test_pointer_indexed_rewrite_inventory_caps_renamed_base_fallback_to_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140006000_CappedPointerIndexedRewrite"
            function_dir.mkdir(parents=True)
            raw_path = function_dir / "CappedPointerIndexedRewrite.raw.cpp"
            cleaned_path = function_dir / "CappedPointerIndexedRewrite.cleaned.cpp"
            preview_metadata_path = function_dir / "CappedPointerIndexedRewrite.layout-rewrite-preview.json"
            summary_path = function_dir / "CappedPointerIndexedRewrite.ida-batch-summary.json"
            raw_path.write_text(
                r"""
__int64 __fastcall CappedPointerIndexedRewrite(__int64 argument0)
{
  __int64 v9;

  v9 = argument0;
  *((_QWORD *)v9 + 2) = argument0;
  *((_DWORD *)v9 + 8) = 1;
  *((_DWORD *)v9 + 9) = 2;
  return v9;
}
""",
                encoding="utf-8",
            )
            cleaned_path.write_text(
                r"""
__int64 __fastcall CappedPointerIndexedRewrite(__int64 argument0)
{
  __int64 pool;

  pool = argument0;
  pool->field_10 /* _QWORD +0x10 */ = argument0;
  pool->field_20 /* _DWORD +0x20 */ = 1;
  return pool;
}
""",
                encoding="utf-8",
            )
            preview_metadata_path.write_text(
                json.dumps(
                    {
                        "canonical_cleaned_output_modified": True,
                        "rewritten_bases": ["pool"],
                        "preview_plans": [
                            {
                                "base": "pool",
                                "advertised_offsets": [16, 32],
                            }
                        ],
                        "rewrite_results": {
                            "pool": {
                                "rewritten_accesses": 2,
                                "rewritten_fields": 2,
                            }
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "CappedPointerIndexedRewrite",
                        "function_ea": "0x140006000",
                        "artifacts": {
                            "raw_pseudocode": "CappedPointerIndexedRewrite.raw.cpp",
                            "cleaned_pseudocode": "CappedPointerIndexedRewrite.cleaned.cpp",
                            "layout_rewrite_preview_metadata": "CappedPointerIndexedRewrite.layout-rewrite-preview.json",
                            "summary": "CappedPointerIndexedRewrite.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            totals = report["pointer_indexed_offset_stats"]["totals"]

            self.assertEqual(3, totals["raw_pointer_indexed_offset_deref_patterns"])
            self.assertEqual(0, totals["pointer_indexed_offset_deref_patterns"])
            self.assertEqual(2, totals["pointer_indexed_layout_rewrite_candidates"])
            self.assertEqual(2, totals["pointer_indexed_rewrite_applied"])

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
            ["base_identity_candidates", "source_identity_gap_candidates"],
            _layout_rewrite_blocker_review_profiles(
                ["trusted rewrite source is required for canonical body rewrite"]
            ),
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
            ["base_stability_blockers", "address_taken_base_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["base address is taken"]
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
            ["type_evidence_blockers", "irregular_overlay_type_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["one or more offsets mix irregular field access widths"]
            ),
        )
        self.assertEqual(
            ["type_evidence_blockers", "alignment_type_blockers"],
            _layout_rewrite_blocker_review_profiles(
                ["one or more typed offsets are not naturally aligned"]
            ),
        )

    def test_layout_promotion_next_action_prioritizes_fail_closed_review(self) -> None:
        self.assertEqual(
            "collect_more_exact_field_evidence",
            _layout_promotion_next_action(
                {"identity_evidence": "stable_argument_source"},
                [
                    "domain identity profile is report-only",
                    "rewrite offset threshold requires at least 8 offsets",
                ],
                "threshold_blocked",
            ),
        )
        self.assertEqual(
            "review_report_only_field_aliases",
            _layout_promotion_next_action(
                {"identity_evidence": "stable_argument_source"},
                [
                    "domain identity profile is report-only",
                    "rewrite offset threshold requires at least 8 offsets",
                ],
                "threshold_blocked",
                {"field_count": 2},
            ),
        )
        self.assertEqual(
            "prove_source_stability_before_rewrite",
            _layout_promotion_next_action(
                {"identity_evidence": "stable_argument_source"},
                ["base is reassigned after layout access"],
                "source_stability_blocked",
            ),
        )
        self.assertEqual(
            "resolve_type_width_or_subfield_conflict",
            _layout_promotion_next_action(
                {"identity_evidence": "stable_argument_source"},
                ["one or more offsets mix narrow subfield access widths"],
                "type_evidence_blocked",
            ),
        )
        self.assertEqual(
            "add_exact_identity_or_keep_review_only",
            _layout_promotion_next_action(
                {"identity_evidence": "none"},
                ["rewrite access threshold requires at least 12 accesses"],
                "missing_identity_evidence",
            ),
        )
        self.assertEqual(
            "prove_source_provenance_before_rewrite",
            _layout_promotion_next_action(
                {
                    "identity_evidence": "stable_argument_source",
                    "source_provenance": "unknown_source_alias",
                },
                [],
                "source_provenance_blocked",
            ),
        )
        self.assertEqual(
            "add_exact_source_identity_or_keep_review_only",
            _layout_promotion_next_action(
                {"identity_evidence": "none"},
                ["trusted rewrite source is required for canonical body rewrite"],
                "trusted_source_missing",
            ),
        )
        self.assertEqual(
            ["report_only_profile", "offset_threshold_gap"],
            _layout_promotion_next_action_details(
                {"identity_evidence": "stable_argument_source"},
                [
                    "domain identity profile is report-only",
                    "rewrite offset threshold requires at least 8 offsets",
                ],
                "collect_more_exact_field_evidence",
            ),
        )
        self.assertEqual(
            ["report_only_profile", "offset_threshold_gap", "observed_field_aliases"],
            _layout_promotion_next_action_details(
                {"identity_evidence": "stable_argument_source"},
                [
                    "domain identity profile is report-only",
                    "rewrite offset threshold requires at least 8 offsets",
                ],
                "review_report_only_field_aliases",
                {"field_count": 2},
            ),
        )
        self.assertEqual(
            ["post_access_reassignment", "address_taken"],
            _layout_promotion_next_action_details(
                {"identity_evidence": "stable_argument_source"},
                [
                    "base is reassigned after layout access",
                    "base address is taken before layout access",
                ],
                "prove_source_stability_before_rewrite",
            ),
        )
        self.assertEqual(
            [
                "report_only_profile",
                "observed_field_aliases",
                "multiple_initializers",
                "offset_threshold_gap",
                "access_threshold_gap",
                "narrow_subfield_conflict",
                "alignment_conflict",
            ],
            _layout_promotion_next_action_details(
                {"identity_evidence": "stable_argument_source"},
                [
                    "domain identity profile is report-only",
                    "base has multiple initializers before layout access",
                    "rewrite offset threshold requires at least 8 offsets",
                    "rewrite access threshold requires at least 12 accesses",
                    "one or more offsets mix narrow subfield access widths",
                    "one or more typed offsets are not naturally aligned",
                ],
                "prove_source_stability_before_rewrite",
                {"field_count": 6},
            ),
        )
        self.assertEqual(
            ["narrow_subfield_conflict", "alignment_conflict"],
            _layout_promotion_next_action_details(
                {"identity_evidence": "stable_argument_source"},
                [
                    "one or more offsets mix narrow subfield access widths",
                    "one or more typed offsets are not naturally aligned",
                ],
                "resolve_type_width_or_subfield_conflict",
            ),
        )
        self.assertEqual(
            ["trusted_source_required", "missing_identity_evidence"],
            _layout_promotion_next_action_details(
                {"identity_evidence": "none"},
                ["trusted rewrite source is required for canonical body rewrite"],
                "add_exact_source_identity_or_keep_review_only",
            ),
        )

    def test_body_offset_review_evidence_distinguishes_source_report_only(self) -> None:
        blockers = [
            {
                "reasons": [
                    "source domain identity profile is report-only",
                    "trusted rewrite source is required for canonical body rewrite",
                ]
            }
        ]

        evidence = _body_offset_residue_review_evidence(
            "source_identity_blocked_residue",
            [],
            [],
            blockers,
            [],
            {},
            {},
        )
        hints = _body_offset_residue_promotion_hints(
            "source_identity_blocked_residue",
            "add_exact_source_identity_or_keep_review_only",
            blockers,
            [],
            {},
            {},
        )

        self.assertIn("report_only_source_identity", evidence)
        self.assertIn("trusted_source_required", evidence)
        self.assertNotIn("report_only_profile_kept_closed", evidence)
        self.assertIn("promote_source_profile_before_alias_rewrite", hints)
        self.assertIn("require_exact_function_build_source_identity", hints)
        self.assertNotIn("do_not_promote_report_only_profile", hints)

    def test_body_offset_next_action_details_explain_fail_closed_gates(self) -> None:
        blockers = [
            {
                "reasons": [
                    "domain identity profile is report-only",
                    "source domain identity profile is report-only",
                    "trusted rewrite source is required for canonical body rewrite",
                    "base is reassigned after layout access",
                    "one or more offsets mix wide overlay access widths",
                    "rewrite offset threshold requires at least 8 offsets",
                ]
            }
        ]
        domain_identities = [
            {
                "base": "keyControlBlock",
                "mode": "report-only",
                "field_count": 2,
            }
        ]
        evidence = _body_offset_residue_review_evidence(
            "source_identity_blocked_residue",
            [],
            [],
            blockers,
            domain_identities,
            {},
            {"shape_class": "temp_offset_shape_review"},
        )
        hints = _body_offset_residue_promotion_hints(
            "source_identity_blocked_residue",
            "add_exact_source_identity_or_keep_review_only",
            blockers,
            domain_identities,
            {},
            {"shape_class": "temp_offset_shape_review"},
        )
        details = _body_offset_residue_next_action_details(
            "source_identity_blocked_residue",
            "add_exact_source_identity_or_keep_review_only",
            evidence,
            hints,
            blockers,
            domain_identities,
            {},
            {"shape_class": "temp_offset_shape_review"},
        )

        self.assertIn("keep_report_only_until_exact_private_layout_source", details)
        self.assertIn("field_aliases_available_for_manual_review", details)
        self.assertIn("promote_source_identity_before_alias_rewrite", details)
        self.assertIn("exact_function_build_source_identity_required", details)
        self.assertIn("prove_single_stable_source_before_body_rewrite", details)
        self.assertIn("resolve_width_alignment_or_overlay_before_rewrite", details)
        self.assertIn("collect_access_and_offset_threshold_evidence", details)
        self.assertIn("trace_temp_initializer_before_promotion", details)

    def test_body_offset_shape_profile_splits_parameter_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140002100_ParameterResidue"
            function_dir.mkdir(parents=True)
            cleaned_path = function_dir / "ParameterResidue.cleaned.cpp"
            summary_path = function_dir / "ParameterResidue.ida-batch-summary.json"
            cleaned_path.write_text(
                "\n".join(
                    [
                        "__int64 __fastcall ParameterResidue(PVOID argument0)",
                        "{",
                        "  int result;",
                        "  result = *(_DWORD *)(argument0 + 0x10);",
                        "  result += *(_DWORD *)(argument0 + 0x18);",
                        "  result += *(_DWORD *)(argument0 + 0x20);",
                        "  result += *(_DWORD *)(argument0 + 0x28);",
                        "  return result;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "ParameterResidue",
                        "function_ea": "0x140002100",
                        "artifacts": {
                            "cleaned_pseudocode": "ParameterResidue.cleaned.cpp",
                            "summary": "ParameterResidue.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            profile = _offset_deref_shape_profile(cleaned_path)
            report = analyze_corpus(root)
            stats = report["body_offset_residue_review_stats"]
            item = stats["top_functions"][0]
            decompiler_arg_path = root / "DecompilerArg.cleaned.cpp"
            decompiler_arg_path.write_text(
                "\n".join(
                    [
                        "__int64 __fastcall DecompilerArg(__int64 a1)",
                        "{",
                        "  return *(_DWORD *)(a1 + 0x10)",
                        "    + *(_DWORD *)(a1 + 0x18)",
                        "    + *(_DWORD *)(a1 + 0x20)",
                        "    + *(_DWORD *)(a1 + 0x28);",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            decompiler_arg_profile = _offset_deref_shape_profile(decompiler_arg_path)

            self.assertEqual("parameter_offset_shape_review", profile["shape_class"])
            self.assertEqual("renamed_argument", profile["max_base_class"])
            self.assertEqual(4, profile["max_base_access_count"])
            self.assertEqual(4, profile["max_base_offset_count"])
            self.assertEqual("parameter_offset_shape_review", decompiler_arg_profile["shape_class"])
            self.assertEqual("decompiler_argument", decompiler_arg_profile["max_base_class"])
            self.assertEqual(1, stats["review_classes"]["parameter_offset_shape_review"])
            self.assertEqual(1, stats["next_actions"]["add_parameter_profile_or_keep_review_only"])
            self.assertEqual(1, stats["review_evidence"]["parameter_offset_shape_review"])
            self.assertEqual(
                1,
                stats["promotion_hints"]["validate_parameter_semantics_before_type_correction"],
            )
            self.assertEqual(1, stats["offset_shape_classes"]["parameter_offset_shape_review"])
            self.assertEqual(1, stats["offset_base_classes"]["renamed_argument"])
            self.assertEqual("ParameterResidue", item["name"])
            self.assertEqual("parameter_offset_shape_review", item["review_class"])
            self.assertIn("argument0", item["top_bases"])

    def test_body_offset_review_queues_group_actionable_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def write_function(
                ea: str,
                name: str,
                text: str,
                summary_extra: dict[str, object] | None = None,
            ) -> None:
                function_dir = root / "functions" / ("%s_%s" % (ea.replace("0x", ""), name))
                function_dir.mkdir(parents=True)
                cleaned_name = "%s.cleaned.cpp" % name
                summary_name = "%s.ida-batch-summary.json" % name
                summary = {
                    "mode": "ida_batch_export",
                    "function": name,
                    "function_ea": ea,
                    "artifacts": {
                        "cleaned_pseudocode": cleaned_name,
                        "summary": summary_name,
                    },
                }
                if summary_extra:
                    summary.update(summary_extra)
                (function_dir / cleaned_name).write_text(text, encoding="utf-8")
                (function_dir / summary_name).write_text(
                    json.dumps(summary, indent=2),
                    encoding="utf-8",
                )

            write_function(
                "0x140010000",
                "CmpQueueResidue",
                "\n".join(
                    [
                        "/*",
                        "    Kernel insights:",
                        "      - domain_structure_identity: Domain identity for keyControlBlock: role keyControlBlock, structure CM_KEY_CONTROL_BLOCK, mode report-only, profile windows.registry_config.queue parameter 0. Fields field_10=+0x10 ULONG_PTR, field_18=+0x18 ULONG_PTR.",
                        "      - inferred_offset_stable_base_source: Stable base source for keyControlBlock: transactionLogEntry (parameter source, parameter_direct_alias), 4 typed dereference(s) across 4 offset(s). Review-only; temp/generic base keeps rewrite blocked until source identity is trusted. confidence=0.68",
                        "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for keyControlBlock: domain identity profile is report-only; source domain identity profile is report-only; trusted rewrite source is required for canonical body rewrite. Review-only aliases remain available. confidence=0.73",
                        "*/",
                        "__int64 __fastcall CmpQueueResidue(PVOID keyControlBlock)",
                        "{",
                        "  return *(_QWORD *)(keyControlBlock + 0x10)",
                        "       + *(_QWORD *)(keyControlBlock + 0x18)",
                        "       + *(_QWORD *)(keyControlBlock + 0x20)",
                        "       + *(_QWORD *)(keyControlBlock + 0x28);",
                        "}",
                        "",
                    ]
                ),
            )
            write_function(
                "0x140020000",
                "MiTypeConflictResidue",
                "\n".join(
                    [
                        "/*",
                        "    Kernel insights:",
                        "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v5: one or more offsets mix wide overlay access widths; one or more typed offsets are not naturally aligned. Review-only aliases remain available. confidence=0.73",
                        "*/",
                        "__int64 __fastcall MiTypeConflictResidue(__int64 a1)",
                        "{",
                        "  __int64 v5;",
                        "  v5 = a1;",
                        "  return *(_QWORD *)(v5 + 0x10)",
                        "       + *(_QWORD *)(v5 + 0x18)",
                        "       + *(_QWORD *)(v5 + 0x20)",
                        "       + *(_QWORD *)(v5 + 0x28);",
                        "}",
                        "",
                    ]
                ),
            )
            write_function(
                "0x140025000",
                "MiBuildMismatchResidue",
                "\n".join(
                    [
                        "/*",
                        "    Kernel insights:",
                        "      - domain_structure_identity: Domain identity for memoryContext: role memoryContext, structure MI_PRIVATE_CONTEXT, mode report-only, profile windows.memory_manager.build_mismatch parameter 0. Fields field_10=+0x10 ULONG_PTR, field_18=+0x18 ULONG_PTR.",
                        "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for memoryContext: domain identity profile is report-only; trusted rewrite source is required for canonical body rewrite. Review-only aliases remain available. confidence=0.73",
                        "*/",
                        "__int64 __fastcall MiBuildMismatchResidue(PVOID memoryContext)",
                        "{",
                        "  return *(_QWORD *)(memoryContext + 0x10)",
                        "       + *(_QWORD *)(memoryContext + 0x18)",
                        "       + *(_QWORD *)(memoryContext + 0x20)",
                        "       + *(_QWORD *)(memoryContext + 0x28);",
                        "}",
                        "",
                    ]
                ),
                {
                    "domain_identity_summary": {
                        "total_hits": 1,
                        "report_only_hits": 1,
                        "preview_rewrite_hits": 0,
                        "canonical_rewrite_eligible_hits": 0,
                        "blocker_counts": {"build_mismatch": 1, "profile_report_only": 1},
                        "profile_counts": {"windows.memory_manager.build_mismatch": 1},
                    }
                },
            )
            write_function(
                "0x140030000",
                "ParameterResidue",
                "\n".join(
                    [
                        "__int64 __fastcall ParameterResidue(PVOID argument0)",
                        "{",
                        "  return *(_DWORD *)(argument0 + 0x10)",
                        "       + *(_DWORD *)(argument0 + 0x18)",
                        "       + *(_DWORD *)(argument0 + 0x20)",
                        "       + *(_DWORD *)(argument0 + 0x28);",
                        "}",
                        "",
                    ]
                ),
            )

            report = analyze_corpus(root)
            stats = report["body_offset_residue_review_stats"]
            queues = stats["review_queues"]

            self.assertIn("next_action_details", stats)
            self.assertIn("priority_factors", stats)
            self.assertIn("fail_closed_gates", stats)
            self.assertIn("fail_closed_families", stats)
            self.assertIn("rewrite_safety_policies", stats)
            self.assertIn("evidence_maturity", stats)
            self.assertIn("review_focuses", stats)
            self.assertEqual(
                2,
                queues["report_only_exact_promotion_candidates"]["functions"],
            )
            self.assertEqual(
                2,
                queues["report_only_field_alias_review"]["functions"],
            )
            self.assertEqual(
                2,
                queues["source_identity_required"]["functions"],
            )
            self.assertEqual(
                1,
                queues["source_provenance_review"]["functions"],
            )
            self.assertEqual(
                1,
                queues["type_conflict_required"]["functions"],
            )
            self.assertEqual(
                1,
                queues["parameter_profile_candidates"]["functions"],
            )
            self.assertEqual(
                2,
                stats["next_action_details"]["field_aliases_available_for_manual_review"],
            )
            self.assertEqual(
                1,
                stats["next_action_details"]["resolve_width_alignment_or_overlay_before_rewrite"],
            )
            self.assertEqual(
                1,
                stats["next_action_details"]["stable_source_provenance_available_for_review"],
            )
            self.assertEqual(
                1,
                stats["next_action_details"]["direct_parameter_source_alias_available"],
            )
            self.assertEqual(1, stats["fail_closed_gates"]["report_only_private_layout"])
            self.assertEqual(1, stats["fail_closed_gates"]["source_build_mismatch"])
            self.assertEqual(1, stats["fail_closed_gates"]["type_conflict_required"])
            self.assertEqual(1, stats["fail_closed_families"]["report_only_identity"])
            self.assertEqual(1, stats["fail_closed_families"]["source_identity"])
            self.assertEqual(1, stats["fail_closed_families"]["type_conflict"])
            self.assertEqual(1, stats["rewrite_safety_policies"]["do_not_rewrite_report_only_profile"])
            self.assertEqual(1, stats["rewrite_safety_policies"]["resolve_build_identity_before_rewrite"])
            self.assertEqual(1, stats["rewrite_safety_policies"]["resolve_type_conflicts_before_rewrite"])
            self.assertEqual(1, stats["evidence_maturity"]["report_only_alias_with_stable_source"])
            self.assertEqual(1, stats["evidence_maturity"]["build_identity_mismatch"])
            self.assertEqual(1, stats["evidence_maturity"]["type_conflict_unresolved"])
            self.assertEqual(3, stats["priority_factors"]["core_subsystem"])
            self.assertEqual(1, stats["priority_factors"]["source_build_mismatch"])
            self.assertEqual(2, stats["priority_factors"]["report_only_field_alias_available"])
            self.assertEqual(1, stats["priority_factors"]["stable_source_provenance_available"])
            self.assertEqual(1, stats["priority_factors"]["direct_parameter_source_alias"])
            self.assertTrue(
                any(
                    key.startswith("registry/report_only_private_layout")
                    for key in stats["review_focuses"]
                )
            )
            self.assertIn(
                "Report-only identities",
                queues["report_only_exact_promotion_candidates"]["description"],
            )
            self.assertIn(
                "exact private layout source",
                queues["report_only_exact_promotion_candidates"]["recommended_next_step"],
            )
            self.assertIn(
                "canonical rewrite",
                queues["report_only_field_alias_review"]["recommended_next_step"],
            )
            self.assertIn(
                "parameter_direct_alias",
                queues["source_provenance_review"]["stable_source_provenance"],
            )
            cmp_queue_item = next(
                item
                for item in queues["report_only_exact_promotion_candidates"]["items"]
                if item["name"] == "CmpQueueResidue"
            )
            self.assertEqual(
                "report_only_private_layout",
                cmp_queue_item["fail_closed_gate"],
            )
            self.assertEqual("report_only_identity", cmp_queue_item["fail_closed_family"])
            self.assertEqual(
                "do_not_rewrite_report_only_profile",
                cmp_queue_item["rewrite_safety_policy"],
            )
            self.assertEqual("report_only_alias_with_stable_source", cmp_queue_item["evidence_maturity"])
            self.assertIn(
                "report_only_field_alias_available",
                cmp_queue_item["priority_factors"],
            )
            self.assertEqual(
                {"parameter_direct_alias": 1},
                cmp_queue_item["stable_source_provenance"],
            )
            self.assertEqual(
                {"parameter": 1},
                cmp_queue_item["stable_source_kinds"],
            )
            self.assertEqual(
                {"transactionLogEntry": 1},
                cmp_queue_item["top_stable_sources"],
            )
            self.assertEqual(
                {"windows.registry_config.queue": 1},
                cmp_queue_item["domain_profiles"],
            )
            self.assertIn(
                "review_focus",
                queues["report_only_exact_promotion_candidates"]["items"][0],
            )
            self.assertTrue(
                any(
                    item["name"] == "MiBuildMismatchResidue"
                    and item["fail_closed_gate"] == "source_build_mismatch"
                    for item in queues["report_only_exact_promotion_candidates"]["items"]
                )
            )
            self.assertIn(
                "exact_function_build_source_identity_required",
                queues["source_identity_required"]["items"][0]["next_action_details"],
            )

    def test_body_offset_named_goal_targets_stay_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            def write_function(ea: str, name: str, text: str) -> None:
                function_dir = root / "functions" / ("%s_%s" % (ea.replace("0x", ""), name))
                function_dir.mkdir(parents=True)
                cleaned_name = "%s.cleaned.cpp" % name
                summary_name = "%s.ida-batch-summary.json" % name
                (function_dir / cleaned_name).write_text(text, encoding="utf-8")
                (function_dir / summary_name).write_text(
                    json.dumps(
                        {
                            "mode": "ida_batch_export",
                            "function": name,
                            "function_ea": ea,
                            "artifacts": {
                                "cleaned_pseudocode": cleaned_name,
                                "summary": summary_name,
                            },
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )

            write_function(
                "0x140040000",
                "CmpFreeKeyControlBlock",
                "\n".join(
                    [
                        "/*",
                        "    Kernel insights:",
                        "      - domain_structure_identity: Domain identity for keyControlBlock: role keyControlBlock, structure CM_KEY_CONTROL_BLOCK, mode report-only, profile windows.registry_config.cmp_free_key_control_block parameter 0. Fields field_8=+0x8 ULONG.",
                        "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for keyControlBlock: domain identity profile is report-only; rewrite offset threshold requires at least 8 offsets. Review-only aliases remain available. confidence=0.73",
                        "*/",
                        "__int64 __fastcall CmpFreeKeyControlBlock(PVOID keyControlBlock)",
                        "{",
                        "  return *(_DWORD *)(keyControlBlock + 0x8);",
                        "}",
                        "",
                    ]
                ),
            )
            write_function(
                "0x140050000",
                "MiPrefetchVirtualMemory",
                "\n".join(
                    [
                        "__int64 __fastcall MiPrefetchVirtualMemory(__int64 context)",
                        "{",
                        "  return *(_DWORD *)(context + 0x10);",
                        "}",
                        "",
                    ]
                ),
            )

            report = analyze_corpus(root)
            stats = report["body_offset_residue_review_stats"]
            queues = stats["review_queues"]
            named_items = queues["named_goal_targets"]["items"]

            self.assertEqual("registry", _body_offset_named_goal_target_group("CmpFreeKeyControlBlock"))
            self.assertEqual("memory", _body_offset_named_goal_target_group("MiPrefetchVirtualMemory"))
            self.assertEqual("object_callback_token", _body_offset_named_goal_target_group("ObpFreeObject"))
            self.assertEqual(2, stats["totals"]["functions_with_named_goal_targets"])
            self.assertEqual(1, stats["named_target_groups"]["registry"])
            self.assertEqual(1, stats["named_target_groups"]["memory"])
            self.assertEqual(2, queues["named_goal_targets"]["functions"])
            self.assertEqual(
                {"registry": 1, "memory": 1},
                queues["named_goal_targets"]["target_groups"],
            )
            self.assertTrue(all(item["named_goal_target"] for item in named_items))
            self.assertTrue(
                any(
                    item["name"] == "CmpFreeKeyControlBlock"
                    and item["named_goal_target_group"] == "registry"
                    and item["fail_closed_family"] == "report_only_identity"
                    and item["rewrite_safety_policy"] == "do_not_rewrite_report_only_profile"
                    for item in named_items
                )
            )
            self.assertTrue(
                any(
                    item["name"] == "MiPrefetchVirtualMemory"
                    and item["named_goal_target_group"] == "memory"
                    and "named_goal_target" in item["priority_factors"]
                    for item in named_items
                )
            )
            self.assertEqual("report_only_identity", _body_offset_fail_closed_family("report_only_private_layout"))
            self.assertEqual("indexed_layout", _body_offset_fail_closed_family("pointer_indexed_separate_model"))
            self.assertEqual(
                "require_exact_function_build_source_identity",
                _body_offset_rewrite_safety_policy(
                    "exact_source_identity_required",
                    "source_identity_blocked_residue",
                    ["trusted_source_required"],
                    ["exact_function_build_source_identity_required"],
                ),
            )

    def test_low_pressure_queue_keeps_stronger_report_only_gate_separate(self) -> None:
        report_only_item = {
            "review_class": "report_only_blocked_residue",
            "fail_closed_gate": "report_only_private_layout",
            "next_action_details": [
                "field_aliases_available_for_manual_review",
                "defer_low_pressure_residue",
            ],
            "priority_factors": [
                "core_subsystem",
                "report_only_field_alias_available",
                "core_report_only_deferred_shape",
            ],
            "review_evidence": ["report_only_profile_kept_closed"],
        }
        low_pressure_item = {
            "review_class": "low_pressure_offset_residue",
            "fail_closed_gate": "low_pressure_deferred",
            "next_action_details": ["defer_low_pressure_residue"],
            "priority_factors": ["low_pressure_deferred"],
            "review_evidence": ["low_pressure_offset_residue"],
        }

        self.assertTrue(
            _body_offset_residue_item_matches_queue(
                "report_only_field_alias_review",
                report_only_item,
            )
        )
        self.assertFalse(
            _body_offset_residue_item_matches_queue(
                "low_pressure_deferred",
                report_only_item,
            )
        )
        self.assertTrue(
            _body_offset_residue_item_matches_queue(
                "low_pressure_deferred",
                low_pressure_item,
            )
        )

    def test_rewrite_blocker_parser_preserves_source_identity_detail(self) -> None:
        blockers = _extract_layout_rewrite_blockers(
            "/*\n"
            "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v6: "
            "source domain identity profile is report-only. Source identity completionApc "
            "(parameter_back_container_alias) is report-only profile "
            "windows.io_manager.iop_complete_request_apc for completionApc/KAPC; exact "
            "function/build/source identity is required before canonical rewrite. "
            "Review-only aliases remain available. confidence=0.73\n"
            "*/\n"
        )

        self.assertEqual(1, len(blockers))
        self.assertEqual("v6", blockers[0]["base"])
        self.assertEqual(["source domain identity profile is report-only"], blockers[0]["reasons"])
        self.assertEqual("completionApc", blockers[0]["source_identity_source"])
        self.assertEqual(
            "parameter_back_container_alias",
            blockers[0]["source_identity_source_provenance"],
        )
        self.assertEqual(
            "windows.io_manager.iop_complete_request_apc",
            blockers[0]["source_identity_profile_id"],
        )
        self.assertEqual("completionApc", blockers[0]["source_identity_role"])
        self.assertEqual("KAPC", blockers[0]["source_identity_structure"])

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
            self.assertEqual(1, stats["application_statuses"]["review_only"])
            self.assertEqual(1, stats["review_classes"]["partial_review_only"])
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
                {"review_only": 1},
                stats["top_functions"][0]["application_statuses"],
            )
            self.assertEqual(
                {"partial_review_only": 1},
                stats["top_functions"][0]["review_classes"],
            )
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
                1,
                report["layout_rewrite_partial_opportunity_stats"]["application_statuses"][
                    "validated_partial_applied"
                ],
            )
            self.assertEqual(
                1,
                report["layout_rewrite_partial_opportunity_stats"]["review_classes"][
                    "validated_partial_rewrite"
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
            self.assertEqual(
                {"validated_partial_applied": 1},
                report["layout_rewrite_partial_opportunity_stats"]["top_functions"][0][
                    "application_statuses"
                ],
            )
            self.assertEqual(
                {"validated_partial_rewrite": 1},
                report["layout_rewrite_partial_opportunity_stats"]["top_functions"][0][
                    "review_classes"
                ],
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
            self.assertIn("api_semantic_review_queue", report)
            prototype_stats = report["prototype_correction_stats"]
            self.assertEqual(1, prototype_stats["totals"]["function_identity_candidates"])
            self.assertEqual(2, prototype_stats["totals"]["parameter_type_corrections"])
            self.assertEqual(1, prototype_stats["totals"]["applied_parameter_type_corrections"])
            self.assertEqual(1, prototype_stats["totals"]["blocked_parameter_type_corrections"])
            self.assertEqual(1, prototype_stats["totals"]["corrected_parameter_map_entries"])
            self.assertEqual(1, prototype_stats["totals"]["body_rewrite_ready"])
            self.assertEqual(1, prototype_stats["totals"]["body_rewrite_blockers"])
            self.assertEqual(1, prototype_stats["totals"]["generic_parameter_survivors"])
            self.assertEqual(1, prototype_stats["totals"]["offset_deref_survivors"])
            self.assertEqual(1, prototype_stats["totals"]["functions_with_correction_evidence"])
            self.assertEqual(0, prototype_stats["totals"]["negative_control_functions"])
            self.assertEqual(0, prototype_stats["negative_controls"]["function_count"])
            self.assertEqual(1, prototype_stats["blocker_counts"]["report_only_profile"])
            self.assertEqual(1, prototype_stats["blocker_counts"]["type_conflict"])
            self.assertEqual(1, prototype_stats["blocker_counts"]["overlay"])
            self.assertEqual(1, prototype_stats["profile_counts"]["windows.io_manager.delete_device"])
            self.assertEqual(1, prototype_stats["profile_counts"]["windows.io_manager.call_driver"])
            self.assertEqual(1, prototype_stats["function_identity_profiles"]["windows.io_manager.delete_device"])
            self.assertEqual(1, prototype_stats["canonical_types"]["PDEVICE_OBJECT"])
            self.assertEqual(2, prototype_stats["body_rewrite_source_provenance"]["corrected_parameter_map"])
            self.assertEqual("Sample", prototype_stats["top_functions"][0]["name"])
            self.assertEqual(1, prototype_stats["top_functions"][0]["applied_parameter_type_corrections"])
            type_conflict_queue = prototype_stats["review_queues"]["type_conflict_type_corrections"]
            self.assertEqual(1, type_conflict_queue["function_count"])
            self.assertEqual(1, type_conflict_queue["blocked_parameter_type_corrections"])
            self.assertEqual(1, type_conflict_queue["blockers"]["type_conflict"])
            self.assertEqual("Sample", type_conflict_queue["items"][0]["name"])
            body_offset_stats = report["body_offset_residue_review_stats"]
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_offset_residue"])
            self.assertEqual(1, body_offset_stats["totals"]["offset_deref_survivors"])
            self.assertEqual(1, body_offset_stats["totals"]["generic_parameter_survivors"])
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_rewrite_ready"])
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_rewrite_blockers"])
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_hot_field_clusters"])
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_stable_base_sources"])
            self.assertEqual(1, body_offset_stats["totals"]["functions_with_indexed_callback_tables"])
            self.assertEqual(1, body_offset_stats["subsystems"]["other"])
            self.assertEqual(
                1,
                body_offset_stats["next_actions"]["verify_validated_rewrite_or_partial_residue"],
            )
            self.assertEqual(1, body_offset_stats["review_classes"]["rewrite_ready_residue"])
            self.assertEqual("Sample", body_offset_stats["top_functions"][0]["name"])
            self.assertEqual("rewrite_ready_residue", body_offset_stats["top_functions"][0]["review_class"])
            self.assertIn("sessionSpace", body_offset_stats["top_functions"][0]["top_bases"])
            self.assertEqual(
                1,
                body_offset_stats["review_evidence"]["validated_rewrite_still_has_residue"],
            )
            self.assertEqual(
                1,
                body_offset_stats["promotion_hints"]["verify_validated_rewrite_output"],
            )
            self.assertIn(
                "validated_rewrite_still_has_residue",
                body_offset_stats["top_functions"][0]["review_evidence"],
            )
            self.assertIn(
                "verify_validated_rewrite_output",
                body_offset_stats["top_functions"][0]["promotion_hints"],
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
            temp_stats = report["layout_temp_provenance_stats"]
            self.assertEqual(2, temp_stats["totals"]["trace_comments"])
            self.assertEqual(1, temp_stats["totals"]["trusted_temp_sources"])
            self.assertEqual(1, temp_stats["totals"]["blocked_candidates"])
            self.assertEqual(1, temp_stats["totals"]["rewrite_ready_unlocked"])
            self.assertEqual(1, temp_stats["trust_classes"]["trusted_stable_temp"])
            self.assertEqual(2, temp_stats["trust_classes"]["reassignment_blocked"])
            self.assertEqual(2, temp_stats["source_origins"]["call_result"])
            self.assertEqual(1, temp_stats["source_origins"]["function_parameter"])
            self.assertEqual(1, temp_stats["branch_merge_shapes"]["same_source_family"])
            self.assertEqual(1, temp_stats["block_reasons"]["post_access_reassignment"])
            self.assertEqual("Sample", temp_stats["top_functions"][0]["name"])
            self.assertEqual(2, temp_stats["top_functions"][0]["trace_count"])
            self.assertEqual(1, temp_stats["top_functions"][0]["trusted_count"])
            self.assertEqual(1, temp_stats["top_functions"][0]["blocked_count"])
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
            hot_cluster_stats = report["layout_hot_field_cluster_stats"]
            self.assertEqual(1, hot_cluster_stats["totals"]["cluster_comments"])
            self.assertEqual(1, hot_cluster_stats["totals"]["functions_with_cluster_comments"])
            self.assertEqual(27, hot_cluster_stats["totals"]["access_observations"])
            self.assertEqual(6, hot_cluster_stats["totals"]["offset_observations"])
            self.assertEqual(3, hot_cluster_stats["totals"]["field_observations"])
            self.assertEqual(1, hot_cluster_stats["top_bases"]["context"])
            self.assertEqual(1, hot_cluster_stats["base_kinds"]["generic"])
            self.assertEqual(1, hot_cluster_stats["field_types"]["_DWORD"])
            self.assertEqual(1, hot_cluster_stats["field_types"]["_QWORD *"])
            self.assertEqual("Sample", hot_cluster_stats["top_functions"][0]["name"])
            self.assertEqual(27, hot_cluster_stats["top_functions"][0]["max_access_count"])
            self.assertEqual(10, hot_cluster_stats["top_functions"][0]["max_top_field_access_count"])
            indexed_callback_stats = report["layout_indexed_callback_table_stats"]
            self.assertEqual(1, indexed_callback_stats["totals"]["evidence_comments"])
            self.assertEqual(1, indexed_callback_stats["totals"]["functions_with_evidence_comments"])
            self.assertEqual(8, indexed_callback_stats["totals"]["access_observations"])
            self.assertEqual(8, indexed_callback_stats["totals"]["slot_observations"])
            self.assertEqual(4, indexed_callback_stats["totals"]["scalar_index_observations"])
            self.assertEqual(4, indexed_callback_stats["totals"]["callback_slot_observations"])
            self.assertEqual(1, indexed_callback_stats["top_bases"]["argument0"])
            self.assertEqual(1, indexed_callback_stats["base_kinds"]["argument_identity"])
            self.assertEqual(1, indexed_callback_stats["alias_bases"]["v4"])
            self.assertEqual("Sample", indexed_callback_stats["top_functions"][0]["name"])
            self.assertEqual(8, indexed_callback_stats["top_functions"][0]["max_access_count"])
            self.assertEqual(8, indexed_callback_stats["top_functions"][0]["max_slot_count"])
            self.assertEqual(
                {"v4": 1},
                indexed_callback_stats["top_functions"][0]["alias_bases"],
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
                {"add_exact_identity_or_keep_review_only": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "threshold_gap_candidates"
                ]["promotion_next_actions"],
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
                {"consider_validated_profile_promotion": 1},
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["promotion_next_actions"],
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
                "consider_validated_profile_promotion",
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["promotion_next_action"],
            )
            self.assertEqual(
                ["identity_only"],
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["promotion_risk_factors"],
            )
            self.assertEqual(
                ["stable_argument_source"],
                report["layout_rewrite_blocker_stats"]["review_queues"][
                    "base_identity_candidates"
                ]["items"][0]["promotion_next_action_details"],
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
            self.assertEqual(
                {
                    "add_exact_identity_or_keep_review_only": 1,
                    "consider_validated_profile_promotion": 1,
                },
                report["layout_rewrite_blocker_stats"]["top_functions"][0][
                    "promotion_next_actions"
                ],
            )
            self.assertEqual(
                {"missing_identity_evidence": 1, "stable_argument_source": 1},
                report["layout_rewrite_blocker_stats"]["top_functions"][0][
                    "promotion_next_action_details"
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
            self.assertEqual(1, report["text_stats"]["inferred_offset_field_hot_clusters"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_indexed_callback_table_evidence"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_subfield_overlays"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_narrow_subfields"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_bitfield_aliases"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_stable_base_sources"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_base_stability"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_base_merge_evidence"])
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_call_result_parameter_merge_provenance"],
            )
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_call_result_merge_equivalence"],
            )
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_allocation_null_merge_dominance"],
            )
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_call_result_temporary_merge_provenance"],
            )
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_bugcheck_parameter_merge_identity"],
            )
            self.assertEqual(
                1,
                report["text_stats"]["inferred_offset_same_source_family_merge_dominance"],
            )
            self.assertEqual(1, report["text_stats"]["inferred_offset_same_family_merge_provenance"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_call_result_parameter_dominance"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_base_relocation_evidence"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_post_access_mutation_blocker"])
            self.assertEqual(2, report["text_stats"]["inferred_offset_temp_provenance_trace"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_trusted_temp_source"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_temp_promotion_blocked"])
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
                {"call_result_status_carrier_target": 3, "complex_or_memory_target": 1},
                decimal_stats["target_evidence"],
            )
            self.assertEqual(
                {"status_flow_target": 3, "complex_or_memory_review": 1},
                decimal_stats["target_review_hints"],
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
                {"call_result_status_carrier_target": 2, "complex_or_memory_target": 1},
                decimal_stats["review_queues"]["strong_profiled_status_literals"][
                    "target_evidence"
                ],
            )
            self.assertEqual(
                1,
                decimal_stats["target_review_queues"]["complex_or_memory_targets"]["literals"],
            )
            self.assertEqual(
                1,
                decimal_stats["target_review_queues"]["complex_or_memory_targets"][
                    "functions"
                ],
            )
            self.assertEqual(
                {"profiled_status_literal_candidate": 1},
                decimal_stats["target_review_queues"]["complex_or_memory_targets"][
                    "review_classes"
                ],
            )
            self.assertEqual(
                {"complex_or_memory_target": 1},
                decimal_stats["target_review_queues"]["complex_or_memory_targets"][
                    "target_evidence"
                ],
            )
            self.assertEqual(
                {"complex_or_memory_review": 1},
                decimal_stats["target_review_queues"]["complex_or_memory_targets"][
                    "target_review_hints"
                ],
            )
            self.assertEqual(
                0,
                decimal_stats["target_review_queues"]["four_byte_scalar_targets"][
                    "literals"
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
                {"call_result_status_carrier_target": 3, "complex_or_memory_target": 1},
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
                "call_result_status_carrier_target",
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
            self.assertNotIn("inferred_offset_field_hot_clusters", report["body_text_stats"])
            self.assertNotIn(
                "inferred_offset_indexed_callback_table_evidence",
                report["body_text_stats"],
            )
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

    def test_api_semantic_review_queue_groups_actionable_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_api_queue_fixture(
                root,
                "QueueOne",
                "0x140001000",
                [
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "large_dispatcher",
                        "old": "v14",
                        "new": "irp",
                        "callee": "IoReuseIrp",
                        "argument_index": 0,
                        "argument": "v14",
                        "parameter": "Irp",
                        "parameter_type": "PIRP",
                    },
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "weak_parameter_name",
                        "old": "v2",
                        "callee": "ExAcquireFastMutex",
                        "argument_index": 0,
                        "argument": "v2",
                        "parameter": "FastMutex",
                        "parameter_type": "PFAST_MUTEX",
                    },
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "conflict_target",
                        "old": "v12",
                        "new": "object",
                        "callee": "ObfDereferenceObject",
                        "argument_index": 0,
                        "argument": "v12",
                        "parameter": "Object",
                        "parameter_type": "PVOID",
                        "candidate_details": [
                            {"old": "v12", "new": "object", "source": "api-argument"},
                            {"old": "v19", "new": "object", "source": "api-argument"},
                        ],
                    },
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "unsafe_wrapper_role",
                        "old": "v4",
                        "new": "pool",
                        "callee": "ExFreePoolWithTag",
                        "argument_index": 0,
                        "argument": "v4",
                        "parameter": "P",
                        "parameter_type": "PVOID",
                    },
                    {
                        "stage": "api-out-param",
                        "status": "rejected",
                        "reason": "missing_profile",
                        "old": "v8",
                        "new": "keyValueInformation",
                        "callee": "ZwQueryValueKey",
                        "argument_index": 3,
                        "argument": "v8",
                        "parameter": "KeyValueInformation",
                        "parameter_type": "PVOID",
                    },
                ],
            )
            _write_api_queue_fixture(
                root,
                "QueueTwo",
                "0x140002000",
                [
                    {
                        "stage": "api-argument",
                        "status": "rejected",
                        "reason": "weak_parameter_name",
                        "old": "v7",
                        "callee": "ExAcquireFastMutex",
                        "argument_index": 0,
                        "argument": "v7",
                        "parameter": "FastMutex",
                        "parameter_type": "PFAST_MUTEX",
                    }
                ],
            )

            report = analyze_corpus(root)
            queue = report["api_semantic_review_queue"]
            markdown = render_quality_markdown(report)
            weak_targets = [
                item
                for item in queue["top_repeated_targets"]
                if item["category"] == "weak_parameter_name_gap"
            ]

            self.assertEqual("api_semantic_review_queue_v1", queue["schema"])
            self.assertEqual(6, queue["item_count"])
            self.assertEqual(1, queue["repeated_target_count"])
            self.assertEqual(1, queue["category_counts"]["correctly_blocked_large_dispatcher"])
            self.assertEqual(1, queue["category_counts"]["likely_profile_gap"])
            self.assertEqual(2, queue["category_counts"]["weak_parameter_name_gap"])
            self.assertEqual(1, queue["category_counts"]["shadow_or_conflict_needs_manual_review"])
            self.assertEqual(1, queue["category_counts"]["unsafe_wrapper_role"])
            self.assertEqual("ExAcquireFastMutex", weak_targets[0]["callee"])
            self.assertEqual("FastMutex", weak_targets[0]["parameter"])
            self.assertEqual(2, weak_targets[0]["count"])
            self.assertEqual(2, weak_targets[0]["function_count"])
            self.assertEqual(
                2,
                queue["categories"]["weak_parameter_name_gap"]["top_repeated_targets"][0]["count"],
            )
            self.assertIn("### API Semantic Review Queue", markdown)
            self.assertIn("correctly_blocked_large_dispatcher", markdown)
            self.assertIn("weak_parameter_name_gap", markdown)
            self.assertIn("ExAcquireFastMutex", markdown)

    def test_prototype_metrics_ignore_pseudoforge_header_comment_terminator_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140002000_HeaderNoise"
            function_dir.mkdir(parents=True)
            (function_dir / "HeaderNoise.cleaned.cpp").write_text(
                "\n".join(
                    [
                        "/*",
                        "    Generated by PseudoForge.",
                        "    Kernel insights:",
                        "      - inferred_offset_field_preview: Review fields for context (generic base): +0x18 mixed(_KPROCESS */_QWORD) field_18.",
                        "*/",
                        "",
                        "__int64 __fastcall HeaderNoise(__int64 context, __int64 *argument1)",
                        "{",
                        "  return *(_QWORD *)(context + 8);",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (function_dir / "HeaderNoise.ida-batch-summary.json").write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "HeaderNoise",
                        "function_ea": "0x140002000",
                        "artifacts": {
                            "cleaned_pseudocode": "HeaderNoise.cleaned.cpp",
                            "summary": "HeaderNoise.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            prototype_stats = report["prototype_correction_stats"]

            self.assertEqual(2, prototype_stats["totals"]["generic_parameter_survivors"])
            self.assertEqual(1, prototype_stats["totals"]["offset_deref_survivors"])
            self.assertEqual(1, prototype_stats["negative_controls"]["function_count"])
            self.assertEqual("HeaderNoise", prototype_stats["negative_controls"]["top_functions"][0]["name"])

    def test_analyze_corpus_prefers_structured_warning_diagnostics_for_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_LiveIn"
            function_dir.mkdir(parents=True)
            warnings_path = function_dir / "LiveIn.warnings.json"
            diagnostics_path = function_dir / "LiveIn.warning-diagnostics.json"
            summary_path = function_dir / "LiveIn.ida-batch-summary.json"
            warnings_path.write_text(
                json.dumps(["Skipped PascalCase LLM rename a1->PageTableBase"]),
                encoding="utf-8",
            )
            diagnostics_path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "unassigned_local_live_in_register",
                            "message": "Uninitialized local risk: v1 appears to be a live-in register value (r8d)",
                            "symbol": "v1",
                            "usage": "call argument to EtwpEventWriteFull",
                            "usage_class": "call_argument",
                            "register": "r8d",
                            "register_class": "abi_argument",
                            "candidate_action": "parameter_gap_candidate",
                            "confidence": 0.78,
                            "source": "validation.unassigned_local_usage",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "LiveIn",
                        "function_ea": "0x140001000",
                        "warnings": 1,
                        "artifacts": {
                            "warnings": warnings_path.name,
                            "warning_diagnostics": diagnostics_path.name,
                            "summary": summary_path.name,
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            self.assertEqual(1, report["warning_stats"]["all_classes"]["parameter_gap_candidate"])
            self.assertNotIn("llm_pascal_case", report["warning_stats"]["all_classes"])

    def test_analyze_corpus_prefers_refined_candidate_action_over_legacy_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_LiveIn"
            function_dir.mkdir(parents=True)
            diagnostics_path = function_dir / "LiveIn.warning-diagnostics.json"
            summary_path = function_dir / "LiveIn.ida-batch-summary.json"
            diagnostics_path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "unassigned_local_live_in_register",
                            "message": "Uninitialized local risk: v1 appears to be a live-in register value (r8d)",
                            "symbol": "v1",
                            "usage": "call argument to ZwQuerySystemInformation",
                            "usage_class": "call_argument",
                            "register": "r8d",
                            "register_class": "abi_argument",
                            "candidate_action": "caller_parameter_gap_candidate",
                            "legacy_candidate_action": "parameter_gap_candidate",
                            "callee_name": "ZwQuerySystemInformation",
                            "call_index": 0,
                            "argument_index": 2,
                            "confidence": 0.78,
                            "source": "validation.unassigned_local_usage",
                        },
                        {
                            "kind": "unassigned_local_live_in_register",
                            "message": "Uninitialized local risk: v2 appears to be a live-in register value (r8)",
                            "symbol": "v2",
                            "usage": "call argument to MiLockWorkingSetShared",
                            "usage_class": "call_argument",
                            "register": "r8",
                            "register_class": "abi_argument",
                            "candidate_action": "internal_lock_helper_residue",
                            "legacy_candidate_action": "parameter_gap_candidate",
                            "callee_name": "MiLockWorkingSetShared",
                            "call_index": 1,
                            "argument_index": 2,
                            "callee_contract_action": "internal_lock_helper_residue",
                            "callee_contract_confidence": 0.72,
                            "confidence": 0.72,
                            "source": "validation.unassigned_local_usage",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "LiveIn",
                        "function_ea": "0x140001000",
                        "warnings": 2,
                        "artifacts": {
                            "warning_diagnostics": diagnostics_path.name,
                            "summary": summary_path.name,
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            self.assertEqual(1, report["warning_stats"]["all_classes"]["caller_parameter_gap_candidate"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["internal_lock_helper_residue"])
            self.assertNotIn("parameter_gap_candidate", report["warning_stats"]["all_classes"])

    def test_analyze_corpus_counts_stack_pseudo_local_diagnostic_class(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140272090_KxReleaseQueuedSpinLock"
            function_dir.mkdir(parents=True)
            diagnostics_path = function_dir / "function.warning-diagnostics.json"
            warnings_path = function_dir / "function.warnings.json"
            summary_path = function_dir / "function.ida-batch-summary.json"
            diagnostics_path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "unassigned_local_stack_pseudo_local",
                            "message": "Stack pseudo-local report-only: retaddr appears to be a return-address stack pseudo-local",
                            "symbol": "retaddr",
                            "usage": "call argument to KiReleaseQueuedSpinLockInstrumented",
                            "usage_class": "call_argument",
                            "register": "",
                            "register_class": "stack_pseudo_local",
                            "candidate_action": "stack_pseudo_local_report_only",
                            "confidence": 0.6,
                            "source": "validation.unassigned_local_usage",
                            "callee_name": "KiReleaseQueuedSpinLockInstrumented",
                            "call_index": 19,
                            "argument_index": 1,
                            "stack_declaration": "_UNKNOWN *retaddr; // [rsp+28h] [rbp+0h]",
                            "stack_slot": "[rsp+28h] [rbp+0h]",
                            "pseudo_local_evidence": "instrumentation helper consumes return-address context",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            warnings_path.write_text(json.dumps(["legacy fallback warning"]), encoding="utf-8")
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "KxReleaseQueuedSpinLock",
                        "function_ea": "0x140272090",
                        "warnings": 1,
                        "artifacts": {
                            "warnings": warnings_path.name,
                            "warning_diagnostics": diagnostics_path.name,
                            "summary": summary_path.name,
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            self.assertEqual(1, report["warning_stats"]["all_classes"]["stack_pseudo_local_report_only"])
            self.assertNotIn("other", report["warning_stats"]["all_classes"])

    def test_analyze_corpus_counts_diagnostics_only_warning_totals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_LiveIn"
            function_dir.mkdir(parents=True)
            diagnostics_path = function_dir / "LiveIn.warning-diagnostics.json"
            summary_path = function_dir / "LiveIn.ida-batch-summary.json"
            diagnostics_path.write_text(
                json.dumps(
                    [
                        {
                            "kind": "unassigned_local_live_in_register",
                            "message": "Uninitialized local risk: v1 appears to be a live-in register value (r8d)",
                            "symbol": "v1",
                            "usage": "call argument to EtwpEventWriteFull",
                            "usage_class": "call_argument",
                            "register": "r8d",
                            "register_class": "abi_argument",
                            "candidate_action": "parameter_gap_candidate",
                            "confidence": 0.78,
                            "source": "validation.unassigned_local_usage",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "LiveIn",
                        "function_ea": "0x140001000",
                        "warnings": 0,
                        "artifacts": {
                            "warning_diagnostics": diagnostics_path.name,
                            "summary": summary_path.name,
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)

            self.assertEqual(1, report["totals"]["warnings"])
            self.assertEqual(1, report["totals"]["functions_with_warnings"])
            self.assertEqual(1, report["top_warning_functions"][0]["warning_count"])
            self.assertEqual(1, report["warning_stats"]["all_classes"]["parameter_gap_candidate"])

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
                "Prototype Correction Evidence",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "- Parameter type corrections: `2` applied `1`, blocked `1`",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `PDEVICE_OBJECT` | 1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Prototype Correction Negative Controls",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Residue Offset Shape Classes",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Residue Offset Base Classes",
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
                "Indexed Callback Table Evidence",
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
                "| `base_identity_candidates` | 1 | 1 | 8 | 13 | v14=1 | stable_argument_source=1 | direct_argument_alias=1 | stable_source_promotion_review=1 | consider_validated_profile_promotion=1 | stable_argument_source=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | `v14` | 8 | 13 | stable_argument_source | direct_argument_alias, argument, argument2 | stable_source_promotion_review | consider_validated_profile_promotion | stable_argument_source | identity_only | base is a decompiler temporary |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 | add_exact_identity_or_keep_review_only=1 | missing_identity_evidence=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `offset_threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 | add_exact_identity_or_keep_review_only=1 | missing_identity_evidence=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `access_threshold_gap_candidates` | 1 | 1 | 3 | 6 | sessionSpace=1 | none=1 | none=1 | missing_identity_evidence=1 | add_exact_identity_or_keep_review_only=1 | missing_identity_evidence=1 |",
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
                "Decimal Status-Like Target Evidence Review Queues",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `strong_profiled_status_literals` | 3 | 1 | profiled_status_literal_candidate=3 | call_result_status_carrier_target=2, complex_or_memory_target=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `complex_or_memory_targets` | 1 | 1 | profiled_status_literal_candidate=1 | complex_or_memory_target=1 | complex_or_memory_review=1 |",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "| `Sample` | `0x140001000` | 4 | 3 | 1 | profiled_status_literal_candidate=3, unprofiled_ntstatus_error_candidate=1 | call_result_status_carrier_target=3, complex_or_memory_target=1 | comparison=3, return=1 |",
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

    def test_analyze_corpus_reports_prototype_negative_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            _write_quality_fixture(root)
            other_dir = root / "functions" / "0000000140002000_Other"
            other_dir.mkdir(parents=True)
            (other_dir / "Other.cleaned.cpp").write_text(
                "\n".join(
                    [
                        "__int64 __fastcall Other(PVOID argument0)",
                        "{",
                        "  return *(_DWORD *)(argument0 + 8);",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (other_dir / "Other.ida-batch-summary.json").write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "Other",
                        "function_ea": "0x140002000",
                        "artifacts": {
                            "cleaned_pseudocode": "Other.cleaned.cpp",
                            "summary": "Other.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            negative_controls = report["prototype_correction_stats"]["negative_controls"]

            self.assertEqual(2, report["totals"]["summaries"])
            self.assertEqual(1, negative_controls["function_count"])
            self.assertEqual("Other", negative_controls["top_functions"][0]["name"])
            self.assertEqual(1, negative_controls["top_functions"][0]["generic_parameter_survivors"])
            self.assertEqual(1, negative_controls["top_functions"][0]["offset_deref_survivors"])

    def test_analyze_corpus_counts_domain_identity_summary_as_prototype_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            function_dir = root / "functions" / "0000000140003000_DomainOnly"
            function_dir.mkdir(parents=True)
            (function_dir / "DomainOnly.cleaned.cpp").write_text(
                "\n".join(
                    [
                        "void __fastcall DomainOnly(PVOID argument0)",
                        "{",
                        "  return;",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (function_dir / "DomainOnly.ida-batch-summary.json").write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "DomainOnly",
                        "function_ea": "0x140003000",
                        "domain_identity_summary": {
                            "total_hits": 2,
                            "blocker_counts": {"profile_report_only": 2},
                            "profile_counts": {"windows.io_manager.delete_device": 2},
                        },
                        "artifacts": {
                            "cleaned_pseudocode": "DomainOnly.cleaned.cpp",
                            "summary": "DomainOnly.ida-batch-summary.json",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            report = analyze_corpus(root)
            prototype_stats = report["prototype_correction_stats"]

            self.assertEqual(2, prototype_stats["totals"]["function_identity_candidates"])
            self.assertEqual(1, prototype_stats["totals"]["functions_with_correction_evidence"])
            self.assertEqual(0, prototype_stats["totals"]["negative_control_functions"])
            self.assertEqual(2, prototype_stats["blocker_counts"]["profile_report_only"])
            self.assertEqual(2, prototype_stats["function_identity_profiles"]["windows.io_manager.delete_device"])

    def test_prototype_correction_review_queues_surface_low_confidence_followups(self) -> None:
        queues = _prototype_correction_review_queues(
            [
                {
                    "ea": "0x140001000",
                    "name": "MiWsleFree",
                    "function_identity_candidates": 1,
                    "parameter_type_corrections": 4,
                    "applied_parameter_type_corrections": 0,
                    "blocked_parameter_type_corrections": 4,
                    "generic_parameter_survivors": 0,
                    "offset_deref_survivors": 67,
                    "profiles": {"windows.memory_manager.wsle_free": 4},
                    "canonical_types": {},
                    "blockers": {"low_confidence": 4},
                    "summary_path": "MiWsleFree.ida-batch-summary.json",
                },
                {
                    "ea": "0x140002000",
                    "name": "BuildMismatch",
                    "function_identity_candidates": 1,
                    "parameter_type_corrections": 1,
                    "applied_parameter_type_corrections": 0,
                    "blocked_parameter_type_corrections": 1,
                    "generic_parameter_survivors": 1,
                    "offset_deref_survivors": 0,
                    "profiles": {"windows.memory_manager.sample": 1},
                    "canonical_types": {},
                    "blockers": {"build_mismatch": 1},
                    "summary_path": "BuildMismatch.ida-batch-summary.json",
                },
            ],
            top=10,
        )

        low_confidence_queue = queues["low_confidence_type_corrections"]
        build_queue = queues["build_mismatch_type_corrections"]

        self.assertEqual(1, low_confidence_queue["function_count"])
        self.assertEqual(4, low_confidence_queue["blocked_parameter_type_corrections"])
        self.assertEqual(4, low_confidence_queue["blockers"]["low_confidence"])
        self.assertEqual("MiWsleFree", low_confidence_queue["items"][0]["name"])
        self.assertIn("raise profile confidence", low_confidence_queue["recommended_next_step"])
        self.assertEqual("BuildMismatch", build_queue["items"][0]["name"])

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
                "function_identity_candidates": [
                    {
                        "profile_id": "windows.io_manager.delete_device",
                        "effective_mode": "report-only",
                        "blockers": ["report_only_profile"],
                    }
                ],
                "parameter_type_corrections": [
                    {
                        "parameter_index": 0,
                        "old_name": "a1",
                        "new_name": "deviceObject",
                        "old_type": "__int64",
                        "canonical_type": "PDEVICE_OBJECT",
                        "display_type": "PDEVICE_OBJECT",
                        "profile_id": "windows.io_manager.delete_device",
                        "apply_to_preview": True,
                        "apply_to_idb": False,
                        "blockers": [],
                    },
                    {
                        "parameter_index": 1,
                        "old_name": "a2",
                        "new_name": "irp",
                        "old_type": "int",
                        "canonical_type": "PIRP",
                        "display_type": "PIRP",
                        "profile_id": "windows.io_manager.call_driver",
                        "apply_to_preview": False,
                        "apply_to_idb": False,
                        "blockers": ["type_conflict"],
                    },
                ],
                "corrected_parameter_map": [
                    {
                        "parameter_index": 0,
                        "old_name": "a1",
                        "new_name": "deviceObject",
                        "old_type": "__int64",
                        "canonical_type": "PDEVICE_OBJECT",
                        "display_type": "PDEVICE_OBJECT",
                        "profile_id": "windows.io_manager.delete_device",
                        "source": "domain_profile",
                    }
                ],
                "body_canonical_rewrite_summary": {
                    "rewrite_ready": 1,
                    "rewrite_preview": 1,
                    "rewrite_blockers": 1,
                    "partial_opportunities": 0,
                    "blocker_counts": {"overlay": 1},
                    "source_provenance_counts": {"corrected_parameter_map": 2},
                    "domain_profile_counts": {"windows.io_manager.delete_device": 1},
                    "bases": ["deviceObject"],
                },
                "source_context": {
                    "parameter_count": 1,
                    "raw_signature": "__int64 __fastcall Sample(__int64 a1)",
                },
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


def _write_api_queue_fixture(
    root: Path,
    name: str,
    ea: str,
    diagnostics: list[dict[str, object]],
) -> None:
    function_dir = root / "functions" / ("%s_%s" % (ea.replace("0x", "").rjust(16, "0"), name))
    function_dir.mkdir(parents=True)
    cleaned_name = "%s.cleaned.cpp" % name
    rule_name = "%s.rule-report.json" % name
    summary_name = "%s.ida-batch-summary.json" % name
    (function_dir / cleaned_name).write_text(
        "\n".join(
            [
                "void __fastcall %s(void)" % name,
                "{",
                "  return;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (function_dir / rule_name).write_text(
        json.dumps(
            {
                "matched_rules": [],
                "rewrite_emissions": [],
                "rejected_emissions": [],
                "api_semantic_diagnostics": diagnostics,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (function_dir / summary_name).write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": name,
                "function_ea": ea,
                "artifacts": {
                    "cleaned_pseudocode": cleaned_name,
                    "rule_report": rule_name,
                    "summary": summary_name,
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
