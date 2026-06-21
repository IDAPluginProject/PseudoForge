from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_replay_plan import build_replay_plan, main, render_replay_plan_markdown


class PseudoForgeReplayPlanTests(unittest.TestCase):
    def test_replay_plan_ranks_cleanup_hotspots_and_writes_eas(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            _write_function(
                root,
                ea="0x140001000",
                name="Hotspot",
                warnings=5,
                rename_candidates=20,
                renames=3,
                cleaned_body="""
__int64 __fastcall Hotspot(__int64 a1)
{
  v1 = *(_QWORD *)(a1 + 16);
  v2 = *(_QWORD *)(a1 + 24);
  v3 = *(_QWORD *)(a1 + 32);
  v4 = *(_QWORD *)(a1 + 40);
  v5 = *(_QWORD *)(a1 + 48);
  v6 = *(_QWORD *)(a1 + 56);
  v7 = *(_QWORD *)(a1 + 64);
  v8 = *(_QWORD *)(a1 + 72);
  v9 = *(_QWORD *)(a1 + 80);
  v10 = *(_QWORD *)(a1 + 88);
  if ( v1 )
    goto LABEL_1;
  return -1073741811;
LABEL_1:
  return v2;
}
""",
            )
            _write_function(
                root,
                ea="0x140002000",
                name="Quiet",
                warnings=0,
                rename_candidates=2,
                renames=2,
                cleaned_body="""
__int64 __fastcall Quiet(__int64 status)
{
  return status;
}
""",
            )

            plan = build_replay_plan(root, limit=1)

            self.assertEqual(1, plan["selected_count"])
            self.assertEqual("Hotspot", plan["items"][0]["name"])
            self.assertEqual("0x140001000", plan["items"][0]["ea"])
            self.assertIn("warnings", plan["items"][0]["reasons"])
            self.assertIn("offset_deref_residue", plan["items"][0]["reasons"])
            self.assertIn("generic_unannotated_base_offset_residue", plan["items"][0]["reasons"])
            self.assertIn("temp_unannotated_base_offset_residue", plan["items"][0]["reasons"])
            self.assertEqual(
                10,
                plan["items"][0]["metrics"]["body_offset_deref_unannotated_generic_base_patterns"],
            )
            self.assertEqual(
                10,
                plan["items"][0]["metrics"]["body_offset_deref_unannotated_temp_base_patterns"],
            )
            self.assertIn("Hotspot", render_replay_plan_markdown(plan))

    def test_replay_plan_cli_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            out_dir = Path(temp_dir) / "plan"
            _write_function(
                root,
                ea="0x140001000",
                name="Sample",
                warnings=1,
                rename_candidates=3,
                renames=1,
                cleaned_body="__int64 __fastcall Sample(__int64 a1) { return *(_QWORD *)(a1 + 16); }",
            )

            exit_code = main(["--corpus-root", str(root), "--out", str(out_dir), "--limit", "1"])

            self.assertEqual(0, exit_code)
            self.assertEqual("0x140001000\n", (out_dir / "replay-eas.txt").read_text(encoding="utf-8"))
            self.assertTrue((out_dir / "replay-plan.json").exists())
            self.assertTrue((out_dir / "replay-plan.md").exists())
            payload = json.loads((out_dir / "replay-plan.json").read_text(encoding="utf-8"))
            self.assertIn(str(out_dir / "replay-eas.txt"), payload["recommended_commands"][0])

    def test_replay_plan_exposes_registry_domain_profile_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            _write_function(
                root,
                ea="0x1408704E8",
                name="CmDeleteValueKey",
                warnings=0,
                rename_candidates=4,
                renames=4,
                cleaned_body="""
/*
    Kernel insights:
      - registry_domain_role_evidence: Registry domain role for CmDeleteValueKey: status is statusCarrier/NTSTATUS, mode report-only. Evidence: assigned named NTSTATUS constants. Blockers: report-only registry-domain triage; no registry structure field rewrite is enabled by this profile. confidence=0.90
      - registry_domain_role_evidence: Registry domain role for CmDeleteValueKey: transactionUow is transactionUnitOfWork/CM_TRANS_UOW, mode report-only. Evidence: allocated by CmpAllocateUnitOfWork. Blockers: report-only registry-domain triage; no registry structure field rewrite is enabled by this profile. confidence=0.88
*/
__int64 __fastcall CmDeleteValueKey(__int64 keyBody)
{
  return keyBody;
}
""",
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(2, item["metrics"]["registry_domain_profile_hits"])
            self.assertIn("registry_domain_profile_hit", item["reasons"])
            self.assertEqual(1, plan["reason_counts"]["registry_domain_profile_hit"])
            self.assertIn("registry_domain_profile_hit", render_replay_plan_markdown(plan))

    def test_replay_plan_scores_only_review_only_partial_opportunities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            _write_function(
                root,
                ea="0x140001000",
                name="ReviewOnlyPartial",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body="""
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for context: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Safe offsets +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40, +0x48; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall ReviewOnlyPartial(__int64 context)
{
  return context;
}
""",
            )
            _write_function(
                root,
                ea="0x140002000",
                name="ValidatedPartial",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body="""
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for context: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Safe offsets +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40, +0x48; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Validated partial layout rewrite applied to canonical cleaned output. confidence=0.77
*/
__int64 __fastcall ValidatedPartial(__int64 context)
{
  v0 = *(_QWORD *)(context + 16);
  v1 = *(_QWORD *)(context + 24);
  v2 = *(_QWORD *)(context + 32);
  v3 = *(_QWORD *)(context + 40);
  v4 = *(_QWORD *)(context + 48);
  v5 = *(_QWORD *)(context + 56);
  v6 = *(_QWORD *)(context + 64);
  v7 = *(_QWORD *)(context + 72);
  v8 = *(_QWORD *)(context + 80);
  v9 = *(_QWORD *)(context + 88);
  return v0 + v9;
}
""",
            )

            plan = build_replay_plan(root, limit=2)

            by_name = {item["name"]: item for item in plan["items"]}
            review_only = by_name["ReviewOnlyPartial"]
            validated = by_name["ValidatedPartial"]
            self.assertGreater(review_only["score"], validated["score"])
            self.assertIn("layout_near_ready", review_only["reasons"])
            self.assertNotIn("layout_near_ready", validated["reasons"])
            self.assertEqual(1, review_only["metrics"]["layout_rewrite_partial_review_only"])
            self.assertEqual(0, review_only["metrics"]["layout_rewrite_partial_validated_applied"])
            self.assertEqual(0, validated["metrics"]["layout_rewrite_partial_review_only"])
            self.assertEqual(1, validated["metrics"]["layout_rewrite_partial_validated_applied"])
            self.assertEqual(0, validated["metrics"]["layout_actionability_bases"])
            self.assertEqual(0, validated["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(10, validated["metrics"]["body_offset_deref_bulk_noise_patterns"])

    def test_replay_plan_saturates_bulk_residue_score(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            wide_label_body = "\n".join(
                ["__int64 __fastcall WideResidue(__int64 a1)", "{"]
                + [
                    line
                    for index in range(250)
                    for line in (
                        "  v%d = a1;" % index,
                        "  if ( v%d )" % index,
                        "    goto LABEL_%d;" % index,
                        "LABEL_%d:" % index,
                    )
                ]
                + ["  return v249;", "}"]
            )
            targeted_layout_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for context: base identity unresolved. Review-only aliases remain available. confidence=0.64",
                    "*/",
                    "__int64 __fastcall TargetedLayout(__int64 context)",
                    "{",
                ]
                + [
                    "  v%d = *(_QWORD *)(context + %d);" % (index, 16 + (index * 8))
                    for index in range(90)
                ]
                + ["  return v89;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="WideResidue",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=wide_label_body,
            )
            _write_function(
                root,
                ea="0x140002000",
                name="TargetedLayout",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=targeted_layout_body,
            )

            plan = build_replay_plan(root, limit=2)

            self.assertEqual("TargetedLayout", plan["items"][0]["name"])
            wide_item = next(item for item in plan["items"] if item["name"] == "WideResidue")
            self.assertIn("bulk_residue_saturation", wide_item["reasons"])
            self.assertGreater(wide_item["metrics"]["body_label_overflow_tokens"], 0)
            self.assertEqual(
                120,
                plan["score_model"]["bulk_residue_saturation"]["label_full_score_limit"],
            )

    def test_replay_plan_splits_layout_actionable_and_bulk_offset_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            layout_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for context: base identity unresolved. Review-only aliases remain available. confidence=0.64",
                    "*/",
                    "__int64 __fastcall LayoutOffset(__int64 context)",
                    "{",
                ]
                + [
                    "  v%d = *(_QWORD *)(context + %d);" % (index, 16 + (index * 8))
                    for index in range(80)
                ]
                + ["  return v79;", "}"]
            )
            bulk_body = "\n".join(
                ["__int64 __fastcall BulkOffset(__int64 buffer)", "{"]
                + [
                    "  v%d = *(_QWORD *)(buffer + %d);" % (index, 16 + (index * 8))
                    for index in range(160)
                ]
                + ["  return v159;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="BulkOffset",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=bulk_body,
            )
            _write_function(
                root,
                ea="0x140002000",
                name="LayoutOffset",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=layout_body,
            )

            plan = build_replay_plan(root, limit=2)

            self.assertEqual("LayoutOffset", plan["items"][0]["name"])
            by_name = {item["name"]: item for item in plan["items"]}
            layout_item = by_name["LayoutOffset"]
            bulk_item = by_name["BulkOffset"]
            self.assertIn("layout_actionable_offset_residue", layout_item["reasons"])
            self.assertNotIn("bulk_offset_residue", layout_item["reasons"])
            self.assertNotIn("non_layout_offset_residue", layout_item["reasons"])
            self.assertIn("non_layout_offset_residue", bulk_item["reasons"])
            self.assertIn("unannotated_base_offset_residue", bulk_item["reasons"])
            self.assertIn("named_unannotated_base_offset_residue", bulk_item["reasons"])
            self.assertNotIn("argument_identity_unannotated_base_offset_residue", bulk_item["reasons"])
            self.assertIn("bulk_offset_residue", bulk_item["reasons"])
            self.assertNotIn("layout_actionable_offset_residue", bulk_item["reasons"])
            self.assertEqual(80, layout_item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(0, layout_item["metrics"]["body_offset_deref_bulk_noise_patterns"])
            self.assertEqual(0, bulk_item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(160, bulk_item["metrics"]["body_offset_deref_bulk_noise_patterns"])
            self.assertEqual(
                160,
                bulk_item["metrics"]["body_offset_deref_unannotated_named_base_patterns"],
            )
            self.assertEqual("buffer", bulk_item["offset_base_counts"]["unannotated_named"][0]["base"])
            self.assertEqual(
                1.0,
                plan["score_model"]["offset_actionability"]["no_layout_weight"],
            )

    def test_replay_plan_matches_offset_residue_to_layout_base(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            mixed_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for context: base identity unresolved. Review-only aliases remain available. confidence=0.64",
                    "*/",
                    "__int64 __fastcall MixedOffset(__int64 context, __int64 other)",
                    "{",
                ]
                + [
                    "  v%d = *(_QWORD *)(context + %d);" % (index, 16 + (index * 8))
                    for index in range(20)
                ]
                + [
                    "  v%d = *(_QWORD *)(other + %d);" % (index + 20, 16 + (index * 8))
                    for index in range(140)
                ]
                + ["  return v159;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="MixedOffset",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=mixed_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual("MixedOffset", item["name"])
            self.assertIn("layout_actionable_offset_residue", item["reasons"])
            self.assertIn("non_layout_offset_residue", item["reasons"])
            self.assertIn("unannotated_base_offset_residue", item["reasons"])
            self.assertIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertNotIn("argument_identity_unannotated_base_offset_residue", item["reasons"])
            self.assertIn("bulk_offset_residue", item["reasons"])
            self.assertEqual(160, item["metrics"]["body_offset_deref_patterns"])
            self.assertEqual(160, item["metrics"]["body_offset_deref_simple_base_patterns"])
            self.assertEqual(20, item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(140, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertEqual(140, item["metrics"]["body_offset_deref_unannotated_named_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unmatched_base_patterns"])
            self.assertEqual(140, item["metrics"]["body_offset_deref_bulk_noise_patterns"])
            self.assertEqual("other", item["offset_base_counts"]["unannotated"][0]["base"])
            self.assertEqual(140, item["offset_base_counts"]["unannotated"][0]["count"])
            self.assertEqual("other", item["offset_base_counts"]["unannotated_named"][0]["base"])
            self.assertEqual("context", item["offset_base_counts"]["layout_actionable"][0]["base"])
            self.assertEqual("other", plan["offset_base_breakdown"]["top_unannotated_bases"][0]["base"])
            self.assertEqual("other", plan["offset_base_breakdown"]["top_unannotated_named_bases"][0]["base"])
            self.assertEqual(
                item["metrics"]["body_offset_deref_patterns"],
                item["metrics"]["body_offset_deref_layout_actionable_patterns"]
                + item["metrics"]["body_offset_deref_bulk_noise_patterns"],
            )
            self.assertTrue(plan["score_model"]["offset_actionability"]["full_score_limit_is_shared"])
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Top unannotated bases", markdown)
            self.assertIn("`other`", markdown)

    def test_replay_plan_reports_unmatched_offset_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            unmatched_body = "\n".join(
                ["__int64 __fastcall UnmatchedOffset(__int64 context, __int64 index)", "{"]
                + [
                    "  v%d = *(_QWORD *)(context + index + %d);" % (item_index, 16 + (item_index * 8))
                    for item_index in range(20)
                ]
                + ["  return v19;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="UnmatchedOffset",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=unmatched_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual("UnmatchedOffset", item["name"])
            self.assertIn("offset_deref_residue", item["reasons"])
            self.assertIn("non_layout_offset_residue", item["reasons"])
            self.assertIn("unmatched_base_offset_residue", item["reasons"])
            self.assertNotIn("unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(20, item["metrics"]["body_offset_deref_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_simple_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertEqual(20, item["metrics"]["body_offset_deref_unmatched_base_patterns"])
            self.assertEqual(20, item["metrics"]["body_offset_deref_bulk_noise_patterns"])
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Unannotated offsets", markdown)
            self.assertIn("Unmatched offsets", markdown)

    def test_replay_plan_classifies_argument_alias_base_as_generic_unannotated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            argument_body = "\n".join(
                ["__int64 __fastcall ArgumentBase(__int64 argument0)", "{"]
                + [
                    "  v%d = *(_QWORD *)(argument0 + %d);" % (item_index, 16 + (item_index * 8))
                    for item_index in range(12)
                ]
                + ["  return v11;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="ArgumentBase",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=argument_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertIn("generic_unannotated_base_offset_residue", item["reasons"])
            self.assertIn("argument_identity_unannotated_base_offset_residue", item["reasons"])
            self.assertIn("argument_unannotated_base_offset_residue", item["reasons"])
            self.assertNotIn("context_unannotated_base_offset_residue", item["reasons"])
            self.assertNotIn("bugcheck_unannotated_base_offset_residue", item["reasons"])
            self.assertNotIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_unannotated_generic_base_patterns"])
            self.assertEqual(
                12,
                item["metrics"]["body_offset_deref_unannotated_argument_identity_base_patterns"],
            )
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_context_base_patterns"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_unannotated_argument_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_bugcheck_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_named_base_patterns"])
            self.assertEqual("argument0", item["offset_base_counts"]["unannotated_argument_identity"][0]["base"])
            self.assertEqual("argument0", item["offset_base_counts"]["unannotated_argument"][0]["base"])
            self.assertIn("argument", plan["score_model"]["offset_actionability"]["unannotated_generic_base_pattern"])
            self.assertIn(
                "argument",
                plan["score_model"]["offset_actionability"][
                    "unannotated_argument_identity_base_pattern"
                ],
            )
            argument_queue = plan["source_identity_review_queues"]["argument"]
            self.assertEqual("ArgumentBase", argument_queue[0]["function"])
            self.assertEqual("argument0", argument_queue[0]["base"])
            self.assertEqual(12, argument_queue[0]["offset_derefs"])
            self.assertEqual("argument", argument_queue[0]["source_kind"])
            self.assertEqual(
                "argument_parameter_identity_review",
                argument_queue[0]["disposition"],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Source Identity Review Queues", markdown)
            self.assertIn("argument_parameter_identity_review", markdown)

    def test_replay_plan_excludes_virtual_address_offsets_from_structure_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            code_pointer_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - domain_structure_identity: Domain identity for controlPc: role controlPc, structure VIRTUAL_ADDRESS, mode report-only, profile windows.exception_unwind.rtlpx_virtual_unwind parameter 2 (controlPc). Fields none observed. Role-only evidence; no field rewrite was applied. confidence=0.74",
                    "*/",
                    "__int64 __fastcall RtlpxVirtualUnwind(unsigned __int64 controlPc)",
                    "{",
                ]
                + [
                    "  byte%d = *(_BYTE *)(controlPc + %d);" % (index, index)
                    for index in range(12)
                ]
                + ["  return byte0;", "}"]
            )
            _write_function(
                root,
                ea="0x140234800",
                name="RtlpxVirtualUnwind",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=code_pointer_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(12, item["metrics"]["body_offset_deref_patterns"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_annotated_scalar_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_named_base_patterns"])
            self.assertNotIn("offset_deref_residue", item["reasons"])
            self.assertNotIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual("controlPc", item["offset_base_counts"]["annotated_scalar"][0]["base"])
            self.assertFalse(item["offset_base_counts"]["unannotated_named"])
            self.assertEqual(
                "controlPc",
                plan["offset_base_breakdown"]["top_annotated_scalar_bases"][0]["base"],
            )

    def test_replay_plan_splits_domain_identified_offsets_from_unannotated_named(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            domain_identified_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - domain_structure_identity: Domain identity for securityDescriptor: role securityDescriptor, structure SECURITY_DESCRIPTOR, mode report-only, profile windows.token_security.access_check_with_hint parameter 0 (securityDescriptor). Fields none observed. Role-only evidence; no field rewrite was applied. confidence=0.74",
                    "*/",
                    "__int64 __fastcall SeAccessCheckWithHint(__int64 securityDescriptor)",
                    "{",
                ]
                + [
                    "  field%d = *(_QWORD *)(securityDescriptor + %d);" % (index, 16 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x1403686C0",
                name="SeAccessCheckWithHint",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=domain_identified_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(12, item["metrics"]["body_offset_deref_patterns"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_domain_identified_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_named_base_patterns"])
            self.assertIn("offset_deref_residue", item["reasons"])
            self.assertIn("domain_identified_offset_residue", item["reasons"])
            self.assertNotIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(
                "securityDescriptor",
                item["offset_base_counts"]["domain_identified"][0]["base"],
            )
            self.assertFalse(item["offset_base_counts"]["unannotated_named"])
            self.assertEqual(
                "securityDescriptor",
                plan["offset_base_breakdown"]["top_domain_identified_bases"][0]["base"],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Top domain-identified residual bases", markdown)
            self.assertIn("`securityDescriptor`", markdown)

    def test_replay_plan_uses_rename_map_comments_when_cleaned_header_omits_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            omitted_identity_body = "\n".join(
                [
                    "/*",
                    "    Generated by PseudoForge.",
                    "    Kernel insights:",
                    "      - object_reference: Kernel object/context reference ownership changes are present confidence=0.84",
                    "*/",
                    "__int64 __fastcall AlpcpCompleteDispatchMessage(__int64 dispatchContext)",
                    "{",
                ]
                + [
                    "  field%d = *(_QWORD *)(dispatchContext + %d);" % (index, 8 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x14089A0D0",
                name="AlpcpCompleteDispatchMessage",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=omitted_identity_body,
                rename_map_comments=[
                    {
                        "kind": "domain_structure_identity",
                        "text": (
                            "Domain identity for dispatchContext: role dispatchContext, "
                            "structure ALPC_DISPATCH_MESSAGE_CONTEXT, mode report-only, "
                            "profile windows.alpc_port.complete_dispatch_message parameter 0 "
                            "(dispatchContext). Fields none observed. Canonical rewrite still "
                            "requires existing validation-gated layout export."
                        ),
                        "confidence": 0.74,
                    },
                    {
                        "kind": "inferred_offset_rewrite_blockers",
                        "text": (
                            "Offset field rewrite blocked for dispatchContext: domain identity "
                            "profile is report-only. Review-only aliases remain available."
                        ),
                        "confidence": 0.73,
                    },
                ],
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(12, item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_named_base_patterns"])
            self.assertIn("layout_actionable_offset_residue", item["reasons"])
            self.assertNotIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual("dispatchContext", item["offset_base_counts"]["layout_actionable"][0]["base"])
            self.assertFalse(item["offset_base_counts"]["unannotated_named"])

    def test_replay_plan_splits_temp_source_identity_blockers_from_layout_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            temp_blocked_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v22: base is a decompiler temporary; base is reassigned after layout access. Review-only aliases remain available. confidence=0.74",
                    "*/",
                    "__int64 __fastcall TempBlocked(__int64 source)",
                    "{",
                    "  v22 = source + 32;",
                ]
                + [
                    "  field%d = *(_QWORD *)(v22 + %d);" % (index, 512 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140506ED0",
                name="TempBlocked",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=temp_blocked_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(12, item["metrics"]["body_offset_deref_source_identity_blocked_base_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_non_layout_base_patterns"])
            self.assertIn("source_identity_blocked_offset_residue", item["reasons"])
            self.assertNotIn("layout_actionable_offset_residue", item["reasons"])
            self.assertNotIn("named_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(
                "v22",
                item["offset_base_counts"]["source_identity_blocked"][0]["base"],
            )
            self.assertFalse(item["offset_base_counts"]["layout_actionable"])
            self.assertFalse(item["offset_base_counts"]["unannotated_named"])
            self.assertEqual(
                "v22",
                plan["offset_base_breakdown"]["top_source_identity_blocked_bases"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("TempBlocked", source_queue[0]["function"])
            self.assertEqual("v22", source_queue[0]["base"])
            self.assertEqual("source_identity_recovery_review", source_queue[0]["disposition"])
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Source-id offsets", markdown)
            self.assertIn("Source Identity Review Queues", markdown)
            self.assertIn("source_identity_recovery_review", markdown)

    def test_replay_plan_marks_merge_evidence_source_identity_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            merge_blocked_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v47: base is a decompiler temporary; base has multiple initializers before layout access; base is reassigned after layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_stability: Base stability evidence for v47: 5 initializer(s) before first layout access across 3 distinct RHS (v386; v111; sub_140BD6AF8(v111, v139, *((_DWORD *)v111 + 593))); 5 post-access assignment(s), 4 followed by later layout access. Post-access assignment samples: risky RHS v395; v396. Review initializer dominance before enabling canonical rewrite. confidence=0.76",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v47: 5 initializer(s) before first layout access across 3 source candidate(s): v386; v111; sub_140BD6AF8(v111, v139, *((_DWORD *)v111 + 593)). Candidate classes call_result=1, identifier=2. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.71",
                    "*/",
                    "__int64 __fastcall MergeBlocked(__int64 source)",
                    "{",
                    "  v47 = source;",
                ]
                + [
                    "  field%d = *(_QWORD *)(v47 + %d);" % (index, 1536 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140BD2A04",
                name="MergeBlocked",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=merge_blocked_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_base_merge_evidence"])
            self.assertIn("layout_base_merge_evidence", item["reasons"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_source_identity_blocked_base_patterns"])
            self.assertEqual("v47", item["offset_base_counts"]["base_merge_evidence"][0]["base"])
            self.assertEqual("v47", item["offset_base_counts"]["source_identity_blocked"][0]["base"])
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("MergeBlocked", source_queue[0]["function"])
            self.assertEqual("v47", source_queue[0]["base"])
            self.assertEqual(1, source_queue[0]["layout_base_merge_evidence"])
            self.assertEqual("path_sensitive_merge_review", source_queue[0]["disposition"])
            self.assertIn("branch/call-result source dominance", source_queue[0]["recommended_next"])
            self.assertEqual(
                "path_sensitive_merge_review",
                plan["score_model"]["source_identity_review_queues"]["merge_evidence_disposition"],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("path_sensitive_merge_review", markdown)

    def test_replay_plan_marks_same_source_family_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            merge_blocked_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v22: base is a decompiler temporary; base has multiple initializers before layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_stability: Base stability evidence for v22: 2 initializer(s) before first layout access across 2 distinct RHS (eaBuffer; *(_QWORD *)(eaBuffer + 8)); 0 post-access assignment(s), 0 followed by later layout access. Review initializer dominance before enabling canonical rewrite. confidence=0.67",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v22: 2 initializer(s) before first layout access across 2 source candidate(s): eaBuffer; *(_QWORD *)(eaBuffer + 8). Candidate classes expression=1, identifier=1. Source families parameter:eaBuffer=2; disposition same_source_family_review. Candidate kinds parameter_root=2. Merge shape same_source_family (medium risk); next review same-source-family branch dominance. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.68",
                    "      - inferred_offset_same_source_family_merge_dominance: Same-source-family merge dominance for v22: 2 initializer candidate(s) share parameter root eaBuffer. Branch shapes direct_root=1, field_pointer=1; source offsets 0x0, 0x8; first layout access is not dominated by a base truthiness guard. Candidate sources eaBuffer [direct_root 0x0]; *(_QWORD *)(eaBuffer + 8) [field_pointer 0x8]. Dominance class parameter_root_direct_field_branch. Keep canonical rewrite blocked until path-specific initializer dominance is validated. confidence=0.63",
                    "*/",
                    "__int64 __fastcall SameFamilyMerge(__int64 eaBuffer)",
                    "{",
                    "  v22 = eaBuffer;",
                ]
                + [
                    "  field%d = *(_QWORD *)(v22 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140BD2A04",
                name="SameFamilyMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=merge_blocked_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_same_source_family_merge_dominance"])
            self.assertIn("layout_same_source_family_merge_dominance", item["reasons"])
            self.assertEqual("v22", item["offset_base_counts"]["base_merge_evidence"][0]["base"])
            self.assertEqual(
                "v22",
                item["offset_base_counts"]["base_merge_same_source_family"][0]["base"],
            )
            self.assertEqual(
                "v22",
                item["offset_base_counts"]["same_source_family_merge_dominance"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("SameFamilyMerge", source_queue[0]["function"])
            self.assertEqual("v22", source_queue[0]["base"])
            self.assertEqual("same_source_family", source_queue[0]["merge_shape"])
            self.assertEqual("medium", source_queue[0]["merge_risk"])
            self.assertEqual("same_source_family_dominance_review", source_queue[0]["disposition"])
            self.assertIn("same-root branch dominance", source_queue[0]["recommended_next"])
            self.assertEqual(
                "same_source_family_merge_review",
                plan["score_model"]["source_identity_review_queues"][
                    "same_source_family_merge_disposition"
                ],
            )
            self.assertEqual(
                "same_source_family_dominance_review",
                plan["score_model"]["source_identity_review_queues"][
                    "same_source_family_dominance_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("same_source_family_dominance_review", markdown)
            self.assertIn("same_source_family", markdown)

    def test_replay_plan_marks_allocation_null_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            allocation_null_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for newProviderRecord2: rewrite offset threshold requires at least 8 offsets; base has multiple initializers before layout access; base is reassigned after layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for newProviderRecord2: 23 initializer(s) before first layout access across 3 source candidate(s): ExAllocatePool2(0x100uLL, size, 0x20534C53u); 0LL; (_OWORD *)ExAllocatePool2(0x100uLL, 0x30uLL, 0x20534C53u). Candidate classes call_result=1, expression=2. Source families call_result:ExAllocatePool2=1, expression:0LL=1; disposition distinct_source_family_review. Candidate kinds allocation_call_result=2, null=1. Merge shape allocation_null_branch (medium risk); next review allocation/null guard dominance. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.71",
                    "*/",
                    "__int64 __fastcall AllocationNullMerge(__int64 size)",
                    "{",
                    "  newProviderRecord2 = ExAllocatePool2(0x100uLL, size, 0x20534C53u);",
                ]
                + [
                    "  field%d = *(_QWORD *)(newProviderRecord2 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x14094DF10",
                name="AllocationNullMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=allocation_null_body,
            )

            plan = build_replay_plan(root, limit=1)

            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("AllocationNullMerge", source_queue[0]["function"])
            self.assertEqual("newProviderRecord2", source_queue[0]["base"])
            self.assertEqual("allocation_null_branch", source_queue[0]["merge_shape"])
            self.assertEqual("medium", source_queue[0]["merge_risk"])
            self.assertEqual("allocation_null_dominance_review", source_queue[0]["disposition"])
            self.assertIn("allocation/null guard dominance", source_queue[0]["recommended_next"])
            self.assertEqual(
                "allocation_null_dominance_review",
                plan["score_model"]["source_identity_review_queues"][
                    "allocation_null_merge_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("allocation_null_dominance_review", markdown)
            self.assertIn("allocation_null_branch", markdown)

    def test_replay_plan_marks_call_result_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            call_result_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v21: base is a decompiler temporary; one or more offsets mix irregular field access widths; base has multiple initializers before layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v21: 3 initializer(s) before first layout access across 3 source candidate(s): RtlpInterlockedPopEntrySList(&P->ListHead); RtlpInterlockedPopEntrySList(&L->ListHead); guard_dispatch_icall_no_overrides((unsigned int)L->Type, L->Size). Candidate classes call_result=3. Source families call_result:RtlpInterlockedPopEntrySList=2, call_result:guard_dispatch_icall_no_overrides((unsigned int)L->Type, L->Size=1; disposition distinct_source_family_review. Candidate kinds call_result=2, indirect_call_result=1. Merge shape call_result_branch (medium_high risk); next review call-result object equivalence. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.71",
                    "      - inferred_offset_call_result_merge_equivalence: Call-result merge equivalence for v21: 3 call-result initializer(s), 2 direct call(s), 1 indirect dispatch call(s), 0 opaque call(s). Call families RtlpInterlockedPopEntrySList=2, guard_dispatch_icall_no_overrides=1; equivalence class direct_call_with_indirect_fallback. Keep canonical rewrite blocked until call-result object equivalence is validated. confidence=0.64",
                    "*/",
                    "__int64 __fastcall CallResultMerge(__int64 P, __int64 L)",
                    "{",
                    "  v21 = RtlpInterlockedPopEntrySList(&P->ListHead);",
                ]
                + [
                    "  field%d = *(_QWORD *)(v21 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140967410",
                name="CallResultMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=call_result_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_call_result_merge_equivalence"])
            self.assertIn("layout_call_result_merge_equivalence", item["reasons"])
            self.assertEqual(
                "v21",
                item["offset_base_counts"]["call_result_merge_equivalence"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("CallResultMerge", source_queue[0]["function"])
            self.assertEqual("v21", source_queue[0]["base"])
            self.assertEqual("call_result_branch", source_queue[0]["merge_shape"])
            self.assertEqual("medium_high", source_queue[0]["merge_risk"])
            self.assertEqual("call_result_equivalence_review", source_queue[0]["disposition"])
            self.assertIn("call-result object equivalence", source_queue[0]["recommended_next"])
            self.assertEqual(
                "call_result_equivalence_review",
                plan["score_model"]["source_identity_review_queues"][
                    "call_result_merge_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("call_result_equivalence_review", markdown)
            self.assertIn("call_result_branch", markdown)

    def test_replay_plan_marks_call_result_temporary_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            call_result_temporary_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v20: base is a decompiler temporary; base has multiple initializers before layout access; base is reassigned after layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v20: 2 initializer(s) before first layout access across 2 source candidate(s): ExAllocateFromLookasideListEx(&CcSharedCacheMapLookasideList); *(_QWORD *)(v29 + 8). Candidate classes call_result=1, expression=1. Source families call_result:ExAllocateFromLookasideListEx=1, temporary:v29=1; disposition distinct_source_family_review. Candidate kinds allocation_call_result=1, temporary_root=1. Merge shape call_result_temporary_branch (high risk); next trace temporary/call-result dominance. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.69",
                    "      - inferred_offset_call_result_temporary_merge_provenance: Call-result/temporary merge provenance for v20: 1 call-result initializer(s), 1 temporary-root candidate(s). Call families ExAllocateFromLookasideListEx=1. Temporary roots v29 stable=deref(_QWORD,referencedObject@0x28). Provenance class allocation_call_with_temporary. Keep canonical rewrite blocked until temporary source dominance is validated. confidence=0.64",
                    "*/",
                    "__int64 __fastcall CallResultTemporaryMerge(__int64 CacheMap)",
                    "{",
                    "  v20 = ExAllocateFromLookasideListEx(&CcSharedCacheMapLookasideList);",
                ]
                + [
                    "  field%d = *(_QWORD *)(v20 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140450360",
                name="CallResultTemporaryMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=call_result_temporary_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_call_result_temporary_merge_provenance"])
            self.assertIn("layout_call_result_temporary_merge_provenance", item["reasons"])
            self.assertEqual(
                "v20",
                item["offset_base_counts"]["call_result_temporary_merge_provenance"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("CallResultTemporaryMerge", source_queue[0]["function"])
            self.assertEqual("v20", source_queue[0]["base"])
            self.assertEqual("call_result_temporary_branch", source_queue[0]["merge_shape"])
            self.assertEqual("high", source_queue[0]["merge_risk"])
            self.assertEqual("temporary_provenance_review", source_queue[0]["disposition"])
            self.assertIn("temporary/call-result path dominance", source_queue[0]["recommended_next"])
            self.assertEqual(
                "temporary_provenance_review",
                plan["score_model"]["source_identity_review_queues"][
                    "call_result_temporary_merge_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("temporary_provenance_review", markdown)
            self.assertIn("call_result_temporary_branch", markdown)

    def test_replay_plan_marks_call_result_parameter_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            call_result_parameter_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v47: base is a decompiler temporary; base has multiple initializers before layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v47: 2 initializer(s) before first layout access across 2 source candidate(s): *argument0; LookupLayoutObject(argument0). Candidate classes call_result=1, expression=1. Source families call_result:LookupLayoutObject=1, parameter:argument0=1; disposition distinct_source_family_review. Candidate kinds parameter_root=1, call_result=1. Merge shape call_result_parameter_branch (high risk); next review parameter/call-result path dominance. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.69",
                    "      - inferred_offset_call_result_parameter_merge_provenance: Call-result/parameter merge provenance for v47: 1 call-result initializer(s), 1 parameter-root candidate(s), 0 temporary-root candidate(s). Call families LookupLayoutObject=1. Parameter roots argument0. Parameter candidates *argument0 [pointer_deref]. Temporary roots none. 1 call-result initializer(s) mention parameter root(s). First layout access is dominated by a base truthiness guard. Guard condition v47. Provenance class call_result_with_parameter_root_linked_arguments_pointer_deref. Keep canonical rewrite blocked until parameter/call-result path dominance is validated. confidence=0.65",
                    "*/",
                    "__int64 __fastcall CallResultParameterMerge(__int64 argument0)",
                    "{",
                    "  v47 = *(_QWORD *)argument0;",
                ]
                + [
                    "  field%d = *(_QWORD *)(v47 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140BD2A04",
                name="CallResultParameterMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=call_result_parameter_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_call_result_parameter_merge_provenance"])
            self.assertIn("layout_call_result_parameter_merge_provenance", item["reasons"])
            self.assertEqual(
                "v47",
                item["offset_base_counts"]["call_result_parameter_merge_provenance"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("CallResultParameterMerge", source_queue[0]["function"])
            self.assertEqual("v47", source_queue[0]["base"])
            self.assertEqual("call_result_parameter_branch", source_queue[0]["merge_shape"])
            self.assertEqual("high", source_queue[0]["merge_risk"])
            self.assertEqual("parameter_provenance_review", source_queue[0]["disposition"])
            self.assertIn("parameter/call-result path dominance", source_queue[0]["recommended_next"])
            self.assertEqual(
                "parameter_provenance_review",
                plan["score_model"]["source_identity_review_queues"][
                    "call_result_parameter_merge_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("parameter_provenance_review", markdown)
            self.assertIn("call_result_parameter_branch", markdown)

    def test_replay_plan_marks_bugcheck_parameter_merge_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            bugcheck_parameter_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v12: base is a decompiler temporary; base has multiple initializers before layout access. Review-only aliases remain available. confidence=0.74",
                    "      - inferred_offset_base_merge_evidence: Base merge evidence for v12: 2 initializer(s) before first layout access across 2 source candidate(s): BugCheckParameter3; BugCheckParameter2. Candidate classes identifier=2. Source families bugcheck:BugCheckParameter2=1, bugcheck:BugCheckParameter3=1; disposition distinct_source_family_review. Candidate kinds bugcheck_root=2. Merge shape bugcheck_parameter_branch (high risk); next resolve bugcheck parameter domain identity. Treat as a branch-merged layout base; keep canonical rewrite blocked until path-sensitive dominance is available. confidence=0.69",
                    "      - inferred_offset_bugcheck_parameter_merge_identity: Bugcheck-parameter merge identity for v12: 2 bugcheck-root candidate(s), 0 temporary-root candidate(s). Bugcheck roots BugCheckParameter3, BugCheckParameter2. Bugcheck candidates BugCheckParameter3 [direct_root 0x0]; BugCheckParameter2 [direct_root 0x0]. Temporary roots none. First layout access is dominated by a base truthiness guard. Guard condition v12. Identity class multiple_bugcheck_roots. Treat BugCheckParameter names as unresolved decompiler identity; keep canonical rewrite blocked until domain-specific pointer meaning is validated. confidence=0.63",
                    "*/",
                    "__int64 __fastcall BugcheckParameterMerge(__int64 BugCheckParameter2)",
                    "{",
                    "  v12 = BugCheckParameter2;",
                ]
                + [
                    "  field%d = *(_QWORD *)(v12 + %d);" % (index, 256 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140871C20",
                name="BugcheckParameterMerge",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=bugcheck_parameter_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(1, item["metrics"]["layout_bugcheck_parameter_merge_identity"])
            self.assertIn("layout_bugcheck_parameter_merge_identity", item["reasons"])
            self.assertEqual(
                "v12",
                item["offset_base_counts"]["bugcheck_parameter_merge_identity"][0]["base"],
            )
            source_queue = plan["source_identity_review_queues"]["source_identity_blocked"]
            self.assertEqual("BugcheckParameterMerge", source_queue[0]["function"])
            self.assertEqual("v12", source_queue[0]["base"])
            self.assertEqual("bugcheck_parameter_branch", source_queue[0]["merge_shape"])
            self.assertEqual("high", source_queue[0]["merge_risk"])
            self.assertEqual("bugcheck_identity_review", source_queue[0]["disposition"])
            self.assertIn("bugcheck-parameter domain identity", source_queue[0]["recommended_next"])
            self.assertEqual(
                "bugcheck_identity_review",
                plan["score_model"]["source_identity_review_queues"][
                    "bugcheck_parameter_merge_disposition"
                ],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("bugcheck_identity_review", markdown)
            self.assertIn("bugcheck_parameter_branch", markdown)

    def test_replay_plan_trusts_allocation_stable_source_for_temp_base(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            allocation_sourced_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_stable_base_source: Stable base source for v22: Pool2 (allocation source, allocation_subobject_pointer_alias), 1835 typed dereference(s) across 100 offset(s). Review-only source identity evidence for temp/generic base promotion. confidence=0.68",
                    "      - inferred_offset_rewrite_blockers: Offset field rewrite blocked for v22: base is a decompiler temporary; base is reassigned after layout access. Review-only aliases remain available. confidence=0.74",
                    "*/",
                    "__int64 __fastcall AllocationSourcedTemp(__int64 source)",
                    "{",
                    "  Pool2 = ExAllocatePool2(0x100uLL, 4096uLL, 0x746E494Bu);",
                    "  v18 = (_QWORD *)Pool2;",
                    "  v22 = (__int64)(v18 + 4);",
                ]
                + [
                    "  field%d = *(_QWORD *)(v22 + %d);" % (index, 512 + index * 8)
                    for index in range(12)
                ]
                + ["  return field0;", "}"]
            )
            _write_function(
                root,
                ea="0x140506ED0",
                name="AllocationSourcedTemp",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=allocation_sourced_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertEqual(0, item["metrics"]["body_offset_deref_source_identity_blocked_base_patterns"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertNotIn("source_identity_blocked_offset_residue", item["reasons"])
            self.assertIn("layout_actionable_offset_residue", item["reasons"])
            self.assertFalse(item["offset_base_counts"]["source_identity_blocked"])
            self.assertEqual("v22", item["offset_base_counts"]["layout_actionable"][0]["base"])
            self.assertEqual([], plan["source_identity_review_queues"]["source_identity_blocked"])

    def test_replay_plan_treats_hot_field_cluster_as_layout_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            hot_cluster_body = "\n".join(
                [
                    "/*",
                    "    Kernel insights:",
                    "      - inferred_offset_field_hot_cluster: Hot field cluster for context (generic base): 27 typed dereference(s) concentrated in 6 offset(s); top fields field_20=+0x20 _DWORD x10; field_18=+0x18 _QWORD x8. Review-only access-pressure evidence; no structure type or body rewrite was inferred. confidence=0.72",
                    "*/",
                    "__int64 __fastcall HotCluster(__int64 context)",
                    "{",
                ]
                + [
                    "  v%d = *(_QWORD *)(context + %d);" % (item_index, 16 + (item_index * 8))
                    for item_index in range(12)
                ]
                + ["  return v11;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="HotCluster",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=hot_cluster_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertIn("layout_actionable_offset_residue", item["reasons"])
            self.assertIn("layout_hot_field_cluster", item["reasons"])
            self.assertNotIn("projected_layout_hot_field_cluster", item["reasons"])
            self.assertNotIn("context_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(1, item["metrics"]["layout_hot_field_clusters"])
            self.assertEqual(0, item["metrics"]["projected_layout_hot_field_clusters"])
            self.assertEqual(1, item["metrics"]["layout_actionability_signals"])
            self.assertEqual(1, item["metrics"]["layout_actionability_bases"])
            self.assertEqual(12, item["metrics"]["body_offset_deref_layout_actionable_patterns"])
            self.assertEqual(0, item["metrics"]["body_offset_deref_unannotated_context_base_patterns"])
            self.assertEqual("context", item["offset_base_counts"]["layout_actionable"][0]["base"])
            self.assertEqual([], plan["source_identity_review_queues"]["context"])
            self.assertIn(
                "layout_hot_field_clusters",
                plan["score_model"]["offset_actionability"]["layout_signal_metrics"],
            )

    def test_replay_plan_projects_missing_hot_field_clusters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            projected_body = "\n".join(
                ["__int64 __fastcall ProjectedHotCluster(__int64 context)", "{"]
                + ["  v%d = *(_DWORD *)(context + 32);" % item_index for item_index in range(10)]
                + ["  q%d = *(_QWORD *)(context + 24);" % item_index for item_index in range(8)]
                + ["  r%d = *(_QWORD *)(context + 40);" % item_index for item_index in range(4)]
                + ["  s%d = *(_DWORD *)(context + 34);" % item_index for item_index in range(3)]
                + [
                    "  tail0 = *(_QWORD *)(context + 8);",
                    "  tail1 = *(_DWORD *)(context + 35);",
                    "  return v9 + q7 + r3 + s2 + tail0 + tail1;",
                    "}",
                ]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="ProjectedHotCluster",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=projected_body,
            )

            plan = build_replay_plan(root, limit=1)

            item = plan["items"][0]
            self.assertIn("projected_layout_hot_field_cluster", item["reasons"])
            self.assertIn("context_unannotated_base_offset_residue", item["reasons"])
            self.assertEqual(1, item["metrics"]["projected_layout_hot_field_clusters"])
            self.assertEqual(1, item["metrics"]["projected_layout_hot_field_cluster_bases"])
            self.assertEqual(27, item["metrics"]["projected_layout_hot_field_cluster_accesses"])
            self.assertEqual("context", item["offset_base_counts"]["projected_hot_cluster"][0]["base"])
            self.assertEqual(27, item["offset_base_counts"]["projected_hot_cluster"][0]["count"])
            self.assertEqual(
                "context",
                plan["offset_base_breakdown"]["top_projected_hot_cluster_bases"][0]["base"],
            )
            context_queue = plan["source_identity_review_queues"]["context"]
            self.assertEqual(27, context_queue[0]["projected_hot_cluster_accesses"])
            self.assertIn(
                "projected_layout_hot_field_cluster_accesses",
                plan["score_model"]["hot_cluster_projection"]["access_metric"],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Top projected hot cluster bases", markdown)
            self.assertIn("Projected hot cluster accesses", markdown)

    def test_replay_plan_splits_context_and_bugcheck_argument_identity_bases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            context_body = "\n".join(
                ["__int64 __fastcall ContextBase(__int64 context)", "{"]
                + [
                    "  v%d = *(_QWORD *)(context + %d);" % (item_index, 16 + (item_index * 8))
                    for item_index in range(12)
                ]
                + ["  return v11;", "}"]
            )
            bugcheck_body = "\n".join(
                ["__int64 __fastcall BugcheckBase(__int64 BugCheckParameter2)", "{"]
                + [
                    "  v%d = *(_QWORD *)(BugCheckParameter2 + %d);" % (item_index, 16 + (item_index * 8))
                    for item_index in range(12)
                ]
                + ["  return v11;", "}"]
            )
            _write_function(
                root,
                ea="0x140001000",
                name="ContextBase",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=context_body,
            )
            _write_function(
                root,
                ea="0x140002000",
                name="BugcheckBase",
                warnings=0,
                rename_candidates=1,
                renames=1,
                cleaned_body=bugcheck_body,
            )

            plan = build_replay_plan(root, limit=2)

            by_name = {item["name"]: item for item in plan["items"]}
            context_item = by_name["ContextBase"]
            bugcheck_item = by_name["BugcheckBase"]
            self.assertIn("context_unannotated_base_offset_residue", context_item["reasons"])
            self.assertEqual(12, context_item["metrics"]["body_offset_deref_unannotated_context_base_patterns"])
            self.assertIn("bugcheck_unannotated_base_offset_residue", bugcheck_item["reasons"])
            self.assertEqual(12, bugcheck_item["metrics"]["body_offset_deref_unannotated_bugcheck_base_patterns"])
            self.assertEqual(
                "context",
                plan["offset_base_breakdown"]["top_unannotated_context_bases"][0]["base"],
            )
            self.assertEqual(
                "BugCheckParameter2",
                plan["offset_base_breakdown"]["top_unannotated_bugcheck_bases"][0]["base"],
            )
            context_queue = plan["source_identity_review_queues"]["context"]
            bugcheck_queue = plan["source_identity_review_queues"]["bugcheck"]
            self.assertEqual("ContextBase", context_queue[0]["function"])
            self.assertEqual("context", context_queue[0]["base"])
            self.assertEqual(12, context_queue[0]["offset_derefs"])
            self.assertEqual("generic_parameter_trust_review", context_queue[0]["disposition"])
            self.assertEqual("BugcheckBase", bugcheck_queue[0]["function"])
            self.assertEqual("BugCheckParameter2", bugcheck_queue[0]["base"])
            self.assertEqual(12, bugcheck_queue[0]["offset_derefs"])
            self.assertEqual("bugcheck_parameter_pointer_review", bugcheck_queue[0]["disposition"])
            self.assertEqual(
                15,
                plan["score_model"]["source_identity_review_queues"]["queue_limit"],
            )
            self.assertEqual(
                10,
                plan["score_model"]["source_identity_review_queues"]["min_offset_derefs"],
            )
            markdown = render_replay_plan_markdown(plan)
            self.assertIn("Context parameter candidates", markdown)
            self.assertIn("Bugcheck parameter pointer candidates", markdown)
            self.assertIn("bugcheck_parameter_pointer_review", markdown)


def _write_function(
    root: Path,
    *,
    ea: str,
    name: str,
    warnings: int,
    rename_candidates: int,
    renames: int,
    cleaned_body: str,
    rename_map_comments: list[dict[str, object]] | None = None,
) -> None:
    folder = root / "functions" / ("%016X_%s" % (int(ea, 16), name))
    folder.mkdir(parents=True)
    cleaned_path = folder / f"{name}.cleaned.cpp"
    warnings_path = folder / f"{name}.warnings.json"
    summary_path = folder / f"{name}.ida-batch-summary.json"
    rename_map_path = folder / f"{name}.rename-map.json"
    cleaned_path.write_text(cleaned_body.strip() + "\n", encoding="utf-8")
    warnings_path.write_text(
        json.dumps(["Skipped PascalCase LLM rename a1->PageTableBase"] * warnings),
        encoding="utf-8",
    )
    artifacts = {
        "cleaned_pseudocode": cleaned_path.name,
        "warnings": warnings_path.name,
        "summary": summary_path.name,
    }
    if rename_map_comments is not None:
        rename_map_path.write_text(
            json.dumps({"comments": rename_map_comments}, indent=2),
            encoding="utf-8",
        )
        artifacts["rename_map"] = rename_map_path.name
    summary_path.write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": name,
                "function_ea": ea,
                "rename_candidates": rename_candidates,
                "renames": renames,
                "warnings": warnings,
                "llm_status": "disabled",
                "artifacts": artifacts,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
