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
) -> None:
    folder = root / "functions" / ("%016X_%s" % (int(ea, 16), name))
    folder.mkdir(parents=True)
    cleaned_path = folder / f"{name}.cleaned.cpp"
    warnings_path = folder / f"{name}.warnings.json"
    summary_path = folder / f"{name}.ida-batch-summary.json"
    cleaned_path.write_text(cleaned_body.strip() + "\n", encoding="utf-8")
    warnings_path.write_text(
        json.dumps(["Skipped PascalCase LLM rename a1->PageTableBase"] * warnings),
        encoding="utf-8",
    )
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
                "artifacts": {
                    "cleaned_pseudocode": cleaned_path.name,
                    "warnings": warnings_path.name,
                    "summary": summary_path.name,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
