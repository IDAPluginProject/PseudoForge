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
  return context;
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
