from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_corpus_quality import analyze_corpus, main


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
      - inferred_offset_rewrite_near_ready: Offset field rewrite near-ready for nearlySession: 12 typed dereference(s) across 6 offset(s), missing offset threshold only. Audit only; body rewrite was not applied. confidence=0.75
      - inferred_offset_layout: Offset layout hint: v14 has 13 typed dereference(s) across 8 offset(s) +0x8, +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40; observed types: _BYTE, _DWORD, .... Review as a high-evidence temporary base before inferring a structure. confidence=0.74
      - inferred_offset_stable_base_source: Stable base source for v14: argument2 (argument source), 13 typed dereference(s) across 8 offset(s). Review-only; temp/generic base keeps rewrite blocked until source identity is trusted. confidence=0.68
      - inferred_offset_generic_base_evidence: Generic base evidence for context: 20 typed dereference(s) across 10 offset(s), blocker profile generic_only. Review-only; rewrite remains blocked until the base identity is trusted. confidence=0.74
      - inferred_offset_generic_base_trust_candidate: Generic base trust candidate for context: parameter source, generic-only blockers, 20 typed dereference(s) across 10 offset(s). Promotion review only; rewrite remains disabled until external type identity is confirmed. confidence=0.76
*/
__int64 __fastcall Sample(__int64 a1)
{
  __int64 v1;

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
            self.assertEqual("Sample", report["layout_stable_base_source_stats"]["top_functions"][0]["name"])
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["top_functions"][0]["top_sources"]["argument2"],
            )
            self.assertEqual(
                1,
                report["layout_stable_base_source_stats"]["top_functions"][0]["top_source_kinds"]["argument"],
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
            self.assertEqual("Sample", report["layout_rewrite_ready_stats"]["top_functions"][0]["name"])
            self.assertEqual(8, report["layout_rewrite_ready_stats"]["top_functions"][0]["max_offsets"])
            self.assertEqual(12, report["layout_rewrite_ready_stats"]["top_functions"][0]["max_access_count"])
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
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["totals"]["blockers"])
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["totals"]["functions_with_blockers"])
            self.assertEqual(2, report["layout_rewrite_blocker_stats"]["totals"]["reason_observations"])
            self.assertEqual(1, report["layout_rewrite_blocker_stats"]["top_bases"]["sessionSpace"])
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
            self.assertEqual("Sample", report["layout_rewrite_blocker_stats"]["top_functions"][0]["name"])
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
            self.assertEqual(1, report["text_stats"]["inferred_offset_generic_base_evidence"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_generic_base_trust_candidates"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_ready"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_near_ready"])
            self.assertEqual(1, report["text_stats"]["inferred_offset_rewrite_blockers"])
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
            self.assertNotIn("inferred_offset_layout_hints", report["body_text_stats"])
            self.assertNotIn("inferred_offset_field_aliases", report["body_text_stats"])
            self.assertNotIn("inferred_offset_subfield_overlays", report["body_text_stats"])
            self.assertNotIn("inferred_offset_narrow_subfields", report["body_text_stats"])
            self.assertNotIn("inferred_offset_bitfield_aliases", report["body_text_stats"])
            self.assertNotIn("inferred_offset_stable_base_sources", report["body_text_stats"])
            self.assertNotIn("inferred_offset_generic_base_evidence", report["body_text_stats"])
            self.assertNotIn("inferred_offset_generic_base_trust_candidates", report["body_text_stats"])
            self.assertNotIn("inferred_offset_rewrite_ready", report["body_text_stats"])
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
                "Layout Rewrite Near-Ready",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Layout Rewrite Blockers",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "Code Body Residue",
                (output_dir / "corpus-quality.md").read_text(encoding="utf-8"),
            )


def _write_quality_fixture(root: Path) -> None:
    function_dir = root / "functions" / "0000000140001000_Sample"
    function_dir.mkdir(parents=True)
    cleaned_path = function_dir / "Sample.cleaned.cpp"
    warnings_path = function_dir / "Sample.warnings.json"
    rename_map_path = function_dir / "Sample.rename-map.json"
    buffer_contracts_path = function_dir / "Sample.buffer-contracts.json"
    rule_report_path = function_dir / "Sample.rule-report.json"
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
                    "summary": "old/Sample.ida-batch-summary.json",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
