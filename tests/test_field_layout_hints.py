from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.field_layout_hints import field_layout_comments
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode


class FieldLayoutHintTests(unittest.TestCase):
    def test_repeated_typed_offset_accesses_emit_layout_comment(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "a1",
                                "new": "sessionSpace",
                                "confidence": 0.95,
                                "reason": "base pointer with repeated typed offsets",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(
            """
__int64 __fastcall FieldLayoutSample(__int64 a1)
{
  unsigned int v1;
  __int64 v2;

  v1 = *(_DWORD *)(a1 + 16);
  v2 = *(_QWORD *)(a1 + 24);
  if ( *(_BYTE *)(a1 + 32) )
    return *(_DWORD *)(a1 + 40) + *(_WORD *)(a1 + 48) + v1;
  return v1 + v2;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        comments = [item for item in plan.comments if item.get("kind") == "inferred_offset_layout"]
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(1, len(comments))
        self.assertIn("sessionSpace", comments[0]["text"])
        self.assertIn("+0x10", comments[0]["text"])
        self.assertIn("+0x18", comments[0]["text"])
        self.assertIn("+0x20", comments[0]["text"])
        self.assertIn("inferred_offset_layout", rendered)
        self.assertIn("Offset layout hint: sessionSpace", rendered)
        self.assertIn("inferred_offset_field_preview", rendered)
        self.assertIn("Preview fields for sessionSpace", rendered)
        self.assertIn("inferred_offset_field_aliases", rendered)
        self.assertIn("Alias map for sessionSpace", rendered)
        self.assertIn("inferred_offset_rewrite_blockers", rendered)
        self.assertIn("rewrite offset threshold requires at least 8 offsets", rendered)
        self.assertIn("rewrite access threshold requires at least 12 accesses", rendered)

    def test_sparse_offset_accesses_do_not_emit_layout_comment(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SparseLayout(__int64 a1)
{
  return *(_DWORD *)(a1 + 16) + *(_DWORD *)(a1 + 24);
}
"""
        )

        self.assertEqual([], comments)

    def test_generic_temp_base_requires_stronger_layout_evidence(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall GenericTempLayout(__int64 v14)
{
  if ( *(_BYTE *)(v14 + 1) )
    return *(_DWORD *)(v14 + 4) + *(_QWORD *)(v14 + 32);
  return *(_DWORD *)(v14 + 40);
}
"""
        )

        self.assertEqual([], comments)

    def test_named_layout_with_dense_offsets_emits_preview_only_fields(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall NamedLayout(__int64 sessionSpace)
{
  return *(_DWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_BYTE *)(sessionSpace + 32)
       + *(_WORD *)(sessionSpace + 40)
       + *(_DWORD *)(sessionSpace + 48);
}
"""
        )
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(previews))
        self.assertEqual("sessionSpace", previews[0]["base"])
        self.assertEqual("named", previews[0]["base_kind"])
        self.assertEqual(5, len(previews[0]["fields"]))
        self.assertIn("+0x10 _DWORD field_10", previews[0]["text"])
        self.assertIn("Preview only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        self.assertEqual(1, len(aliases))
        self.assertEqual("sessionSpace", aliases[0]["base"])
        self.assertEqual("named", aliases[0]["base_kind"])
        self.assertEqual(0.73, aliases[0]["confidence"])
        self.assertIn("field_10=+0x10 _DWORD", aliases[0]["text"])
        self.assertIn("review-only shorthand", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertEqual("sessionSpace", blockers[0]["base"])
        self.assertEqual("named", blockers[0]["base_kind"])
        self.assertIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])

    def test_named_layout_threshold_blockers_are_split_by_evidence_type(self) -> None:
        offset_limited = field_layout_comments(
            """
__int64 __fastcall OffsetLimitedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24);
}
"""
        )
        access_limited = field_layout_comments(
            """
__int64 __fastcall AccessLimitedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72);
}
"""
        )

        offset_blockers = [
            item for item in offset_limited if item.get("kind") == "inferred_offset_rewrite_blockers"
        ]
        access_blockers = [
            item for item in access_limited if item.get("kind") == "inferred_offset_rewrite_blockers"
        ]
        offset_near_ready = [
            item for item in offset_limited if item.get("kind") == "inferred_offset_rewrite_near_ready"
        ]
        access_near_ready = [
            item for item in access_limited if item.get("kind") == "inferred_offset_rewrite_near_ready"
        ]

        self.assertEqual(1, len(offset_blockers))
        self.assertIn("rewrite offset threshold requires at least 8 offsets", offset_blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", offset_blockers[0]["blockers"])
        self.assertEqual(1, len(offset_near_ready))
        self.assertEqual("offset", offset_near_ready[0]["missing_threshold"])
        self.assertEqual(5, offset_near_ready[0]["offset_count"])
        self.assertEqual(12, offset_near_ready[0]["access_count"])
        self.assertIn("missing offset threshold only", offset_near_ready[0]["text"])
        self.assertEqual(1, len(access_blockers))
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", access_blockers[0]["blockers"])
        self.assertIn("rewrite access threshold requires at least 12 accesses", access_blockers[0]["blockers"])
        self.assertEqual(1, len(access_near_ready))
        self.assertEqual("access", access_near_ready[0]["missing_threshold"])
        self.assertEqual(8, access_near_ready[0]["offset_count"])
        self.assertEqual(8, access_near_ready[0]["access_count"])
        self.assertIn("missing access threshold only", access_near_ready[0]["text"])

    def test_strong_temp_base_is_marked_as_temporary_low_confidence_hint(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongTempLayout(__int64 v14)
{
  return *(_QWORD *)(v14 + 16)
       + *(_QWORD *)(v14 + 24)
       + *(_QWORD *)(v14 + 32)
       + *(_QWORD *)(v14 + 40)
       + *(_QWORD *)(v14 + 48)
       + *(_QWORD *)(v14 + 56)
       + *(_QWORD *)(v14 + 64)
       + *(_QWORD *)(v14 + 72)
       + *(_QWORD *)(v14 + 80)
       + *(_QWORD *)(v14 + 88)
       + *(_QWORD *)(v14 + 96)
       + *(_QWORD *)(v14 + 104);
}
"""
        )

        self.assertEqual(4, len(comments))
        self.assertEqual("temp", comments[0]["base_kind"])
        self.assertEqual(0.74, comments[0]["confidence"])
        self.assertIn("temporary base", comments[0]["text"])
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        self.assertEqual(1, len(previews))
        self.assertEqual("v14", previews[0]["base"])
        self.assertEqual("temp", previews[0]["base_kind"])
        self.assertEqual(0.7, previews[0]["confidence"])
        self.assertIn("Review fields for v14 (temporary base)", previews[0]["text"])
        self.assertIn("Review only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        self.assertEqual(1, len(aliases))
        self.assertEqual("v14", aliases[0]["base"])
        self.assertEqual("temp", aliases[0]["base_kind"])
        self.assertEqual(0.66, aliases[0]["confidence"])
        self.assertIn("Review aliases for v14 (temporary base)", aliases[0]["text"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertEqual("v14", blockers[0]["base"])
        self.assertEqual("temp", blockers[0]["base_kind"])
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_generic_argument_and_bugcheck_parameter_bases_are_skipped(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall GenericArgumentLayout(__int64 argument0, __int64 BugCheckParameter2)
{
  if ( *(_DWORD *)(argument0 + 48) )
    return *(_QWORD *)(argument0 + 72) + *(_DWORD *)(argument0 + 48);
  return *(_DWORD *)(BugCheckParameter2 + 56)
       + *(_QWORD *)(BugCheckParameter2 + 64)
       + *(_DWORD *)(BugCheckParameter2 + 144)
       + *(_DWORD *)(BugCheckParameter2 + 148)
       + *(_DWORD *)(BugCheckParameter2 + 152)
       + *(_QWORD *)(BugCheckParameter2 + 160)
       + *(_QWORD *)(BugCheckParameter2 + 232)
       + *(_DWORD *)(BugCheckParameter2 + 280);
}
"""
        )

        self.assertEqual([], comments)

    def test_generic_named_context_requires_stronger_layout_evidence(self) -> None:
        weak_comments = field_layout_comments(
            """
__int64 __fastcall WeakContextLayout(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_WORD *)(context + 56)
       + *(_BYTE *)(context + 64)
       + *(_BYTE *)(context + 66)
       + *(_BYTE *)(context + 69)
       + *(_QWORD *)(context + 72);
}
"""
        )
        strong_comments = field_layout_comments(
            """
__int64 __fastcall StrongContextLayout(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88)
       + *(_QWORD *)(context + 104)
       + *(_QWORD *)(context + 112)
       + *(_QWORD *)(context + 120)
       + *(_QWORD *)(context + 128)
       + *(_QWORD *)(context + 136);
}
"""
        )

        self.assertEqual([], weak_comments)
        self.assertEqual(4, len(strong_comments))
        self.assertEqual("generic", strong_comments[0]["base_kind"])
        self.assertEqual(0.78, strong_comments[0]["confidence"])
        self.assertIn("generic base", strong_comments[0]["text"])
        self.assertIn("context", strong_comments[0]["text"])
        previews = [item for item in strong_comments if item.get("kind") == "inferred_offset_field_preview"]
        self.assertEqual(1, len(previews))
        self.assertEqual("context", previews[0]["base"])
        self.assertEqual("generic", previews[0]["base_kind"])
        self.assertEqual(0.74, previews[0]["confidence"])
        self.assertIn("Review fields for context (generic base)", previews[0]["text"])
        self.assertIn("Review only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        aliases = [item for item in strong_comments if item.get("kind") == "inferred_offset_field_aliases"]
        self.assertEqual(1, len(aliases))
        self.assertEqual("context", aliases[0]["base"])
        self.assertEqual("generic", aliases[0]["base_kind"])
        self.assertEqual(0.7, aliases[0]["confidence"])
        self.assertIn("Review aliases for context (generic base)", aliases[0]["text"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        blockers = [item for item in strong_comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertEqual("context", blockers[0]["base"])
        self.assertEqual("generic", blockers[0]["base_kind"])
        self.assertIn("base name is generic", blockers[0]["blockers"])
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in strong_comments))

    def test_named_layout_without_negative_evidence_has_no_rewrite_blocker(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongNamedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_field_aliases" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        self.assertEqual(1, len(ready))
        self.assertEqual("sessionSpace", ready[0]["base"])
        self.assertEqual("named", ready[0]["base_kind"])
        self.assertEqual(8, ready[0]["offset_count"])
        self.assertEqual(12, ready[0]["access_count"])
        self.assertIn("no rewrite blockers found", ready[0]["text"])
        self.assertIn("Audit only; body rewrite was not applied", ready[0]["text"])

    def test_stable_one_time_base_alias_assignment_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableAliasLayout(__int64 a1)
{
  __int64 sessionSpace;

  sessionSpace = a1;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_field_aliases" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_named_layout_rewrite_blocker_reports_mixed_type_and_base_mutation(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MutatedNamedLayout(__int64 sessionSpace, __int64 nextSessionSpace)
{
  result = *(_DWORD *)(sessionSpace + 16);
  result += *(_QWORD *)(sessionSpace + 16);
  result += *(_QWORD *)(sessionSpace + 24);
  result += *(_QWORD *)(sessionSpace + 32);
  result += *(_QWORD *)(sessionSpace + 40);
  result += *(_QWORD *)(sessionSpace + 48);
  result += *(_QWORD *)(sessionSpace + 56);
  result += *(_QWORD *)(sessionSpace + 64);
  result += *(_QWORD *)(sessionSpace + 72);
  result += *(_QWORD *)(sessionSpace + 80);
  result += *(_QWORD *)(sessionSpace + 88);
  result += *(_QWORD *)(sessionSpace + 96);
  sessionSpace = nextSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 104);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]

        self.assertEqual(1, len(overlays))
        self.assertEqual("sessionSpace", overlays[0]["base"])
        self.assertEqual("named", overlays[0]["base_kind"])
        self.assertEqual(1, len(overlays[0]["overlays"]))
        self.assertEqual(16, overlays[0]["overlays"][0]["offset"])
        self.assertEqual([4, 8], overlays[0]["overlays"][0]["sizes"])
        self.assertEqual("dword_qword", overlays[0]["overlays"][0]["size_class"])
        self.assertIn("Subfield overlay evidence for sessionSpace", overlays[0]["text"])
        self.assertIn("+0x10 field_10 uses 4/8-byte accesses", overlays[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets mix partial-width field accesses", blockers[0]["blockers"])
        self.assertIn("base is reassigned after layout access", blockers[0]["blockers"])
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_same_width_type_aliases_do_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SameWidthAliasLayout(__int64 sessionSpace)
{
  return *(_DWORD *)(sessionSpace + 16)
       + *(unsigned int *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(aliases))
        self.assertIn("field_10=+0x10 mixed(_DWORD/unsigned int)", aliases[0]["text"])
        self.assertEqual([], overlays)
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))

    def test_unknown_type_class_conflicts_are_reported_separately(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UnknownTypeConflictLayout(__int64 sessionSpace)
{
  return *(_FOO *)(sessionSpace + 16)
       + *(_BAR *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]

        self.assertEqual([], overlays)
        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets have incompatible access type classes", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix partial-width field accesses", blockers[0]["blockers"])

    def test_compound_base_assignment_blocks_rewrite_even_before_first_access(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall CompoundAliasLayout(__int64 sessionSpace)
{
  sessionSpace += 8;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base uses compound assignment", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_stable_same_rhs_reload_after_layout_access_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableReloadLayout(__int64 a1)
{
  __int64 sessionSpace;
  __int64 result;

  sessionSpace = a1;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = a1;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_stable_saved_alias_reload_after_layout_access_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableSavedAliasReloadLayout(__int64 a1)
{
  __int64 sessionSpace;
  __int64 savedSessionSpace;
  __int64 result;

  sessionSpace = a1;
  savedSessionSpace = sessionSpace;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = savedSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_mutated_saved_alias_reload_after_layout_access_blocks_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MutatedSavedAliasReloadLayout(__int64 a1, __int64 a2)
{
  __int64 sessionSpace;
  __int64 savedSessionSpace;
  __int64 result;

  sessionSpace = a1;
  savedSessionSpace = sessionSpace;
  savedSessionSpace = a2;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = savedSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base is reassigned after layout access", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_multiple_different_initializers_before_layout_access_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MultiInitializerLayout(__int64 a1, __int64 a2)
{
  __int64 sessionSpace;

  sessionSpace = a1;
  sessionSpace = a2;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base has multiple initializers before layout access", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))


if __name__ == "__main__":
    unittest.main()
