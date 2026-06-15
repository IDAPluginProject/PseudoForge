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
        self.assertIn("rewrite threshold requires at least 8 offsets and 12 accesses", rendered)

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
        self.assertIn("rewrite threshold requires at least 8 offsets and 12 accesses", blockers[0]["blockers"])

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
        self.assertNotIn("rewrite threshold requires at least 8 offsets and 12 accesses", blockers[0]["blockers"])

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
        self.assertNotIn("rewrite threshold requires at least 8 offsets and 12 accesses", blockers[0]["blockers"])

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

        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets have conflicting access types", blockers[0]["blockers"])
        self.assertIn("base is assigned or incremented", blockers[0]["blockers"])
        self.assertNotIn("rewrite threshold requires at least 8 offsets and 12 accesses", blockers[0]["blockers"])


if __name__ == "__main__":
    unittest.main()
