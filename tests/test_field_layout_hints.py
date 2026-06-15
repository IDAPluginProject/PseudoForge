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

        self.assertEqual(1, len(previews))
        self.assertEqual("sessionSpace", previews[0]["base"])
        self.assertEqual("named", previews[0]["base_kind"])
        self.assertEqual(5, len(previews[0]["fields"]))
        self.assertIn("+0x10 _DWORD field_10", previews[0]["text"])
        self.assertIn("Preview only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])

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

        self.assertEqual(1, len(comments))
        self.assertEqual("temp", comments[0]["base_kind"])
        self.assertEqual(0.74, comments[0]["confidence"])
        self.assertIn("temporary base", comments[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_field_preview" for item in comments))

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
        self.assertEqual(1, len(strong_comments))
        self.assertEqual("generic", strong_comments[0]["base_kind"])
        self.assertEqual(0.78, strong_comments[0]["confidence"])
        self.assertIn("generic base", strong_comments[0]["text"])
        self.assertIn("context", strong_comments[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_field_preview" for item in strong_comments))


if __name__ == "__main__":
    unittest.main()
