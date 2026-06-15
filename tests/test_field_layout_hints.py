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
    return *(_DWORD *)(a1 + 40) + v1;
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


if __name__ == "__main__":
    unittest.main()
