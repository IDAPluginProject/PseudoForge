from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable, RenameSuggestion
from ida_pseudoforge.core.rename_normalization import normalize_rename_suggestions, pascal_to_lower_camel
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tests.helpers import JsonRenameProvider


SAMPLE = r"""
__int64 __fastcall Sample(__int64 a1)
{
  __int64 v1;

  v1 = a1 + 8;
  return v1;
}
"""


class RenameNormalizationTests(unittest.TestCase):
    def test_pascal_case_llm_local_name_is_normalized_before_validation(self) -> None:
        capture = _capture()
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "kind": "arg",
                        "old": "a1",
                        "new": "PageTableBase",
                        "confidence": 0.95,
                        "reason": "used as the base address for page table indexing",
                    }
                ]
            }
        )

        plan = build_clean_plan(capture, rename_provider=provider)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertTrue(any(item.old == "a1" and item.new == "pageTableBase" and item.apply for item in plan.renames))
        self.assertNotIn("Skipped PascalCase LLM rename a1->PageTableBase", plan.warnings)
        self.assertIn("pageTableBase", rendered)

    def test_pascal_to_lower_camel_preserves_kernel_acronym_boundaries(self) -> None:
        self.assertEqual("pteIndex", pascal_to_lower_camel("PteIndex"))
        self.assertEqual("ioStatusBlock", pascal_to_lower_camel("IoStatusBlock"))
        self.assertEqual("cpuSetMask", pascal_to_lower_camel("CPUSetMask"))
        self.assertEqual("mdlAddress", pascal_to_lower_camel("MDLAddress"))
        self.assertEqual("desc0DataPtr", pascal_to_lower_camel("Desc0_DataPtr"))
        self.assertEqual("arg3Rbx", pascal_to_lower_camel("Arg3_Rbx"))

    def test_pascal_underscore_llm_local_name_is_normalized_before_validation(self) -> None:
        capture = _capture()
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "kind": "lvar",
                        "old": "v1",
                        "new": "Desc0_DataPtr",
                        "confidence": 0.95,
                        "reason": "descriptor data pointer local",
                    }
                ]
            }
        )

        plan = build_clean_plan(capture, rename_provider=provider)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertTrue(any(item.old == "v1" and item.new == "desc0DataPtr" and item.apply for item in plan.renames))
        self.assertNotIn("Skipped PascalCase LLM rename v1->Desc0_DataPtr", plan.warnings)
        self.assertIn("desc0DataPtr", rendered)

    def test_low_confidence_pascal_case_candidate_is_left_for_validator(self) -> None:
        capture = _manual_capture()
        suggestions = [
            RenameSuggestion("lvar", "v1", "PageTableBase", 0.80, "llm", "weak context"),
        ]

        normalized = normalize_rename_suggestions(capture, suggestions)

        self.assertEqual("PageTableBase", normalized[0].new)

    def test_type_like_pascal_case_candidate_is_not_normalized(self) -> None:
        capture = _manual_capture()
        suggestions = [
            RenameSuggestion("lvar", "v1", "ProcessStruct", 0.95, "llm", "looks like a type"),
        ]

        normalized = normalize_rename_suggestions(capture, suggestions)

        self.assertEqual("ProcessStruct", normalized[0].new)

    def test_upper_snake_and_type_like_underscore_candidates_are_not_normalized(self) -> None:
        capture = _manual_capture()
        suggestions = [
            RenameSuggestion("lvar", "v1", "IO_STATUS_BLOCK", 0.95, "llm", "type-like constant"),
            RenameSuggestion("lvar", "v1", "Range_Type", 0.95, "llm", "type-like suffix"),
        ]

        normalized = normalize_rename_suggestions(capture, suggestions)

        self.assertEqual("IO_STATUS_BLOCK", normalized[0].new)
        self.assertEqual("Range_Type", normalized[1].new)


def _capture() -> FunctionCapture:
    return capture_from_pseudocode(SAMPLE)


def _manual_capture() -> FunctionCapture:
    return FunctionCapture(
        ea=0x140001000,
        name="Sample",
        prototype="__int64 __fastcall Sample(__int64 a1)",
        pseudocode=SAMPLE,
        lvars=[
            LocalVariable("a1", "__int64", True, 0),
            LocalVariable("v1", "__int64", False, 1),
        ],
    )


if __name__ == "__main__":
    unittest.main()
