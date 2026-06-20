import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from tests.fixtures.ntset_samples import NTSET_SYSTEM_INFORMATION_SAMPLE


class PlanBuilderTests(unittest.TestCase):
    def test_build_clean_plan_recovers_ntset_semantics(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_INFORMATION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a1"], "systemInformationClass")
        self.assertEqual(rename_map["a2"], "systemInformation")
        self.assertEqual(rename_map["a3"], "systemInformationLength")
        self.assertEqual(rename_map["v5"], "infoClass")
        self.assertEqual(rename_map["PreviousMode"], "previousMode")
        self.assertTrue(plan.flow_rewrites)
        self.assertIn(235, plan.flow_rewrites[0].recovered_cases)
        self.assertIn(243, plan.flow_rewrites[0].recovered_cases)
        self.assertIn(235, plan.flow_rewrites[0].case_bodies)
        self.assertEqual(
            plan.flow_rewrites[0].case_names[235],
            "SystemHypervisorBootPagesInformation",
        )
        classifications = {label.label: label.classification for label in plan.cleanup_labels}
        self.assertEqual(classifications["LABEL_214"], "dereference_object_and_return")
        self.assertEqual(
            classifications["LABEL_421"],
            "cleanup_captured_unicode_string_and_return",
        )

    def test_shadowed_duplicate_target_warnings_are_removed(self) -> None:
        sample = r"""
__int64 __fastcall DuplicateInputLengthSample(int a1, void *a2, ULONG a3)
{
  size_t v3;

  v3 = (unsigned int)a3;
  return v3;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)

        self.assertFalse(any("Skipped duplicate target inputLength" in warning for warning in plan.warnings))

    def test_pointer_sized_parameter_is_not_length_fallback(self) -> None:
        sample = r"""
char __fastcall PointerSizedParameterSample(ULONG_PTR a1, __int64 a2, ULONG_PTR a3, char a4)
{
  *(_BYTE *)(a3 + 15) = 0;
  *(_BYTE *)(a3 + 10) = a4;
  return *(_BYTE *)(a3 + 10);
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("argument2", rename_map["a3"])
        self.assertNotIn("inputLength", rename_map.values())

    def test_plain_ulong_parameter_keeps_length_fallback(self) -> None:
        sample = r"""
__int64 __fastcall LengthFallbackSample(__int64 a1, __int64 a2, ULONG a3)
{
  if ( a3 < 0x20 )
    return 0;
  return a3;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("inputLength", rename_map["a3"])


if __name__ == "__main__":
    unittest.main()
