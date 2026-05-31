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


if __name__ == "__main__":
    unittest.main()
