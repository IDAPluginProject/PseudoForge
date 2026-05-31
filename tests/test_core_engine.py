import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import (
    render_cleaned_pseudocode,
    render_switch_outline,
)
from ida_pseudoforge.version import VERSION
from tests.fixtures.ntset_samples import NTSET_SYSTEM_INFORMATION_SAMPLE


class CoreEngineTests(unittest.TestCase):
    def test_render_cleaned_pseudocode(self):
        capture = capture_from_pseudocode(NTSET_SYSTEM_INFORMATION_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("Version: %s" % VERSION, rendered)
        self.assertIn("infoClass", rendered)
        self.assertIn("systemInformationLength", rendered)
        self.assertIn("NTSTATUS NTAPI NtSetSystemInformation(", rendered)
        self.assertIn("SYSTEM_INFORMATION_CLASS systemInformationClass,", rendered)
        self.assertIn("PVOID systemInformation,", rendered)
        self.assertIn("ULONG systemInformationLength)", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("previousMode = KeGetCurrentThread()->PreviousMode;", rendered)
        self.assertNotIn("KeGetCurrentThread()->previousMode", rendered)
        self.assertIn("STATUS_INFO_LENGTH_MISMATCH", rendered)
        self.assertIn("STATUS_INVALID_INFO_CLASS", rendered)
        self.assertIn("PseudoForge recovered switch view", rendered)
        self.assertIn("switch (infoClass)", rendered)
        self.assertIn("infoClass == SystemFlagsInformation", rendered)
        self.assertIn("infoClass - SystemHypervisorBootPagesInformation", rendered)
        self.assertIn("v116 = infoClass - SystemTrustedAppsRuntimeInformation;", rendered)
        self.assertIn("if ( !v115 )", rendered)
        self.assertIn("if ( !v116 )", rendered)
        self.assertNotIn("v116 = v115 - 8;", rendered)
        self.assertNotIn("infoClass == 9", rendered)
        self.assertLess(
            rendered.index("NTSTATUS NTAPI NtSetSystemInformation("),
            rendered.index("PseudoForge recovered switch view"),
        )

    def test_render_switch_outline(self):
        capture = capture_from_pseudocode(NTSET_SYSTEM_INFORMATION_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_switch_outline(capture, plan)

        self.assertIn("switch (infoClass)", rendered)
        self.assertIn("// SystemHypervisorBootPagesInformation", rendered)
        self.assertIn("case 235:", rendered)
        self.assertIn("return HvlQuerySetBootPagesInfo(systemInformation, 0LL);", rendered)
        self.assertIn("case 243:", rendered)


if __name__ == "__main__":
    unittest.main()
