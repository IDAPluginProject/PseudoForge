from __future__ import annotations

import unittest

from ida_pseudoforge.core.buffer_contracts import render_buffer_struct_header
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ioctl_analysis import render_ioctl_deep_analysis_report
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from tests.test_buffer_contracts import DEEP_HELPER_SAMPLE, HELPER_SAMPLE, IOCTL_CONTRACT_SAMPLE


class IoctlAnalysisTests(unittest.TestCase):
    def test_ioctl_deep_analysis_reports_structs_and_meaningful_path_requirements(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        helper = capture_from_pseudocode(HELPER_SAMPLE)
        deep_helper = capture_from_pseudocode(DEEP_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={
                "QueryConfig": helper,
                "ValidateConfig": deep_helper,
            },
            buffer_contract_case_values=[0x91234000],
        )

        report = render_ioctl_deep_analysis_report(capture, plan, 0x91234000)

        self.assertIn("PseudoForge IOCTL Deep Analysis", report)
        self.assertIn("CTL_CODE(0x9123, 0x0, METHOD_BUFFERED", report)
        self.assertIn("Input And Output Structure Hypotheses", report)
        self.assertIn("PF_IOCTL_91234000_INOUT", report)
        self.assertIn("inputBufferLength == 16", report)
        self.assertIn("outputBufferLength >= 32", report)
        self.assertIn("PF_IOCTL_91234000_INOUT.field_0x00 == 7", report)
        self.assertIn("(PF_IOCTL_91234000_INOUT.field_0x04 & 3) != 2", report)
        self.assertIn("PF_IOCTL_91234000_INOUT.field_0x08 == 0", report)
        self.assertIn("PF_IOCTL_91234000_INOUT.field_0x0C == 5", report)
        self.assertIn("QueryConfig(systemBuffer, outputBufferLength, &information)", report)
        self.assertIn("ValidateConfig(systemBuffer)", report)
        self.assertIn("not a full path satisfiability proof", report)

    def test_ioctl_struct_header_emits_request_response_aliases(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x91234000])

        header = render_buffer_struct_header(capture, plan.buffer_contracts)

        self.assertIn("using PF_IOCTL_91234000_REQUEST = PF_IOCTL_91234000_INOUT;", header)
        self.assertIn("using PF_IOCTL_91234000_RESPONSE = PF_IOCTL_91234000_INOUT;", header)

    def test_non_ioctl_value_reports_decode_boundary(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture)

        report = render_ioctl_deep_analysis_report(capture, plan, 29)

        self.assertIn("Decode: not a Windows IOCTL-shaped value", report)
        self.assertIn("No IOCTL buffer structures were inferred", report)


if __name__ == "__main__":
    unittest.main()
