from __future__ import annotations

import unittest

from ida_pseudoforge.core.buffer_contracts import render_buffer_struct_header
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ioctl_analysis import (
    render_ioctl_deep_analysis_report,
    render_selector_path_analysis_report,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import (
    BufferContract,
    CleanPlan,
    CommandBufferContract,
    FieldAccess,
    FieldConstraint,
    FunctionCapture,
)
from tests.test_buffer_contracts import (
    DEEP_HELPER_SAMPLE,
    EXP_FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE,
    HELPER_SAMPLE,
    IOCTL_CONTRACT_SAMPLE,
    NTSET_SYSTEM_CHAR_LITERAL_RAW_ARGS_SAMPLE,
)


LIKELY_REQUIREMENT_SAMPLE = r"""
NTSTATUS __fastcall DispatchLikely(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID systemBuffer;
  ULONG inputBufferLength;
  ULONG ioControlCode;

  switch ( ioControlCode )
  {
    case 0x81230000:
      if ( inputBufferLength == 32 )
      {
        if ( *(_DWORD *)systemBuffer == 7 )
        {
          status = STATUS_SUCCESS;
          break;
        }
      }
      status = STATUS_INVALID_PARAMETER;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


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

        self.assertIn("PseudoForge Selector Path Analysis", report)
        self.assertIn("Selector domain: `IOCTL`", report)
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

    def test_ntset_system_selector_report_uses_system_information_class_domain(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CHAR_LITERAL_RAW_ARGS_SAMPLE)
        helper = capture_from_pseudocode(EXP_FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={"ExpRegisterFirmwareTableInformationHandler": helper},
            buffer_contract_case_values=[75],
        )

        report = render_selector_path_analysis_report(capture, plan, 75)

        self.assertIn("Selector domain: `SYSTEM_INFORMATION_CLASS`", report)
        self.assertIn("Selector name: `SystemRegisterFirmwareTableInformationHandler`", report)
        self.assertIn("NtSetSystemInformation", report)
        self.assertIn("PF_SYSTEM_SystemRegisterFirmwareTableInformationHandler_INPUT", report)
        self.assertIn("systemInformationLength", report)
        self.assertIn("v3 >= 0x18", report)
        self.assertIn("ExpRegisterFirmwareTableInformationHandler", report)
        self.assertIn("ProviderSignature", report)
        self.assertIn("not a full path satisfiability proof", report)

    def test_unknown_selector_value_reports_selector_boundary(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture)

        report = render_ioctl_deep_analysis_report(capture, plan, 29)

        self.assertIn("Selector: `0x1D` (`29`)", report)
        self.assertIn("No selector buffer structures were inferred", report)

    def test_selector_report_includes_helper_edge_audit(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x91234008])

        report = render_ioctl_deep_analysis_report(capture, plan, 0x91234008)

        self.assertIn("Helper Edge Audit", report)
        self.assertIn("helper_capture_missing", report)
        self.assertIn("MissingHelper", report)
        self.assertIn("decompile the callee", report)
        self.assertIn("Helper Path Families", report)

    def test_selector_report_separates_likely_requirements(self) -> None:
        capture = capture_from_pseudocode(LIKELY_REQUIREMENT_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x81230000])

        report = render_ioctl_deep_analysis_report(capture, plan, 0x81230000)

        self.assertIn("Likely requirements:", report)
        self.assertIn("inputBufferLength == 32", report)
        self.assertIn("PF_IOCTL_81230000_INOUT.field_0x00 == 7", report)
        self.assertIn("Context observations:", report)

    def test_selector_report_separates_output_only_predicates_from_requirements(self) -> None:
        capture = FunctionCapture(
            name="NtQueryInformationProcess",
            prototype="NTSTATUS NTAPI NtQueryInformationProcess(HANDLE h, PROCESSINFOCLASS c, PVOID p, ULONG l, PULONG r)",
        )
        plan = CleanPlan(
            function_ea=0,
            function_name="NtQueryInformationProcess",
            input_fingerprint="fixture",
            buffer_contracts=[
                CommandBufferContract(
                    dispatcher_kind="ntquery_process",
                    dispatcher="processInformationClass",
                    command_value=0x60,
                    command_name="ProcessEnableLogging",
                    buffers=[
                        BufferContract(
                            role="output",
                            source="parameter",
                            variable="processInformation",
                            length_variable="processInformationLength",
                            structure_name="PF_PROCESS_ProcessEnableLogging_OUTPUT",
                            field_accesses=[
                                FieldAccess(
                                    buffer="processInformation",
                                    structure="",
                                    offset=0,
                                    type="ULONG",
                                    field="field_0x00",
                                    access="write",
                                    evidence="*(_DWORD *)processInformation |= flags;",
                                    source="local",
                                )
                            ],
                            field_constraints=[
                                FieldConstraint(
                                    buffer="processInformation",
                                    structure="",
                                    offset=0,
                                    field="field_0x00",
                                    relation=">",
                                    value="2",
                                    evidence="*(_DWORD *)processInformation |= flags;",
                                    source="local",
                                )
                            ],
                        )
                    ],
                )
            ],
        )

        report = render_selector_path_analysis_report(capture, plan, 0x60)

        self.assertIn("Likely requirements:\n\n- none", report)
        self.assertIn("Output-only observations:", report)
        self.assertIn("PF_PROCESS_ProcessEnableLogging_OUTPUT.field_0x00 > 2", report)
        self.assertIn("not values the caller must provide", report)

    def test_selector_report_quarantines_suspicious_disasm_field_accesses(self) -> None:
        capture = FunctionCapture(
            name="NtQueryInformationProcess",
            prototype="NTSTATUS NTAPI NtQueryInformationProcess(HANDLE h, PROCESSINFOCLASS c, PVOID p, ULONG l, PULONG r)",
        )
        plan = CleanPlan(
            function_ea=0,
            function_name="NtQueryInformationProcess",
            input_fingerprint="fixture",
            buffer_contracts=[
                CommandBufferContract(
                    dispatcher_kind="ntquery_process",
                    dispatcher="processInformationClass",
                    command_value=0x20,
                    command_name="ProcessHandleTracing",
                    buffers=[
                        BufferContract(
                            role="inout",
                            source="parameter",
                            variable="processInformation",
                            length_variable="processInformationLength",
                            structure_name="PF_PROCESS_ProcessHandleTracing_INOUT",
                            field_accesses=[
                                FieldAccess(
                                    buffer="processInformation",
                                    structure="",
                                    offset=0,
                                    type="ULONGLONG",
                                    field="field_0x00",
                                    access="read",
                                    evidence="if ( *(_QWORD *)v6 == v229 || !*(_QWORD *)v6 )",
                                    source="local",
                                ),
                                FieldAccess(
                                    buffer="processInformation",
                                    structure="",
                                    offset=0xA08,
                                    type="ULONG",
                                    field="field_0xA08",
                                    access="read",
                                    evidence="mov     rdx, [rsp+0A08h+ObjectNameInformation]",
                                    source="disasm:0x14099FE0F",
                                ),
                            ],
                        )
                    ],
                )
            ],
        )

        report = render_selector_path_analysis_report(capture, plan, 0x20)

        self.assertIn("field accesses: `1`", report)
        self.assertIn("quarantined field-like observations: `1`", report)
        self.assertIn("Quarantined layout observations:", report)
        self.assertNotIn("field_0xA08` accessed as", report)


if __name__ == "__main__":
    unittest.main()
