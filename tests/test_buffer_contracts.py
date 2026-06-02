from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.buffer_contracts import (
    find_case_value_near_line,
    helper_names_for_selected_case,
    recover_buffer_contracts,
    render_buffer_struct_header,
    render_case_context_report,
)
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture, RenameSuggestion


IOCTL_CONTRACT_SAMPLE = r"""
NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  ULONG_PTR information;
  PVOID systemBuffer;
  ULONG inputBufferLength;
  ULONG outputBufferLength;
  ULONG ioControlCode;
  _DWORD *ioStackLocation;

  ioStackLocation = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  systemBuffer = irp->AssociatedIrp.MasterIrp;
  inputBufferLength = ioStackLocation[2];
  outputBufferLength = ioStackLocation[4];
  ioControlCode = ioStackLocation[6];
  information = 0;
  switch ( ioControlCode )
  {
    case 0x91234000:
      if ( inputBufferLength != 16 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_DWORD *)systemBuffer != 7 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      if ( (*((_DWORD *)systemBuffer + 1) & 3) == 2 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = QueryConfig(systemBuffer, outputBufferLength, &information);
      break;
    case 0x91234004:
      if ( outputBufferLength < 24 )
      {
        status = STATUS_BUFFER_TOO_SMALL;
        break;
      }
      *(_QWORD *)(systemBuffer + 8) = 0LL;
      information = 8;
      status = 0;
      break;
    case 0x91234008:
      status = MissingHelper(systemBuffer, inputBufferLength);
      break;
    case 0x9123400C:
      status = STATUS_NOT_SUPPORTED;
      break;
    case 0x91234010:
      status = QueryConfig(systemBuffer, outputBufferLength, &information);
      if ( status < 0 )
      {
        break;
      }
      status = QueryConfig(systemBuffer, outputBufferLength, &information);
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
}
"""


HELPER_SAMPLE = r"""
NTSTATUS __fastcall QueryConfig(PVOID input, ULONG outputLength, ULONG_PTR *information)
{
  if ( outputLength < 32 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  if ( *((_DWORD *)input + 2) != 0 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  if ( ValidateConfig(input) )
  {
    return STATUS_INVALID_PARAMETER;
  }
  *information = 24;
  return 0;
}
"""


DEEP_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateConfig(PVOID input)
{
  if ( *((_DWORD *)input + 3) != 5 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return 0;
}
"""


NTSET_PROCESS_CONTRACT_SAMPLE = r"""
NTSTATUS NTAPI NtSetInformationProcess(
        HANDLE processHandle,
        PROCESSINFOCLASS processInformationClass,
        PVOID processInformation,
        ULONG processInformationLength)
{
  NTSTATUS status;

  switch ( processInformationClass )
  {
    case 29:
      if ( processInformationLength != 4 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_DWORD *)processInformation > 1 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = 0;
      break;
    case 31:
      if ( processInformationLength < 4 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      status = 0;
      break;
    case 61:
      if ( processInformationLength != 1 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      status = 0;
      break;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      break;
  }
  return status;
}
"""


NESTED_SWITCH_SAMPLE = r"""
NTSTATUS __fastcall DispatchNested(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID systemBuffer;
  ULONG inputBufferLength;
  ULONG ioControlCode;
  _DWORD *ioStackLocation;
  int mode;

  ioStackLocation = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  systemBuffer = irp->AssociatedIrp.MasterIrp;
  inputBufferLength = ioStackLocation[2];
  ioControlCode = ioStackLocation[6];
  switch ( ioControlCode )
  {
    case 0x91235000:
      switch ( mode )
      {
        case 1:
          status = STATUS_PENDING;
          break;
        default:
          status = STATUS_NOT_SUPPORTED;
          break;
      }
      if ( inputBufferLength != 8 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_DWORD *)systemBuffer != 5 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = 0;
      break;
    case 0x91235004:
      status = 0;
      break;
    case 0x91235008:
      status = 0;
      break;
    case 0x9123500C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


CONTEXT_FIELD_CASE_SAMPLE = r"""
__int64 __fastcall DispatchContextCase(unsigned int command, __int64 context)
{
  int status;

  switch ( command )
  {
    case 0x83376010:
      status = 0;
      goto LABEL_23;
    case 0x83376014:
      if ( !*(_QWORD *)(context + 576) )
      {
        status = -1073741661;
        goto LABEL_40;
      }
      if ( _InterlockedCompareExchange((volatile signed __int32 *)(context + 800), 1, 0) )
      {
        status = -2147483631;
        goto LABEL_40;
      }
      KeClearEvent((PRKEVENT)(context + 584));
      IoQueueWorkItem(*(PIO_WORKITEM *)(context + 576), WorkerRoutine, DelayedWorkQueue, (PVOID)context);
      goto LABEL_23;
    case 0x83376018:
      status = -1073741811;
      goto LABEL_40;
    case 0x8337601C:
      status = 0;
      goto LABEL_23;
    default:
      status = -1073741811;
      goto LABEL_40;
  }
LABEL_23:
  return 0;
LABEL_40:
  return status;
}
"""


HELPER_ONLY_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchHelperOnly(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID payload;
  ULONG inputLength;
  ULONG outputLength;
  ULONG controlCode;
  ULONG_PTR information;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  payload = irp->AssociatedIrp.MasterIrp;
  inputLength = stack[2];
  outputLength = stack[4];
  controlCode = stack[6];
  information = 0;
  switch ( controlCode )
  {
    case 0x91236000:
      status = HandlePayload(payload, inputLength, outputLength, &information);
      break;
    case 0x91236004:
      status = 0;
      break;
    case 0x91236008:
      status = 0;
      break;
    case 0x9123600C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
}
"""


CASTED_OPAQUE_BUFFER_HELPER_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchCastedOpaqueBuffer(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID deviceExtension;
  PVOID opaquePayload;
  ULONG inputBytes;
  ULONG outputBytes;
  ULONG ioControlCode;
  ULONG_PTR information;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  deviceExtension = deviceObject->DeviceExtension;
  opaquePayload = irp->AssociatedIrp.MasterIrp;
  inputBytes = stack[2];
  outputBytes = stack[4];
  ioControlCode = stack[6];
  information = 0;
  switch ( ioControlCode )
  {
    case 0x91239000:
      status = ValidateOpaqueTransfer(deviceExtension, (_DWORD)opaquePayload, inputBytes, outputBytes, (__int64)&information);
      break;
    case 0x91239004:
      status = 0;
      break;
    case 0x91239008:
      status = 0;
      break;
    case 0x9123900C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
}
"""


CASTED_OPAQUE_BUFFER_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateOpaqueTransfer(__int64 extension, PVOID buffer, ULONG inputLength, ULONG outputLength, ULONG_PTR *information)
{
  if ( inputLength < 16 )
  {
    return 3221225476LL;
  }
  if ( outputLength < 24 )
  {
    return 3221225507LL;
  }
  if ( *(_DWORD *)buffer != 16 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  *information = 24;
  return STATUS_SUCCESS;
}
"""


CASTED_OPAQUE_SIZE_ONLY_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateOpaqueTransfer(__int64 extension, PVOID buffer, ULONG inputLength, ULONG outputLength, ULONG_PTR *information)
{
  if ( inputLength < 16 )
  {
    return 3221225476LL;
  }
  if ( outputLength < 20 )
  {
    return 3221225507LL;
  }
  *information = 20;
  return STATUS_SUCCESS;
}
"""


SHORT_LENGTH_NAME_HELPER_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchShortLengthNames(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID payload;
  ULONG inSize;
  ULONG outSize;
  ULONG ioControlCode;
  ULONG_PTR information;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  payload = irp->AssociatedIrp.MasterIrp;
  inSize = stack[2];
  outSize = stack[4];
  ioControlCode = stack[6];
  information = 0;
  switch ( ioControlCode )
  {
    case 0x9123A000:
      status = ValidateShortTransfer(payload, inSize, outSize, &information);
      break;
    case 0x9123A004:
      status = 0;
      break;
    case 0x9123A008:
      status = 0;
      break;
    case 0x9123A00C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
}
"""


SHORT_LENGTH_NAME_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateShortTransfer(PVOID buffer, ULONG inSize, ULONG outSize, ULONG_PTR *information)
{
  if ( inSize < 8 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  if ( outSize < 12 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  *information = 12;
  return STATUS_SUCCESS;
}
"""


class BufferContractTests(unittest.TestCase):
    def test_ioctl_contract_recovers_sizes_fields_and_helper_edges(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        helper_capture = capture_from_pseudocode(HELPER_SAMPLE)
        deep_helper_capture = capture_from_pseudocode(DEEP_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={
                "QueryConfig": helper_capture,
                "ValidateConfig": deep_helper_capture,
            },
        )

        self.assertTrue(plan.flow_rewrites)
        contracts = {contract.command_value: contract for contract in plan.buffer_contracts}
        self.assertIn(0x91234000, contracts)
        self.assertIn(0x91234008, contracts)

        query_contract = contracts[0x91234000]
        self.assertEqual("ioctl", query_contract.dispatcher_kind)
        self.assertIn("CTL_CODE", query_contract.command_name)
        buffer = query_contract.buffers[0]
        self.assertEqual("systemBuffer", buffer.variable)
        self.assertEqual("PF_IOCTL_91234000_INOUT", buffer.structure_name)
        self.assertTrue(
            any(item.length == "inputBufferLength" and item.relation == "!=" and item.value == "16" for item in buffer.size_constraints)
        )
        self.assertTrue(
            any(item.length == "inputBufferLength" and item.valid_relation == "==" and item.valid_value == "16" for item in buffer.size_constraints)
        )
        self.assertTrue(
            any(
                item.field == "field_0x00"
                and item.relation == "!="
                and item.value == "7"
                and item.valid_relation == "=="
                and item.valid_value == "7"
                for item in buffer.field_constraints
            )
        )
        self.assertTrue(
            any(
                item.field == "field_0x04"
                and item.mask == "3"
                and item.valid_relation == "mask_!="
                and item.valid_value == "2"
                for item in buffer.field_constraints
            )
        )

        self.assertEqual(1, len(query_contract.helper_edges))
        helper_edge = query_contract.helper_edges[0]
        self.assertTrue(helper_edge.resolved)
        self.assertEqual("QueryConfig", helper_edge.callee)
        self.assertIn("systemBuffer", helper_edge.passed_buffers)
        self.assertTrue(
            any(item.length == "outputBufferLength" and item.relation == "<" and item.value == "32" for item in helper_edge.propagated_size_constraints)
        )
        self.assertTrue(
            any(
                item.length == "outputBufferLength"
                and item.valid_relation == ">="
                and item.valid_value == "32"
                for item in helper_edge.propagated_size_constraints
            )
        )
        self.assertTrue(
            any(
                item.field == "field_0x08"
                and item.value == "0"
                and item.valid_relation == "=="
                and item.valid_value == "0"
                for item in helper_edge.propagated_field_constraints
            )
        )
        self.assertEqual(1, len(helper_edge.nested_edges))
        nested_edge = helper_edge.nested_edges[0]
        self.assertEqual("ValidateConfig", nested_edge.callee)
        self.assertTrue(any(item.field == "field_0x0C" and item.value == "5" for item in nested_edge.propagated_field_constraints))

        missing_edge = contracts[0x91234008].helper_edges[0]
        self.assertFalse(missing_edge.resolved)
        self.assertEqual("MissingHelper", missing_edge.callee)
        self.assertIn("helper not available", " ".join(missing_edge.warnings))

    def test_helper_only_case_still_emits_buffer_struct_fields(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        helper_capture = capture_from_pseudocode(HELPER_SAMPLE)
        deep_helper_capture = capture_from_pseudocode(DEEP_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={
                "QueryConfig": helper_capture,
                "ValidateConfig": deep_helper_capture,
            },
            buffer_contract_case_values=[0x91234010],
        )

        self.assertEqual([0x91234010], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual(1, len(contract.helper_edges))
        self.assertEqual("systemBuffer", contract.buffers[0].variable)
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("struct PF_IOCTL_91234010_INOUT", header)
        self.assertIn("std::uint32_t field_0x08;", header)
        self.assertIn("std::uint32_t field_0x0C;", header)
        self.assertIn("field_0x08 != 0", header)
        self.assertIn("valid field_0x08 == 0", header)
        self.assertIn("field_0x0C != 5", header)
        self.assertIn("valid field_0x0C == 5", header)

    def test_ntset_process_contract_uses_process_information_names(self) -> None:
        capture = capture_from_pseudocode(NTSET_PROCESS_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture)

        contracts = {contract.command_value: contract for contract in plan.buffer_contracts}
        self.assertIn(29, contracts)
        contract = contracts[29]
        self.assertEqual("ntset_process", contract.dispatcher_kind)
        self.assertEqual("ProcessBreakOnTermination", contract.command_name)
        buffer = contract.buffers[0]
        self.assertEqual("processInformation", buffer.variable)
        self.assertEqual("PF_PROCESS_ProcessBreakOnTermination_INPUT", buffer.structure_name)
        self.assertTrue(any(item.length == "processInformationLength" and item.value == "4" for item in buffer.size_constraints))
        self.assertTrue(any(item.field == "field_0x00" and item.relation == ">" and item.value == "1" for item in buffer.field_constraints))

    def test_selected_case_filter_limits_buffer_contracts(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(
            capture,
            buffer_contract_case_values=[0x91234004],
        )

        self.assertEqual([0x91234004], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertTrue(any(buffer.structure_name == "PF_IOCTL_91234004_INOUT" for buffer in contract.buffers))

    def test_cursor_line_case_lookup_uses_enclosing_case(self) -> None:
        lines = IOCTL_CONTRACT_SAMPLE.splitlines()
        body_line = next(index for index, line in enumerate(lines) if "outputBufferLength < 24" in line)
        default_line = next(index for index, line in enumerate(lines) if "STATUS_INVALID_DEVICE_REQUEST" in line)

        self.assertEqual(0x91234004, find_case_value_near_line(IOCTL_CONTRACT_SAMPLE, line_index=body_line))
        self.assertEqual(0x91234008, find_case_value_near_line("", line_text="    case 0x91234008:"))
        self.assertIsNone(find_case_value_near_line(IOCTL_CONTRACT_SAMPLE, line_index=default_line))

    def test_nested_switch_does_not_steal_parent_case_tail(self) -> None:
        capture = capture_from_pseudocode(NESTED_SWITCH_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x91235000])

        self.assertEqual([0x91235000], [contract.command_value for contract in plan.buffer_contracts])
        self.assertEqual(["systemBuffer"], [buffer.variable for buffer in plan.buffer_contracts[0].buffers])
        buffer = plan.buffer_contracts[0].buffers[0]
        self.assertTrue(any(item.length == "inputBufferLength" and item.value == "8" for item in buffer.size_constraints))
        self.assertTrue(any(item.field == "field_0x00" and item.value == "5" for item in buffer.field_constraints))

    def test_context_field_case_report_explains_non_buffer_case(self) -> None:
        capture = capture_from_pseudocode(CONTEXT_FIELD_CASE_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x83376014])

        self.assertEqual([], plan.buffer_contracts)
        report = render_case_context_report(capture, plan, 0x83376014)

        self.assertIn("Selected Case Context", report)
        self.assertIn("Body state: `shared_tail`", report)
        self.assertIn("`LABEL_40`", report)
        self.assertIn("`LABEL_23`", report)
        self.assertIn("`context + 0x240`", report)
        self.assertIn("`context + 0x248`", report)
        self.assertIn("`context + 0x320`", report)
        self.assertIn("valid predicate: `*(_QWORD *)(context + 576) != 0`", report)
        self.assertIn("guard expression evaluates to 0:", report)
        self.assertIn("reported separately from command input/output buffers", report)

    def test_selected_case_helper_names_do_not_depend_on_existing_contracts(self) -> None:
        capture = capture_from_pseudocode(HELPER_ONLY_CASE_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x91236000])
        plan.buffer_contracts = []

        self.assertEqual(["HandlePayload"], helper_names_for_selected_case(capture, plan, 0x91236000))

    def test_selected_case_helper_names_handle_renamed_dispatcher_body(self) -> None:
        pseudocode = r"""
NTSTATUS __fastcall DispatchRenamedBody(PIRP irp)
{
  NTSTATUS status;
  PVOID v4;
  ULONG v5;
  ULONG v6;
  ULONG v9;
  ULONG_PTR v7;
  _DWORD *v10;

  v10 = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  v4 = irp->AssociatedIrp.MasterIrp;
  v5 = v10[2];
  v6 = v10[4];
  v9 = v10[6];
  v7 = 0;
  switch ( v9 )
  {
    case 0x91237000:
      status = sub_140001500(v4, v5, v6, &v7);
      break;
    case 0x91237004:
      status = 0;
      break;
    case 0x91237008:
      status = 0;
      break;
    case 0x9123700C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""
        capture = FunctionCapture(
            ea=0x140001000,
            name="DispatchRenamedBody",
            prototype="NTSTATUS __fastcall DispatchRenamedBody(PIRP irp)",
            pseudocode=pseudocode,
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion("local", "v4", "systemBuffer", 0.9, "test", ""),
                RenameSuggestion("local", "v5", "inputBufferLength", 0.9, "test", ""),
                RenameSuggestion("local", "v6", "outputBufferLength", 0.9, "test", ""),
                RenameSuggestion("local", "v9", "ioControlCode", 0.9, "test", ""),
            ],
            flow_rewrites=[
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="ioControlCode",
                    recovered_cases=[0x91237000, 0x91237004, 0x91237008, 0x9123700C],
                )
            ],
        )

        self.assertEqual(["sub_140001500"], helper_names_for_selected_case(capture, plan, 0x91237000))

    def test_selected_case_helper_names_fall_back_to_case_anchor(self) -> None:
        pseudocode = r"""
NTSTATUS __fastcall DispatchAnchorFallback(IRP *irp)
{
  NTSTATUS status;
  void *v4;
  unsigned int v9;
  _DWORD *v10;

  v10 = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  v4 = *(_QWORD *)(irp + 24);
  v9 = v10[6];
  switch ( v9 )
  {
    case 0x91238000:
      status = sub_140001600(v4);
      break;
    case 0x91238004:
      status = 0;
      break;
    case 0x91238008:
      status = 0;
      break;
    case 0x9123800C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""
        capture = FunctionCapture(
            ea=0x140001000,
            name="DispatchAnchorFallback",
            prototype="NTSTATUS __fastcall DispatchAnchorFallback(IRP *irp)",
            pseudocode=pseudocode,
        )
        anchor_line = next(
            index + 1
            for index, line in enumerate(pseudocode.splitlines())
            if "case 0x91238000" in line
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            flow_rewrites=[
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="ioControlCode",
                    recovered_cases=[0x91238000, 0x91238004, 0x91238008, 0x9123800C],
                    case_anchors={0x91238000: anchor_line},
                )
            ],
        )

        self.assertEqual(["sub_140001600"], helper_names_for_selected_case(capture, plan, 0x91238000))

    def test_casted_opaque_argument_before_lengths_is_helper_buffer_candidate(self) -> None:
        capture = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_CASE_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[0x91239000])

        self.assertEqual(["ValidateOpaqueTransfer"], helper_names_for_selected_case(capture, plan, 0x91239000))

    def test_casted_opaque_helper_edge_propagates_contract(self) -> None:
        capture = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_CASE_SAMPLE)
        helper = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={"ValidateOpaqueTransfer": helper},
            buffer_contract_case_values=[0x91239000],
        )

        self.assertEqual([0x91239000], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("opaquePayload", contract.buffers[0].variable)
        self.assertEqual("inout", contract.buffers[0].role)
        self.assertEqual("inputBufferLength, outputBufferLength", contract.buffers[0].length_variable)
        self.assertEqual("PF_IOCTL_91239000_INOUT", contract.buffers[0].structure_name)
        self.assertEqual("AssociatedIrp.SystemBuffer", contract.buffers[0].source)
        self.assertEqual(1, len(contract.helper_edges))
        edge = contract.helper_edges[0]
        self.assertTrue(edge.resolved)
        self.assertNotIn("deviceExtension", edge.passed_buffers)
        self.assertIn("opaquePayload", edge.passed_buffers)
        self.assertTrue(any(item.length == "outputBufferLength" and item.value == "16" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.length == "inputBufferLength" and item.value == "24" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.length == "outputBufferLength" and item.valid_relation == ">=" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.length == "inputBufferLength" and item.valid_relation == ">=" for item in edge.propagated_size_constraints))

    def test_size_only_helper_struct_emits_directional_byte_windows(self) -> None:
        capture = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_CASE_SAMPLE)
        helper = capture_from_pseudocode(CASTED_OPAQUE_SIZE_ONLY_HELPER_SAMPLE)
        contracts = recover_buffer_contracts(
            capture,
            [
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="ioControlCode",
                    recovered_cases=[0x91239000],
                )
            ],
            helper_captures={"ValidateOpaqueTransfer": helper},
            case_values=[0x91239000],
        )

        header = render_buffer_struct_header(capture, contracts)

        self.assertIn("static constexpr std::size_t PF_IOCTL_91239000_INOUT_MIN_INPUT_SIZE = 0x10;", header)
        self.assertIn("static constexpr std::size_t PF_IOCTL_91239000_INOUT_MIN_OUTPUT_SIZE = 0x14;", header)
        self.assertIn("std::uint8_t inout_bytes_0x00[0x10];", header)
        self.assertIn("std::uint8_t output_extension_0x10[0x4];", header)
        self.assertIn(
            "inline bool IsValidPF_IOCTL_91239000_INOUTSize(std::size_t inputBytes, std::size_t outputBytes)",
            header,
        )
        self.assertIn("return inputBytes >= PF_IOCTL_91239000_INOUT_MIN_INPUT_SIZE", header)
        self.assertIn("&& outputBytes >= PF_IOCTL_91239000_INOUT_MIN_OUTPUT_SIZE;", header)
        self.assertNotIn("std::uint8_t reserved_0x00[20];", header)

    def test_short_output_length_name_keeps_output_role(self) -> None:
        capture = capture_from_pseudocode(SHORT_LENGTH_NAME_HELPER_CASE_SAMPLE)
        helper = capture_from_pseudocode(SHORT_LENGTH_NAME_HELPER_SAMPLE)
        contracts = recover_buffer_contracts(
            capture,
            [
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="ioControlCode",
                    recovered_cases=[0x9123A000],
                )
            ],
            helper_captures={"ValidateShortTransfer": helper},
            case_values=[0x9123A000],
        )

        self.assertEqual([0x9123A000], [contract.command_value for contract in contracts])
        buffer = contracts[0].buffers[0]
        self.assertEqual("inout", buffer.role)
        edge = contracts[0].helper_edges[0]
        self.assertTrue(any(item.length == "inSize" and item.role == "input" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.length == "outSize" and item.role == "output" for item in edge.propagated_size_constraints))
        header = render_buffer_struct_header(capture, contracts)
        self.assertIn("PF_IOCTL_9123A000_INOUT_MIN_INPUT_SIZE = 0x8;", header)
        self.assertIn("PF_IOCTL_9123A000_INOUT_MIN_OUTPUT_SIZE = 0xC;", header)
        self.assertIn("std::uint8_t output_extension_0x08[0x4];", header)

    def test_buffer_contract_recovery_does_not_require_canonical_length_names(self) -> None:
        capture = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_CASE_SAMPLE)
        helper = capture_from_pseudocode(CASTED_OPAQUE_BUFFER_HELPER_SAMPLE)
        contracts = recover_buffer_contracts(
            capture,
            [
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="ioControlCode",
                    recovered_cases=[0x91239000],
                )
            ],
            helper_captures={"ValidateOpaqueTransfer": helper},
            case_values=[0x91239000],
        )

        self.assertEqual([0x91239000], [contract.command_value for contract in contracts])
        buffer = contracts[0].buffers[0]
        self.assertEqual("inout", buffer.role)
        self.assertEqual("inputBytes, outputBytes", buffer.length_variable)
        edge = contracts[0].helper_edges[0]
        self.assertTrue(any(item.length == "inputBytes" and item.value == "16" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.length == "outputBytes" and item.value == "24" for item in edge.propagated_size_constraints))

    def test_export_bundle_writes_buffer_contract_artifacts(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture)

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            self.assertIn("buffer_contract_report", artifacts)
            self.assertIn("buffer_contracts", artifacts)
            self.assertIn("buffer_structs", artifacts)
            report = Path(artifacts["buffer_contract_report"]).read_text(encoding="utf-8")
            payload = json.loads(Path(artifacts["buffer_contracts"]).read_text(encoding="utf-8"))
            header = Path(artifacts["buffer_structs"]).read_text(encoding="utf-8")
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))

            self.assertIn("Buffer Contract Report", report)
            self.assertTrue(payload)
            self.assertIn("struct PF_IOCTL_91234000_INOUT", header)
            self.assertIn("std::uint32_t field_0x00;", header)
            self.assertIn("static_assert(offsetof(PF_IOCTL_91234000_INOUT, field_0x04) == 0x4", header)
            self.assertIn("field_0x00 != 7", header)
            self.assertEqual(len(plan.buffer_contracts), summary["buffer_contracts"])
            self.assertEqual(artifacts["buffer_contracts"], summary["artifacts"]["buffer_contracts"])
            self.assertEqual(artifacts["buffer_structs"], summary["artifacts"]["buffer_structs"])


if __name__ == "__main__":
    unittest.main()
