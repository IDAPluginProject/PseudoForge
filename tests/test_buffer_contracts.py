from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.buffer_contracts import (
    _infer_buffer_sources,
    _iter_helper_call_sites,
    _recover_helper_edges,
    find_case_value_near_line,
    helper_names_for_selected_case,
    recover_buffer_contracts,
    render_buffer_struct_header,
    render_case_context_report,
)
from ida_pseudoforge.core.disasm_contracts import DisasmCaseSlice, DisasmInstruction
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.helper_edge_audit import (
    classify_helper_edge,
    helper_edge_audit_records,
    unresolved_helper_edge_records,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import (
    CleanPlan,
    FlowRewrite,
    FunctionCapture,
    HelperContractEdge,
    RenameSuggestion,
)


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
    case ProcessSlistRollbackInformation:
      if ( processInformationLength )
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


NTSET_PROCESS_SHARED_TAIL_LENGTH_SAMPLE = r"""
NTSTATUS NTAPI NtSetInformationProcess(
        HANDLE processHandle,
        PROCESSINFOCLASS processInformationClass,
        PVOID processInformation,
        ULONG processInformationLength)
{
  NTSTATUS status;
  unsigned __int64 expectedLength;
  int selectedClass;

  expectedLength = 0LL;
  selectedClass = 0;
  switch ( processInformationClass )
  {
    case 8:
      expectedLength = 8LL;
      selectedClass = 8;
      break;
    case 29:
      if ( processInformationLength != 4 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto LABEL_DONE;
      }
      if ( *(_DWORD *)processInformation > 1 )
      {
        status = STATUS_INVALID_PARAMETER;
        goto LABEL_DONE;
      }
      status = 0;
      goto LABEL_DONE;
    case 31:
      expectedLength = 4LL;
      selectedClass = 31;
      break;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      goto LABEL_DONE;
  }
  if ( processInformationLength != expectedLength )
  {
    status = STATUS_INFO_LENGTH_MISMATCH;
    goto LABEL_DONE;
  }
  if ( selectedClass == 8 )
  {
    status = 0;
    goto LABEL_DONE;
  }
  status = STATUS_INVALID_INFO_CLASS;
LABEL_DONE:
  return status;
}
"""


NTSET_PROCESS_MULTI_SWITCH_SAMPLE = r"""
NTSTATUS NTAPI NtSetInformationProcess(
        HANDLE processHandle,
        PROCESSINFOCLASS processInformationClass,
        PVOID processInformation,
        ULONG processInformationLength)
{
  NTSTATUS status;
  unsigned __int64 expectedLength;

  expectedLength = 0LL;
  switch ( processInformationClass )
  {
    case ProcessExceptionPort:
      expectedLength = 16LL;
      break;
    case ProcessBreakOnTermination:
      expectedLength = 4LL;
      break;
    case ProcessPriorityClass:
      expectedLength = 4LL;
      break;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      goto LABEL_DONE;
  }
  switch ( processInformationClass )
  {
    case ProcessExceptionPort:
      if ( processInformationLength != expectedLength )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto LABEL_DONE;
      }
      if ( !*(void **)processInformation )
      {
        status = STATUS_INVALID_PARAMETER;
        goto LABEL_DONE;
      }
      if ( *((_DWORD *)processInformation + 2) > 3 )
      {
        status = STATUS_INVALID_PARAMETER;
        goto LABEL_DONE;
      }
      status = 0;
      goto LABEL_DONE;
    case ProcessBreakOnTermination:
      if ( processInformationLength != 4 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto LABEL_DONE;
      }
      status = 0;
      goto LABEL_DONE;
    case ProcessPriorityClass:
      status = 0;
      goto LABEL_DONE;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      goto LABEL_DONE;
  }
LABEL_DONE:
  return status;
}
"""


NTSET_THREAD_ENUM_LABEL_SAMPLE = r"""
NTSTATUS NTAPI NtSetInformationThread(
        HANDLE threadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength)
{
  NTSTATUS status;
  unsigned int v4;

  v4 = ThreadInformationLength;
  switch ( ThreadInformationClass )
  {
    case ThreadBasePriority:
      if ( ThreadInformationLength != 4 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_DWORD *)ThreadInformation < -2 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = 0;
      break;
    case ThreadAffinityMask:
      if ( v4 != 8 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( !*(_QWORD *)ThreadInformation )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = 0;
      break;
    case ThreadEnableAlignmentFaultFixup:
    case ThreadCounterProfiling:
      if ( ThreadInformationLength != 1 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_BYTE *)ThreadInformation > 1u )
      {
        status = STATUS_INVALID_PARAMETER;
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


NTSET_SYSTEM_POINTER_DISPATCHER_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        char *systemInformationClass,
        __m128i *systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  __m128i *infoBuffer128;
  char *infoClass;

  infoBuffer128 = systemInformation;
  infoClass = systemInformationClass;
  switch ( systemInformationClass )
  {
    case SystemVmGenerationCountInformation:
      if ( systemInformationLength != 8 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      status = 0;
      break;
    case SystemCpuSetTagInformation:
      if ( systemInformationLength < 16 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      if ( *(_DWORD *)infoBuffer128 != 0 )
      {
        status = STATUS_INVALID_PARAMETER;
        break;
      }
      status = 0;
      break;
    case SystemLeapSecondInformation:
      if ( systemInformationLength != 8 )
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


NTSET_SYSTEM_DISPATCHER_CONDITION_TAIL_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        __m128i *systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  SYSTEM_INFORMATION_CLASS infoClass;
  __m128i *systemInformation128;
  int cacheFlags;

  infoClass = systemInformationClass;
  systemInformation128 = systemInformation;
  if ( infoClass == 81 )
  {
LABEL_175:
    if ( (unsigned int)systemInformationLength < 0x40 )
    {
      return STATUS_INFO_LENGTH_MISMATCH;
    }
    if ( infoClass == 21 )
    {
      cacheFlags = 0;
    }
    else
    {
      cacheFlags = systemInformation128[3].m128i_i32[3];
      if ( (cacheFlags & 0xFFFFFFF0) != 0 )
      {
        return STATUS_INVALID_PARAMETER_2;
      }
    }
    return MmAdjustWorkingSetSizeEx(
        systemInformation128[1].m128i_i64[1],
        systemInformation128[2].m128i_i64[0],
        cacheFlags);
  }
  if ( infoClass == 21 )
  {
    goto LABEL_175;
  }
  if ( infoClass == 24 )
  {
    if ( systemInformationLength != 20 )
    {
      return STATUS_INFO_LENGTH_MISMATCH;
    }
    return STATUS_SUCCESS;
  }
  return STATUS_INVALID_INFO_CLASS;
}
"""


NTSET_SYSTEM_CONTEXT_FALLBACK_POLLUTION_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        __m128i *systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  SYSTEM_INFORMATION_CLASS infoClass;
  __m128i *systemInformation128;

  infoClass = systemInformationClass;
  systemInformation128 = systemInformation;
  switch ( infoClass )
  {
    case 24:
      if ( systemInformationLength != 20 )
      {
        return STATUS_INFO_LENGTH_MISMATCH;
      }
      if ( systemInformation128[1].m128i_i32[0] != 0 )
      {
        return STATUS_INVALID_PARAMETER;
      }
      return STATUS_SUCCESS;
    case 21:
      status = STATUS_SUCCESS;
      break;
    case 161:
      if ( systemInformationLength != 8 )
      {
        return STATUS_INFO_LENGTH_MISMATCH;
      }
      return STATUS_SUCCESS;
    default:
      return STATUS_INVALID_INFO_CLASS;
  }
  if ( infoClass == 21 )
  {
    if ( systemInformationLength < 0x40 )
    {
      return STATUS_INFO_LENGTH_MISMATCH;
    }
    return MmAdjustWorkingSetSizeEx(
        systemInformation128[1].m128i_i64[1],
        systemInformation128[2].m128i_i64[0],
        0);
  }
  return status;
}
"""


NTSET_SYSTEM_CASTED_HANDLER_ESCAPE_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  SYSTEM_INFORMATION_CLASS infoClass;
  unsigned int inputLength;
  KPROCESSOR_MODE previousMode;

  infoClass = systemInformationClass;
  inputLength = systemInformationLength;
  switch ( infoClass )
  {
    case SystemRegisterFirmwareTableInformationHandler:
      LOBYTE(systemInformationLength) = previousMode;
      return (unsigned int)((__int64 (__fastcall *)(__int64, _QWORD, __int64, __int64))FirmwareTableRegistrationHandler)(
        systemInformation,
        (unsigned int)inputLength,
        systemInformationLength,
        1LL);
    case SystemFirmwareTableInformation:
      status = STATUS_SUCCESS;
      break;
    case SystemModuleInformationEx:
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      break;
  }
  return status;
}
"""


NTSET_SYSTEM_CHAR_LITERAL_RAW_ARGS_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(int a1, __int64 a2, __int64 a3)
{
  unsigned int v3;
  char PreviousMode;

  v3 = a3;
  switch ( a1 )
  {
    case 'K':
      LOBYTE(a3) = PreviousMode;
      return (unsigned int)ExpRegisterFirmwareTableInformationHandler(a2, (unsigned int)v3, a3, 1LL);
    case 0x4C:
      return 0LL;
    default:
      return 0xC0000003LL;
  }
}
"""


NTSET_SYSTEM_ALIAS_HELPER_ESCAPE_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  SYSTEM_INFORMATION_CLASS infoClass;
  PVOID infoBuffer;
  unsigned int inputLength;

  infoClass = systemInformationClass;
  infoBuffer = systemInformation;
  inputLength = systemInformationLength;
  switch ( infoClass )
  {
    case SystemVerifierAddDriverInformation:
      status = RegisterNameOnlyBuffer((PCUNICODE_STRING)infoBuffer);
      break;
    case SystemBootMetadataInformation:
      status = RegisterLengthBearingBuffer(infoBuffer, (unsigned int)inputLength);
      break;
    case SystemFirmwareTableInformation:
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_INVALID_INFO_CLASS;
      break;
  }
  return status;
}
"""


NTSET_SYSTEM_GOTO_LABEL_TAIL_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        __m128i *systemInformation,
        __int64 systemInformationLength)
{
  NTSTATUS status;
  SYSTEM_INFORMATION_CLASS infoClass;
  int loadFlags;
  int extendedLayout;
  __int64 imageBase;
  char imageName[56];

  infoClass = systemInformationClass;
  imageBase = 0;
  switch ( infoClass )
  {
    case SystemLoadGdiDriverInSystemSpace:
      LODWORD(loadFlags) = 0;
      goto LABEL_LOAD_IMAGE;
    case SystemPrefetcherInformation:
      return PrefetchInformation(systemInformation, (unsigned int)systemInformationLength);
    case SystemFirmwareTableInformation:
      return STATUS_NOT_SUPPORTED;
    default:
      return STATUS_INVALID_INFO_CLASS;
  }
LABEL_LOAD_IMAGE:
  if ( (_DWORD)systemInformationLength == 48 )
  {
    extendedLayout = 0;
  }
  else
  {
    if ( (_DWORD)systemInformationLength != 56 )
      return STATUS_INFO_LENGTH_MISMATCH;
    extendedLayout = 1;
  }
  *(__m128i *)imageName = *systemInformation;
  if ( extendedLayout )
  {
    systemInformation[1].m128i_i64[0] = imageBase;
    return LoadSystemImageEx((unsigned int)imageName, loadFlags);
  }
  systemInformation[1].m128i_i64[0] = imageBase;
  return LoadSystemImage((unsigned int)imageName, loadFlags);
}
"""


GOTO_HELPER_TAIL_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchGotoHelperTail(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  SYSTEM_INFORMATION_CLASS infoClass;
  NTSTATUS status;
  PVOID payload;
  ULONG inputLength;
  ULONG ioControlCode;
  ULONG_PTR information;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  payload = irp->AssociatedIrp.MasterIrp;
  inputLength = stack[2];
  ioControlCode = stack[6];
  information = 0;
  switch ( ioControlCode )
  {
    case 0x9123C000:
      goto LABEL_HELPER_TAIL;
    case 0x9123C004:
      if ( inputLength != 8 )
      {
        return STATUS_INFO_LENGTH_MISMATCH;
      }
      status = STATUS_SUCCESS;
      break;
    case 0x9123C008:
      status = STATUS_SUCCESS;
      break;
    case 0x9123C00C:
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
LABEL_HELPER_TAIL:
  return ValidateTailSystemBuffer(payload, inputLength);
}
"""


TAIL_SYSTEM_BUFFER_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateTailSystemBuffer(PVOID input, ULONG inputLength)
{
  if ( inputLength < 16 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  if ( *(_DWORD *)input != 7 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return STATUS_SUCCESS;
}
"""


FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE = r"""
NTSTATUS __fastcall FirmwareTableRegistrationHandler(
        SYSTEM_FIRMWARE_TABLE_HANDLER *pTableHandler,
        unsigned int tableHandlerSize,
        KPROCESSOR_MODE previousMode)
{
  ULONG providerSignature;
  PFNFTH firmwareTableHandler;
  PVOID driverObject;

  if ( previousMode )
  {
    return STATUS_PRIVILEGE_NOT_HELD;
  }
  if ( !pTableHandler || tableHandlerSize < 0x18 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  providerSignature = pTableHandler->ProviderSignature;
  if ( pTableHandler->Register )
  {
    firmwareTableHandler = pTableHandler->FirmwareTableHandler;
    driverObject = pTableHandler->DriverObject;
    return RegisterProvider(providerSignature, firmwareTableHandler, driverObject);
  }
  return UnregisterProvider(providerSignature, pTableHandler->DriverObject);
}
"""


EXP_FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ExpRegisterFirmwareTableInformationHandler(
        SYSTEM_FIRMWARE_TABLE_HANDLER *pTableHandler,
        unsigned int tableHandlerSize,
        KPROCESSOR_MODE previousMode)
{
  ULONG providerSignature;
  PFNFTH firmwareTableHandler;
  PVOID driverObject;

  if ( previousMode )
  {
    return STATUS_PRIVILEGE_NOT_HELD;
  }
  if ( !pTableHandler || tableHandlerSize < 0x18 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  providerSignature = pTableHandler->ProviderSignature;
  if ( pTableHandler->Register )
  {
    firmwareTableHandler = pTableHandler->FirmwareTableHandler;
    driverObject = pTableHandler->DriverObject;
    return RegisterProvider(providerSignature, firmwareTableHandler, driverObject);
  }
  return UnregisterProvider(providerSignature, pTableHandler->DriverObject);
}
"""


NTSET_SYSTEM_SUPERFETCH_COPY_ALIAS_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        __int64 systemInformationLength)
{
  switch ( systemInformationClass )
  {
    case SystemSuperfetchInformation:
      return (unsigned int)PfSetSuperfetchInformation(79LL, (__int128 *)systemInformation, systemInformationLength, previousMode);
    default:
      return STATUS_INVALID_INFO_CLASS;
  }
}
"""


SUPERFETCH_COPY_ALIAS_HELPER_SAMPLE = r"""
__int64 __fastcall PfSetSuperfetchInformation(__int64 a1, __int128 *a2, int a3, KPROCESSOR_MODE a4)
{
  int v12;
  __int128 v30;
  __int128 v31;

  if ( a3 != 32 )
  {
    LODWORD(v12) = -1073741820;
    goto LABEL_13;
  }
  v30 = *a2;
  v31 = a2[1];
  if ( (_QWORD)v30 != 0x6B7568430000002DLL )
    goto LABEL_26;
  if ( DWORD2(v30) != 3 )
    goto LABEL_26;
  if ( DWORD2(v31) != 24 )
    goto LABEL_45;
  if ( a4 && (v31 & 7) != 0 )
    ExRaiseDatatypeMisalignment();
  return 0LL;
LABEL_26:
  LODWORD(v12) = -1073741811;
  goto LABEL_13;
LABEL_45:
  LODWORD(v12) = -1073741306;
LABEL_13:
  return (unsigned int)v12;
}
"""


NTSET_SYSTEM_LITERAL_SIZE_ALIAS_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        __int64 systemInformationLength)
{
  unsigned int expectedLength;

  switch ( systemInformationClass )
  {
    case SystemTimeZoneInformation:
      expectedLength = 172;
      if ( (_DWORD)systemInformationLength != expectedLength )
      {
        return STATUS_INFO_LENGTH_MISMATCH;
      }
      return (ULONG)ExpSetTimeZoneInformation((_OWORD *)systemInformation, expectedLength);
    default:
      return STATUS_INVALID_INFO_CLASS;
  }
}
"""


TIME_ZONE_POINTER_INDEX_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ExpSetTimeZoneInformation(_OWORD *a1, int a2)
{
  _OWORD v14[10];

  if ( a2 == 172 )
  {
    v14[0] = *a1;
    v14[1] = a1[1];
    return STATUS_SUCCESS;
  }
  return STATUS_INFO_LENGTH_MISMATCH;
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


HELPER_LENGTH_ALIAS_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchAliasedHelperLength(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID systemBuffer;
  ULONG inputBufferLength;
  ULONG outputBufferLength;
  ULONG ioControlCode;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  systemBuffer = irp->AssociatedIrp.MasterIrp;
  inputBufferLength = stack[2];
  outputBufferLength = stack[4];
  ioControlCode = stack[6];
  switch ( ioControlCode )
  {
    case 0x9123B000:
      status = ValidateAliasedLength(systemBuffer, inputBufferLength, outputBufferLength);
      break;
    case 0x9123B004:
      status = 0;
      break;
    case 0x9123B008:
      status = 0;
      break;
    case 0x9123B00C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


HELPER_LENGTH_ALIAS_SAMPLE = r"""
NTSTATUS __fastcall ValidateAliasedLength(PVOID buffer, ULONG inputLength, ULONG outputLength)
{
  ULONG localInput;
  ULONG localOutput;

  localInput = inputLength;
  localOutput = outputLength;
  if ( localInput < 0x18 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  if ( localOutput < 0x20 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  if ( *(_DWORD *)buffer != 3 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return STATUS_SUCCESS;
}
"""


HELPER_FLAGS_BEFORE_LENGTH_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchFlagsBeforeLength(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID systemBuffer;
  ULONG flags;
  ULONG inputBufferLength;
  ULONG ioControlCode;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  systemBuffer = irp->AssociatedIrp.MasterIrp;
  flags = stack[1];
  inputBufferLength = stack[2];
  ioControlCode = stack[6];
  switch ( ioControlCode )
  {
    case 0x9123B100:
      status = ValidateFlagsBeforeLength(systemBuffer, flags, inputBufferLength);
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


HELPER_FLAGS_BEFORE_LENGTH_HELPER_SAMPLE = r"""
NTSTATUS __fastcall ValidateFlagsBeforeLength(PVOID buffer, ULONG flags, ULONG inputLength)
{
  if ( flags )
  {
    return STATUS_INVALID_PARAMETER;
  }
  if ( inputLength < 0x20 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  if ( *(_DWORD *)buffer != 3 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return STATUS_SUCCESS;
}
"""


DISASM_WEAK_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchDisasmWeak(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
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
  switch ( ioControlCode )
  {
    case 0x9123D000:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


DISASM_SHARED_TAIL_SAMPLE = r"""
NTSTATUS __fastcall DispatchDisasmTail(PIRP irp)
{
  NTSTATUS status;
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
  switch ( ioControlCode )
  {
    case 0x9123D010:
      goto LABEL_TAIL;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
LABEL_TAIL:
  status = 0;
  return status;
}
"""


DISASM_CONFLICT_CASE_SAMPLE = r"""
NTSTATUS __fastcall DispatchDisasmConflict(PIRP irp)
{
  NTSTATUS status;
  PVOID systemBuffer;
  ULONG inputBufferLength;
  ULONG ioControlCode;
  _DWORD *ioStackLocation;

  ioStackLocation = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  systemBuffer = irp->AssociatedIrp.MasterIrp;
  inputBufferLength = ioStackLocation[2];
  ioControlCode = ioStackLocation[6];
  switch ( ioControlCode )
  {
    case 0x9123D020:
      if ( inputBufferLength != 0x10 )
      {
        status = STATUS_INFO_LENGTH_MISMATCH;
        break;
      }
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
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
        audit = helper_edge_audit_records([contracts[0x91234008]])
        unresolved = unresolved_helper_edge_records(audit)
        self.assertEqual(1, len(unresolved))
        self.assertEqual("helper_capture_missing", unresolved[0]["classification"])
        self.assertEqual("high", unresolved[0]["severity"])

    def test_helper_depth_limit_is_reported_as_auditable_edge(self) -> None:
        capture = capture_from_pseudocode(IOCTL_CONTRACT_SAMPLE)
        helper_capture = capture_from_pseudocode(HELPER_SAMPLE)
        deep_helper_capture = capture_from_pseudocode(DEEP_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={
                "QueryConfig": helper_capture,
                "ValidateConfig": deep_helper_capture,
            },
            buffer_contract_case_values=[0x91234000],
            buffer_contract_helper_depth=1,
        )

        contract = [item for item in plan.buffer_contracts if item.command_value == 0x91234000][0]
        audit = helper_edge_audit_records([contract])
        unresolved = unresolved_helper_edge_records(audit)

        self.assertTrue(any(item["callee"] == "ValidateConfig" for item in unresolved))
        self.assertTrue(
            any(
                item["callee"] == "ValidateConfig"
                and item["classification"] == "depth_limit_reached"
                for item in unresolved
            )
        )

    def test_profile_known_external_helper_is_summary_gap(self) -> None:
        edge = HelperContractEdge(
            callee="RtlEqualUnicodeString",
            arguments=["String1", "String2", "1"],
            passed_buffers=["String1"],
            resolved=False,
            depth=2,
            evidence="RtlEqualUnicodeString(String1, String2, 1)",
            warnings=[
                "helper not available for buffer contract analysis",
                "buffer pointer escapes to unknown function",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("external_api_profile_summary", record["classification"])
        self.assertEqual("info", record["severity"])
        self.assertFalse(record["blocks_recovery"])
        self.assertEqual("wdm.h", record["external_profile"]["header"])
        self.assertEqual("input_only", record["external_profile"]["summary_kind"])

    def test_depth_limited_input_only_external_helper_is_nonblocking_summary(self) -> None:
        edge = HelperContractEdge(
            callee="RtlCompareMemory",
            arguments=["left", "right", "length"],
            passed_buffers=["left"],
            resolved=False,
            depth=5,
            evidence="RtlCompareMemory(left, right, length)",
            warnings=[
                "helper depth limit reached",
                "helper not analyzed because maximum helper depth was reached",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("depth_limit_external_profile_summary", record["classification"])
        self.assertFalse(record["blocks_recovery"])

    def test_depth_limited_terminal_sink_is_nonblocking_summary(self) -> None:
        edge = HelperContractEdge(
            callee="KeBugCheck2",
            arguments=["code", "p1", "p2", "p3", "p4", "0"],
            passed_buffers=["p1"],
            resolved=False,
            depth=5,
            evidence="KeBugCheck2(code, p1, p2, p3, p4, 0)",
            warnings=[
                "helper depth limit reached",
                "helper not analyzed because maximum helper depth was reached",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("depth_limit_terminal_sink", record["classification"])
        self.assertFalse(record["blocks_recovery"])

    def test_depth_limited_internal_state_probes_are_nonblocking_context(self) -> None:
        for callee in [
            "ExpCheckForResource",
            "KeCheckForTimer",
            "MmIsNonPagedPoolNx",
            "ExGetHeapFromVA",
        ]:
            with self.subTest(callee=callee):
                edge = HelperContractEdge(
                    callee=callee,
                    arguments=["systemInformation", "a3"],
                    passed_buffers=["systemInformation"],
                    resolved=False,
                    depth=5,
                    evidence="%s(systemInformation, a3)" % callee,
                    warnings=[
                        "helper depth limit reached",
                        "helper not analyzed because maximum helper depth was reached",
                    ],
                )

                record = classify_helper_edge(edge)

                self.assertEqual("depth_limit_internal_state_probe", record["classification"])
                self.assertEqual("info", record["severity"])
                self.assertFalse(record["blocks_recovery"])

    def test_missing_lock_boundary_with_explicit_length_is_nonblocking_summary(self) -> None:
        edge = HelperContractEdge(
            callee="SubsystemAcquireLock",
            arguments=["context", "systemInformation", "systemInformationLength", "previousMode"],
            passed_buffers=["systemInformation"],
            resolved=False,
            depth=2,
            evidence="SubsystemAcquireLock(context, systemInformation, systemInformationLength, previousMode)",
            warnings=[
                "helper not available for buffer contract analysis",
                "buffer pointer escapes to unknown function",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("external_lock_boundary_summary", record["classification"])
        self.assertEqual("info", record["severity"])
        self.assertFalse(record["blocks_recovery"])

    def test_missing_lock_boundary_without_explicit_length_stays_blocking(self) -> None:
        edge = HelperContractEdge(
            callee="SubsystemAcquireLock",
            arguments=["context", "systemInformation", "previousMode"],
            passed_buffers=["systemInformation"],
            resolved=False,
            depth=2,
            evidence="SubsystemAcquireLock(context, systemInformation, previousMode)",
            warnings=[
                "helper not available for buffer contract analysis",
                "buffer pointer escapes to unknown function",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("helper_capture_missing", record["classification"])
        self.assertTrue(record["blocks_recovery"])

    def test_missing_set_boundary_with_length_stays_blocking(self) -> None:
        edge = HelperContractEdge(
            callee="SubsystemSetInformation",
            arguments=["context", "systemInformation", "systemInformationLength"],
            passed_buffers=["systemInformation"],
            resolved=False,
            depth=2,
            evidence="SubsystemSetInformation(context, systemInformation, systemInformationLength)",
            warnings=[
                "helper not available for buffer contract analysis",
                "buffer pointer escapes to unknown function",
            ],
        )

        record = classify_helper_edge(edge)

        self.assertEqual("helper_capture_missing", record["classification"])
        self.assertTrue(record["blocks_recovery"])

    def test_guard_dispatch_target_argument_is_not_payload_buffer(self) -> None:
        edges = _recover_helper_edges(
            "guard_dispatch_icall_no_overrides(Object, v4);",
            {"Object": {"source": "helper argument", "role": "input"}},
            {},
            max_depth=2,
            depth=0,
            visited=set(),
        )

        self.assertEqual([], edges)

    def test_guard_dispatch_payload_buffer_records_target_expression(self) -> None:
        edges = _recover_helper_edges(
            "guard_dispatch_icall_no_overrides(v5, systemInformation);",
            {"systemInformation": {"source": "parameter", "role": "input"}},
            {},
            max_depth=2,
            depth=0,
            visited=set(),
        )

        self.assertEqual(1, len(edges))
        edge = edges[0]
        self.assertEqual(["systemInformation"], edge.passed_buffers)
        self.assertIn("indirect dispatch target argument: v5", edge.warnings)

        record = classify_helper_edge(edge)

        self.assertEqual("indirect_dispatch_target_unresolved", record["classification"])
        self.assertEqual("v5", record["indirect_target"])
        self.assertTrue(record["blocks_recovery"])

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

    def test_helper_length_aliases_are_propagated_to_caller_lengths(self) -> None:
        capture = capture_from_pseudocode(HELPER_LENGTH_ALIAS_CASE_SAMPLE)
        helper_capture = capture_from_pseudocode(HELPER_LENGTH_ALIAS_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={"ValidateAliasedLength": helper_capture},
            buffer_contract_case_values=[0x9123B000],
        )

        self.assertEqual([0x9123B000], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual(1, len(contract.helper_edges))
        helper_edge = contract.helper_edges[0]
        self.assertEqual("ValidateAliasedLength", helper_edge.callee)
        self.assertTrue(
            any(
                item.length == "inputBufferLength"
                and item.relation == "<"
                and item.value == "0x18"
                and item.valid_relation == ">="
                for item in helper_edge.propagated_size_constraints
            )
        )
        self.assertTrue(
            any(
                item.length == "outputBufferLength"
                and item.relation == "<"
                and item.value == "0x20"
                and item.valid_relation == ">="
                for item in helper_edge.propagated_size_constraints
            )
        )
        self.assertFalse(
            any(item.length in {"localInput", "localOutput"} for item in helper_edge.propagated_size_constraints)
        )

    def test_helper_integer_flags_before_length_are_not_treated_as_size(self) -> None:
        capture = capture_from_pseudocode(HELPER_FLAGS_BEFORE_LENGTH_CASE_SAMPLE)
        helper_capture = capture_from_pseudocode(HELPER_FLAGS_BEFORE_LENGTH_HELPER_SAMPLE)
        plan = build_clean_plan(
            capture,
            helper_captures={"ValidateFlagsBeforeLength": helper_capture},
            buffer_contract_case_values=[0x9123B100],
        )

        self.assertEqual([0x9123B100], [contract.command_value for contract in plan.buffer_contracts])
        helper_edge = plan.buffer_contracts[0].helper_edges[0]
        self.assertEqual("ValidateFlagsBeforeLength", helper_edge.callee)
        self.assertTrue(
            any(
                item.length == "inputBufferLength"
                and item.relation == "<"
                and item.value == "0x20"
                and item.valid_relation == ">="
                for item in helper_edge.propagated_size_constraints
            )
        )
        self.assertFalse(any(item.length == "flags" for item in helper_edge.propagated_size_constraints))

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
        zero_length_buffer = contracts[113].buffers[0]
        self.assertTrue(
            any(
                item.length == "processInformationLength"
                and item.relation == "!="
                and item.value == "0"
                and item.valid_relation == "=="
                for item in zero_length_buffer.size_constraints
            )
        )
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("PF_PROCESS_ProcessSlistRollbackInformation_INPUT_SIZE = 0x0;", header)
        zero_struct = header[
            header.index("struct PF_PROCESS_ProcessSlistRollbackInformation_INPUT"):
            header.index("inline bool IsValidPF_PROCESS_ProcessSlistRollbackInformation_INPUTSize")
        ]
        self.assertIn("No bytes are accepted for this buffer role.", zero_struct)
        self.assertNotIn("std::uint8_t reserved_0x00[1];", zero_struct)

    def test_ntset_shared_tail_length_assignment_recovers_case_contract(self) -> None:
        capture = capture_from_pseudocode(NTSET_PROCESS_SHARED_TAIL_LENGTH_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[8])

        self.assertEqual([8], [contract.command_value for contract in plan.buffer_contracts])
        buffer = plan.buffer_contracts[0].buffers[0]
        self.assertEqual("processInformation", buffer.variable)
        self.assertTrue(
            any(
                item.length == "processInformationLength"
                and item.relation == "!="
                and item.value == "8LL"
                and item.valid_relation == "=="
                and item.valid_value == "8LL"
                for item in buffer.size_constraints
            )
        )
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("PF_PROCESS_ProcessExceptionPort_INPUT_SIZE = 0x8;", header)
        self.assertIn("std::uint8_t input_bytes_0x00[0x8];", header)

    def test_ntset_process_duplicate_switch_uses_richer_case_body(self) -> None:
        capture = capture_from_pseudocode(NTSET_PROCESS_MULTI_SWITCH_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[8])

        self.assertEqual([8], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("ProcessExceptionPort", contract.command_name)
        buffer = contract.buffers[0]
        self.assertEqual("processInformation", buffer.variable)
        self.assertTrue(any(item.offset == 0 for item in buffer.field_accesses))
        self.assertTrue(any(item.offset == 8 for item in buffer.field_accesses))
        self.assertTrue(any(item.field == "field_0x08" and item.relation == ">" for item in buffer.field_constraints))
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertNotIn("void field_0x00;", header)
        self.assertIn("void * field_0x00;", header)

    def test_ntset_thread_enum_labels_and_length_aliases_recover_contracts(self) -> None:
        capture = capture_from_pseudocode(NTSET_THREAD_ENUM_LABEL_SAMPLE)
        plan = build_clean_plan(capture)

        contracts = {contract.command_value: contract for contract in plan.buffer_contracts}
        self.assertIn(3, contracts)
        self.assertIn(4, contracts)
        self.assertIn(7, contracts)
        self.assertIn(32, contracts)
        base_contract = contracts[3]
        self.assertEqual("ntset_thread", base_contract.dispatcher_kind)
        self.assertEqual("ThreadBasePriority", base_contract.command_name)
        self.assertEqual("PF_THREAD_ThreadBasePriority_INPUT", base_contract.buffers[0].structure_name)
        self.assertTrue(
            any(
                item.length == "threadInformationLength"
                and item.relation == "!="
                and item.value == "4"
                for item in base_contract.buffers[0].size_constraints
            )
        )
        affinity_buffer = contracts[4].buffers[0]
        self.assertEqual("threadInformation", affinity_buffer.variable)
        self.assertTrue(
            any(
                item.length == "threadInformationLength"
                and item.relation == "!="
                and item.value == "8"
                for item in affinity_buffer.size_constraints
            )
        )

    def test_ntset_system_pointer_typed_dispatcher_is_not_buffer_source(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_POINTER_DISPATCHER_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[161])

        self.assertEqual([161], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("SystemVmGenerationCountInformation", contract.command_name)
        self.assertEqual(["systemInformation"], [buffer.variable for buffer in contract.buffers])
        self.assertNotIn("systemInformationClass", [buffer.variable for buffer in contract.buffers])

    def test_ntset_system_dispatcher_condition_tail_recovers_selected_case_fields(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_DISPATCHER_CONDITION_TAIL_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[21])

        self.assertEqual([21], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("SystemFileCacheInformation", contract.command_name)
        buffer = contract.buffers[0]
        self.assertEqual("systemInformation", buffer.variable)
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "<"
                and item.value == "0x40"
                and item.valid_relation == ">="
                for item in buffer.size_constraints
            )
        )
        offsets = {item.offset for item in buffer.field_accesses}
        self.assertIn(0x18, offsets)
        self.assertIn(0x20, offsets)
        self.assertNotIn(0x3C, offsets)

    def test_ntset_system_context_fallback_does_not_pollute_existing_case_evidence(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CONTEXT_FALLBACK_POLLUTION_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[24])

        self.assertEqual([24], [contract.command_value for contract in plan.buffer_contracts])
        buffer = plan.buffer_contracts[0].buffers[0]
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "!="
                and item.value == "20"
                for item in buffer.size_constraints
            )
        )
        self.assertFalse(any(item.value == "0x40" for item in buffer.size_constraints))
        offsets = {item.offset for item in buffer.field_accesses}
        self.assertIn(0x10, offsets)
        self.assertNotIn(0x18, offsets)
        self.assertNotIn(0x20, offsets)

    def test_ntset_system_goto_label_tail_recovers_selected_case_sizes(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_GOTO_LABEL_TAIL_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[54])

        self.assertEqual([54], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("SystemLoadGdiDriverInSystemSpace", contract.command_name)
        buffer = contract.buffers[0]
        self.assertEqual("inout", buffer.role)
        self.assertEqual("systemInformation", buffer.variable)
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "=="
                and item.value == "48"
                for item in buffer.size_constraints
            )
        )
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "!="
                and item.value == "56"
                and item.valid_relation == "=="
                and item.valid_value == "56"
                for item in buffer.size_constraints
            )
        )
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("PF_SYSTEM_SystemLoadGdiDriverInSystemSpace_INOUT", header)
        self.assertIn("PF_SYSTEM_SystemLoadGdiDriverInSystemSpace_INOUT_INPUT_SIZE_0x30", header)
        self.assertIn("PF_SYSTEM_SystemLoadGdiDriverInSystemSpace_INOUT_INPUT_SIZE_0x38", header)
        self.assertIn(" || ", header)
        self.assertIn("valid systemInformationLength == 56", header)

    def test_goto_label_tail_helper_is_used_for_focused_capture_and_contract(self) -> None:
        capture = capture_from_pseudocode(GOTO_HELPER_TAIL_CASE_SAMPLE)
        helper = capture_from_pseudocode(TAIL_SYSTEM_BUFFER_HELPER_SAMPLE)
        initial_plan = build_clean_plan(capture, buffer_contract_case_values=[0x9123C000])

        self.assertNotIn("ValidateTailSystemBuffer", _infer_buffer_sources(capture.pseudocode or "", capture))
        self.assertEqual(
            ["ValidateTailSystemBuffer"],
            helper_names_for_selected_case(capture, initial_plan, 0x9123C000),
        )

        plan = build_clean_plan(
            capture,
            helper_captures={"ValidateTailSystemBuffer": helper},
            buffer_contract_case_values=[0x9123C000],
        )

        self.assertEqual([0x9123C000], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual(1, len(contract.helper_edges))
        edge = contract.helper_edges[0]
        self.assertTrue(edge.resolved)
        self.assertEqual(["payload"], edge.passed_buffers)
        self.assertTrue(
            any(
                item.length == "outputBufferLength"
                and item.value == "16"
                and item.valid_relation == ">="
                for item in edge.propagated_size_constraints
            )
        )
        self.assertTrue(any(item.field == "field_0x00" for item in edge.propagated_field_constraints))

    def test_ntset_system_casted_handler_call_records_buffer_escape_contract(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CASTED_HANDLER_ESCAPE_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[75])

        self.assertEqual(
            ["FirmwareTableRegistrationHandler"],
            helper_names_for_selected_case(capture, plan, 75),
        )
        self.assertEqual([75], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("SystemRegisterFirmwareTableInformationHandler", contract.command_name)
        self.assertEqual(1, len(contract.helper_edges))
        edge = contract.helper_edges[0]
        self.assertEqual("FirmwareTableRegistrationHandler", edge.callee)
        self.assertFalse(edge.resolved)
        self.assertEqual(["systemInformation"], edge.passed_buffers)
        buffer = contract.buffers[0]
        self.assertEqual("systemInformation", buffer.variable)
        self.assertIn("inputLength", buffer.length_variable)
        self.assertIn("systemInformationLength", buffer.length_variable)
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("struct PF_SYSTEM_SystemRegisterFirmwareTableInformationHandler_INPUT", header)
        self.assertIn("Layout was not recovered for this buffer role.", header)
        self.assertNotIn("No bytes are accepted for this buffer role.", header)

    def test_focused_case_contract_falls_back_to_native_switch_without_flow(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CASTED_HANDLER_ESCAPE_SAMPLE)

        contracts = recover_buffer_contracts(capture, [], case_values=[75])

        self.assertEqual([75], [contract.command_value for contract in contracts])
        contract = contracts[0]
        self.assertEqual("SystemRegisterFirmwareTableInformationHandler", contract.command_name)
        self.assertEqual(1, len(contract.helper_edges))
        self.assertEqual("FirmwareTableRegistrationHandler", contract.helper_edges[0].callee)
        self.assertEqual(["systemInformation"], contract.helper_edges[0].passed_buffers)
        self.assertEqual("systemInformation", contract.buffers[0].variable)

    def test_helper_typed_struct_arrow_fields_propagate_to_caller_buffer(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CASTED_HANDLER_ESCAPE_SAMPLE)
        helper = capture_from_pseudocode(FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE)

        plan = build_clean_plan(
            capture,
            helper_captures={"FirmwareTableRegistrationHandler": helper},
            buffer_contract_case_values=[75],
        )

        self.assertEqual([75], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        edge = contract.helper_edges[0]
        self.assertTrue(edge.resolved)
        fields_by_name = {access.field: access for access in edge.propagated_field_accesses}
        self.assertEqual(0, fields_by_name["ProviderSignature"].offset)
        self.assertEqual(4, fields_by_name["Register"].offset)
        self.assertEqual(8, fields_by_name["FirmwareTableHandler"].offset)
        self.assertEqual(16, fields_by_name["DriverObject"].offset)
        self.assertTrue(any("profile:SYSTEM_FIRMWARE_TABLE_HANDLER" in item.source for item in fields_by_name.values()))

        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("std::uint32_t ProviderSignature;", header)
        self.assertIn("std::uint8_t Register;", header)
        self.assertIn("std::uint8_t reserved_0x05[3];", header)
        self.assertIn("PFNFTH FirmwareTableHandler;", header)
        self.assertIn("void * DriverObject;", header)
        self.assertNotIn("std::uint8_t reserved_0x00[24];", header)

    def test_ntset_system_char_literal_raw_args_resolves_helper_contract(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_CHAR_LITERAL_RAW_ARGS_SAMPLE)
        helper = capture_from_pseudocode(EXP_FIRMWARE_TABLE_HANDLER_HELPER_SAMPLE)

        plan = build_clean_plan(
            capture,
            helper_captures={"ExpRegisterFirmwareTableInformationHandler": helper},
            buffer_contract_case_values=[75],
        )

        self.assertEqual(75, find_case_value_near_line("", line_text="    case 'K':"))
        self.assertEqual([75], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        self.assertEqual("SystemRegisterFirmwareTableInformationHandler", contract.command_name)
        self.assertEqual(["systemInformation"], [buffer.variable for buffer in contract.buffers])
        self.assertIn("systemInformationLength", contract.buffers[0].length_variable)
        self.assertIn("v3", contract.buffers[0].length_variable)
        edge = contract.helper_edges[0]
        self.assertTrue(edge.resolved)
        self.assertEqual("ExpRegisterFirmwareTableInformationHandler", edge.callee)
        self.assertEqual(["systemInformation"], edge.passed_buffers)
        self.assertTrue(
            any(
                item.length == "v3"
                and item.value == "0x18"
                and item.valid_relation == ">="
                for item in edge.propagated_size_constraints
            )
        )
        fields_by_name = {access.field: access for access in edge.propagated_field_accesses}
        self.assertEqual(0, fields_by_name["ProviderSignature"].offset)
        self.assertEqual(4, fields_by_name["Register"].offset)
        self.assertEqual(8, fields_by_name["FirmwareTableHandler"].offset)
        self.assertEqual(16, fields_by_name["DriverObject"].offset)

        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("struct PF_SYSTEM_SystemRegisterFirmwareTableInformationHandler_INPUT", header)
        self.assertIn("std::uint32_t ProviderSignature;", header)
        self.assertIn("std::uint8_t Register;", header)
        self.assertIn("PFNFTH FirmwareTableHandler;", header)
        self.assertIn("void * DriverObject;", header)

    def test_helper_copy_aliases_project_field_guards_to_caller_buffer(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_SUPERFETCH_COPY_ALIAS_SAMPLE)
        helper = capture_from_pseudocode(SUPERFETCH_COPY_ALIAS_HELPER_SAMPLE)

        plan = build_clean_plan(
            capture,
            helper_captures={"PfSetSuperfetchInformation": helper},
            buffer_contract_case_values=[79],
        )

        self.assertEqual([79], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        buffer = contract.buffers[0]
        self.assertEqual("systemInformation", buffer.variable)
        helper_edge = contract.helper_edges[0]
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "!="
                and item.value == "32"
                and item.valid_relation == "=="
                and item.valid_value == "32"
                for item in helper_edge.propagated_size_constraints
            )
        )
        self.assertTrue(any(item.offset == 0x00 for item in helper_edge.propagated_field_accesses))
        self.assertTrue(any(item.offset == 0x10 for item in helper_edge.propagated_field_accesses))
        self.assertTrue(
            any(
                item.offset == 0x00
                and item.relation == "!="
                and item.value == "0x6B7568430000002DLL"
                and item.valid_relation == "=="
                for item in helper_edge.propagated_field_constraints
            )
        )
        self.assertTrue(
            any(
                item.offset == 0x08
                and item.relation == "!="
                and item.value == "3"
                and item.valid_relation == "=="
                for item in helper_edge.propagated_field_constraints
            )
        )
        self.assertTrue(
            any(
                item.offset == 0x18
                and item.relation == "!="
                and item.value == "24"
                and item.valid_relation == "=="
                for item in helper_edge.propagated_field_constraints
            )
        )
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("PF_SYSTEM_SystemSuperfetchInformation_INPUT_SIZE = 0x20", header)
        self.assertIn("__int128 field_0x00;", header)
        self.assertIn("std::uint32_t field_0x08;", header)
        self.assertIn("std::uint32_t field_0x18;", header)

    def test_literal_size_alias_and_pointer_index_helper_fields_are_recovered(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_LITERAL_SIZE_ALIAS_SAMPLE)
        helper = capture_from_pseudocode(TIME_ZONE_POINTER_INDEX_HELPER_SAMPLE)

        plan = build_clean_plan(
            capture,
            helper_captures={"ExpSetTimeZoneInformation": helper},
            buffer_contract_case_values=[93],
        )

        self.assertEqual([93], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        buffer = contract.buffers[0]
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "!="
                and item.value == "172"
                and item.valid_relation == "=="
                for item in buffer.size_constraints
            )
        )
        helper_edge = contract.helper_edges[0]
        self.assertTrue(any(item.offset == 0 for item in helper_edge.propagated_field_accesses))
        self.assertTrue(any(item.offset == 0x10 for item in helper_edge.propagated_field_accesses))
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("PF_SYSTEM_SystemTimeZoneInformation_INPUT_SIZE = 0xAC", header)
        self.assertIn("std::uint8_t reserved_0x08[8];", header)

    def test_ntset_parameter_fallback_uses_prototype_name_when_capture_name_empty(self) -> None:
        capture = FunctionCapture(
            name="",
            prototype="__int64 __fastcall NtSetSystemInformation(int a1, __int64 a2, __int64 a3)",
            pseudocode=NTSET_SYSTEM_CHAR_LITERAL_RAW_ARGS_SAMPLE,
        )

        sources = _infer_buffer_sources(capture.pseudocode, capture)

        self.assertIn("a2", sources)
        self.assertEqual("input", sources["a2"]["role"])
        self.assertEqual("a3", sources["a2"]["length"])

    def test_disasm_slice_recovers_size_guard_and_field_writes_for_weak_case(self) -> None:
        capture = capture_from_pseudocode(DISASM_WEAK_CASE_SAMPLE)
        case_slice = DisasmCaseSlice(
            command_value=0x9123D000,
            instructions=[
                DisasmInstruction(mnemonic="mov", operands=["rbx", "systemBuffer"], text="mov rbx, systemBuffer"),
                DisasmInstruction(mnemonic="mov", operands=["ecx", "inputBufferLength"], text="mov ecx, inputBufferLength"),
                DisasmInstruction(mnemonic="cmp", operands=["ecx", "0x10"], text="cmp ecx, 0x10"),
                DisasmInstruction(mnemonic="jb", operands=["reject"], text="jb reject", branch_taken_reject=True),
                DisasmInstruction(
                    mnemonic="mov",
                    operands=["dword ptr [rbx+4]", "eax"],
                    text="mov dword ptr [rbx+4], eax",
                ),
                DisasmInstruction(
                    mnemonic="cmp",
                    operands=["dword ptr [rbx+8]", "0x22"],
                    text="cmp dword ptr [rbx+8], 0x22",
                ),
                DisasmInstruction(mnemonic="jne", operands=["reject"], text="jne reject", branch_taken_reject=True),
                DisasmInstruction(
                    mnemonic="test",
                    operands=["dword ptr [rbx+0xC]", "0xF0"],
                    text="test dword ptr [rbx+0xC], 0xF0",
                ),
                DisasmInstruction(mnemonic="jnz", operands=["reject"], text="jnz reject", branch_taken_reject=True),
            ],
        )

        plan = build_clean_plan(
            capture,
            buffer_contract_case_values=[0x9123D000],
            buffer_contract_disasm_slices={0x9123D000: case_slice},
        )

        self.assertEqual([0x9123D000], [contract.command_value for contract in plan.buffer_contracts])
        contract = plan.buffer_contracts[0]
        buffer = contract.buffers[0]
        self.assertEqual("systemBuffer", buffer.variable)
        self.assertTrue(
            any(
                item.length == "inputBufferLength"
                and item.relation == "<"
                and item.value == "0x10"
                and item.valid_relation == ">="
                for item in buffer.size_constraints
            )
        )
        self.assertTrue(any(item.offset == 4 and item.access == "write" for item in buffer.field_accesses))
        self.assertTrue(
            any(
                item.offset == 8
                and item.relation == "!="
                and item.value == "0x22"
                and item.valid_relation == "=="
                for item in buffer.field_constraints
            )
        )
        self.assertTrue(
            any(
                item.offset == 0xC
                and item.relation == "mask_!="
                and item.mask == "0xF0"
                and item.valid_relation == "mask_=="
                for item in buffer.field_constraints
            )
        )
        header = render_buffer_struct_header(capture, plan.buffer_contracts)
        self.assertIn("std::uint32_t field_0x04;", header)
        self.assertIn("std::uint32_t field_0x08;", header)
        self.assertIn("std::uint32_t field_0x0C;", header)
        self.assertIn("source: disasm", header)
        self.assertIn("evidence: mov dword ptr [rbx+4], eax", header)
        self.assertNotIn("Size-only byte range", header)

    def test_disasm_indirect_helper_call_recovers_target_arguments_and_propagates(self) -> None:
        capture = capture_from_pseudocode(DISASM_WEAK_CASE_SAMPLE)
        helper = capture_from_pseudocode(
            r"""
NTSTATUS __fastcall ValidateDisasmHelper(PVOID buffer, ULONG length)
{
  if ( length < 0x30 )
  {
    return STATUS_INFO_LENGTH_MISMATCH;
  }
  if ( *(_DWORD *)(buffer + 0xC) != 1 )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return STATUS_SUCCESS;
}
"""
        )
        case_slice = DisasmCaseSlice(
            command_value=0x9123D000,
            instructions=[
                DisasmInstruction(mnemonic="mov", operands=["rax", "ValidateDisasmHelper"], text="mov rax, ValidateDisasmHelper"),
                DisasmInstruction(mnemonic="mov", operands=["rcx", "systemBuffer"], text="mov rcx, systemBuffer"),
                DisasmInstruction(mnemonic="mov", operands=["edx", "inputBufferLength"], text="mov edx, inputBufferLength"),
                DisasmInstruction(
                    mnemonic="mov",
                    operands=["qword ptr [rsp+20h]", "outputBufferLength"],
                    text="mov qword ptr [rsp+20h], outputBufferLength",
                ),
                DisasmInstruction(mnemonic="call", operands=["rax"], text="call rax"),
                DisasmInstruction(mnemonic="call", operands=["OtherHelper"], text="call OtherHelper"),
            ],
        )

        plan = build_clean_plan(
            capture,
            helper_captures={"ValidateDisasmHelper": helper},
            buffer_contract_case_values=[0x9123D000],
            buffer_contract_disasm_slices={0x9123D000: case_slice},
        )

        self.assertEqual([0x9123D000], [contract.command_value for contract in plan.buffer_contracts])
        self.assertEqual(1, len(plan.buffer_contracts[0].helper_edges))
        edge = plan.buffer_contracts[0].helper_edges[0]
        self.assertTrue(edge.resolved)
        self.assertEqual("ValidateDisasmHelper", edge.callee)
        self.assertEqual(["systemBuffer"], edge.passed_buffers)
        self.assertEqual(["systemBuffer", "inputBufferLength", "outputBufferLength"], edge.arguments)
        self.assertTrue(any(item.length == "inputBufferLength" and item.value == "0x30" for item in edge.propagated_size_constraints))
        self.assertTrue(any(item.offset == 0xC for item in edge.propagated_field_constraints))

    def test_disasm_helper_slice_propagates_without_pseudocode_capture(self) -> None:
        capture = capture_from_pseudocode(DISASM_WEAK_CASE_SAMPLE)
        case_slice = DisasmCaseSlice(
            command_value=0x9123D000,
            function_name="DispatchDisasmWeak",
            instructions=[
                DisasmInstruction(mnemonic="mov", operands=["rax", "ValidateDisasmOnly"], text="mov rax, ValidateDisasmOnly"),
                DisasmInstruction(mnemonic="mov", operands=["rcx", "systemBuffer"], text="mov rcx, systemBuffer"),
                DisasmInstruction(mnemonic="mov", operands=["edx", "inputBufferLength"], text="mov edx, inputBufferLength"),
                DisasmInstruction(mnemonic="call", operands=["rax"], text="call rax"),
            ],
        )
        helper_slice = DisasmCaseSlice(
            command_value=0,
            function_name="ValidateDisasmOnly",
            instructions=[
                DisasmInstruction(mnemonic="cmp", operands=["edx", "0x40"], text="cmp edx, 0x40"),
                DisasmInstruction(mnemonic="jb", operands=["reject"], text="jb reject", branch_taken_reject=True),
                DisasmInstruction(
                    mnemonic="cmp",
                    operands=["dword ptr [rcx+0x10]", "3"],
                    text="cmp dword ptr [rcx+0x10], 3",
                ),
                DisasmInstruction(mnemonic="jne", operands=["reject"], text="jne reject", branch_taken_reject=True),
            ],
        )

        plan = build_clean_plan(
            capture,
            buffer_contract_case_values=[0x9123D000],
            buffer_contract_disasm_slices=[case_slice, helper_slice],
        )

        self.assertEqual([0x9123D000], [contract.command_value for contract in plan.buffer_contracts])
        edge = plan.buffer_contracts[0].helper_edges[0]
        self.assertTrue(edge.resolved)
        self.assertEqual("ValidateDisasmOnly", edge.callee)
        self.assertTrue(
            any(
                item.length == "inputBufferLength"
                and item.value == "0x40"
                and item.valid_relation == ">="
                for item in edge.propagated_size_constraints
            )
        )
        self.assertTrue(
            any(
                item.offset == 0x10
                and item.value == "3"
                and item.valid_relation == "=="
                for item in edge.propagated_field_constraints
            )
        )

    def test_disasm_shared_tail_slice_adds_selected_case_tail_fields(self) -> None:
        capture = capture_from_pseudocode(DISASM_SHARED_TAIL_SAMPLE)
        case_slice = DisasmCaseSlice(
            command_value=0x9123D010,
            instructions=[
                DisasmInstruction(mnemonic="mov", operands=["rbx", "systemBuffer"], text="mov rbx, systemBuffer"),
                DisasmInstruction(mnemonic="mov", operands=["ecx", "outputBufferLength"], text="mov ecx, outputBufferLength"),
                DisasmInstruction(mnemonic="cmp", operands=["ecx", "0x20"], text="cmp ecx, 0x20"),
                DisasmInstruction(mnemonic="jb", operands=["reject"], text="jb reject", branch_taken_reject=True),
                DisasmInstruction(
                    mnemonic="mov",
                    operands=["qword ptr [rbx+0x10]", "rax"],
                    text="mov qword ptr [rbx+0x10], rax",
                ),
            ],
            evidence="offline shared-tail CFG slice",
        )

        plan = build_clean_plan(
            capture,
            buffer_contract_case_values=[0x9123D010],
            buffer_contract_disasm_slices={0x9123D010: case_slice},
        )

        self.assertEqual([0x9123D010], [contract.command_value for contract in plan.buffer_contracts])
        buffer = plan.buffer_contracts[0].buffers[0]
        self.assertTrue(any(item.length == "outputBufferLength" and item.valid_relation == ">=" for item in buffer.size_constraints))
        self.assertTrue(any(item.offset == 0x10 and item.type == "ULONGLONG" for item in buffer.field_accesses))

    def test_pseudocode_disasm_size_conflict_warns_without_overwrite(self) -> None:
        capture = capture_from_pseudocode(DISASM_CONFLICT_CASE_SAMPLE)
        case_slice = DisasmCaseSlice(
            command_value=0x9123D020,
            instructions=[
                DisasmInstruction(mnemonic="mov", operands=["ecx", "inputBufferLength"], text="mov ecx, inputBufferLength"),
                DisasmInstruction(mnemonic="cmp", operands=["ecx", "0x18"], text="cmp ecx, 0x18"),
                DisasmInstruction(mnemonic="jne", operands=["reject"], text="jne reject", branch_taken_reject=True),
            ],
        )

        plan = build_clean_plan(
            capture,
            buffer_contract_case_values=[0x9123D020],
            buffer_contract_disasm_slices={0x9123D020: case_slice},
        )

        contract = plan.buffer_contracts[0]
        buffer = contract.buffers[0]
        self.assertTrue(any(item.value == "0x10" for item in buffer.size_constraints))
        self.assertTrue(any(item.value == "0x18" for item in buffer.size_constraints))
        self.assertTrue(any("pseudocode/disassembly size conflict" in warning for warning in contract.warnings))

    def test_offline_focused_case_without_disasm_keeps_existing_behavior(self) -> None:
        capture = capture_from_pseudocode(DISASM_WEAK_CASE_SAMPLE)

        plan = build_clean_plan(capture, buffer_contract_case_values=[0x9123D000])

        self.assertEqual([], plan.buffer_contracts)

    def test_casted_indirect_call_parser_ignores_type_tokens(self) -> None:
        text = (
            "return ((__int64 (__fastcall *)(PVOID, ULONG_PTR))RealIndirectHandler)"
            "(systemInformation, systemInformationLength);"
        )

        call_sites = _iter_helper_call_sites(text)

        self.assertEqual(["RealIndirectHandler"], [site.callee for site in call_sites])
        self.assertEqual(["systemInformation", "systemInformationLength"], call_sites[0].arguments)
        self.assertTrue(call_sites[0].indirect)

    def test_ntset_system_alias_helper_escape_records_canonical_buffer_contract(self) -> None:
        capture = capture_from_pseudocode(NTSET_SYSTEM_ALIAS_HELPER_ESCAPE_SAMPLE)
        plan = build_clean_plan(capture, buffer_contract_case_values=[40, 150])

        contracts = {contract.command_value: contract for contract in plan.buffer_contracts}
        self.assertIn(40, contracts)
        self.assertIn(150, contracts)
        verifier_buffer = contracts[40].buffers[0]
        self.assertEqual("systemInformation", verifier_buffer.variable)
        self.assertIn("systemInformationLength", verifier_buffer.length_variable)
        self.assertEqual(["systemInformation"], contracts[40].helper_edges[0].passed_buffers)
        self.assertEqual(
            ["(PCUNICODE_STRING)systemInformation"],
            contracts[40].helper_edges[0].arguments,
        )
        metadata_buffer = contracts[150].buffers[0]
        self.assertEqual("systemInformation", metadata_buffer.variable)
        self.assertIn("inputLength", metadata_buffer.length_variable)
        self.assertEqual(["systemInformation"], contracts[150].helper_edges[0].passed_buffers)
        self.assertEqual(
            ["systemInformation", "(unsigned int)inputLength"],
            contracts[150].helper_edges[0].arguments,
        )

    def test_flow_recovered_raw_case_body_uses_rename_map_for_ntset_system_contract(self) -> None:
        capture = FunctionCapture(
            ea=0x1400AE1320,
            name="NtSetSystemInformation",
            prototype="__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)",
            pseudocode=r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  int v5;

  v4 = a2;
  v5 = (int)a1;
  switch ( v5 )
  {
    case SystemCpuSetTagInformation:
      if ( (_DWORD)a3 < 8 )
      {
        return 3221225476LL;
      }
      return (unsigned int)v4->m128i_i64[0];
    default:
      break;
  }
  return 0;
}
""",
        )
        flow = FlowRewrite(
            kind="switch_recovery",
            dispatcher="infoClass",
            recovered_cases=[206],
            case_names={206: "SystemLeapSecondInformation"},
            case_bodies={
                206: [
                    "if ( (_DWORD)a3 != 8 )",
                    "return 3221225476LL;",
                    "if ( !(unsigned __int8)PsIsCurrentThreadInServerSilo(v109, a2, a3, v8) )",
                    "LOBYTE(v118[0]) = (unsigned __int8)v4->m128i_i64[0] != 0;",
                    "return updated;",
                ]
            },
        )

        contracts = recover_buffer_contracts(
            capture,
            [flow],
            rename_map={
                "a1": "systemInformationClass",
                "a2": "systemInformation",
                "a3": "systemInformationLength",
                "v4": "infoBuffer128",
            },
            case_values=[206],
        )

        self.assertEqual([206], [contract.command_value for contract in contracts])
        buffer = contracts[0].buffers[0]
        self.assertEqual("SystemLeapSecondInformation", contracts[0].command_name)
        self.assertEqual("systemInformation", buffer.variable)
        self.assertTrue(
            any(
                item.length == "systemInformationLength"
                and item.relation == "!="
                and item.value == "8"
                for item in buffer.size_constraints
            )
        )
        self.assertTrue(any(item.offset == 0 for item in buffer.field_accesses))

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
