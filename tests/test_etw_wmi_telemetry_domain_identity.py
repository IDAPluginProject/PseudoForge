from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class EtwWmiTelemetryDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_etw_registration_enable_and_set_information_roles(self) -> None:
        register_plan = self._plan(
            """
NTSTATUS __stdcall EtwRegister(LPCGUID ProviderId, PETWENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle)
{
  struct _LIST_ENTRY *Flink;

  Flink = PsGetCurrentServerSiloGlobals()[52].Flink;
  return EtwpRegisterKMProvider((int)Flink, EnableCallback, 3, ProviderId, CallbackContext, 0, RegHandle);
}
"""
        )
        classic_plan = self._plan(
            """
__int64 __fastcall EtwRegisterClassicProvider(ULONGLONG providerId, __int64 enableMask, __int64 enableCallback, __int64 callbackContext, __int64 *registrationHandle)
{
  return EtwpRegisterKMProvider(EtwpHostSiloState, providerId, 2, enableCallback, callbackContext, 0, registrationHandle);
}
"""
        )
        unregister_plan = self._plan(
            """
NTSTATUS __stdcall EtwUnregister(REGHANDLE RegHandle)
{
  struct _EVENT_DATA_DESCRIPTOR UserData;

  EtwWrite(RegHandle, &UserData, 1, 0);
  EtwpUnreferenceGuidEntry(RegHandle);
  EtwpReleaseProviderTraitsReference(RegHandle);
  return STATUS_SUCCESS;
}
"""
        )
        enable_plan = self._plan(
            """
__int64 __fastcall EtwEnableTrace(__int64 ContextHandle, __int64 Flags, __int64 TraceHandle, __int64 ProviderId, char KernelLevel, __int64 ProviderGuid, __int64 EnableInfo, int CallbackContext)
{
  return EtwpEnableTrace(ContextHandle, Flags, TraceHandle, ProviderId, KernelLevel, ProviderGuid, EnableInfo, CallbackContext);
}
"""
        )
        set_info_plan = self._plan(
            """
NTSTATUS __stdcall EtwSetInformation(REGHANDLE RegHandle, EVENT_INFO_CLASS InformationClass, PVOID EventInformation, ULONG InformationLength)
{
  __int64 optionalInfoPtr;

  if ( InformationClass == EventProviderSetTraits )
  {
    return EtwpSetProviderTraitsKm(RegHandle, EventInformation, InformationLength);
  }
  return EtwpTrackProviderBinaryKm(RegHandle, optionalInfoPtr, InformationClass == EventProviderSetReserved2);
}
"""
        )

        register_roles = self._roles(register_plan, "windows.etw_wmi_telemetry.etw_register")
        classic_roles = self._roles(classic_plan, "windows.etw_wmi_telemetry.etw_register_classic_provider")
        unregister_roles = self._roles(unregister_plan, "windows.etw_wmi_telemetry.etw_unregister")
        enable_roles = self._roles(enable_plan, "windows.etw_wmi_telemetry.etw_enable_trace")
        set_info_roles = self._roles(set_info_plan, "windows.etw_wmi_telemetry.etw_set_information")

        self.assertEqual("GUID", register_roles["providerId"])
        self.assertEqual("PETWENABLECALLBACK", register_roles["enableCallback"])
        self.assertEqual("ETW_CALLBACK_CONTEXT", register_roles["callbackContext"])
        self.assertEqual("REGHANDLE_OUTPUT", register_roles["registrationHandleOutput"])
        self.assertEqual("ETW_SILO_STATE", register_roles["siloState"])
        self.assertEqual("TRACE_GUID", classic_roles["providerId"])
        self.assertEqual("TRACE_ENABLE_MASK", classic_roles["enableMask"])
        self.assertEqual("PETWENABLECALLBACK", classic_roles["enableCallback"])
        self.assertEqual("ETW_CALLBACK_CONTEXT", classic_roles["callbackContext"])
        self.assertEqual("REGHANDLE_OUTPUT", classic_roles["registrationHandleOutput"])
        self.assertEqual("REGHANDLE", unregister_roles["registrationHandle"])
        self.assertEqual("EVENT_DATA_DESCRIPTOR", unregister_roles["unregisterEventData"])
        self.assertEqual("TRACEHANDLE", enable_roles["contextHandle"])
        self.assertEqual("TRACE_ENABLE_FLAGS", enable_roles["flags"])
        self.assertEqual("TRACE_LEVEL", enable_roles["kernelLevel"])
        self.assertEqual("GUID", enable_roles["providerGuid"])
        self.assertEqual("ETW_CALLBACK_CONTEXT", enable_roles["callbackContext"])
        self.assertEqual("REGHANDLE", set_info_roles["registrationHandle"])
        self.assertEqual("EVENT_INFO_CLASS", set_info_roles["informationClass"])
        self.assertEqual("EVENT_INFORMATION_BUFFER", set_info_roles["informationBuffer"])
        self.assertEqual("BUFFER_LENGTH", set_info_roles["informationLength"])
        self.assertEqual("EVENT_INFORMATION_BUFFER", set_info_roles["optionalInformation"])

    def test_etw_write_and_trace_message_roles(self) -> None:
        event_enabled_plan = self._plan(
            """
BOOLEAN __stdcall EtwEventEnabled(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor)
{
  return RegHandle && EtwpLevelKeywordEnabled(RegHandle, EventDescriptor->Level, EventDescriptor->Keyword);
}
"""
        )
        provider_enabled_plan = self._plan(
            """
BOOLEAN __stdcall EtwProviderEnabled(REGHANDLE RegHandle, UCHAR Level, ULONGLONG Keyword)
{
  return RegHandle && EtwpLevelKeywordEnabled(RegHandle, Level, Keyword);
}
"""
        )
        write_plan = self._plan(
            """
NTSTATUS __stdcall EtwWriteEx(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG64 Filter, ULONG Flags, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)
{
  if ( EtwpLevelKeywordEnabled(RegHandle, EventDescriptor->Level, EventDescriptor->Keyword) )
  {
    return EtwpEventWriteFull(RegHandle, Filter, Flags, EventDescriptor, ActivityId, RelatedActivityId, UserDataCount, UserData);
  }
  return STATUS_SUCCESS;
}
"""
        )
        wmi_trace_plan = self._plan(
            """
__int64 WmiTraceMessage(unsigned __int64 traceHandle, __int64 messageId, __int128 *dataBuffer, __int16 flags, ...)
{
  va_list varArgs;

  va_start(varArgs, flags);
  return EtwpTraceMessageVa(traceHandle, messageId, dataBuffer, flags, (__int64)varArgs, 0);
}
"""
        )
        trace_va_plan = self._plan(
            """
NTSTATUS __fastcall EtwpTraceMessageVa(unsigned __int64 traceHandle, __int64 messageId, __int128 *userData, __int16 traceFlags, __int64 varArgs, unsigned __int8 siloFlag)
{
  struct _KTHREAD *currentThread;
  NTSTATUS status;

  currentThread = KeGetCurrentThread();
  if ( EtwpLevelKeywordEnabled(traceHandle, 0, 0) )
  {
    status = EtwpReserveTraceBuffer(traceHandle, userData);
    EtwpSendTraceEvent(traceHandle, userData, status);
  }
  return status;
}
"""
        )

        event_enabled_roles = self._roles(event_enabled_plan, "windows.etw_wmi_telemetry.etw_event_enabled")
        provider_enabled_roles = self._roles(provider_enabled_plan, "windows.etw_wmi_telemetry.etw_provider_enabled")
        write_roles = self._roles(write_plan, "windows.etw_wmi_telemetry.etw_write_ex")
        wmi_trace_roles = self._roles(wmi_trace_plan, "windows.etw_wmi_telemetry.wmi_trace_message")
        trace_va_roles = self._roles(trace_va_plan, "windows.etw_wmi_telemetry.etwp_trace_message_va")

        self.assertEqual("REGHANDLE", event_enabled_roles["registrationHandle"])
        self.assertEqual("EVENT_DESCRIPTOR", event_enabled_roles["eventDescriptor"])
        self.assertEqual("REGHANDLE", provider_enabled_roles["registrationHandle"])
        self.assertEqual("TRACE_LEVEL", provider_enabled_roles["eventLevel"])
        self.assertEqual("TRACE_KEYWORD_MASK", provider_enabled_roles["keywordMask"])
        self.assertEqual("REGHANDLE", write_roles["registrationHandle"])
        self.assertEqual("EVENT_DESCRIPTOR", write_roles["eventDescriptor"])
        self.assertEqual("ETW_FILTER", write_roles["filter"])
        self.assertEqual("ETW_WRITE_FLAGS", write_roles["writeFlags"])
        self.assertEqual("GUID", write_roles["activityId"])
        self.assertEqual("GUID", write_roles["relatedActivityId"])
        self.assertEqual("EVENT_DATA_COUNT", write_roles["userDataCount"])
        self.assertEqual("EVENT_DATA_DESCRIPTOR", write_roles["userData"])
        self.assertEqual("TRACEHANDLE", wmi_trace_roles["traceHandle"])
        self.assertEqual("TRACE_MESSAGE_ID", wmi_trace_roles["messageId"])
        self.assertEqual("EVENT_DATA_DESCRIPTOR", wmi_trace_roles["dataBuffer"])
        self.assertEqual("TRACE_MESSAGE_FLAGS", wmi_trace_roles["messageFlags"])
        self.assertEqual("VA_LIST", wmi_trace_roles["varArgs"])
        self.assertEqual("TRACEHANDLE", trace_va_roles["traceHandle"])
        self.assertEqual("TRACE_MESSAGE_ID", trace_va_roles["messageId"])
        self.assertEqual("EVENT_DATA_DESCRIPTOR", trace_va_roles["userData"])
        self.assertEqual("TRACE_MESSAGE_FLAGS", trace_va_roles["traceFlags"])
        self.assertEqual("VA_LIST", trace_va_roles["varArgs"])
        self.assertEqual("ETHREAD", trace_va_roles["currentThread"])
        self.assertEqual("NTSTATUS", trace_va_roles["status"])

    def test_log_context_swap_event_thread_roles(self) -> None:
        plan = self._plan(
            """
char __fastcall EtwpLogContextSwapEvent(__int64 loggerSet, __int64 argument1, __int64 argument2)
{
  LARGE_INTEGER LoggerTimeStamp;
  __int64 loggerContext;
  __int64 eventBuffer;

  loggerContext = *(_QWORD *)(loggerSet + 712);
  LoggerTimeStamp.QuadPart = 0;
  eventBuffer = 0;
  if ( argument1 )
  {
    *(_DWORD *)(eventBuffer + 4) = *(_DWORD *)(argument1 + 1296);
    *(_BYTE *)(eventBuffer + 9) = *(_BYTE *)(argument1 + 195);
    *(_BYTE *)(eventBuffer + 13) ^= (*(_BYTE *)(argument1 + 391) ^ *(_BYTE *)(eventBuffer + 13)) & 1;
  }
  if ( argument2 )
  {
    *(_DWORD *)eventBuffer = *(_DWORD *)(argument2 + 1296);
    *(_BYTE *)(eventBuffer + 8) = *(_BYTE *)(argument2 + 195);
    *(_BYTE *)(eventBuffer + 11) = *(_BYTE *)(argument2 + 518);
    EtwpStackTraceDispatcher(loggerContext, (unsigned int *)&LoggerTimeStamp, (_KTHREAD *)argument2, 0x505A05u);
    EtwpTraceLastBranchRecord(loggerContext, &LoggerTimeStamp, (struct _KTHREAD *)argument2, 5265925);
  }
  return EtwpCCSwapTrace(argument1, argument2, *(unsigned int *)(loggerContext + 200), &LoggerTimeStamp);
}
"""
        )

        roles = self._roles(plan, "windows.etw_wmi_telemetry.etwp_log_context_swap_event")
        rename_map = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("KTHREAD", roles["oldThread"])
        self.assertEqual("KTHREAD", roles["newThread"])
        self.assertEqual("oldThread", rename_map["argument1"])
        self.assertEqual("newThread", rename_map["argument2"])

    def test_log_context_swap_event_requires_thread_trace_dispatch(self) -> None:
        plan = self._plan(
            """
char __fastcall EtwpLogContextSwapEvent(__int64 loggerSet, __int64 argument1, __int64 argument2)
{
  LARGE_INTEGER LoggerTimeStamp;
  __int64 loggerContext;

  loggerContext = *(_QWORD *)(loggerSet + 712);
  LoggerTimeStamp.QuadPart = 0;
  return EtwpCCSwapTrace(argument1, argument2, *(unsigned int *)(loggerContext + 200), &LoggerTimeStamp);
}
"""
        )

        self.assertEqual(
            [],
            self._profile_identities(plan, "windows.etw_wmi_telemetry.etwp_log_context_swap_event"),
        )

    def test_etw_contiguous_allocation_profile_corrects_weak_private_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
BOOLEAN __fastcall EtwTraceContAllocationEvent(PVOID BaseAddress, __int64 a2, __int64 a3, __int64 a4, __int64 a5, int a6, int a7, int a8, int a9, int a10, unsigned __int8 a11, int a12, __int64 a13)
{
  struct _EVENT_DATA_DESCRIPTOR UserData;
  if ( EtwEventEnabled(EtwpMemoryProvRegHandle, &KERNEL_MEM_EVENT_CONT_ALLOCATION) )
  {
    UserData.Ptr = (ULONGLONG)&a2;
    return EtwWriteEx(EtwpMemoryProvRegHandle, &KERNEL_MEM_EVENT_CONT_ALLOCATION, 0, 1, 0, 0, 1, &UserData);
  }
  return 0;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.etw_wmi_telemetry.etw_trace_cont_allocation_event"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        roles = self._roles(plan, profile_id)

        self.assertEqual(13, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertIn("PFN_NUMBER startPage", rendered)
        self.assertIn("PFN_NUMBER endPage", rendered)
        self.assertIn("ULONG partitionId", rendered)
        self.assertIn("ULONG node", rendered)
        self.assertIn("ULONG cacheType", rendered)
        self.assertIn("ULONG priority", rendered)
        self.assertIn("ULONG flags", rendered)
        self.assertIn("BOOLEAN largePage", rendered)
        self.assertIn("ULONG extraFlags", rendered)
        self.assertIn("ULONG64 startTimestamp", rendered)
        self.assertEqual("EVENT_DATA_DESCRIPTOR", roles["eventData"])
        self.assertEqual("VIRTUAL_ADDRESS", roles["baseAddress"])
        self.assertEqual("MEMORY_PARTITION_ID", roles["partitionId"])
        self.assertEqual("NUMA_NODE", roles["node"])
        self.assertEqual("MEMORY_CACHING_TYPE", roles["cacheType"])
        self.assertEqual("MEMORY_PRIORITY", roles["priority"])
        self.assertEqual("ETW_ALLOCATION_FLAGS", roles["flags"])
        self.assertEqual("ETW_EXTRA_FLAGS", roles["extraFlags"])
        self.assertEqual("TIMESTAMP", roles["startTimestamp"])
        self.assertEqual([], plan.corrected_parameter_map)

    def test_etw_contiguous_allocation_requires_trace_write_evidence(self) -> None:
        plan = self._plan(
            """
BOOLEAN __fastcall EtwTraceContAllocationEvent(PVOID BaseAddress, __int64 a2, __int64 a3, __int64 a4, __int64 a5, int a6, int a7, int a8, int a9, int a10, unsigned __int8 a11, int a12, __int64 a13)
{
  return BaseAddress != 0;
}
"""
        )

        self.assertEqual(
            [],
            self._profile_identities(plan, "windows.etw_wmi_telemetry.etw_trace_cont_allocation_event"),
        )

    def test_dbgk_wer_live_kernel_dump_profile_corrects_wrapper_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall DbgkWerCaptureLiveKernelDump(const wchar_t *a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7, __int64 a8, int a9)
{
  _DWORD options[10];
  options[0] = 1;
  return DbgkWerCaptureLiveKernelDump2(a1, a5, a6, (__int64)options);
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.etw_wmi_telemetry.dbgk_wer_capture_live_kernel_dump"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]

        self.assertEqual(9, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertIn("PCWSTR dumpFilePath", rendered)
        self.assertIn("ULONG_PTR werContext", rendered)
        self.assertIn("ULONG_PTR secondaryContext", rendered)
        self.assertIn("ULONG_PTR captureContext", rendered)
        self.assertIn("ULONG_PTR dumpType", rendered)
        self.assertIn("ULONG_PTR bugCheckData", rendered)
        self.assertIn("ULONG_PTR optionBlockHigh", rendered)
        self.assertIn("ULONG_PTR optionBlockLow", rendered)
        self.assertIn("ULONG optionFlags", rendered)
        self.assertEqual([], plan.corrected_parameter_map)

    def test_etwp_ti_vad_query_event_write_profile_corrects_partial_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall EtwpTiVadQueryEventWrite(PEVENT_DATA_DESCRIPTOR UserData, int a2, unsigned int a3, int a4, __int64 a5, unsigned int a6, PCEVENT_DESCRIPTOR EventDescriptor, char a8)
{
  ULONG UserDataCount;
  __int64 timestamp;

  timestamp = 0;
  UserDataCount = a3 + 1;
  UserData[a3].Ptr = (ULONGLONG)&timestamp;
  if ( a8 )
  {
    return EtwpTiAsyncVadQueryEventWrite((_DWORD)UserData, a2, UserDataCount, a4, a5, a6, (__int64)EventDescriptor);
  }
  return EtwWriteEx(EtwThreatIntProvRegHandle, EventDescriptor, 0, 0, 0, 0, UserDataCount, UserData);
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.etw_wmi_telemetry.etwp_ti_vad_query_event_write"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        roles = self._roles(plan, profile_id)

        self.assertEqual(5, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertIn("PEVENT_DATA_DESCRIPTOR userData", rendered)
        self.assertIn("ULONG baseUserDataCount", rendered)
        self.assertIn("ULONG zeroVadCount", rendered)
        self.assertIn("PCEVENT_DESCRIPTOR eventDescriptor", rendered)
        self.assertIn("BOOLEAN asyncWrite", rendered)
        self.assertEqual("EVENT_DATA_DESCRIPTOR", roles["userData"])
        self.assertEqual("EVENT_DATA_COUNT", roles["baseUserDataCount"])
        self.assertEqual("VAD_EVENT_COUNT", roles["zeroVadCount"])
        self.assertEqual("EVENT_DESCRIPTOR", roles["eventDescriptor"])
        self.assertEqual("BOOLEAN", roles["asyncWrite"])
        self.assertEqual([], plan.corrected_parameter_map)

    def test_trace_event_control_and_callback_roles(self) -> None:
        trace_event_plan = self._plan(
            """
NTSTATUS __fastcall NtTraceEvent(__int128 *RegistrationObject, __int64 InformationClass, unsigned int BufferSize, __int64 DataBuffer)
{
  PVOID referencedObject;
  struct _KTHREAD *currentThread;
  char previousMode;

  currentThread = KeGetCurrentThread();
  previousMode = currentThread->PreviousMode;
  ObReferenceObjectByHandle(RegistrationObject, 0, 0, previousMode, &referencedObject, 0);
  EtwpWriteUserEvent(referencedObject, DataBuffer, BufferSize);
  EtwpTraceMessageVa((unsigned __int64)referencedObject, InformationClass, (__int128 *)DataBuffer, 0, 0, 0);
  return STATUS_SUCCESS;
}
"""
        )
        trace_control_plan = self._plan(
            """
__int64 __fastcall NtTraceControl(unsigned int ControlCode, unsigned int *InputBuffer, int InputLength, void *OutputBuffer, unsigned int OutputLength, void *ReturnLength)
{
  unsigned int *allocatedBufferPtr;
  unsigned int *loggerInfoPtr;
  HANDLE traceObjectHandle;
  PVOID referencedObject;

  allocatedBufferPtr = ExAllocatePool2(0, InputLength, 0x50777445);
  EtwpStartTrace(allocatedBufferPtr, InputBuffer, InputLength);
  EtwpQueryTrace(loggerInfoPtr, OutputBuffer, OutputLength);
  EtwpFlushTrace(traceObjectHandle, referencedObject);
  return EtwpStopTrace(ControlCode, ReturnLength);
}
"""
        )
        event_callback_plan = self._plan(
            """
NTSTATUS __fastcall EtwRegisterEventCallback(__int64 EventId, __int64 CallbackFunction, __int64 CallbackContext)
{
  __int64 acquiredCtxPtr;
  _QWORD *callbackDataBlock;

  acquiredCtxPtr = EtwpAcquireLoggerContextByLoggerId(EtwpHostSiloState, EventId, 0);
  callbackDataBlock = ExAllocatePool2(0, 0x10, 0x43777445);
  callbackDataBlock[1] = CallbackContext;
  return acquiredCtxPtr && CallbackFunction ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
"""
        )

        trace_event_roles = self._roles(trace_event_plan, "windows.etw_wmi_telemetry.nt_trace_event")
        trace_control_roles = self._roles(trace_control_plan, "windows.etw_wmi_telemetry.nt_trace_control")
        event_callback_roles = self._roles(event_callback_plan, "windows.etw_wmi_telemetry.etw_register_event_callback")

        self.assertEqual("ETW_REGISTRATION_OBJECT", trace_event_roles["registrationObject"])
        self.assertEqual("TRACE_INFORMATION_CLASS", trace_event_roles["traceInformationClass"])
        self.assertEqual("BUFFER_LENGTH", trace_event_roles["bufferSize"])
        self.assertEqual("TRACE_EVENT_BUFFER", trace_event_roles["dataBuffer"])
        self.assertEqual("ETW_TRACE_OBJECT", trace_event_roles["referencedTraceObject"])
        self.assertEqual("ETHREAD", trace_event_roles["currentThread"])
        self.assertEqual("KPROCESSOR_MODE", trace_event_roles["previousMode"])
        self.assertEqual("TRACE_CONTROL_CODE", trace_control_roles["controlCode"])
        self.assertEqual("TRACE_CONTROL_INPUT", trace_control_roles["inputBuffer"])
        self.assertEqual("BUFFER_LENGTH", trace_control_roles["inputBufferLength"])
        self.assertEqual("TRACE_CONTROL_OUTPUT", trace_control_roles["outputBuffer"])
        self.assertEqual("BUFFER_LENGTH", trace_control_roles["outputBufferLength"])
        self.assertEqual("TRACE_CONTROL_BUFFER", trace_control_roles["allocatedControlBuffer"])
        self.assertEqual("ETW_LOGGER_INFO", trace_control_roles["loggerInfo"])
        self.assertEqual("HANDLE", trace_control_roles["traceObjectHandle"])
        self.assertEqual("ETW_TRACE_OBJECT", trace_control_roles["referencedTraceObject"])
        self.assertEqual("ETW_EVENT_ID", event_callback_roles["eventId"])
        self.assertEqual("ETW_EVENT_CALLBACK", event_callback_roles["callbackFunction"])
        self.assertEqual("ETW_CALLBACK_CONTEXT", event_callback_roles["callbackContext"])
        self.assertEqual("ETW_LOGGER_CONTEXT", event_callback_roles["loggerContext"])
        self.assertEqual("ETW_CALLBACK_DATA_BLOCK", event_callback_roles["callbackDataBlock"])

    def test_wmi_provider_legacy_bridge_roles(self) -> None:
        register_provider_plan = self._plan(
            """
void __fastcall WmipRegisterEtwProvider(__int64 ProviderEntry, __int64 EventId)
{
  __int64 v2;
  __int64 newProviderRecord;

  v2 = *(_QWORD *)(ProviderEntry + 56);
  newProviderRecord = ExAllocatePool2(0, 0x18, 0x70696D57);
  WmipReferenceEntry(*(_QWORD *)(ProviderEntry + 64));
  WmipQueueLegacyEtwWork(newProviderRecord, v2, EventId);
}
"""
        )
        unregister_provider_plan = self._plan(
            """
void __fastcall WmipUnregisterEtwProvider(__int64 ProviderContext)
{
  ULONG_PTR refCountBlockPtr;
  __int64 newProviderRecord;

  refCountBlockPtr = *(_QWORD *)(ProviderContext + 56);
  newProviderRecord = ExAllocatePool2(0, 0x18, 0x70696D57);
  WmipQueueLegacyEtwWork(newProviderRecord, refCountBlockPtr, 0);
}
"""
        )
        legacy_register_plan = self._plan(
            """
LONG __fastcall WmipProcessLegacyEtwRegister(__int64 providerContextPtr, __int64 targetInfoClass)
{
  REGHANDLE existingHandle;
  LARGE_INTEGER handleTemp;

  existingHandle = *(_QWORD *)(providerContextPtr + 104);
  if ( existingHandle )
  {
    EtwUnregister(existingHandle);
  }
  return EtwRegisterClassicProvider((int)providerContextPtr + 72, 0, (unsigned int)WmipLegacyEtwCallback, providerContextPtr, (__int64)&handleTemp);
}
"""
        )
        legacy_unregister_plan = self._plan(
            """
LONG __fastcall WmipProcessLegacyEtwUnregister(__int64 etwRegContextPtr)
{
  REGHANDLE regHandle;

  regHandle = *(_QWORD *)(etwRegContextPtr + 104);
  return EtwUnregister(regHandle);
}
"""
        )

        register_provider_roles = self._roles(register_provider_plan, "windows.etw_wmi_telemetry.wmip_register_etw_provider")
        unregister_provider_roles = self._roles(unregister_provider_plan, "windows.etw_wmi_telemetry.wmip_unregister_etw_provider")
        legacy_register_roles = self._roles(legacy_register_plan, "windows.etw_wmi_telemetry.wmip_process_legacy_etw_register")
        legacy_unregister_roles = self._roles(legacy_unregister_plan, "windows.etw_wmi_telemetry.wmip_process_legacy_etw_unregister")

        self.assertEqual("WMI_PROVIDER_ENTRY", register_provider_roles["providerEntry"])
        self.assertEqual("ETW_EVENT_ID", register_provider_roles["eventId"])
        self.assertEqual("WMI_PROVIDER_OBJECT", register_provider_roles["providerObject"])
        self.assertEqual("WMI_LEGACY_ETW_WORK_ITEM", register_provider_roles["legacyWorkItem"])
        self.assertEqual("WMI_PROVIDER_CONTEXT", unregister_provider_roles["providerContext"])
        self.assertEqual("WMI_PROVIDER_OBJECT", unregister_provider_roles["providerRefCountBlock"])
        self.assertEqual("WMI_LEGACY_ETW_WORK_ITEM", unregister_provider_roles["legacyWorkItem"])
        self.assertEqual("WMI_PROVIDER_CONTEXT", legacy_register_roles["providerContext"])
        self.assertEqual("TRACE_INFORMATION_CLASS", legacy_register_roles["targetInformationClass"])
        self.assertEqual("REGHANDLE", legacy_register_roles["existingRegistrationHandle"])
        self.assertEqual("REGHANDLE_OUTPUT", legacy_register_roles["newRegistrationHandle"])
        self.assertEqual("WMI_PROVIDER_CONTEXT", legacy_unregister_roles["providerContext"])
        self.assertEqual("REGHANDLE", legacy_unregister_roles["registrationHandle"])

    def test_wmi_notification_ioctl_and_irp_roles(self) -> None:
        set_notify_plan = self._plan(
            """
void __fastcall WmipSetTraceNotify(PDEVICE_OBJECT DeviceObject, int traceNotifyClass)
{
  __int64 *notifyRoutineArrayPtr;
  PIRP allocatedIrp;
  ULONG providerId;

  notifyRoutineArrayPtr = &EtwpDiskIoNotifyRoutines;
  allocatedIrp = IoAllocateIrp(2, 0);
  providerId = IoWMIDeviceObjectToProviderId(DeviceObject);
  WmipForwardWmiIrp(allocatedIrp, traceNotifyClass, providerId);
  IoFreeIrp(allocatedIrp);
}
"""
        )
        receive_plan = self._plan(
            """
__int64 __fastcall WmipReceiveNotifications(unsigned int *GuidHandleArray, int *NotificationCount, __int64 Irp)
{
  _BYTE *objectListBuffer;
  PVOID referencedObject;
  struct _KLOCK_QUEUE_HANDLE spinLockHandle;

  objectListBuffer = ExAllocatePool2(0, *GuidHandleArray, 0x70696D57);
  ObReferenceObjectByHandle(GuidHandleArray[0], 4, WmipGuidObjectType, 1, &referencedObject, 0);
  WmipCopyFromEventQueues(objectListBuffer, NotificationCount, Irp);
  IofCompleteRequest((PIRP)Irp, 0);
  return spinLockHandle.LockQueue.Next ? STATUS_SUCCESS : STATUS_SUCCESS;
}
"""
        )
        queue_plan = self._plan(
            """
__int64 __fastcall WmipQueueNotification(struct _KEVENT *NotificationEvent, char **QueueBufferDescriptor, unsigned int *Payload)
{
  char *Pool2;
  unsigned int Size;

  Size = *Payload;
  Pool2 = ExAllocatePool2(0, Size, 0x70696D57);
  memmove(Pool2, Payload, Size);
  KeSetEvent(NotificationEvent, 0, 0);
  return 0;
}
"""
        )
        ioctl_plan = self._plan(
            """
NTSTATUS __fastcall WmipIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  struct _IO_STACK_LOCATION *CurrentStackLocation;
  __int64 MasterIrp;
  unsigned int LowPart;
  PVOID referencedObject;

  CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
  MasterIrp = (__int64)Irp->AssociatedIrp.MasterIrp;
  LowPart = CurrentStackLocation->Parameters.Read.ByteOffset.LowPart;
  WmipProbeWnodeSingleInstance(MasterIrp, LowPart, 0, 0);
  WmipReceiveNotifications((unsigned int *)MasterIrp, (int *)&LowPart, (__int64)Irp);
  WmipOpenBlock((HANDLE)LowPart, &referencedObject);
  return STATUS_SUCCESS;
}
"""
        )
        register_device_plan = self._plan(
            """
NTSTATUS __fastcall WmipRegisterDevice(struct _DEVICE_OBJECT *DeviceObject, int RegistrationFlags)
{
  char *RegEntryByDevice;
  PDEVICE_OBJECT AttachedDeviceReference;

  RegEntryByDevice = WmipFindRegEntryByDevice((__int64)DeviceObject);
  AttachedDeviceReference = IoGetAttachedDeviceReference(DeviceObject);
  WmipRegisterOrUpdateDS(RegEntryByDevice, RegistrationFlags);
  return STATUS_SUCCESS;
}
"""
        )
        send_irp_plan = self._plan(
            """
__int64 __fastcall WmipSendWmiIrp(__int64 a1, __int64 a2, __int64 a3, int infoClass, __int64 masterIrpPtr, _OWORD *ioStatusBlockOut)
{
  PIRP Irp;
  PIRP savedIrpPtr;
  unsigned int forwardResult;

  Irp = IoAllocateIrp(WmipServiceDeviceObject->StackSize + 1, 0);
  savedIrpPtr = Irp;
  Irp->AssociatedIrp.MasterIrp = (struct _IRP *)masterIrpPtr;
  forwardResult = WmipForwardWmiIrp(Irp, infoClass, masterIrpPtr);
  *ioStatusBlockOut = *(_OWORD *)&savedIrpPtr->IoStatus.Status;
  IoFreeIrp(savedIrpPtr);
  return forwardResult;
}
"""
        )
        event_notification_plan = self._plan(
            """
__int64 WmipEventNotification()
{
  PLIST_ENTRY removed_event_entry;
  struct _LIST_ENTRY *event_object_ptr;
  __int64 unref_target_ptr;
  __int64 work_item_count_prev;

  removed_event_entry = ExInterlockedRemoveHeadList(&WmipNPEvent, &WmipNPNotificationSpinlock);
  event_object_ptr = removed_event_entry[1].Blink;
  WmipProcessEvent(event_object_ptr);
  unref_target_ptr = (__int64)removed_event_entry[1].Flink;
  WmipUnreferenceRegEntry(unref_target_ptr);
  work_item_count_prev = _InterlockedExchangeAdd(&WmipEventWorkItems, -1);
  return work_item_count_prev;
}
"""
        )

        set_notify_roles = self._roles(set_notify_plan, "windows.etw_wmi_telemetry.wmip_set_trace_notify")
        receive_roles = self._roles(receive_plan, "windows.etw_wmi_telemetry.wmip_receive_notifications")
        queue_roles = self._roles(queue_plan, "windows.etw_wmi_telemetry.wmip_queue_notification")
        ioctl_roles = self._roles(ioctl_plan, "windows.etw_wmi_telemetry.wmip_io_control")
        register_device_roles = self._roles(register_device_plan, "windows.etw_wmi_telemetry.wmip_register_device")
        send_irp_roles = self._roles(send_irp_plan, "windows.etw_wmi_telemetry.wmip_send_wmi_irp")
        event_notification_roles = self._roles(event_notification_plan, "windows.etw_wmi_telemetry.wmip_event_notification")

        self.assertEqual("DEVICE_OBJECT", set_notify_roles["deviceObject"])
        self.assertEqual("WMI_TRACE_NOTIFY_CLASS", set_notify_roles["traceNotifyClass"])
        self.assertEqual("ETW_NOTIFY_ROUTINE_ARRAY", set_notify_roles["notifyRoutineArray"])
        self.assertEqual("IRP", set_notify_roles["allocatedIrp"])
        self.assertEqual("WMI_PROVIDER_ID", set_notify_roles["providerId"])
        self.assertEqual("WMI_GUID_HANDLE_ARRAY", receive_roles["guidHandleArray"])
        self.assertEqual("NOTIFICATION_COUNT_OUTPUT", receive_roles["notificationCount"])
        self.assertEqual("IRP", receive_roles["irp"])
        self.assertEqual("WMI_GUID_OBJECT_LIST", receive_roles["objectListBuffer"])
        self.assertEqual("WMI_GUID_OBJECT", receive_roles["referencedGuidObject"])
        self.assertEqual("KLOCK_QUEUE_HANDLE", receive_roles["spinLockHandle"])
        self.assertEqual("KEVENT", queue_roles["notificationEvent"])
        self.assertEqual("WMI_NOTIFICATION_QUEUE", queue_roles["queueBufferDescriptor"])
        self.assertEqual("WMI_NOTIFICATION_PAYLOAD", queue_roles["payload"])
        self.assertEqual("WMI_NOTIFICATION_QUEUE_BUFFER", queue_roles["allocatedQueueBuffer"])
        self.assertEqual("BUFFER_LENGTH", queue_roles["payloadLength"])
        self.assertEqual("DEVICE_OBJECT", ioctl_roles["deviceObject"])
        self.assertEqual("IRP", ioctl_roles["irp"])
        self.assertEqual("IO_STACK_LOCATION", ioctl_roles["currentStackLocation"])
        self.assertEqual("WMI_WNODE_BUFFER", ioctl_roles["systemBuffer"])
        self.assertEqual("IOCTL_CODE", ioctl_roles["ioControlCode"])
        self.assertEqual("WMI_GUID_OBJECT", ioctl_roles["referencedGuidObject"])
        self.assertEqual("DEVICE_OBJECT", register_device_roles["deviceObject"])
        self.assertEqual("WMI_REGISTRATION_FLAGS", register_device_roles["registrationFlags"])
        self.assertEqual("WMI_REGISTRATION_ENTRY", register_device_roles["registrationEntry"])
        self.assertEqual("DEVICE_OBJECT", register_device_roles["attachedDeviceReference"])
        self.assertEqual("WMI_IRP_INFO_CLASS", send_irp_roles["infoClass"])
        self.assertEqual("IRP", send_irp_roles["masterIrp"])
        self.assertEqual("IO_STATUS_BLOCK_OUTPUT", send_irp_roles["ioStatusBlockOutput"])
        self.assertEqual("IRP", send_irp_roles["allocatedIrp"])
        self.assertEqual("IRP", send_irp_roles["savedIrp"])
        self.assertEqual("NTSTATUS", send_irp_roles["forwardStatus"])
        self.assertEqual("WMI_EVENT_QUEUE_ENTRY", event_notification_roles["removedEventEntry"])
        self.assertEqual("WMI_EVENT_OBJECT", event_notification_roles["eventObject"])
        self.assertEqual("WMI_REGISTRATION_ENTRY", event_notification_roles["registrationEntry"])
        self.assertEqual("WORK_ITEM_COUNT", event_notification_roles["previousWorkItemCount"])

    def test_report_only_etw_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall EtwWriteEx(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG64 Filter, ULONG Flags, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)
{
  __int64 probe;

  probe = *(_QWORD *)(RegHandle + 16)
        + *(_QWORD *)(RegHandle + 24)
        + *(_QWORD *)(RegHandle + 32)
        + *(_QWORD *)(RegHandle + 40)
        + *(_QWORD *)(RegHandle + 48)
        + *(_QWORD *)(RegHandle + 56)
        + *(_QWORD *)(RegHandle + 64)
        + *(_QWORD *)(RegHandle + 72)
        + *(_QWORD *)(RegHandle + 16)
        + *(_QWORD *)(RegHandle + 24)
        + *(_QWORD *)(RegHandle + 32)
        + *(_QWORD *)(RegHandle + 40);
  return EtwpEventWriteFull(RegHandle, Filter, Flags, EventDescriptor, ActivityId, RelatedActivityId, UserDataCount, UserData, probe);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.etw_wmi_telemetry.etw_write_ex",
            "regHandle",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "regHandle"
        ]

        self.assertEqual("REGHANDLE", identity["structure_name"])
        self.assertEqual("registrationHandle", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "regHandle"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall EtwEventEnabled(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor)
{
  return EtwpLevelKeywordEnabled(RegHandle, EventDescriptor->Level, EventDescriptor->Keyword);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.etw_wmi_telemetry.etw_event_enabled",
            role="registrationHandle",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_callback_type(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall EtwRegister(LPCGUID ProviderId, int EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle)
{
  return EtwpRegisterKMProvider(0, EnableCallback, 3, ProviderId, CallbackContext, 0, RegHandle);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.etw_wmi_telemetry.etw_register"
                and item["trusted_role"] == "enableCallback"
                for item in self._identities(plan)
            )
        )

    def test_etw_wmi_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
BOOLEAN __stdcall EtwEventEnabled(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor)
{
  return EtwpLevelKeywordEnabled(RegHandle, EventDescriptor->Level, EventDescriptor->Keyword);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/etw_wmi_telemetry.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _roles(self, plan, profile_id: str) -> dict[str, str]:
        return {
            str(item["trusted_role"]): str(item["structure_name"])
            for item in self._profile_identities(plan, profile_id)
        }

    def _single_identity(
        self,
        plan,
        profile_id: str,
        role: str = "",
    ) -> dict[str, object]:
        identities = self._profile_identities(plan, profile_id)
        if role:
            identities = [item for item in identities if item.get("trusted_role") == role]
        self.assertEqual(1, len(identities))
        return identities[0]

    def _identity_for_base(self, plan, profile_id: str, base: str) -> dict[str, object]:
        identities = [
            item
            for item in self._identities(plan)
            if item.get("profile_id") == profile_id and item.get("base") == base
        ]
        self.assertEqual(1, len(identities))
        return identities[0]
