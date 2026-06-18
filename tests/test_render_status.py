from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles.loader import get_status_name
from tools.build_status_codes_profile import build_status_code_profile, parse_ntstatus_definitions


NON_STATUS_ZERO_SAMPLE = r"""
char __fastcall MiBooleanLikeHelper(__int64 a1)
{
  int status;

  status = 0;
  if ( a1 )
    status = 1;
  return status;
}
"""


NTSTATUS_ZERO_SAMPLE = r"""
NTSTATUS __fastcall StatusOnlySuccess(void)
{
  NTSTATUS status;

  status = 0;
  return 0;
}
"""


MIXED_ERROR_ZERO_RETURN_SAMPLE = r"""
__int64 __fastcall MixedErrorZeroReturn(int a1)
{
  if ( a1 )
    return 3221225476LL;
  return 0LL;
}
"""


LLM_STATUS_ZERO_ASSIGNMENT_SAMPLE = r"""
__int64 __fastcall LlmStatusZeroAssignment(int a1)
{
  int v9;

  v9 = 0;
  if ( a1 )
    v9 = -1073741811;
  return (unsigned int)v9;
}
"""


STATUS_COMPARISON_SAMPLE = r"""
NTSTATUS __fastcall StatusComparisonSample(int a1)
{
  NTSTATUS sectionCreateStatus;
  NTSTATUS v194;
  int v195;
  int buildNumber;

  sectionCreateStatus = -1073741811;
  if ( sectionCreateStatus == -1073740277 )
    RtlRaiseStatus(-1073741811);
  if ( -1073740277 == sectionCreateStatus )
    return sectionCreateStatus;
  if ( v194 != -1073741199 )
    return v194;
  if ( v195 != -1073741199 )
    return sectionCreateStatus;
  if ( buildNumber == -1073740277 )
    return sectionCreateStatus;
  return 0;
}
"""


STATUS_TERNARY_SAMPLE = r"""
__int64 __fastcall StatusTernarySample(int a1, int a2)
{
  signed int v26;
  unsigned int v27;
  __int64 mask;
  ACCESS_MASK desiredAccess;
  NTSTATUS status;

  v26 = a1 < a2 ? 0xC0000095 : 0;
  v27 = a1 ? 0 : -1073741670;
  mask = a1 ? 0xC0000095 : 0;
  desiredAccess = a1 ? 0xC0000095 : 0;
  status = a1 ? 0xC0000095 : 0LL;
  return v26;
}
"""


STATUS_ALIAS_COMPARISON_SAMPLE = r"""
NTSTATUS __fastcall StatusAliasComparisonSample(int a1)
{
  int v26;
  int v27;
  NTSTATUS status;
  int buildNumber;

  if ( (v26 = SomeStatusCall(a1), status = v26, v26 == -1073740748) )
    return status;
  if ( (v27 = SomeIntegerCall(a1), buildNumber = v27, v27 == -1073740748) )
    return STATUS_INVALID_PARAMETER;
  if ( (v26 = SomeStatusCall(a1), status = v26, -1073741675 == v26) )
    return status;
  return STATUS_SUCCESS;
}
"""


STATUS_FLOW_COMPARISON_SAMPLE = r"""
NTSTATUS __fastcall StatusFlowComparisonSample(int a1)
{
  int callStatus;
  int indirectStatus;
  int status;
  int aliasedStatus;
  int relatedStatus;
  int bitwiseResult;
  int statusMaskResult;
  int castedResult;
  int plainValue;

  callStatus = SomeStatusCall(a1);
  if ( callStatus >= 0 )
    return STATUS_SUCCESS;
  if ( callStatus == -1073741738 )
    return callStatus;
  if ( -1073740541 != callStatus )
    return STATUS_INVALID_PARAMETER;
  indirectStatus = (*(__int64 (__fastcall **)(int))(a1 + 16))(
                     a1);
  if ( indirectStatus < 0 )
  {
    if ( indirectStatus == -1073741267 )
      return indirectStatus;
  }
  aliasedStatus = SomeStatusCall(a1);
  status = aliasedStatus;
  if ( aliasedStatus != -1073741789 )
    return status;
  relatedStatus = SomeStatusCall(a1);
  status = relatedStatus;
  if ( !relatedStatus || relatedStatus == -1073741789 )
    return status;
  bitwiseResult = SomeStatusCall(a1);
  status = bitwiseResult;
  plainValue = bitwiseResult | 1;
  if ( bitwiseResult != -1073741789 )
    return status;
  statusMaskResult = SomeStatusCall(a1);
  if ( statusMaskResult >= 0 )
    return STATUS_SUCCESS;
  if ( (statusMaskResult & 0xC0000000) == 0x80000000 || statusMaskResult == -1073741191 )
    return statusMaskResult;
  castedResult = SomeStatusCall(a1);
  status = castedResult;
  if ( (_DWORD)castedResult != -1073741664 )
    return status;
  castedResult = a1 + 1;
  if ( (_DWORD)castedResult != -1073741664 )
    return STATUS_INVALID_PARAMETER;
  plainValue = a1;
  if ( (plainValue & 0xC0000000) == 0x80000000 || plainValue == -1073741191 )
    return STATUS_INVALID_PARAMETER;
  if ( plainValue >= 0 )
    return STATUS_SUCCESS;
  if ( plainValue == -1073741738 )
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}
"""


MM_INTERNAL_STATUS_SAMPLE = r"""
NTSTATUS __fastcall MiResolveMappedFileFaultSample(int a1)
{
  int v46;
  int plainValue;

  v46 = MiCopyFileOnlyGlobalSubsectionPage(a1);
  if ( v46 >= 0 )
    return 3221435187LL;
  if ( v46 == -1073532109 )
    return STATUS_MORE_PROCESSING_REQUIRED;
  plainValue = -1073532109;
  return STATUS_SUCCESS;
}

__int64 __fastcall MiDispatchFaultSample(int a1)
{
  unsigned int v15;
  unsigned int v24;
  __int64 result;
  int *outPage;

  v24 = MiResolvePageFileFault(a1);
  v15 = v24;
  result = v15;
  if ( v15 == -1073532109 )
    *outPage = a1;
  return result;
}

NTSTATUS __fastcall PlainInternalStatusSample(int a1)
{
  int plainValue;

  plainValue = -1073532109;
  if ( plainValue == -1073532109 )
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}
"""


STATUS_CALL_RESULT_COMPARISON_SAMPLE = r"""
NTSTATUS __fastcall StatusCallResultComparisonSample(HANDLE handle, int a1)
{
  int scratch;
  int internalStatus;
  int zwStatus;
  int plainResult;

  if ( ZwQuerySecurityObject(handle, 4u, 0LL, 0, &scratch) == -1073741789 )
    return STATUS_BUFFER_TOO_SMALL;
  if ( (unsigned int)InternalStatusQuery(a1) != -1073741275 )
    return STATUS_NOT_FOUND;
  if ( -1073741789 == (unsigned int)InternalStatusQuery(a1) )
    return STATUS_BUFFER_TOO_SMALL;
  internalStatus = InternalStatusQuery(a1);
  if ( internalStatus == -1073739509 )
    return internalStatus;
  zwStatus = ZwQuerySecurityObject(handle, 4u, 0LL, 0, &scratch);
  if ( zwStatus != -1073741789 )
    return zwStatus;
  plainResult = PlainIntegerCall(a1);
  if ( plainResult == -1073739509 )
    scratch = 3;
  if ( PlainIntegerCall(a1) == -1073741789 )
    scratch = 1;
  if ( (unsigned int)sub_140001000(a1) == -1073741789 )
    scratch = 2;
  return STATUS_SUCCESS;
}
"""


GUARD_DISPATCH_STATUS_FLOW_SAMPLE = r"""
NTSTATUS __fastcall GuardDispatchStatusFlowSample(__int64 a1, __int64 a2)
{
  int callbackStatus;
  int dispatchResult;
  int aliasedDispatchStatus;
  int ternaryStatus;
  int fallbackStatus;
  int alternateFallbackStatus;
  int bitwiseFallback;
  int plainValue;

  if ( a1 )
    callbackStatus = KnownCallback(a1, a2);
  else
    callbackStatus = guard_dispatch_icall_no_overrides(a1, a2);
  if ( callbackStatus == -1073741822 )
    return callbackStatus;
  if ( -1073741536 == callbackStatus )
    return callbackStatus;
  dispatchResult = guard_dispatch_icall_no_overrides(a1, a2);
  aliasedDispatchStatus = dispatchResult;
  if ( aliasedDispatchStatus != -1073741822 )
    return aliasedDispatchStatus;
  ternaryStatus = a1 == KnownCallback
      ? KnownCallback(a1, a2)
      : guard_dispatch_icall_no_overrides(a1, a2);
  if ( ternaryStatus != -1073741802 )
    return ternaryStatus;
  fallbackStatus = qword_140FD8390 ? guard_dispatch_icall_no_overrides(a1, a2) : -1073741637;
  if ( fallbackStatus < 0 )
    return fallbackStatus;
  alternateFallbackStatus = qword_140FD8390 ? -1073741637 : guard_dispatch_icall_no_overrides(a1, a2);
  if ( alternateFallbackStatus < 0 )
    return alternateFallbackStatus;
  bitwiseFallback = qword_140FD8390 ? guard_dispatch_icall_no_overrides(a1, a2) : -1073741637;
  plainValue = bitwiseFallback | 0x10000000;
  plainValue = SomeIntegerCall(a1);
  if ( plainValue == -1073741822 )
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}
"""


STATUS_CARRIER_LITERAL_SAMPLE = r"""
NTSTATUS __fastcall StatusCarrierLiteralSample(int a1, int a2)
{
  int v73;
  int v127;
  int plainValue;

  v73 = 0;
  v73 = STATUS_NO_MEMORY;
  if ( a1 )
    v73 = -2147483643;
  else
    v73 = STATUS_INTEGER_OVERFLOW;
  if ( v73 == -1073741675 )
    v127 = v73;
  v127 = STATUS_INVALID_HANDLE;
  if ( a2 )
    v127 = STATUS_SHUTDOWN_IN_PROGRESS;
  if ( a1 )
    v127 = -2147483643;
  if ( v127 != -2147483643 )
    return v127;
  plainValue = -2147483643;
  if ( plainValue == -1073741675 )
    return STATUS_INVALID_PARAMETER;
  return STATUS_SUCCESS;
}
"""


STATUS_FIELD_COMPARISON_SAMPLE = r"""
NTSTATUS __fastcall StatusFieldComparisonSample(int *context, int *plainField)
{
  int slotStatus;
  int pointerStatus;

  context[22] = -1073741536;
  slotStatus = context[22];
  if ( slotStatus == -1073741536 )
    return slotStatus;
  if ( context[22] >= 0 )
    return STATUS_SUCCESS;
  if ( context[22] == -1073741536 )
    return context[22];
  if ( *(int *)context < 0 )
  {
    if ( *(_DWORD *)context == -1073741275 )
      pointerStatus = *(_DWORD *)context;
  }
  if ( -1073741772 == *(_DWORD *)context )
    return STATUS_CANCELLED;
  plainField[2] = -1073741536;
  if ( plainField[2] == -1073741536 )
    return STATUS_INVALID_PARAMETER;
  if ( *(_DWORD *)plainField == -1073741275 )
    return STATUS_INVALID_PARAMETER;
  return (unsigned int)context[22];
}
"""


PNP_TELEMETRY_STATUS_SAMPLE = r"""
void __fastcall PiDevCfgLogDeviceConfiguredSample(int argument4)
{
  int v187;
  int plainValue;

  if ( argument4 < 0 )
  {
    if ( argument4 == -1073740959 )
      plainValue = 1;
  }
  if ( v187 < 0 )
    plainValue = 0;
  PnpTraceDeviceConfig(
    v187 == -1073741789,
    argument4);
  plainValue = 0;
  if ( plainValue < 0 )
    plainValue = 1;
  if ( plainValue == -1073740959 )
    plainValue = 2;
}
"""


STATUS_ARGUMENT_SAMPLE = r"""
void __fastcall StatusArgumentSample(__int64 a1)
{
  int status;

  status = -1073741492;
  SetFailureLocation(a1, 1, SomeHelper(1, 2), -1073741492, 96);
  SetFailureLocation(a1, 1, 34, 1073741833, 32);
  TraceFailureLocation(a1, 1, 34, -1073741492, 96);
}
"""


STATUS_POINTER_STORE_SAMPLE = r"""
void __fastcall StatusPointerStoreSample(
        int *accessStatus,
        int *plainValue,
        NTSTATUS *strongStatus,
        int *singleStatus,
        int *computedValue,
        int a6)
{
  *accessStatus = -1073741790;
  *accessStatus = 0;
  *accessStatus = -1073741811;
  *plainValue = -1073741790;
  *plainValue = 5;
  *strongStatus = -1073741275;
  *singleStatus = -1073741790;
  *computedValue = -1073741790;
  *computedValue = a6;
}
"""


LOW_DWORD_STATUS_CARRIER_SAMPLE = r"""
__int64 __fastcall LowDwordStatusCarrierSample(int a1)
{
  __int64 statusCarrier;
  __int64 singleCarrier;
  __int64 mixedCounter;

  LODWORD(statusCarrier) = SomeStatusCall(a1);
  if ( (int)statusCarrier < 0 )
    return (unsigned int)statusCarrier;
  if ( a1 == 1 )
    LODWORD(statusCarrier) = -1073741790;
  if ( a1 == 2 )
    LODWORD(statusCarrier) = -1073741811;
  LODWORD(statusCarrier) = 0;
  LODWORD(singleCarrier) = -1073741275;
  LODWORD(mixedCounter) = -1073741790;
  LODWORD(mixedCounter) = -1073741811;
  LODWORD(mixedCounter) = (_DWORD)mixedCounter + 1;
  return (unsigned int)statusCarrier;
}
"""


NESTED_DWORD_STATUS_POINTER_STORE_SAMPLE = r"""
__int64 __fastcall NestedDwordStatusPointerStoreSample(__int64 a1, __int64 a2)
{
  int *v10;
  int *v11;
  int *v12;

  **(_DWORD **)(a1 + 16) = -1073741790;
  **(_DWORD **)(a1 + 16) = 0;
  if ( **(int **)(a1 + 16) < 0 )
    return 0;
  **(_DWORD **)(a1 + 16) = -1073741659;
  v10 = *(_DWORD **)(a1 + 16);
  *v10 = -1073741811;
  **(_DWORD **)(a2 + 16) = -1073741790;
  v11 = *(_DWORD **)(a2 + 16);
  *v11 = -1073741811;
  **(_QWORD **)(a1 + 24) = 3221225626LL;
  **(_DWORD **)(a1 + 8) = -1073741790;
  **(_DWORD **)(a1 + 8) = -1073741811;
  **(_DWORD **)(a1 + 8) = 5;
  if ( **(int **)(a1 + 8) < 0 )
    return 0;
  v12 = *(_DWORD **)(a1 + 16);
  *v12 = -1073741790;
  *v12 = 5;
  return 1;
}
"""


class RenderStatusTests(unittest.TestCase):
    def test_zero_status_literal_requires_status_context(self) -> None:
        capture = capture_from_pseudocode(NON_STATUS_ZERO_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = 0;", rendered)
        self.assertNotIn("STATUS_SUCCESS", rendered)

    def test_zero_status_literal_is_kept_for_ntstatus_function(self) -> None:
        capture = capture_from_pseudocode(NTSTATUS_ZERO_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = STATUS_SUCCESS;", rendered)
        self.assertIn("return STATUS_SUCCESS;", rendered)

    def test_direct_zero_return_requires_strong_ntstatus_return_context(self) -> None:
        capture = capture_from_pseudocode(MIXED_ERROR_ZERO_RETURN_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("return STATUS_INFO_LENGTH_MISMATCH;", rendered)
        self.assertIn("return 0LL;", rendered)
        self.assertNotIn("return STATUS_SUCCESS;", rendered)

    def test_llm_status_name_does_not_enable_zero_status_assignment(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v9",
                                "new": "status",
                                "confidence": 0.90,
                                "reason": "status-like return accumulator",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(LLM_STATUS_ZERO_ASSIGNMENT_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = 0;", rendered)
        self.assertIn("status = STATUS_INVALID_PARAMETER;", rendered)
        self.assertNotIn("status = STATUS_SUCCESS;", rendered)

    def test_status_profile_covers_driver_dispatch_status_values(self) -> None:
        source = """
NTSTATUS __fastcall StatusProfileSample()
{
  int status;

  status = -1073741592;
  status = -1073741738;
  status = -1073741661;
  status = -2147483631;
  status = -1073741789;
  status = -1073741808;
  status = -1069154301;
  return status;
}
"""
        capture = capture_from_pseudocode(source)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = STATUS_INVALID_USER_BUFFER;", rendered)
        self.assertIn("status = STATUS_DELETE_PENDING;", rendered)
        self.assertIn("status = STATUS_DEVICE_NOT_READY;", rendered)
        self.assertIn("status = STATUS_DEVICE_BUSY;", rendered)
        self.assertIn("status = STATUS_BUFFER_TOO_SMALL;", rendered)
        self.assertIn("status = STATUS_INVALID_DEVICE_REQUEST;", rendered)
        self.assertIn("status = STATUS_IORING_VERSION_NOT_SUPPORTED;", rendered)
        self.assertNotIn("-1073741592", rendered)
        self.assertNotIn("-2147483631", rendered)

    def test_status_profile_includes_wdk_severity_codes_without_wait_success_values(self) -> None:
        self.assertEqual(get_status_name("0"), "STATUS_SUCCESS")
        self.assertEqual(get_status_name("259"), "STATUS_PENDING")
        self.assertEqual(get_status_name("1"), "")
        self.assertEqual(get_status_name("3225812995"), "STATUS_IORING_VERSION_NOT_SUPPORTED")
        self.assertEqual(get_status_name("-1069154301"), "STATUS_IORING_VERSION_NOT_SUPPORTED")
        self.assertEqual(get_status_name("3236823552"), "STATUS_PRM_HANDLER_NOT_FOUND")
        self.assertEqual(get_status_name("-1058078719"), "STATUS_ACCELERATOR_SUBMISSION_QUEUE_FULL")

    def test_status_profile_generator_filters_low_success_aliases(self) -> None:
        source = """
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_WAIT_0                    ((NTSTATUS)0x00000000L)
#define STATUS_WAIT_1                    ((NTSTATUS)0x00000001L)
#define STATUS_PENDING                   ((NTSTATUS)0x00000103L)
#define STATUS_OBJECT_NAME_EXISTS        ((NTSTATUS)0x40000000L)
#define STATUS_DEVICE_BUSY               ((NTSTATUS)0x80000011L)
#define STATUS_IORING_VERSION_NOT_SUPPORTED ((NTSTATUS)0xC0460003L)
"""
        profile = build_status_code_profile(parse_ntstatus_definitions(source))

        self.assertEqual(profile["0"], "STATUS_SUCCESS")
        self.assertNotIn("1", profile)
        self.assertEqual(profile["259"], "STATUS_PENDING")
        self.assertEqual(profile["1073741824"], "STATUS_OBJECT_NAME_EXISTS")
        self.assertEqual(profile["2147483665"], "STATUS_DEVICE_BUSY")
        self.assertEqual(profile["-2147483631"], "STATUS_DEVICE_BUSY")
        self.assertEqual(profile["3225812995"], "STATUS_IORING_VERSION_NOT_SUPPORTED")
        self.assertEqual(profile["-1069154301"], "STATUS_IORING_VERSION_NOT_SUPPORTED")

    def test_error_status_literals_rewrite_in_32bit_assignments_and_stores(self) -> None:
        source = """
__int64 __fastcall StatusStoreSample(__int64 a1)
{
  unsigned int v16;
  __int64 v17;

  v16 = 0xC000009A;
  *(_DWORD *)(a1 + 784) = 0xC000009A;
  *((_DWORD *)a1 + 6) = -1073741670;
  v17 = 0xC000009A;
  *(_QWORD *)(a1 + 792) = 0xC000009A;
  return v16;
}
"""
        capture = capture_from_pseudocode(source)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("v16 = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("*(_DWORD *)(argument0 + 784) = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("*((_DWORD *)argument0 + 6) = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("v17 = 0xC000009A;", rendered)
        self.assertIn("*(_QWORD *)(argument0 + 792) = 0xC000009A;", rendered)

    def test_status_comparisons_and_raise_status_literals_are_named(self) -> None:
        capture = capture_from_pseudocode(STATUS_COMPARISON_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("status == STATUS_CROSS_PARTITION_VIOLATION", rendered)
        self.assertIn("STATUS_CROSS_PARTITION_VIOLATION == status", rendered)
        self.assertIn("v194 != STATUS_VALIDATE_CONTINUE", rendered)
        self.assertIn("v195 != -1073741199", rendered)
        self.assertIn("RtlRaiseStatus(STATUS_INVALID_PARAMETER);", rendered)
        self.assertIn("buildNumber == -1073740277", rendered)

    def test_status_ternary_error_arms_are_named_for_32bit_status_candidates(self) -> None:
        capture = capture_from_pseudocode(STATUS_TERNARY_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("v26 = argument0 < argument1 ? STATUS_INTEGER_OVERFLOW : 0;", rendered)
        self.assertIn("v27 = argument0 ? 0 : STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("status = argument0 ? STATUS_INTEGER_OVERFLOW : 0LL;", rendered)
        self.assertIn("mask = argument0 ? 0xC0000095 : 0;", rendered)
        self.assertIn("desiredAccess = argument0 ? 0xC0000095 : 0;", rendered)

    def test_status_alias_comparison_literals_are_named_in_same_expression(self) -> None:
        capture = capture_from_pseudocode(STATUS_ALIAS_COMPARISON_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("status = v26, v26 == STATUS_PTE_CHANGED", rendered)
        self.assertIn("status = v26, STATUS_INTEGER_OVERFLOW == v26", rendered)
        self.assertIn("buildNumber = v27, v27 == -1073740748", rendered)

    def test_status_flow_comparison_literals_require_call_result_and_range_check(self) -> None:
        capture = capture_from_pseudocode(STATUS_FLOW_COMPARISON_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("callStatus == STATUS_DELETE_PENDING", rendered)
        self.assertIn("STATUS_CALLBACK_BYPASS != callStatus", rendered)
        self.assertIn("indirectStatus == STATUS_RETRY", rendered)
        self.assertIn("aliasedStatus != STATUS_BUFFER_TOO_SMALL", rendered)
        self.assertIn("relatedStatus == STATUS_BUFFER_TOO_SMALL", rendered)
        self.assertIn("bitwiseResult != -1073741789", rendered)
        self.assertIn("(statusMaskResult & 0xC0000000) == 0x80000000", rendered)
        self.assertIn("statusMaskResult == STATUS_IO_REPARSE_TAG_NOT_HANDLED", rendered)
        self.assertIn("plainValue == -1073741191", rendered)
        self.assertEqual(1, rendered.count("(_DWORD)castedResult != STATUS_MEMORY_NOT_ALLOCATED"))
        self.assertEqual(1, rendered.count("(_DWORD)castedResult != -1073741664"))
        self.assertIn("plainValue == -1073741738", rendered)

    def test_mm_internal_status_sentinel_is_named_only_in_mm_fault_context(self) -> None:
        capture = capture_from_pseudocode(MM_INTERNAL_STATUS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("return MI_STATUS_PAGE_READ_REQUIRED;", rendered)
        self.assertIn("v46 == MI_STATUS_PAGE_READ_REQUIRED", rendered)
        self.assertIn("v15 == MI_STATUS_PAGE_READ_REQUIRED", rendered)
        self.assertIn("plainValue = -1073532109;", rendered)
        self.assertIn("plainValue == -1073532109", rendered)

    def test_status_call_result_comparison_literals_are_named_for_trusted_calls(self) -> None:
        capture = capture_from_pseudocode(STATUS_CALL_RESULT_COMPARISON_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("ZwQuerySecurityObject(handle, 4u, 0LL, 0, &scratch) == STATUS_BUFFER_TOO_SMALL", rendered)
        self.assertIn("(unsigned int)InternalStatusQuery(argument1) != STATUS_NOT_FOUND", rendered)
        self.assertIn("STATUS_BUFFER_TOO_SMALL == (unsigned int)InternalStatusQuery(argument1)", rendered)
        self.assertIn("internalStatus == STATUS_BAD_DATA", rendered)
        self.assertIn("zwStatus != STATUS_BUFFER_TOO_SMALL", rendered)
        self.assertIn("plainResult == -1073739509", rendered)
        self.assertIn("PlainIntegerCall(argument1) == -1073741789", rendered)
        self.assertIn("(unsigned int)sub_140001000(argument1) == -1073741789", rendered)

    def test_guard_dispatch_status_flow_comparison_literals_are_named(self) -> None:
        capture = capture_from_pseudocode(GUARD_DISPATCH_STATUS_FLOW_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("callbackStatus == STATUS_NOT_IMPLEMENTED", rendered)
        self.assertIn("STATUS_CANCELLED == callbackStatus", rendered)
        self.assertIn("aliasedDispatchStatus != STATUS_NOT_IMPLEMENTED", rendered)
        self.assertIn("ternaryStatus != STATUS_MORE_PROCESSING_REQUIRED", rendered)
        self.assertIn(
            "fallbackStatus = qword_140FD8390 ? guard_dispatch_icall_no_overrides(argument0, argument1) : STATUS_NOT_SUPPORTED;",
            rendered,
        )
        self.assertIn(
            "alternateFallbackStatus = qword_140FD8390 ? STATUS_NOT_SUPPORTED : guard_dispatch_icall_no_overrides(argument0, argument1);",
            rendered,
        )
        self.assertIn(
            "bitwiseFallback = qword_140FD8390 ? guard_dispatch_icall_no_overrides(argument0, argument1) : -1073741637;",
            rendered,
        )
        self.assertIn("plainValue = bitwiseFallback | 0x10000000;", rendered)
        self.assertIn("plainValue == -1073741822", rendered)

    def test_status_carrier_literals_are_named_after_status_assignments(self) -> None:
        capture = capture_from_pseudocode(STATUS_CARRIER_LITERAL_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("v73 = 0;", rendered)
        self.assertIn("v73 = STATUS_BUFFER_OVERFLOW;", rendered)
        self.assertIn("v73 == STATUS_INTEGER_OVERFLOW", rendered)
        self.assertIn("v127 = STATUS_BUFFER_OVERFLOW;", rendered)
        self.assertIn("v127 != STATUS_BUFFER_OVERFLOW", rendered)
        self.assertIn("plainValue = -2147483643;", rendered)
        self.assertIn("plainValue == -1073741675", rendered)

    def test_pnp_telemetry_status_comparisons_are_named_after_range_checks(self) -> None:
        capture = capture_from_pseudocode(PNP_TELEMETRY_STATUS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("argument0 == STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT", rendered)
        self.assertIn("v187 == STATUS_BUFFER_TOO_SMALL", rendered)
        self.assertIn("plainValue == -1073740959", rendered)

    def test_status_field_comparisons_are_named_for_status_slots(self) -> None:
        capture = capture_from_pseudocode(STATUS_FIELD_COMPARISON_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("context[22] = STATUS_CANCELLED;", rendered)
        self.assertIn("slotStatus == STATUS_CANCELLED", rendered)
        self.assertIn("context[22] == STATUS_CANCELLED", rendered)
        self.assertIn("*(_DWORD *)context == STATUS_NOT_FOUND", rendered)
        self.assertIn("STATUS_OBJECT_NAME_NOT_FOUND == *(_DWORD *)context", rendered)
        self.assertIn("plainField[2] = -1073741536;", rendered)
        self.assertIn("plainField[2] == -1073741536", rendered)
        self.assertIn("*(_DWORD *)plainField == -1073741275", rendered)

    def test_profiled_status_argument_literals_are_named(self) -> None:
        capture = capture_from_pseudocode(STATUS_ARGUMENT_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "SetFailureLocation(argument0, 1, SomeHelper(1, 2), STATUS_REGISTRY_CORRUPT, 96);",
            rendered,
        )
        self.assertIn("SetFailureLocation(argument0, 1, 34, 1073741833, 32);", rendered)
        self.assertIn("TraceFailureLocation(argument0, 1, 34, -1073741492, 96);", rendered)

    def test_status_pointer_store_literals_are_named_for_status_out_params(self) -> None:
        capture = capture_from_pseudocode(STATUS_POINTER_STORE_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("*argument0 = STATUS_ACCESS_DENIED;", rendered)
        self.assertIn("*argument0 = 0;", rendered)
        self.assertIn("*argument0 = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("*strongStatus = STATUS_NOT_FOUND;", rendered)
        self.assertIn("*singleStatus = STATUS_ACCESS_DENIED;", rendered)
        self.assertIn("*plainValue = -1073741790;", rendered)
        self.assertIn("*computedValue = -1073741790;", rendered)

    def test_low_dword_status_carrier_literals_are_named_conservatively(self) -> None:
        capture = capture_from_pseudocode(LOW_DWORD_STATUS_CARRIER_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("LODWORD(statusCarrier) = STATUS_ACCESS_DENIED;", rendered)
        self.assertIn("LODWORD(statusCarrier) = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("LODWORD(statusCarrier) = 0;", rendered)
        self.assertIn("LODWORD(singleCarrier) = -1073741275;", rendered)
        self.assertIn("LODWORD(mixedCounter) = -1073741790;", rendered)
        self.assertIn("LODWORD(mixedCounter) = -1073741811;", rendered)
        self.assertIn("LODWORD(mixedCounter) = (_DWORD)mixedCounter + 1;", rendered)

    def test_nested_dword_status_pointer_store_literals_are_named_conservatively(self) -> None:
        capture = capture_from_pseudocode(NESTED_DWORD_STATUS_POINTER_STORE_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("**(_DWORD **)(context + 16) = STATUS_ACCESS_DENIED;", rendered)
        self.assertIn("**(_DWORD **)(context + 16) = 0;", rendered)
        self.assertIn("**(_DWORD **)(context + 16) = STATUS_BAD_IMPERSONATION_LEVEL;", rendered)
        self.assertIn("*v10 = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("**(_DWORD **)(argument1 + 16) = -1073741790;", rendered)
        self.assertIn("*v11 = -1073741811;", rendered)
        self.assertIn("**(_QWORD **)(context + 24) = 3221225626LL;", rendered)
        self.assertIn("**(_DWORD **)(context + 8) = -1073741790;", rendered)
        self.assertIn("**(_DWORD **)(context + 8) = -1073741811;", rendered)
        self.assertIn("**(_DWORD **)(context + 8) = 5;", rendered)
        self.assertIn("*v12 = -1073741790;", rendered)
        self.assertIn("*v12 = 5;", rendered)


if __name__ == "__main__":
    unittest.main()
