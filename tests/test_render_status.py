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
  int buildNumber;

  sectionCreateStatus = -1073741811;
  if ( sectionCreateStatus == -1073740277 )
    RtlRaiseStatus(-1073741811);
  if ( -1073740277 == sectionCreateStatus )
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


if __name__ == "__main__":
    unittest.main()
