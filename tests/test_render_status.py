from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode


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

    def test_error_status_literals_rewrite_in_32bit_assignments_and_stores(self) -> None:
        source = """
__int64 __fastcall StatusStoreSample(__int64 a1)
{
  unsigned int v16;
  __int64 v17;

  v16 = 0xC000009A;
  *(_DWORD *)(a1 + 784) = 0xC000009A;
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
        self.assertIn("v17 = 0xC000009A;", rendered)
        self.assertIn("*(_QWORD *)(argument0 + 792) = 0xC000009A;", rendered)


if __name__ == "__main__":
    unittest.main()
