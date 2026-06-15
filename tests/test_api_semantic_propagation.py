from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode


class ApiSemanticPropagationTests(unittest.TestCase):
    def test_profile_parameter_names_rename_matching_kernel_api_arguments(self) -> None:
        capture = capture_from_pseudocode(
            r"""
NTSTATUS __fastcall NtSetInformationVirtualMemory(
        HANDLE a1,
        VIRTUAL_MEMORY_INFORMATION_CLASS a2,
        ULONG_PTR a3,
        PMEMORY_RANGE_ENTRY a4,
        PVOID a5,
        ULONG a6)
{
  if ( a3 )
    return 0;
  return -1073741811;
}
"""
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("processHandle", active["a1"])
        self.assertEqual("vmInformationClass", active["a2"])
        self.assertEqual("numberOfEntries", active["a3"])
        self.assertEqual("virtualAddresses", active["a4"])
        self.assertEqual("vmInformation", active["a5"])
        self.assertEqual("vmInformationLength", active["a6"])

    def test_profiled_call_arguments_rename_generic_wrapper_parameters(self) -> None:
        capture = capture_from_pseudocode(
            r"""
NTSTATUS __fastcall Wrapper(__int64 a1, __int64 a2, char a3)
{
  return KeDelayExecutionThread(a1, a3, a2);
}
"""
        )

        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("waitMode", active["a1"])
        self.assertEqual("interval", active["a2"])
        self.assertEqual("alertable", active["a3"])
        self.assertIn("KeDelayExecutionThread(waitMode, alertable, interval)", rendered)

    def test_profiled_out_parameter_renames_address_taken_generic_local(self) -> None:
        capture = capture_from_pseudocode(
            r"""
NTSTATUS __fastcall LookupProcess(__int64 a1)
{
  NTSTATUS status;
  __int64 v1;

  status = PsLookupProcessByProcessId(a1, (PEPROCESS *)&v1);
  if ( status >= 0 )
    ObDereferenceObject(v1);
  return status;
}
"""
        )

        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("processId", active["a1"])
        self.assertEqual("process", active["v1"])
        self.assertIn("PsLookupProcessByProcessId(processId, (PEPROCESS *)&process)", rendered)
        self.assertIn("ObDereferenceObject(process)", rendered)

    def test_conflicting_profiled_argument_roles_are_not_propagated(self) -> None:
        capture = capture_from_pseudocode(
            r"""
NTSTATUS __fastcall AmbiguousWrapper(__int64 a1)
{
  KeDelayExecutionThread(a1, 0, 0);
  return KeWaitForSingleObject(a1, 0, 0, 0, 0);
}
"""
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertNotEqual("waitMode", active.get("a1"))
        self.assertNotEqual("object", active.get("a1"))
        self.assertTrue(
            any(
                item.get("stage") == "api-argument"
                and item.get("reason") == "conflict_old"
                and item.get("old") == "a1"
                for item in plan.rule_report.get("api_semantic_diagnostics", [])
            )
        )

    def test_large_dispatcher_api_out_parameter_rejection_is_reported(self) -> None:
        branches = "\n".join(
            "  if ( a1 == %d )\n    return %d;" % (index, index)
            for index in range(16)
        )
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall LargeLookupDispatcher(__int64 a1)
{
  __int64 v1; // [rsp+20h] [rbp-8h] BYREF

%s
  return PsLookupProcessByProcessId(a1, (PEPROCESS *)&v1);
}
"""
            % branches
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}
        diagnostics = plan.rule_report.get("api_semantic_diagnostics", [])

        self.assertNotEqual("process", active.get("v1"))
        self.assertTrue(
            any(
                item.get("stage") == "api-out-param"
                and item.get("reason") == "large_dispatcher"
                and item.get("old") == "v1"
                and item.get("new") == "process"
                for item in diagnostics
            )
        )

    def test_large_dispatcher_repeated_api_argument_role_is_propagated(self) -> None:
        branches = "\n".join(
            "  if ( a1 == %d )\n    return %d;" % (index, index)
            for index in range(16)
        )
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall LargeObjectDispatcher(__int64 a1)
{
  __int64 v1;

%s
  KeWaitForSingleObject(v1, 0, 0, 0, 0);
  KeWaitForSingleObject(v1, 0, 0, 0, 0);
  return 0;
}
"""
            % branches
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("object", active["v1"])

    def test_large_dispatcher_repeated_api_out_parameter_role_is_propagated(self) -> None:
        branches = "\n".join(
            "  if ( a1 == %d )\n    return %d;" % (index, index)
            for index in range(16)
        )
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall LargeLookupDispatcher(__int64 a1, __int64 a2)
{
  __int64 v1; // [rsp+20h] [rbp-8h] BYREF

%s
  PsLookupProcessByProcessId(a1, (PEPROCESS *)&v1);
  PsLookupProcessByProcessId(a2, (PEPROCESS *)&v1);
  return 0;
}
"""
            % branches
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("process", active["v1"])

    def test_large_dispatcher_single_use_wrapper_local_role_is_propagated(self) -> None:
        branches = "\n".join(
            "  if ( a1 == %d )\n    return %d;" % (index, index)
            for index in range(16)
        )
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall LargeObjectDispatcher(__int64 a1)
{
  __int64 v1;

%s
  v1 = a1;
  KeWaitForSingleObject(v1, 0, 0, 0, 0);
  return 0;
}
"""
            % branches
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("object", active["v1"])

    def test_large_dispatcher_conflicting_api_roles_are_not_propagated(self) -> None:
        branches = "\n".join(
            "  if ( a1 == %d )\n    return %d;" % (index, index)
            for index in range(16)
        )
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall LargeAmbiguousDispatcher(__int64 a1)
{
  __int64 v1;

%s
  KeDelayExecutionThread(v1, 0, 0);
  KeWaitForSingleObject(v1, 0, 0, 0, 0);
  return 0;
}
"""
            % branches
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}

        self.assertNotEqual("waitMode", active.get("v1"))
        self.assertNotEqual("object", active.get("v1"))

    def test_unsafe_wrapper_role_rejection_is_reported(self) -> None:
        capture = capture_from_pseudocode(
            r"""
__int64 __fastcall CompleteIrpHelper(int a1, __int64 a2)
{
  IofCompleteRequest((IRP *)a2, 0);
  return (unsigned int)a1;
}
"""
        )

        plan = build_clean_plan(capture)
        active = {item.old: item.new for item in plan.active_renames()}
        diagnostics = plan.rule_report.get("api_semantic_diagnostics", [])

        self.assertNotEqual("irp", active.get("a2"))
        self.assertTrue(
            any(
                item.get("stage") == "api-argument"
                and item.get("reason") == "unsafe_wrapper_role"
                and item.get("old") == "a2"
                and item.get("new") == "irp"
                for item in diagnostics
            )
        )


if __name__ == "__main__":
    unittest.main()
