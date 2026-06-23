from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable, RenameSuggestion
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.validation import unassigned_local_usage_diagnostics, unassigned_local_usage_warnings
from tests.helpers import JsonRenameProvider


BAD_INVARIANT_RENAME_SAMPLE = r"""
__int64 __fastcall BadInvariantRenameSample(int a1)
{
  int v7;
  __int64 v8;
  KPROCESSOR_MODE PreviousMode;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  v7 = 1;
  v8 = 1LL;
  if ( a1 )
    v7 = a1;
  LOBYTE(v8) = PreviousMode;
  return v7 + v8;
}
"""


WEAK_LLM_DISPATCHER_SAMPLE = (
    r"""
__int64 __fastcall LargeDispatcherSample(int a1, void *a2)
{
  int v5;
  void *Buf1[2];
  void *Src[2];
  _DWORD v118[2];
  int v126;
  void *v200;
  __int64 result;
  ULONG v38;
  int v113;
  HANDLE v138;
  HANDLE v146;

  v5 = a1;
  Buf1[0] = 0LL;
  Src[0] = a2;
  v118[0] = 0;
  v126 = 0;
  v200 = a2;
  result = VfProbeAndCaptureUnicodeString(Buf1, a2, 1LL);
  v38 = VfAddVerifierEntry((PCUNICODE_STRING)a2);
  v113 = v5 - 219;
  v138 = (HANDLE)a2;
  v146 = (HANDLE)Src[0];
  VfProbeAndCaptureUnicodeString(Buf1, a2, 1LL);
"""
    + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
    + r"""
  Buf1[1] = Src[0];
  v118[1] = v126;
  if ( v113 == 1 )
    v38 = VfRemoveVerifierEntry(Buf1, a2, v5, 1LL);
  ObReferenceObjectByHandle(v138, 2u, 0LL, 1, &v146, 0LL);
  result = ExSetLeapSecondEnabled();
  if ( v200 )
    return v118[0];
  return v126 + v38 + result;
}
"""
)


POINTER_BOUND_RENAME_SAMPLE = r"""
__int64 __fastcall PointerBoundRenameSample(void *a1, unsigned __int16 a2)
{
  void *Src[2];
  char *v93;

  Src[1] = a1;
  v93 = (char *)Src[1] + a2;
  if ( (unsigned __int64)v93 > 0x7FFFFFFF0000LL || v93 < Src[1] )
    return 0;
  return a2;
}
"""


MIOBTAIN_SYSTEM_VA_SAMPLE = r"""
__int64 __fastcall MiObtainSystemVa(__int64 a1, unsigned int a2)
{
  __int64 v2;
  unsigned int v3;

  v2 = MiSystemVaToDynamicBitmap(a2);
  return MiObtainDynamicVa(v2, v3);
}
"""


OUT_PARAM_LOCAL_SAMPLE = r"""
NTSTATUS __fastcall OutParamLocalSample(HANDLE a1)
{
  NTSTATUS status;
  void *v1;

  status = PsLookupProcessByProcessId(a1, (PEPROCESS *)&v1);
  if ( status >= 0 )
    ObDereferenceObject(v1);
  return status;
}
"""


class LlmRenameFilterTests(unittest.TestCase):
    def test_llm_invariant_names_are_rejected_when_values_change(self) -> None:
        capture = capture_from_pseudocode(BAD_INVARIANT_RENAME_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v7",
                        "new": "booleanTrue",
                        "confidence": 0.90,
                        "reason": "initialized to one",
                    },
                    {
                        "old": "v8",
                        "new": "one",
                        "confidence": 0.90,
                        "reason": "initialized to one",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v7", rename_map)
        self.assertNotIn("v8", rename_map)
        self.assertIn("Skipped value-invariant rename v7->booleanTrue", plan.warnings)
        self.assertIn("Skipped value-invariant rename v8->one", plan.warnings)
        self.assertNotIn("int booleanTrue", rendered)
        self.assertNotIn("__int64 one", rendered)
        self.assertNotIn("LOBYTE(one)", rendered)

    def test_weak_llm_context_names_are_rejected_in_large_dispatchers(self) -> None:
        capture = capture_from_pseudocode(WEAK_LLM_DISPATCHER_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "Buf1",
                        "new": "capturedUnicodeString",
                        "confidence": 0.90,
                        "reason": "temporary captured unicode string",
                    },
                    {
                        "old": "Src",
                        "new": "capturedUnicodeStringBuffer",
                        "confidence": 0.90,
                        "reason": "temporary captured unicode string buffer",
                    },
                    {
                        "old": "v118",
                        "new": "flagsScratch",
                        "confidence": 0.90,
                        "reason": "temporary flags",
                    },
                    {
                        "old": "v126",
                        "new": "scratchFlags",
                        "confidence": 0.90,
                        "reason": "temporary flags",
                    },
                    {
                        "old": "result",
                        "new": "statusResult",
                        "confidence": 0.90,
                        "reason": "status returned by helper calls",
                    },
                    {
                        "old": "v38",
                        "new": "verifierStatus",
                        "confidence": 0.90,
                        "reason": "verifier helper status",
                    },
                    {
                        "old": "v113",
                        "new": "difVerificationOperation",
                        "confidence": 0.90,
                        "reason": "operation selector",
                    },
                    {
                        "old": "v138",
                        "new": "inputHandle",
                        "confidence": 0.90,
                        "reason": "input handle",
                    },
                    {
                        "old": "v146",
                        "new": "targetHandle",
                        "confidence": 0.90,
                        "reason": "target handle",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        normalized_body = rendered.split("PseudoForge normalized original pseudocode.", 1)[-1]
        section = render_forge_function_section(capture, plan, rendered)

        self.assertNotIn("Buf1", rename_map)
        self.assertNotIn("Src", rename_map)
        self.assertNotIn("v118", rename_map)
        self.assertNotIn("v126", rename_map)
        self.assertNotIn("result", rename_map)
        self.assertNotIn("v38", rename_map)
        self.assertNotIn("v113", rename_map)
        self.assertNotIn("v138", rename_map)
        self.assertNotIn("v146", rename_map)
        self.assertIn("Skipped reused dispatcher rename Buf1->capturedUnicodeString", plan.warnings)
        self.assertIn("Skipped reused dispatcher rename Src->capturedUnicodeStringBuffer", plan.warnings)
        self.assertIn("Skipped weak dispatcher rename v118->flagsScratch", plan.warnings)
        self.assertIn("Skipped weak dispatcher rename v126->scratchFlags", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename result->statusResult", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v38->verifierStatus", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v113->difVerificationOperation", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v138->inputHandle", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v146->targetHandle", plan.warnings)
        self.assertNotIn("Skipped weak dispatcher rename", rendered)
        self.assertNotIn("Skipped unsupported dispatcher rename", rendered)
        self.assertNotIn("Skipped reused dispatcher rename", rendered)
        self.assertIn("void *Buf1[2];", rendered)
        self.assertIn("void *Src[2];", rendered)
        self.assertIn("_DWORD v118[2];", rendered)
        self.assertIn("int v126;", rendered)
        self.assertIn("__int64 result;", rendered)
        self.assertIn("ULONG v38;", rendered)
        self.assertIn("int v113;", rendered)
        self.assertIn("HANDLE v138;", rendered)
        self.assertIn("HANDLE v146;", rendered)
        self.assertNotIn("void *capturedUnicodeString", rendered)
        self.assertNotIn("void *capturedUnicodeStringBuffer", rendered)
        self.assertNotIn("_DWORD flagsScratch", rendered)
        self.assertNotIn("int scratchFlags", rendered)
        self.assertNotIn("statusResult", normalized_body)
        self.assertNotIn("verifierStatus", normalized_body)
        self.assertNotIn("difVerificationOperation", normalized_body)
        self.assertNotIn("inputHandle", normalized_body)
        self.assertNotIn("targetHandle", normalized_body)
        self.assertIn("// Warnings: 0", section)
        self.assertIn("    Warnings: 0", section)

    def test_stable_status_llm_rename_is_salvaged_in_large_dispatcher(self) -> None:
        sample = (
            r"""
NTSTATUS __fastcall LargeStatusDispatcher(int a1)
{
  int v5;
  int v10;

  v5 = a1;
  v10 = -1073741670;
  if ( v5 == 1 )
  {
    v10 = IopGetRegistryValue(0LL, 0LL, 0, 0LL);
    if ( v10 < 0 )
      return (unsigned int)v10;
  }
"""
            + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
            + r"""
  if ( v10 >= 0 )
    return (unsigned int)v10;
  RtlRaiseStatus(v10);
  return (unsigned int)v10;
}
"""
        )
        capture = capture_from_pseudocode(sample)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v10",
                        "new": "status",
                        "confidence": 0.90,
                        "reason": "carries NTSTATUS values through the dispatcher",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("status", rename_map["v10"])
        self.assertNotIn("Skipped unsupported dispatcher rename v10->status", plan.warnings)
        self.assertNotIn("Skipped reused dispatcher rename v10->status", plan.warnings)

    def test_status_like_flag_llm_rename_is_not_salvaged_in_large_dispatcher(self) -> None:
        sample = (
            r"""
__int64 __fastcall LargeStatusFlagDispatcher(__int64 a1)
{
  int v5;
  int *v33;
  int v48;

  v5 = (int)a1;
  v33 = (int *)(a1 + 2520);
  v48 = *(_DWORD *)(a1 + 2524) | 0x400;
  *(_DWORD *)(a1 + 2524) = v48;
"""
            + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
            + r"""
  if ( (*v33 & 0x8000000) == 0 )
    return v48;
  return 0;
}
"""
        )
        capture = capture_from_pseudocode(sample)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v48",
                        "new": "updatedStatusValue",
                        "confidence": 0.90,
                        "reason": "status-like bitfield value",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertNotIn("v48", rename_map)
        self.assertIn("Skipped unsupported dispatcher rename v48->updatedStatusValue", plan.warnings)

    def test_stable_handle_llm_rename_is_salvaged_in_large_dispatcher(self) -> None:
        sample = (
            r"""
__int64 __fastcall LargeHandleDispatcher(int a1)
{
  int v5;
  HANDLE Handle;

  v5 = a1;
  Handle = 0LL;
"""
            + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
            + r"""
  if ( (int)IopCreateFile((int)&Handle, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) < 0 )
    return 0;
  if ( Handle )
    ObCloseHandle(Handle, 0);
  return 0;
}
"""
        )
        capture = capture_from_pseudocode(sample)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "Handle",
                        "new": "fileHandle",
                        "confidence": 0.90,
                        "reason": "local file handle is opened and closed in this function",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("fileHandle", rename_map["Handle"])
        self.assertNotIn("Skipped reused dispatcher rename Handle->fileHandle", plan.warnings)

    def test_shadowed_llm_skip_warning_is_removed_when_stronger_rename_wins(self) -> None:
        capture = capture_from_pseudocode(
            WEAK_LLM_DISPATCHER_SAMPLE.replace(
                "int v5;\n",
                "int v5;\n  struct _KPROCESS *Process;\n",
            ).replace(
                "v5 = a1;\n",
                "v5 = a1;\n  Process = KeGetCurrentThread()->ApcState.Process;\n",
            ).replace(
                "HANDLE v146;",
                "HANDLE v146;\n  UNICODE_STRING DriverServiceName;",
            )
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "DriverServiceName",
                        "new": "driverServiceName",
                        "confidence": 0.90,
                        "reason": "driver service name",
                    }
                ],
                "warnings": [
                    "Skipped reused dispatcher rename DriverServiceName->driverServiceName",
                    "Skipped reused dispatcher rename Process->process",
                ],
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["DriverServiceName"], "driverServiceName")
        self.assertNotIn("Skipped reused dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertNotIn("Skipped unsupported dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertEqual(rename_map["Process"], "currentProcess")
        self.assertNotIn("Skipped reused dispatcher rename Process->process", plan.warnings)

    def test_pointer_bound_llm_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(POINTER_BOUND_RENAME_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v93",
                        "new": "destinationBuffer",
                        "confidence": 0.90,
                        "reason": "computed destination buffer",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("v93", rename_map)
        self.assertIn("Skipped pointer-bound rename v93->destinationBuffer", plan.warnings)
        self.assertIn("char *v93;", rendered)
        self.assertNotIn("destinationBuffer", body)

    def test_unassigned_call_argument_llm_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(MIOBTAIN_SYSTEM_VA_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v2",
                        "new": "dynamicBitmapPtr",
                        "confidence": 0.91,
                        "reason": "result of MiSystemVaToDynamicBitmap",
                    },
                    {
                        "old": "v3",
                        "new": "allocationSize",
                        "confidence": 0.91,
                        "reason": "second argument to MiObtainDynamicVa",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertEqual("dynamicBitmapPtr", rename_map["v2"])
        self.assertNotIn("v3", rename_map)
        self.assertTrue(
            any(
                warning.startswith(
                    "Uninitialized local risk: skipped LLM rename v3->allocationSize"
                )
                for warning in plan.warnings
            )
        )
        self.assertIn("__int64 dynamicBitmapPtr;", rendered)
        self.assertIn("unsigned int v3;", rendered)
        self.assertIn("MiObtainDynamicVa(dynamicBitmapPtr, v3)", body)
        self.assertNotIn("allocationSize", body)

    def test_address_taken_unassigned_out_param_llm_rename_is_allowed(self) -> None:
        capture = capture_from_pseudocode(OUT_PARAM_LOCAL_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v1",
                        "new": "process",
                        "confidence": 0.91,
                        "reason": "receives process object through out parameter",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("process", rename_map["v1"])
        self.assertFalse(any("Uninitialized local risk" in warning for warning in plan.warnings))

    def test_unassigned_local_warning_preserves_non_llm_rename(self) -> None:
        capture = capture_from_pseudocode(MIOBTAIN_SYSTEM_VA_SAMPLE)
        renames = [
            RenameSuggestion(
                kind="lvar",
                old="v3",
                new="allocationSize",
                confidence=0.91,
                source="kernel-api",
                evidence="api parameter role",
                apply=True,
            )
        ]

        warnings = unassigned_local_usage_warnings(capture, renames)

        self.assertTrue(renames[0].apply)
        self.assertTrue(
            any(
                "v3 renamed to allocationSize by kernel-api" in warning
                for warning in warnings
            )
        )

    def test_comma_assignment_locals_are_not_reported_as_unassigned(self) -> None:
        capture = capture_from_pseudocode(
            """
void __fastcall CommaAssignmentSample(__int64 context)
{
  __int64 Size;
  __int64 Type;
  __int64 v52;
  unsigned int v53;
  __int64 v60;
  int missing;

  if ( (v52 = *(_QWORD *)(context + 248), (v53 = *(_DWORD *)(v52 + 104)) != 0) )
    *(_DWORD *)(v52 + 104) = v53 - 1;
  if ( (Size = *(_QWORD *)(context + 8), Type = *(unsigned int *)(context + 16), (v60 = guard_dispatch_icall_no_overrides(Type, Size)) != 0) )
    UseAllocated(v60);
  UseMissing(missing);
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertTrue(any("missing is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("Size is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("Type is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v52 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v53 is declared but has no direct assignment" in warning for warning in warnings))

    def test_known_noarg_helper_placeholders_are_not_reported_as_unassigned(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall ApcDeliveryPlaceholderSample(__int64 context)
{
  __int64 v7;
  __int64 v8;
  __int64 v9;
  __int64 v43;
  __int64 v44;
  __int64 v45;
  int missing;

  KiCheckForKernelApcDelivery(1LL, v7, v8, v9);
  if ( context )
    return (__int64)KiCheckForKernelApcDelivery(v44, v43, v45, v9);
  UseMissing(missing);
  return context;
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertTrue(any("missing is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v7 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v8 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v9 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v43 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v44 is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("v45 is declared but has no direct assignment" in warning for warning in warnings))

    def test_member_assignment_locals_are_not_reported_as_unassigned(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MemberAssignmentSample()
{
  unsigned int v7; // r13d
  unsigned int v9; // ebx
  unsigned int missing; // r8d

  v7.AllFields = 0;
  v9.AllFields = 537133055;
  return UsePair(__PAIR64__(v9.AllFields, v7.AllFields), missing);
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertFalse(any("v7 appears to be a live-in register value" in warning for warning in warnings))
        self.assertFalse(any("v9 appears to be a live-in register value" in warning for warning in warnings))
        self.assertTrue(any("missing appears to be a live-in register value (r8d)" in warning for warning in warnings))

    def test_member_update_operators_are_assignment_evidence(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MemberUpdateOperatorSample()
{
  unsigned int v10;
  unsigned int v11;
  unsigned int v12;
  unsigned int v13;
  unsigned int v14;
  unsigned int v15;
  unsigned int v16;

  v10.Flags += 1;
  v11.Flags -= 1;
  v12.Flags |= 1;
  v13.Flags &= 1;
  v14.Flags ^= 1;
  v15.Flags++;
  v16.Flags--;
  return UseFields(v10.Flags, v11.Flags, v12.Flags, v13.Flags, v14.Flags, v15.Flags, v16.Flags);
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        for name in ("v10", "v11", "v12", "v13", "v14", "v15", "v16"):
            self.assertFalse(any("%s is declared but has no direct assignment" % name in warning for warning in warnings))

    def test_member_assignment_requires_exact_root_local_name(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MemberAssignmentNameBoundarySample()
{
  unsigned int v7; // r13d
  unsigned int v70;

  v70.AllFields = 1;
  return UseValue(v7);
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertTrue(any("v7 appears to be a live-in register value (r13d)" in warning for warning in warnings))
        self.assertFalse(any("v70 is declared but has no direct assignment" in warning for warning in warnings))

    def test_member_read_and_comparison_do_not_count_as_assignment_evidence(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MemberReadComparisonSample()
{
  unsigned int v7; // r13d
  unsigned int v8; // r8d

  if ( v7.AllFields == 0 )
    return UseField(v7.AllFields);
  return UseField(v8.AllFields);
}
"""
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertTrue(any("v7 appears to be a live-in register value (r13d)" in warning for warning in warnings))
        self.assertTrue(any("v8 appears to be a live-in register value (r8d)" in warning for warning in warnings))

    def test_signature_parameters_are_not_reported_as_unassigned_locals(self) -> None:
        text = """
NTSTATUS __stdcall NtReadFile(
        HANDLE FileHandle,
        PVOID Buffer,
        ULONG Length)
{
  NTSTATUS result;
  int Missing;

  result = IopReadFile((ULONG_PTR)FileHandle, Buffer, Length, Missing);
  return result;
}
"""
        capture = FunctionCapture(
            name="NtReadFile",
            prototype="NTSTATUS __stdcall NtReadFile(HANDLE FileHandle, PVOID Buffer, ULONG Length)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="FileHandle", type="HANDLE", is_arg=False),
                LocalVariable(name="Buffer", type="PVOID", is_arg=False),
                LocalVariable(name="Length", type="ULONG", is_arg=False),
                LocalVariable(name="Missing", type="int", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertTrue(any("Missing is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("FileHandle is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("Buffer is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("Length is declared but has no direct assignment" in warning for warning in warnings))

    def test_live_in_register_locals_are_reported_as_omitted_parameter_candidates(self) -> None:
        text = """
__int64 EtwWriteKMSecurityEvent()
{
  int v1; // r8d
  __int64 v2; // r9
  __int64 v3; // r10

  return EtwpEventWriteFull(0, 0, 0, 0, v3, 0, 0, 0LL, 0LL, v1, v2);
}
"""
        capture = FunctionCapture(
            name="EtwWriteKMSecurityEvent",
            prototype="__int64 EtwWriteKMSecurityEvent()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="int", is_arg=False),
                LocalVariable(name="v2", type="__int64", is_arg=False),
                LocalVariable(name="v3", type="__int64", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(3, len(warnings))
        self.assertTrue(any("v1 appears to be a live-in register value (r8d)" in warning for warning in warnings))
        self.assertTrue(any("v2 appears to be a live-in register value (r9)" in warning for warning in warnings))
        self.assertTrue(any("v3 appears to be a live-in register value (r10)" in warning for warning in warnings))
        self.assertTrue(
            any("v1 appears to be a live-in register value (r8d)" in warning
                and "Hex-Rays may have omitted a function parameter" in warning for warning in warnings)
        )
        self.assertTrue(
            any("v2 appears to be a live-in register value (r9)" in warning
                and "Hex-Rays may have omitted a function parameter" in warning for warning in warnings)
        )
        self.assertTrue(
            any("v3 appears to be a live-in register value (r10)" in warning
                and "thunk/syscall input or scratch register" in warning for warning in warnings)
        )
        self.assertFalse(
            any("v3 appears to be a live-in register value (r10)" in warning
                and "Hex-Rays may have omitted a function parameter" in warning for warning in warnings)
        )

    def test_mixed_abi_register_usage_is_manual_review_not_parameter_gap(self) -> None:
        text = """
__int64 __fastcall MixedLiveInUsageSample(int flag)
{
  int v1; // r8d

  ConsumeLiveIn(v1);
  if ( flag )
    return v1;
  return 0;
}
"""
        capture = FunctionCapture(
            name="MixedLiveInUsageSample",
            prototype="__int64 __fastcall MixedLiveInUsageSample(int flag)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="int", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])
        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("classified as abi_argument/mixed", warnings[0])
        self.assertIn("manual review is required", warnings[0])
        self.assertNotIn("Hex-Rays may have omitted a function parameter", warnings[0])
        self.assertEqual(1, len(diagnostics))
        self.assertEqual("mixed", diagnostics[0].usage_class)
        self.assertEqual("manual_review_candidate", diagnostics[0].candidate_action)
        self.assertFalse(diagnostics[0].legacy_candidate_action)

    def test_true_public_abi_gap_remains_caller_parameter_gap_candidate(self) -> None:
        text = """
__int64 PublicAbiGapSample()
{
  int missingLength; // r8d

  return ZwQuerySystemInformation(5, 0, missingLength, 0);
}
"""
        capture = FunctionCapture(
            name="PublicAbiGapSample",
            prototype="__int64 PublicAbiGapSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="missingLength", type="int", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(1, len(diagnostics))
        self.assertEqual("caller_parameter_gap_candidate", diagnostics[0].candidate_action)
        self.assertEqual("parameter_gap_candidate", diagnostics[0].legacy_candidate_action)
        self.assertEqual("ZwQuerySystemInformation", diagnostics[0].callee_name)
        self.assertEqual(2, diagnostics[0].argument_index)
        self.assertFalse(diagnostics[0].callee_contract_action)

    def test_ex_reference_callback_block_live_ins_are_helper_arity_residue(self) -> None:
        text = """
__int64 __fastcall CallbackBlockResidueSample()
{
  __int64 v1; // rdx
  __int64 v2; // r8
  __int64 v3; // r9

  return ExReferenceCallBackBlock(&PspCreateThreadNotifyRoutine, v1, v2, v3) != 0;
}
"""
        capture = FunctionCapture(
            name="CallbackBlockResidueSample",
            prototype="__int64 __fastcall CallbackBlockResidueSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False),
                LocalVariable(name="v2", type="__int64", is_arg=False),
                LocalVariable(name="v3", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])
        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(3, len(diagnostics))
        self.assertEqual({"callee_arity_residue_candidate"}, {item.candidate_action for item in diagnostics})
        self.assertTrue(all(item.callee_name == "ExReferenceCallBackBlock" for item in diagnostics))
        self.assertTrue(all(item.callee_contract_action == "callee_arity_residue_candidate" for item in diagnostics))
        self.assertFalse(any("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))
        self.assertTrue(any("callee arity/helper residue" in warning for warning in warnings))

    def test_hal_mm_alloc_ctx_alloc_live_ins_are_helper_arity_residue(self) -> None:
        text = """
__int64 __fastcall HalEmergencyResourceResidueSample(__int64 argument0)
{
  __int64 v1; // rcx

  return HalpMmAllocCtxAlloc(argument0, 56) && HalpMmAllocCtxAlloc(v1, 56);
}
"""
        capture = FunctionCapture(
            name="HalEmergencyResourceResidueSample",
            prototype="__int64 __fastcall HalEmergencyResourceResidueSample(__int64 argument0)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])
        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(1, len(diagnostics))
        self.assertEqual("callee_arity_residue_candidate", diagnostics[0].candidate_action)
        self.assertEqual("HalpMmAllocCtxAlloc", diagnostics[0].callee_name)
        self.assertEqual("callee_arity_residue_candidate", diagnostics[0].callee_contract_action)
        self.assertFalse(any("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))
        self.assertTrue(any("callee arity/helper residue" in warning for warning in warnings))

    def test_repeated_dif_thunk_slots_are_helper_thunk_candidates(self) -> None:
        text = """
bool __fastcall VfBindDifDDIWrappers(int argument0, int argument1, __int64 argument2)
{
  int v3; // edx
  int v4; // r8d
  int v5; // r9d
  __int64 v6; // r10
  int v7; // edx
  int v8; // r8d
  int v9; // r9d
  __int64 v10; // r10

  return (unsigned __int8)ViBindDifThunkNormal((unsigned int)&VfDifThunks, argument1, argument0, argument1, argument2)
      || (unsigned __int8)ViBindDifThunkNormal((unsigned int)&VfPoolThunks, v3, v4, v5, v6)
      || (unsigned __int8)ViBindDifThunkNormal((unsigned int)&VfRegularThunks, v7, v8, v9, v10) != 0;
}
"""
        capture = FunctionCapture(
            name="VfBindDifDDIWrappers",
            prototype="bool __fastcall VfBindDifDDIWrappers(int argument0, int argument1, __int64 argument2)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v3", type="int", is_arg=False),
                LocalVariable(name="v4", type="int", is_arg=False),
                LocalVariable(name="v5", type="int", is_arg=False),
                LocalVariable(name="v6", type="__int64", is_arg=False),
                LocalVariable(name="v7", type="int", is_arg=False),
                LocalVariable(name="v8", type="int", is_arg=False),
                LocalVariable(name="v9", type="int", is_arg=False),
                LocalVariable(name="v10", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])
        actions = {item.symbol: item.candidate_action for item in diagnostics}
        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(8, len(diagnostics))
        self.assertEqual({"helper_thunk_slot_candidate"}, set(actions.values()))
        self.assertTrue(all(item.callee_name == "ViBindDifThunkNormal" for item in diagnostics))
        self.assertTrue(all(item.callee_contract_action == "helper_thunk_slot_candidate" for item in diagnostics))
        self.assertTrue(all(item.call_index in {1, 2} for item in diagnostics))
        self.assertTrue(all(item.argument_index in {1, 2, 3, 4} for item in diagnostics))
        self.assertFalse(any("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))
        self.assertTrue(any("repeated helper/thunk slot residue" in warning for warning in warnings))

    def test_internal_lock_helpers_are_not_caller_parameter_gap_candidates(self) -> None:
        text = """
__int64 __fastcall InternalLockResidueSample()
{
  __int64 v6; // rdx
  __int64 v7; // rcx
  __int64 v8; // r8
  __int64 v9; // r9
  __int64 v12; // rcx

  if ( CmpAcquireShutdownRundown(v7, v6, v8, v9) )
    return CmpReleaseShutdownRundown(v12);
  return 0;
}
"""
        capture = FunctionCapture(
            name="InternalLockResidueSample",
            prototype="__int64 __fastcall InternalLockResidueSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v6", type="__int64", is_arg=False),
                LocalVariable(name="v7", type="__int64", is_arg=False),
                LocalVariable(name="v8", type="__int64", is_arg=False),
                LocalVariable(name="v9", type="__int64", is_arg=False),
                LocalVariable(name="v12", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(5, len(diagnostics))
        self.assertEqual({"internal_lock_helper_residue"}, {item.candidate_action for item in diagnostics})
        self.assertTrue(all(item.callee_contract_confidence > 0 for item in diagnostics))

    def test_io_dependency_cleanup_helpers_are_internal_lock_residue(self) -> None:
        text = """
NTSTATUS __fastcall IoDuplicateDependencySample()
{
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v9; // rdx
  __int64 v10; // r8

  PnpReleaseDependencyRelationsLock(v6, v5, v7);
  return PipCreateDependencyNode(0, v9, v10) != 0;
}
"""
        capture = FunctionCapture(
            name="IoDuplicateDependencySample",
            prototype="NTSTATUS __fastcall IoDuplicateDependencySample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v5", type="__int64", is_arg=False),
                LocalVariable(name="v6", type="__int64", is_arg=False),
                LocalVariable(name="v7", type="__int64", is_arg=False),
                LocalVariable(name="v9", type="__int64", is_arg=False),
                LocalVariable(name="v10", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])
        actions = {item.symbol: item.candidate_action for item in diagnostics}

        self.assertEqual("internal_lock_helper_residue", actions["v5"])
        self.assertEqual("internal_lock_helper_residue", actions["v6"])
        self.assertEqual("internal_lock_helper_residue", actions["v7"])
        self.assertEqual("callee_arity_residue_candidate", actions["v9"])
        self.assertEqual("callee_arity_residue_candidate", actions["v10"])

    def test_repeated_working_set_lock_helpers_are_internal_lock_residue(self) -> None:
        text = """
NTSTATUS __fastcall MiPrepareImagePagesForHotPatchSample()
{
  __int64 v9; // rdx
  __int64 v10; // r8
  __int64 v11; // r9

  return MiLockWorkingSetShared(0, v9, v10, v11);
}
"""
        capture = FunctionCapture(
            name="MiPrepareImagePagesForHotPatchSample",
            prototype="NTSTATUS __fastcall MiPrepareImagePagesForHotPatchSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v9", type="__int64", is_arg=False),
                LocalVariable(name="v10", type="__int64", is_arg=False),
                LocalVariable(name="v11", type="__int64", is_arg=False),
            ],
        )

        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(3, len(diagnostics))
        self.assertEqual({"internal_lock_helper_residue"}, {item.candidate_action for item in diagnostics})

    def test_return_only_live_in_registers_are_not_parameter_gaps(self) -> None:
        text = """
__int64 __fastcall ReturnCarrierSample(int flag)
{
  int result; // eax
  __int64 fallback; // r10

  if ( flag )
    return result;
  return fallback;
}
"""
        capture = FunctionCapture(
            name="ReturnCarrierSample",
            prototype="__int64 __fastcall ReturnCarrierSample(int flag)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="result", type="int", is_arg=False),
                LocalVariable(name="fallback", type="__int64", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(2, len(warnings))
        self.assertTrue(
            any("result appears to be a live-in register value (eax)" in warning
                and "unrecovered return/default-path register carrier" in warning for warning in warnings)
        )
        self.assertTrue(
            any("fallback appears to be a live-in register value (r10)" in warning
                and "unrecovered return/default-path register carrier" in warning for warning in warnings)
        )
        self.assertFalse(any("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))

    def test_nonvolatile_live_in_call_arguments_are_not_parameter_gaps(self) -> None:
        text = """
__int64 __fastcall TrapStateSample()
{
  __int64 v1; // rsi
  int v2; // r13d

  return PreserveTrapState(v1, v2);
}
"""
        capture = FunctionCapture(
            name="TrapStateSample",
            prototype="__int64 __fastcall TrapStateSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False),
                LocalVariable(name="v2", type="int", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(2, len(warnings))
        self.assertTrue(any("preserved register or trap-state context" in warning for warning in warnings))
        self.assertFalse(any("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))

    def test_stack_pointer_retaddr_is_not_reported_as_omitted_parameter_candidate(self) -> None:
        text = """
__int64 InstrumentedLockRelease(__int64 argument0)
{
  void *retaddr; // [rsp+28h] [rbp+0h]

  return KiReleaseQueuedSpinLockInstrumented(argument0, retaddr);
}
"""
        capture = FunctionCapture(
            name="InstrumentedLockRelease",
            prototype="__int64 InstrumentedLockRelease(__int64 argument0)",
            pseudocode=text,
            lvars=[
                LocalVariable(name="argument0", type="__int64", is_arg=True),
                LocalVariable(name="retaddr", type="void *", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])
        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("Stack pseudo-local report-only", warnings[0])
        self.assertIn("return-address stack pseudo-local", warnings[0])
        self.assertIn("KiReleaseQueuedSpinLockInstrumented", warnings[0])
        self.assertIn("[rsp+28h] [rbp+0h]", warnings[0])
        self.assertNotIn("live-in register value", warnings[0])
        self.assertNotIn("omitted a function parameter", warnings[0])
        self.assertEqual(1, len(diagnostics))
        self.assertEqual("unassigned_local_stack_pseudo_local", diagnostics[0].kind)
        self.assertEqual("stack_pseudo_local_report_only", diagnostics[0].candidate_action)
        self.assertEqual("stack_pseudo_local", diagnostics[0].register_class)
        self.assertEqual("KiReleaseQueuedSpinLockInstrumented", diagnostics[0].callee_name)
        self.assertEqual(1, diagnostics[0].argument_index)
        self.assertEqual("[rsp+28h] [rbp+0h]", diagnostics[0].stack_slot)
        self.assertIn("retaddr", diagnostics[0].stack_declaration)
        self.assertIn("return-address context", diagnostics[0].pseudo_local_evidence)

    def test_plain_unassigned_stack_local_still_warns_normally(self) -> None:
        text = """
__int64 PlainStackLocalSample()
{
  void *stackLocal; // [rsp+20h] [rbp-8h]

  return ConsumeStackLocal(stackLocal);
}
"""
        capture = FunctionCapture(
            name="PlainStackLocalSample",
            prototype="__int64 PlainStackLocalSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="stackLocal", type="void *", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])
        diagnostics = unassigned_local_usage_diagnostics(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("Uninitialized local risk", warnings[0])
        self.assertIn("stackLocal is declared but has no direct assignment", warnings[0])
        self.assertFalse(diagnostics)

    def test_spoiled_or_memory_locations_are_not_live_in_hints(self) -> None:
        text = """
__int64 __fastcall LocationNoiseSample()
{
  __int64 v1;
  __int64 v2;

  return ForwardLocationNoise(v1, v2);
}
"""
        capture = FunctionCapture(
            name="LocationNoiseSample",
            prototype="__int64 __fastcall LocationNoiseSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False, location="spoiled:rax"),
                LocalVariable(name="v2", type="__int64", is_arg=False, location="memory:r8"),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(2, len(warnings))
        self.assertTrue(all("is declared but has no direct assignment" in warning for warning in warnings))
        self.assertFalse(any("live-in register value" in warning for warning in warnings))

    def test_invalid_numbered_register_comment_is_not_live_in_hint(self) -> None:
        text = """
__int64 NumberedRegisterCommentSample()
{
  __int64 v1; // r1

  return UseRegisterComment(v1);
}
"""
        capture = FunctionCapture(
            name="NumberedRegisterCommentSample",
            prototype="__int64 NumberedRegisterCommentSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("v1 is declared but has no direct assignment", warnings[0])
        self.assertNotIn("live-in register value", warnings[0])

    def test_lvar_location_register_hint_marks_live_in_candidate(self) -> None:
        text = """
__int64 LocationRegisterSample()
{
  __int64 v1;

  return ForwardLiveIn(v1);
}
"""
        capture = FunctionCapture(
            name="LocationRegisterSample",
            prototype="__int64 LocationRegisterSample()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="v1", type="__int64", is_arg=False, location="reg:r9"),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("v1 appears to be a live-in register value (r9)", warnings[0])

    def test_pascalcase_llm_local_renames_are_style_normalized(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall PascalCaseKernelSample(__int64 *a1)
{
  __int64 v3;
  int v5;
  void *v7;

  v3 = *a1;
  v5 = *(_DWORD *)(v3 + 56);
  v7 = (void *)a1[1];
  ExFreePoolWithTag(v7, 0);
  return v5;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a1",
                        "new": "Subsection",
                        "confidence": 0.96,
                        "reason": "inferred structure role",
                    },
                    {
                        "old": "v3",
                        "new": "ControlArea",
                        "confidence": 0.96,
                        "reason": "inferred from offset use",
                    },
                    {
                        "old": "v5",
                        "new": "ControlAreaFlags",
                        "confidence": 0.92,
                        "reason": "flags field value",
                    },
                    {
                        "old": "v7",
                        "new": "subsectionBase",
                        "confidence": 0.90,
                        "reason": "lower camel local name",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a1"], "subsection")
        self.assertEqual(rename_map["v3"], "controlArea")
        self.assertEqual(rename_map["v5"], "controlAreaFlags")
        self.assertEqual(rename_map["v7"], "subsectionBase")
        self.assertNotIn("Skipped PascalCase LLM rename a1->Subsection", plan.warnings)
        self.assertNotIn("Skipped PascalCase LLM rename v3->ControlArea", plan.warnings)
        self.assertNotIn("Skipped PascalCase LLM rename v5->ControlAreaFlags", plan.warnings)

    def test_llm_path_suppresses_generic_prototype_argument_renames(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericArgumentSample(__int64 a1, int a2)
{
  if ( a2 )
  {
    return a1;
  }
  return 0LL;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=JsonRenameProvider('{"renames":[]}'))
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("a1", rename_map)
        self.assertNotIn("a2", rename_map)
        self.assertIn("__int64 a1, int a2", rendered)
        self.assertNotIn("argument0", rendered)

    def test_generic_llm_argument_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericArgumentSample(__int64 a1)
{
  return a1;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a1",
                        "new": "argument0",
                        "confidence": 0.95,
                        "reason": "generic LLM placeholder",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a1", rename_map)
        self.assertIn("Skipped generic argument rename a1->argument0", plan.warnings)
        self.assertNotIn("argument0", body)

    def test_weak_llm_argument_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall WeakArgumentSample(__int64 a1, int a2, int a3, unsigned int a4)
{
  return a4;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "alignmentPages",
                        "confidence": 0.72,
                        "reason": "uncertain forwarded argument role",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertIn("Skipped weak argument rename a4->alignmentPages", plan.warnings)
        self.assertNotIn("alignmentPages", body)

    def test_saved_argument_copy_rename_requires_supported_argument_name(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall SavedArgumentCopySample(__int64 a1, int a2, int a3, unsigned int a4)
{
  unsigned int v29;

  v29 = a4;
  return v29;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "allocationFlags",
                        "confidence": 0.62,
                        "reason": "uncertain forwarded flag role",
                    },
                    {
                        "old": "v29",
                        "new": "savedAllocationFlags",
                        "confidence": 0.91,
                        "reason": "saved copy of a4",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertNotIn("v29", rename_map)
        self.assertIn("Skipped LLM rename a4->allocationFlags: low confidence 0.62", plan.warnings)
        self.assertIn("Skipped unsupported saved-argument rename v29->savedAllocationFlags", plan.warnings)
        self.assertNotIn("savedAllocationFlags", body)

    def test_saved_argument_copy_rename_is_allowed_when_argument_name_is_supported(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall SavedArgumentCopySample(__int64 a1, int a2, int a3, unsigned int a4)
{
  unsigned int v29;

  v29 = a4;
  return v29;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "allocationFlags",
                        "confidence": 0.90,
                        "reason": "forwarded flag role",
                    },
                    {
                        "old": "v29",
                        "new": "savedAllocationFlags",
                        "confidence": 0.91,
                        "reason": "saved copy of a4",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a4"], "allocationFlags")
        self.assertEqual(rename_map["v29"], "savedAllocationFlags")

    def test_numeric_dispatcher_llm_rename_is_rejected(self) -> None:
        sample = WEAK_LLM_DISPATCHER_SAMPLE.replace("  int v113;\n", "  int v113;\n  int v115;\n")
        capture = capture_from_pseudocode(sample)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v115",
                        "new": "classMinus235",
                        "confidence": 0.90,
                        "reason": "derived from dispatcher class delta",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v115", rename_map)
        self.assertIn("Skipped numeric dispatcher rename v115->classMinus235", plan.warnings)
        self.assertIn("int v115;", rendered)
        self.assertNotIn("classMinus235", rendered.rsplit("*/", 1)[-1])


if __name__ == "__main__":
    unittest.main()
