from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable, RenameSuggestion
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.validation import unassigned_local_usage_warnings
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
        self.assertTrue(all("Hex-Rays may have omitted a function parameter" in warning for warning in warnings))

    def test_stack_pointer_retaddr_is_not_reported_as_omitted_parameter_candidate(self) -> None:
        text = """
__int64 InstrumentedLockRelease()
{
  void *retaddr; // rsp

  return ExpReleaseSpinLockSharedFromDpcLevelInstrumented(retaddr);
}
"""
        capture = FunctionCapture(
            name="InstrumentedLockRelease",
            prototype="__int64 InstrumentedLockRelease()",
            pseudocode=text,
            lvars=[
                LocalVariable(name="retaddr", type="void *", is_arg=False),
            ],
        )

        warnings = unassigned_local_usage_warnings(capture, [])

        self.assertEqual(1, len(warnings))
        self.assertIn("retaddr is declared but has no direct assignment", warnings[0])
        self.assertNotIn("live-in register value", warnings[0])

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
