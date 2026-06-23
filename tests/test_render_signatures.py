from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.domain_identity import DomainIdentityPrototype
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture, ParameterTypeCorrection
from ida_pseudoforge.core.render import _find_signature_end as legacy_find_signature_end
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_signatures import (
    _correct_signature_prototype,
    apply_known_function_signature,
    apply_profile_parameter_type_corrections,
    find_signature_end,
)


NTSET_TYPED_ACCESS_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  UNICODE_STRING DriverServiceName;
  void *Buf1[2];
  char *v6;
  char *v7;
  char *v8;

  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  DriverServiceName.Buffer = L"\Registry\Machine\System";
  v6 = "\SystemRoot\System32\ntoskrnl.exe";
  v7 = "C:\Windows\Temp\driver.sys";
  v8 = "line\nnot_a_path";
  if ( (_DWORD)a3 )
    a1 = &a2->m128i_i8[(unsigned int)a3];
  *(__m128i *)Buf1 = *a2;
  if ( !memcmp((const void *)a2->m128i_i64[1], L"\SystemRoot\System32\win32k.sys", 0x3EuLL) )
    updated = 1;
  LOBYTE(a3) = PreviousMode;
  updated += PsSetCpuQuotaInformation(a2, (unsigned int)v5, a3, 1LL);
  LOBYTE(a2) = PreviousMode;
  updated += MmIssueMemoryListCommand(v5, a2, -1LL, 1LL);
  updated = a2->m128i_i32[0];
  updated += a2[1].m128i_i32[0];
  return updated;
}
"""


class RenderSignatureTests(unittest.TestCase):
    def test_apply_known_function_signature_uses_prototype_name_when_capture_name_is_empty(self) -> None:
        prototype = "__int64 __fastcall DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)"
        text = "\n".join(
            [
                prototype,
                "{",
                "  Irp->IoStatus.Status = 0;",
                "  IofCompleteRequest(Irp, 0);",
                "  return 0;",
                "}",
            ]
        )
        capture = FunctionCapture(name="", prototype=prototype, pseudocode=text)

        rendered = apply_known_function_signature(text, capture)

        self.assertIn("NTSTATUS __fastcall DispatchDeviceControl(", rendered)
        self.assertIn("        PDEVICE_OBJECT deviceObject,", rendered)
        self.assertIn("        PIRP irp)", rendered)

    def test_known_pvoid_signature_keeps_typed_body_alias(self) -> None:
        capture = capture_from_pseudocode(NTSET_TYPED_ACCESS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("PVOID systemInformation,", rendered)
        self.assertIn("__m128i *systemInfo128;", rendered)
        self.assertIn("PVOID userProbeEnd;", rendered)
        self.assertIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)
        self.assertIn("status = systemInfo128->m128i_i32[0];", rendered)
        self.assertIn("status += systemInfo128[1].m128i_i32[0];", rendered)
        self.assertIn("= *systemInfo128;", rendered)
        self.assertIn('driverServiceName.Buffer = L"\\\\Registry\\\\Machine\\\\System";', rendered)
        self.assertIn('"\\\\SystemRoot\\\\System32\\\\ntoskrnl.exe"', rendered)
        self.assertIn('"C:\\\\Windows\\\\Temp\\\\driver.sys"', rendered)
        self.assertIn('"line\\nnot_a_path"', rendered)
        self.assertIn('L"\\\\SystemRoot\\\\System32\\\\win32k.sys"', rendered)
        self.assertIn("PsSetCpuQuotaInformation(systemInformation, (unsigned int)infoClass, (unsigned __int8)previousMode, 1LL);", rendered)
        self.assertIn("MmIssueMemoryListCommand(infoClass, (unsigned __int8)previousMode, -1LL, 1LL);", rendered)
        self.assertNotIn("LOBYTE(systemInformationLength)", rendered)
        self.assertNotIn("LOBYTE(systemInformation)", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("systemInformation[1]", rendered)
        self.assertNotIn("*systemInformation", rendered)
        self.assertNotIn("systemInformationClass = &", rendered)

    def test_profile_type_correction_only_rewrites_signature_parameter(self) -> None:
        text = """
__int64 __fastcall IopExample(__int64 a1)
{
  __int64 local;

  local = (__int64)a1;
  return local;
}
""".lstrip()
        capture = capture_from_pseudocode(text)
        plan = CleanPlan(
            function_ea=0,
            function_name="IopExample",
            input_fingerprint=capture.input_fingerprint(),
            type_corrections=[
                ParameterTypeCorrection(
                    parameter_index=0,
                    old_name="a1",
                    new_name="a1",
                    old_type="__int64",
                    canonical_type="PDEVICE_OBJECT",
                    profile_id="test.type",
                    confidence=0.91,
                    effective_mode="report-only",
                )
            ],
        )

        rendered = apply_profile_parameter_type_corrections(text, capture, plan)

        self.assertIn("__int64 __fastcall IopExample(PDEVICE_OBJECT a1)", rendered)
        self.assertIn("local = (__int64)a1;", rendered)

    def test_profile_type_correction_matches_demangled_prototype_when_capture_name_is_mangled(self) -> None:
        prototype = "__int64 __fastcall ST_STORE<SM_TRAITS>::StWorkItemProcess(__int64 store, unsigned __int64 workItem, unsigned __int64 workItemContext)"
        text = "\n".join(
            [
                prototype,
                "{",
                "  return *(_QWORD *)(store + 24) + workItem + workItemContext;",
                "}",
            ]
        )
        capture = FunctionCapture(
            name="?StWorkItemProcess@?$ST_STORE@USM_TRAITS@@@@QEAAX_K0@Z",
            prototype=prototype,
            pseudocode=text,
        )
        plan = CleanPlan(
            function_ea=0,
            function_name="StWorkItemProcess",
            input_fingerprint=capture.input_fingerprint(),
            type_corrections=[
                ParameterTypeCorrection(
                    parameter_index=0,
                    old_name="store",
                    new_name="store",
                    old_type="__int64",
                    canonical_type="PST_STORE_SM_TRAITS",
                    profile_id="windows.memory_manager.store_work_item_process",
                    confidence=0.84,
                    effective_mode="report-only",
                ),
                ParameterTypeCorrection(
                    parameter_index=1,
                    old_name="workItem",
                    new_name="workItem",
                    old_type="unsigned __int64",
                    canonical_type="PST_WORK_ITEM",
                    profile_id="windows.memory_manager.store_work_item_process",
                    confidence=0.84,
                    effective_mode="report-only",
                ),
                ParameterTypeCorrection(
                    parameter_index=2,
                    old_name="workItemContext",
                    new_name="workItemContext",
                    old_type="unsigned __int64",
                    canonical_type="ULONG_PTR",
                    profile_id="windows.memory_manager.store_work_item_process",
                    confidence=0.78,
                    effective_mode="report-only",
                ),
            ],
        )

        rendered = apply_profile_parameter_type_corrections(text, capture, plan)

        self.assertIn(
            "ST_STORE<SM_TRAITS>::StWorkItemProcess(PST_STORE_SM_TRAITS store, PST_WORK_ITEM workItem, ULONG_PTR workItemContext)",
            rendered,
        )
        self.assertIn("return *(_QWORD *)(store + 24) + workItem + workItemContext;", rendered)

    def test_profile_prototype_calling_convention_does_not_keep_existing_convention_as_return_type(self) -> None:
        prototype = DomainIdentityPrototype(
            profile_id="test.prototype",
            function_name="NtExample",
            return_type="",
            calling_convention="__stdcall",
            parameters=(),
            signature_preview=True,
            body_canonical_rewrite=False,
            apply_to_idb_default=False,
        )

        rendered = _correct_signature_prototype(
            "__int64 __fastcall NtExample(int a1)",
            prototype,
            ["NtExample"],
        )

        self.assertEqual("__int64 __stdcall NtExample(int a1)", rendered)
        self.assertNotIn("__fastcall __stdcall", rendered)

    def test_find_signature_end_handles_multiline_signatures(self) -> None:
        lines = [
            "NTSTATUS Sample(",
            "        PVOID input,",
            "        ULONG length)",
            "{",
        ]

        self.assertEqual(find_signature_end(lines, 0), 2)
        self.assertEqual(legacy_find_signature_end(lines, 0), 2)


if __name__ == "__main__":
    unittest.main()
