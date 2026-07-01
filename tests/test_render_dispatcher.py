from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_dispatcher import (
    replace_char_literal_cases,
    rewrite_process_information_class_literals,
    rewrite_system_information_class_literals,
)
from ida_pseudoforge.profiles.loader import (
    get_process_information_class_name,
    get_process_information_class_value,
)


CHAR_CASE_SAMPLE = r"""
__int64 __fastcall CharCaseSample(int a1)
{
  switch ( a1 )
  {
    case 'K':
      return 1;
    case ';':
      return 2;
    default:
      return 0;
  }
}
"""


NTSET_INFORMATION_PROCESS_SAMPLE = r"""
NTSTATUS __fastcall NtSetInformationProcess(ULONG_PTR BugCheckParameter1, __int64 a2, __int128 *a3, __int64 a4)
{
  size_t v4;
  __int128 *v5;
  int v6;
  HANDLE v7;

  v4 = (unsigned int)a4;
  v5 = a3;
  v6 = a2;
  v7 = (HANDLE)BugCheckParameter1;
  if ( (_DWORD)a2 != 96 )
  {
    switch ( (int)a2 )
    {
      case 5:
        if ( (_DWORD)a4 != 4 )
          return -1073741820;
        return PspSetBasePriority(v7, *(_DWORD *)v5);
      case 87:
        break;
      case 112:
        if ( (_DWORD)a4 != 8 )
          return -1073741820;
        *(_QWORD *)v5 = 0LL;
        return 0;
      case 113:
        if ( (_DWORD)a4 )
          return -1073741820;
        return 0;
      default:
        return -1073741821;
    }
  }
  if ( (_DWORD)a2 == 87 && !(_DWORD)a4 || (unsigned int)a4 < 4 && (_DWORD)a2 == 96 )
    return -1073741820;
  return 0;
}
"""


NTQUERY_INFORMATION_PROCESS_SAMPLE = r"""
NTSTATUS __fastcall NtQueryInformationProcess(__int64 a1, unsigned int a2, void *a3, unsigned int a4, unsigned int *a5)
{
  switch ( a2 )
  {
    case 0:
      if ( a4 < 48 )
        return -1073741820;
      *(_QWORD *)a3 = 0LL;
      return 0;
    case 7:
      if ( a4 != 8 )
        return -1073741820;
      *(_QWORD *)a3 = -1LL;
      return 0;
    case 29:
      if ( a4 < 4 )
        return -1073741820;
      *(_DWORD *)a3 = 0;
      return 0;
    default:
      return -1073741821;
  }
}
"""


class RenderDispatcherTests(unittest.TestCase):
    def test_system_information_class_literals_and_delta_chain(self) -> None:
        rendered = rewrite_system_information_class_literals(
            "  if ( infoClass == 9 )\n"
            "    return 0;\n"
            "  v115 = infoClass - 235;\n"
            "  if ( v115 == 8 )\n"
            "    return 1;\n"
        )

        self.assertIn("infoClass == SystemFlagsInformation", rendered)
        self.assertIn("v115 = infoClass - SystemHypervisorBootPagesInformation;", rendered)
        self.assertIn(
            "v115 == SystemTrustedAppsRuntimeInformation - SystemHypervisorBootPagesInformation",
            rendered,
        )

    def test_process_information_class_cases_and_comparisons(self) -> None:
        rendered = rewrite_process_information_class_literals(
            "  switch ( (int)processInformationClass )\n"
            "  {\n"
            "    case 113:\n"
            "      return 0;\n"
            "  }\n"
            "  if ( (_DWORD)processInformationClass == 96 )\n"
            "    return 1;\n"
        )

        self.assertIn("case ProcessSlistRollbackInformation:", rendered)
        self.assertIn("processInformationClass == ProcessEnableLogging", rendered)

    def test_process_information_class_profile_is_current_to_25h2(self) -> None:
        self.assertEqual(get_process_information_class_name(112), "ProcessSchedulerSharedData")
        self.assertEqual(get_process_information_class_name(113), "ProcessSlistRollbackInformation")
        self.assertEqual(get_process_information_class_name(116), "ProcessEnclaveAddressSpaceRestriction")
        self.assertEqual(get_process_information_class_name(117), "ProcessAvailableCpus")
        self.assertEqual(get_process_information_class_value("ProcessAvailableCpus"), 117)

    def test_ntset_information_process_uses_processinfo_profile(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "BugCheckParameter1",
                                "new": "ProcessHandle",
                                "confidence": 0.99,
                            },
                            {
                                "old": "a2",
                                "new": "ProcessInformationClass",
                                "confidence": 0.99,
                            },
                            {
                                "old": "a3",
                                "new": "ProcessInformation",
                                "confidence": 0.99,
                            },
                            {
                                "old": "a4",
                                "new": "ProcessInformationLength",
                                "confidence": 0.99,
                            },
                        ]
                    }
                )

        capture = capture_from_pseudocode(NTSET_INFORMATION_PROCESS_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["BugCheckParameter1"], "processHandle")
        self.assertEqual(rename_map["a2"], "processInformationClass")
        self.assertEqual(rename_map["a3"], "processInformation")
        self.assertEqual(rename_map["a4"], "processInformationLength")
        self.assertTrue(plan.flow_rewrites)
        self.assertEqual(plan.flow_rewrites[0].dispatcher, "processInformationClass")
        self.assertEqual(plan.flow_rewrites[0].case_names[112], "ProcessSchedulerSharedData")
        self.assertNotIn("Skipped PascalCase LLM rename a2->ProcessInformationClass", plan.warnings)
        self.assertIn("NTSTATUS NTAPI NtSetInformationProcess(", rendered)
        self.assertIn("HANDLE processHandle,", rendered)
        self.assertIn("PROCESSINFOCLASS processInformationClass,", rendered)
        self.assertIn("PVOID processInformation,", rendered)
        self.assertIn("ULONG processInformationLength)", rendered)
        self.assertIn("switch ( (int)processInformationClass )", rendered)
        self.assertIn("case ProcessBasePriority:", rendered)
        self.assertIn("case ProcessEnableReadWriteVmLogging:", rendered)
        self.assertIn("case ProcessSchedulerSharedData:", rendered)
        self.assertIn("case ProcessSlistRollbackInformation:", rendered)
        self.assertIn("processInformationClass != ProcessEnableLogging", rendered)
        self.assertIn("source=native_switch outline=suppressed", rendered)
        self.assertNotIn("switch (processInformationLength)", rendered)
        self.assertNotIn("dispatcher=processInformationLength", rendered)

    def test_process_information_class_literals_rewrite_only_process_dispatcher(self) -> None:
        source = """
  switch ( (int)processInformationClass )
  {
    case 113:
      return 0;
  }
  if ( (_DWORD)processInformationClass == 96 )
    return 1;
"""
        rendered = rewrite_process_information_class_literals(source)

        self.assertIn("case ProcessSlistRollbackInformation:", rendered)
        self.assertIn("processInformationClass == ProcessEnableLogging", rendered)

    def test_ntquery_process_signature_and_cases_are_process_domain(self) -> None:
        capture = capture_from_pseudocode(NTQUERY_INFORMATION_PROCESS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertTrue(plan.flow_rewrites)
        self.assertEqual(plan.flow_rewrites[0].dispatcher, "processInformationClass")
        self.assertEqual(plan.flow_rewrites[0].case_names[0], "ProcessBasicInformation")
        self.assertIn("NTSTATUS NTAPI NtQueryInformationProcess(", rendered)
        self.assertIn("HANDLE processHandle,", rendered)
        self.assertIn("PROCESSINFOCLASS processInformationClass,", rendered)
        self.assertIn("PVOID processInformation,", rendered)
        self.assertIn("ULONG processInformationLength,", rendered)
        self.assertIn("PULONG returnLength)", rendered)
        self.assertIn("case ProcessBasicInformation:", rendered)
        self.assertIn("case ProcessDebugPort:", rendered)
        self.assertNotIn("SystemBasicInformation", rendered)

    def test_system_information_class_delta_chain_preserves_delta_variables(self) -> None:
        source = """
  classMinus235 = infoClass - 235;
  if ( !classMinus235 )
    return first();
  classMinus243 = classMinus235 - 8;
  if ( !classMinus243 )
    return second();
  classMinus245 = classMinus243 - 2;
  if ( classMinus245 )
  {
    if ( classMinus245 == 1 )
      return fourth();
    return fallback();
  }
"""
        rendered = rewrite_system_information_class_literals(source)

        self.assertIn("classMinus235 = infoClass - SystemHypervisorBootPagesInformation;", rendered)
        self.assertIn("if ( !classMinus235 )", rendered)
        self.assertIn("classMinus243 = infoClass - SystemTrustedAppsRuntimeInformation;", rendered)
        self.assertIn("if ( !classMinus243 )", rendered)
        self.assertIn("classMinus245 = infoClass - SystemResourceDeadlockTimeout;", rendered)
        self.assertIn("if ( classMinus245 )", rendered)
        self.assertIn(
            "if ( classMinus245 == SystemBreakOnContextUnwindFailureInformation - SystemResourceDeadlockTimeout )",
            rendered,
        )
        self.assertIn(
            "if ( infoClass == SystemErrorPortInformation )",
            rewrite_system_information_class_literals("if ( infoClass == 0x59 )"),
        )
        suffix_rendered = rewrite_system_information_class_literals(
            "if ( infoClass == 0x59u )\n"
            "classMinus235 = infoClass - 235ULL;\n"
            "classMinus243 = classMinus235 - 8u;\n"
            "if ( classMinus243 == 3UL )"
        )
        self.assertIn("if ( infoClass == SystemErrorPortInformation )", suffix_rendered)
        self.assertIn("classMinus235 = infoClass - SystemHypervisorBootPagesInformation;", suffix_rendered)
        self.assertIn("classMinus243 = infoClass - SystemTrustedAppsRuntimeInformation;", suffix_rendered)
        self.assertIn(
            "if ( classMinus243 == SystemBreakOnContextUnwindFailureInformation - SystemTrustedAppsRuntimeInformation )",
            suffix_rendered,
        )

    def test_system_information_class_delta_rewrite_expires_after_large_gap(self) -> None:
        filler = "\n".join("  scratch%d = scratch%d + 1;" % (index, index) for index in range(40))
        source = """
  classMinus235 = infoClass - 235;
%s
  if ( classMinus235 == 1 )
    return stale();
""" % filler

        rendered = rewrite_system_information_class_literals(source)

        self.assertIn("classMinus235 = infoClass - SystemHypervisorBootPagesInformation;", rendered)
        self.assertIn("if ( classMinus235 == 1 )", rendered)
        self.assertNotIn("SystemHypervisorRootSchedulerInformation - SystemHypervisorBootPagesInformation", rendered)

    def test_system_information_class_delta_chain_assignment_survives_large_branch_body(self) -> None:
        branch_body = "\n".join("    trace%d();" % index for index in range(40))
        source = """
  v85 = infoClass - SystemCriticalProcessErrorLogInformation;
  if ( !v85 )
  {
%s
    return handled();
  }
  v86 = v85 - 8;
  if ( !v86 )
    return boot_metadata();
  v87 = v86 - 1;
  if ( v87 != 1 )
    return invalid();
""" % branch_body

        rendered = rewrite_system_information_class_literals(source)

        self.assertIn("v86 = infoClass - SystemBootMetadataInformation;", rendered)
        self.assertIn("if ( !v86 )", rendered)
        self.assertIn("v87 = infoClass - SystemSoftRebootInformation;", rendered)
        self.assertIn(
            "if ( v87 != SystemElamCertificateInformation - SystemSoftRebootInformation )",
            rendered,
        )
        self.assertNotIn("v86 = v85 - 8;", rendered)
        self.assertNotIn("v87 = v86 - 1;", rendered)

    def test_char_literal_case_labels_become_numeric_cases(self) -> None:
        rendered = replace_char_literal_cases(
            "  switch ( code )\n"
            "  {\n"
            "    case 'K':\n"
            "      return 1;\n"
            "  }\n"
        )

        self.assertIn("case 75:", rendered)
        self.assertNotIn("case 'K':", rendered)

    def test_char_literal_case_labels_are_normalized_to_numbers(self) -> None:
        capture = capture_from_pseudocode(CHAR_CASE_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("case 75:", rendered)
        self.assertIn("case 59:", rendered)
        self.assertNotIn("case 'K':", rendered)
        self.assertNotIn("case ';':", rendered)


if __name__ == "__main__":
    unittest.main()
