from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ProcessThreadDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_exit_process_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __fastcall PspExitProcess(char is_full_cleanup, __int64 eprocess_ptr)
{
  __int64 probe;
  _InterlockedOr((volatile signed __int32 *)(eprocess_ptr + 500), 4u);
  probe = *(_DWORD *)(eprocess_ptr + 16)
        + *(_QWORD *)(eprocess_ptr + 24)
        + *(_DWORD *)(eprocess_ptr + 32)
        + *(_QWORD *)(eprocess_ptr + 40)
        + *(_DWORD *)(eprocess_ptr + 48)
        + *(_QWORD *)(eprocess_ptr + 56)
        + *(_DWORD *)(eprocess_ptr + 64)
        + *(_QWORD *)(eprocess_ptr + 72)
        + *(_DWORD *)(eprocess_ptr + 16)
        + *(_QWORD *)(eprocess_ptr + 24)
        + *(_DWORD *)(eprocess_ptr + 32)
        + *(_QWORD *)(eprocess_ptr + 40);
  if ( probe )
  {
    PsSetProcessTelemetryAppState((PRKPROCESS)eprocess_ptr);
  }
}
"""
        )

        identity = self._identity_for_base(plan, "windows.process_thread.psp_exit_process", "eprocess_ptr")
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers" and item.get("base") == "eprocess_ptr"
        ]

        self.assertEqual("EPROCESS", identity["structure_name"])
        self.assertEqual("exitingProcess", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready" and item.get("base") == "eprocess_ptr"
                for item in plan.comments
            )
        )

    def test_nt_terminate_process_requires_handle_reference_callee(self) -> None:
        without_callee = self._plan(
            """
NTSTATUS __fastcall NtTerminateProcess(ULONG_PTR a1, unsigned int a2)
{
  PVOID referencedObject;
  referencedObject = 0;
  return 0;
}
"""
        )
        with_callee = self._plan(
            """
NTSTATUS __fastcall NtTerminateProcess(ULONG_PTR a1, unsigned int a2)
{
  PVOID referencedObject;
  referencedObject = 0;
  ObpReferenceObjectByHandleWithTag(a1, 1, (__int64)PsProcessType, 0, POOL_TAG('P', 's', 'T', 'e'), &referencedObject, 0, 0);
  ObfDereferenceObjectWithTag(referencedObject, POOL_TAG('P', 's', 'T', 'e'));
  return 0;
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.process_thread.nt_terminate_process"
                for item in self._identities(without_callee)
            )
        )
        identities = [
            item
            for item in self._identities(with_callee)
            if item.get("profile_id") == "windows.process_thread.nt_terminate_process"
        ]

        self.assertTrue(any(item.get("trusted_role") == "processHandle" for item in identities))
        self.assertTrue(any(item.get("trusted_role") == "referencedProcessObject" for item in identities))
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))

    def test_psp_create_thread_identifies_process_and_thread_roles(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall PspCreateThread(__int64 a1, int a2, __int64 a3, ULONG_PTR inputLength, _KPROCESS *a5, __int64 a6, __int64 a7, __int64 a8, __int64 a9, char a10, __int64 a11, __int64 a12, __int64 a13)
{
  PVOID referencedObject;
  struct _KTHREAD *currentThread;
  _KPROCESS *currentProcess;
  referencedObject = 0;
  currentThread = KeGetCurrentThread();
  currentProcess = currentThread->ApcState.Process;
  return 0;
}
"""
        )

        roles = {
            item.get("trusted_role"): item.get("structure_name")
            for item in self._identities(plan)
            if item.get("profile_id") == "windows.process_thread.psp_create_thread"
        }

        self.assertEqual("THREAD_HANDLE_OUTPUT", roles["threadHandleOutput"])
        self.assertEqual("HANDLE", roles["targetProcessHandle"])
        self.assertEqual("EPROCESS", roles["targetProcessObject"])
        self.assertEqual("EPROCESS", roles["referencedProcessObject"])
        self.assertEqual("ETHREAD", roles["currentThread"])
        self.assertEqual("EPROCESS", roles["currentProcess"])

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __fastcall PspExitProcess(char is_full_cleanup, __int64 eprocess_ptr)
{
  _InterlockedOr((volatile signed __int32 *)(eprocess_ptr + 500), 4u);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._identity_for_base(plan, "windows.process_thread.psp_exit_process", "eprocess_ptr")

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_process_parameter_type(self) -> None:
        plan = self._plan(
            """
void __fastcall PspExitProcess(char is_full_cleanup, int eprocess_ptr)
{
  _InterlockedOr((volatile signed __int32 *)(eprocess_ptr + 500), 4u);
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.process_thread.psp_exit_process"
                and item.get("base") == "eprocess_ptr"
                for item in self._identities(plan)
            )
        )

    def test_process_thread_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __fastcall PspExitProcess(char is_full_cleanup, __int64 eprocess_ptr)
{
  _InterlockedOr((volatile signed __int32 *)(eprocess_ptr + 500), 4u);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/process_thread.json" for item in manifests)
        )

    def test_convert_silo_to_server_silo_globals_fields_are_report_only(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall PspConvertSiloToServerSilo(__int64 argument0, __int64 argument1, ULONG_PTR handle, int argument3)
{
  char *Pool2;
  struct _KTHREAD *currentThread;

  Pool2 = (char *)ExAllocatePool2(0x100, 0x598uLL, 0x476C6953u);
  *((_DWORD *)Pool2 + 318) = 0;
  *((_DWORD *)Pool2 + 319) = 259;
  *((_DWORD *)Pool2 + 334) = argument3;
  currentThread = KeGetCurrentThread();
  PspLockJobExclusive(argument0, currentThread);
  if ( (*(_DWORD *)(argument0 + 256) & 0x400000) != 0 )
  {
    *(_QWORD *)(argument0 + 1504) = Pool2;
  }
  PspUnlockJob(argument0, currentThread);
  return 0;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.process_thread.psp_convert_silo_to_server_silo",
            "Pool2",
        )
        job_identity = self._identity_for_base(
            plan,
            "windows.process_thread.psp_convert_silo_to_server_silo",
            "jobObject",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") in {"Pool2", "jobObject"}
        ]

        self.assertEqual("PS_SERVER_SILO_GLOBALS", identity["structure_name"])
        self.assertEqual("serverSiloGlobals", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual({0x4F8, 0x4FC, 0x538}, self._field_offsets(identity))
        self.assertEqual("EJOB", job_identity["structure_name"])
        self.assertTrue(job_identity["suppress_layout_inference"])
        self.assertEqual(set(), self._field_offsets(job_identity))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(any(item.get("base") == "jobObject" for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "Pool2"
                for item in plan.comments
            )
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _identity_for_base(self, plan, profile_id: str, base: str) -> dict[str, object]:
        identities = [
            item
            for item in self._identities(plan)
            if item.get("profile_id") == profile_id and item.get("base") == base
        ]
        self.assertEqual(1, len(identities))
        return identities[0]

    def _field_offsets(self, identity: dict[str, object]) -> set[int]:
        return {
            int(field.get("offset", -1))
            for field in identity.get("fields", []) or []
            if isinstance(field, dict)
        }
