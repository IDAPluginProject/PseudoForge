from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ProcessThreadNotifyDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_public_process_notify_registration_roles(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, BOOLEAN Remove)
{
  return PspSetCreateProcessNotifyRoutine(NotifyRoutine, Remove != 0);
}
"""
        )

        identities = self._profile_identities(
            plan,
            "windows.process_thread_notify.ps_set_create_process_notify",
        )

        self.assertEqual(
            {
                "processNotifyCallback": "PCREATE_PROCESS_NOTIFY_ROUTINE",
                "removeRegistration": "BOOLEAN",
            },
            {item["trusted_role"]: item["structure_name"] for item in identities},
        )
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertTrue(all("profile_report_only" in item["blockers"] for item in identities))

    def test_private_thread_notify_registration_requires_callback_allocation(self) -> None:
        without_callee = self._plan(
            """
__int64 __fastcall PspSetCreateThreadNotifyRoutine(__int64 callbackRoutinePtr, unsigned int flagsOrContext)
{
  return 0;
}
"""
        )
        with_callee = self._plan(
            """
__int64 __fastcall PspSetCreateThreadNotifyRoutine(__int64 callbackRoutinePtr, unsigned int flagsOrContext)
{
  struct _EX_RUNDOWN_REF *callbackEntryPtr;
  callbackEntryPtr = (struct _EX_RUNDOWN_REF *)ExAllocateCallBack(callbackRoutinePtr, flagsOrContext);
  return 0;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.process_thread_notify.psp_set_create_thread_notify"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.process_thread_notify.psp_set_create_thread_notify",
            )
        }

        self.assertEqual("THREAD_NOTIFY_CALLBACK", roles["threadNotifyCallback"])
        self.assertEqual("THREAD_NOTIFY_FLAGS", roles["setRoutineFlags"])
        self.assertEqual("EX_CALLBACK_BLOCK", roles["callbackBlock"])

    def test_thread_notify_dispatch_adds_callback_block_without_ambiguity(self) -> None:
        plan = self._plan(
            """
void __fastcall PspCallThreadNotifyRoutines(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4)
{
  struct _EX_RUNDOWN_REF *v8;
  v8 = ExReferenceCallBackBlock((signed __int64 *)&PspCreateThreadNotifyRoutine.Ptr, a2, a3, a4);
  ExDereferenceCallBackBlock((signed __int64 *)&PspCreateThreadNotifyRoutine.Ptr, v8);
}
"""
        )

        lifecycle_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.process_thread.psp_call_thread_notify_routines",
            )
        }
        notify_identity = self._single_identity(
            plan,
            "windows.process_thread_notify.psp_call_thread_notify_callback_block",
        )

        self.assertEqual("ETHREAD", lifecycle_roles["threadObject"])
        self.assertEqual("BOOLEAN", lifecycle_roles["isCreateEvent"])
        self.assertEqual("v8", notify_identity["base"])
        self.assertEqual("callbackBlock", notify_identity["trusted_role"])
        self.assertEqual("EX_CALLBACK_BLOCK", notify_identity["structure_name"])
        self.assertFalse(any(item["profile_id"] == "ambiguous" for item in self._identities(plan)))

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, BOOLEAN Remove)
{
  return PspSetCreateProcessNotifyRoutine(NotifyRoutine, Remove != 0);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.process_thread_notify.ps_set_create_process_notify",
            role="processNotifyCallback",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_callback_type(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutine(int NotifyRoutine, BOOLEAN Remove)
{
  return STATUS_INVALID_PARAMETER;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.process_thread_notify.ps_set_create_process_notify"
                and item["trusted_role"] == "processNotifyCallback"
                for item in self._identities(plan)
            )
        )

    def test_notify_pack_manifest_is_reported_when_used(self) -> None:
        self._plan(
            """
NTSTATUS __stdcall PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, BOOLEAN Remove)
{
  return PspSetCreateProcessNotifyRoutine(NotifyRoutine, Remove != 0);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/process_thread_notify.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

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
