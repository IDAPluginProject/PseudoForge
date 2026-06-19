from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class MemoryManagerDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_locate_address_roles(self) -> None:
        plan = self._plan(
            """
struct _LIST_ENTRY *__fastcall MiLocateAddress(unsigned __int64 a1)
{
  _KPROCESS *currentProcess;
  struct _LIST_ENTRY *result;

  currentProcess = KeGetCurrentThread()->ApcState.Process;
  result = currentProcess[3].Header.WaitListHead.Flink;
  return result;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.memory_manager.locate_address",
            )
        }

        self.assertEqual("VIRTUAL_ADDRESS", roles["virtualAddress"])
        self.assertEqual("EPROCESS", roles["currentProcess"])
        self.assertEqual("MMVAD", roles["foundVad"])
        self.assertTrue(
            all(
                item["effective_mode"] == "report-only"
                for item in self._profile_identities(plan, "windows.memory_manager.locate_address")
            )
        )

    def test_insert_vad_requires_avl_insert(self) -> None:
        without_callee = self._plan(
            """
void __fastcall MiInsertVad(__int64 vadNode, __int64 parentVadShort, char insertFlags)
{
  unsigned __int64 startingAddress;
  unsigned __int64 endingAddress;

  startingAddress = 0;
  endingAddress = 0;
}
"""
        )
        with_callee = self._plan(
            """
void __fastcall MiInsertVad(__int64 vadNode, __int64 parentVadShort, char insertFlags)
{
  unsigned __int64 startingAddress;
  unsigned __int64 endingAddress;

  startingAddress = 0;
  endingAddress = 0;
  RtlAvlInsertNodeEx(parentVadShort + 1368, 0, 0, vadNode);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.insert_vad"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.memory_manager.insert_vad",
            )
        }

        self.assertEqual("MMVAD", roles["insertedVad"])
        self.assertEqual("EPROCESS", roles["targetProcess"])
        self.assertEqual("VAD_INSERT_FLAGS", roles["insertFlags"])
        self.assertEqual("VPN", roles["startingVpn"])
        self.assertEqual("VPN", roles["endingVpn"])

    def test_remove_vad_requires_remove_and_dereference_callees(self) -> None:
        without_callees = self._plan(
            """
_BOOL8 __fastcall MiRemoveVad(__int64 removedVad, int removeAccounting, __int64 replacementVad)
{
  __int64 currentProcess;
  __int64 PreviousVad;
  __int64 NextVad;

  currentProcess = 0;
  PreviousVad = 0;
  NextVad = 0;
  return 0;
}
"""
        )
        with_callees = self._plan(
            """
_BOOL8 __fastcall MiRemoveVad(__int64 removedVad, int removeAccounting, __int64 replacementVad)
{
  __int64 currentProcess;
  __int64 PreviousVad;
  __int64 NextVad;

  currentProcess = (__int64)KeGetCurrentThread()->ApcState.Process;
  PreviousVad = MiGetPreviousVad((unsigned __int64 *)removedVad);
  NextVad = MiGetNextVad(removedVad);
  RtlAvlRemoveNode(currentProcess + 1368, removedVad);
  MiDereferenceVad(removedVad);
  if ( replacementVad )
  {
    MiInsertVad(replacementVad, currentProcess, 2);
  }
  return 1;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.remove_vad"
                for item in self._identities(without_callees)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callees,
                "windows.memory_manager.remove_vad",
            )
        }

        self.assertEqual("MMVAD", roles["removedVad"])
        self.assertEqual("BOOLEAN", roles["removeAddressSpaceAccounting"])
        self.assertEqual("MMVAD", roles["replacementVad"])
        self.assertEqual("EPROCESS", roles["currentProcess"])
        self.assertEqual("MMVAD", roles["previousVad"])
        self.assertEqual("MMVAD", roles["nextVad"])

    def test_obtain_referenced_vad_ex_requires_lookup_and_unlock(self) -> None:
        without_callees = self._plan(
            """
__int64 __fastcall MiObtainReferencedVadEx(unsigned __int64 a1, __int64 a2, int *a3, __int64 a4)
{
  __int64 Address;
  Address = 0;
  *a3 = 0;
  return Address;
}
"""
        )
        with_callees = self._plan(
            """
__int64 __fastcall MiObtainReferencedVadEx(unsigned __int64 a1, __int64 a2, int *a3, __int64 a4)
{
  _KPROCESS *currentProcess;
  __int64 Address;

  *a3 = 0;
  currentProcess = KeGetCurrentThread()->ApcState.Process;
  Address = MiLocateAddress(a1);
  MiUnlockVadTree(0, 0);
  return Address;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.obtain_referenced_vad_ex"
                for item in self._identities(without_callees)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callees,
                "windows.memory_manager.obtain_referenced_vad_ex",
            )
        }

        self.assertEqual("VIRTUAL_ADDRESS", roles["virtualAddress"])
        self.assertEqual("VAD_OBTAIN_FLAGS", roles["obtainFlags"])
        self.assertEqual("NTSTATUS_OUTPUT", roles["statusOutput"])
        self.assertEqual("VAD_OBTAIN_CONTEXT", roles["callerContext"])
        self.assertEqual("MMVAD", roles["referencedVad"])
        self.assertEqual("EPROCESS", roles["currentProcess"])

    def test_check_virtual_address_requires_user_check_callee(self) -> None:
        without_callee = self._plan(
            """
__int64 __fastcall MiCheckVirtualAddress(unsigned __int64 a1, _DWORD *a2, struct _LIST_ENTRY **a3)
{
  struct _LIST_ENTRY *Flink;
  Flink = 0;
  *a3 = Flink;
  return 0;
}
"""
        )
        with_callee = self._plan(
            """
__int64 __fastcall MiCheckVirtualAddress(unsigned __int64 a1, _DWORD *a2, struct _LIST_ENTRY **a3)
{
  _KPROCESS *currentProcess;
  struct _LIST_ENTRY *Flink;

  currentProcess = KeGetCurrentThread()->ApcState.Process;
  Flink = currentProcess[3].Header.WaitListHead.Flink;
  *a3 = Flink;
  return MiCheckUserVirtualAddress(a1, (__int64)Flink, (__int64)currentProcess, (int *)a2);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.check_virtual_address"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.memory_manager.check_virtual_address",
            )
        }

        self.assertEqual("VIRTUAL_ADDRESS", roles["virtualAddress"])
        self.assertEqual("VAD_CHECK_RESULT_OUTPUT", roles["checkResultOutput"])
        self.assertEqual("MMVAD_OUTPUT", roles["foundVadOutput"])
        self.assertEqual("EPROCESS", roles["currentProcess"])
        self.assertEqual("MMVAD", roles["foundVad"])

    def test_charge_and_range_roles(self) -> None:
        charge_plan = self._plan(
            """
__int64 __fastcall MiInsertVadCharges(__int64 vadEntryPtr, __int64 processPtr)
{
  struct _KTHREAD *currentThread;
  __int128 vadChargesStruct;

  currentThread = KeGetCurrentThread();
  vadChargesStruct = 0;
  MiComputeVadCharges(vadEntryPtr, (__int64)&vadChargesStruct);
  return PsChargeProcessPagedPoolQuota(processPtr, 1);
}
"""
        )
        range_plan = self._plan(
            """
__int64 __fastcall MiLockVadRange(__int64 targetProcess, unsigned __int64 rangeStart, unsigned __int64 rangeEnd, int exclusiveLock)
{
  struct _LIST_ENTRY *FirstVad;
  unsigned __int64 NextVad;

  FirstVad = MiLocateAddress(rangeStart);
  NextVad = MiGetNextVad((unsigned __int64)FirstVad);
  return exclusiveLock + rangeEnd + NextVad;
}
"""
        )

        charge_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                charge_plan,
                "windows.memory_manager.insert_vad_charges",
            )
        }
        range_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                range_plan,
                "windows.memory_manager.lock_vad_range",
            )
        }

        self.assertEqual("MMVAD", charge_roles["chargedVad"])
        self.assertEqual("EPROCESS", charge_roles["chargedProcess"])
        self.assertEqual("ETHREAD", charge_roles["currentThread"])
        self.assertEqual("VAD_CHARGES", charge_roles["computedCharges"])
        self.assertEqual("EPROCESS", range_roles["targetProcess"])
        self.assertEqual("VIRTUAL_ADDRESS", range_roles["rangeStart"])
        self.assertEqual("VIRTUAL_ADDRESS", range_roles["rangeEnd"])
        self.assertEqual("BOOLEAN", range_roles["exclusiveLock"])
        self.assertEqual("MMVAD", range_roles["firstVad"])
        self.assertEqual("MMVAD", range_roles["nextVad"])

    def test_report_only_vad_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __fastcall MiInsertVad(__int64 vadNode, __int64 parentVadShort, char insertFlags)
{
  __int64 probe;

  probe = *(_QWORD *)(vadNode + 16)
        + *(_QWORD *)(vadNode + 24)
        + *(_QWORD *)(vadNode + 32)
        + *(_QWORD *)(vadNode + 40)
        + *(_QWORD *)(vadNode + 48)
        + *(_QWORD *)(vadNode + 56)
        + *(_QWORD *)(vadNode + 64)
        + *(_QWORD *)(vadNode + 72)
        + *(_QWORD *)(vadNode + 16)
        + *(_QWORD *)(vadNode + 24)
        + *(_QWORD *)(vadNode + 32)
        + *(_QWORD *)(vadNode + 40);
  RtlAvlInsertNodeEx(parentVadShort + 1368, 0, 0, vadNode);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.memory_manager.insert_vad",
            "vadNode",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "vadNode"
        ]

        self.assertEqual("MMVAD", identity["structure_name"])
        self.assertEqual("insertedVad", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "vadNode"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __fastcall MiReferenceVad(__int64 vad_ptr)
{
  _InterlockedIncrement((volatile signed __int32 *)(vad_ptr + 36));
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.memory_manager.reference_vad",
            role="referencedVad",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_vad_type(self) -> None:
        plan = self._plan(
            """
void __fastcall MiReferenceVad(int vad_ptr)
{
  vad_ptr = 0;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.reference_vad"
                and item["trusted_role"] == "referencedVad"
                for item in self._identities(plan)
            )
        )

    def test_memory_manager_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __fastcall MiReferenceVad(__int64 vad_ptr)
{
  _InterlockedIncrement((volatile signed __int32 *)(vad_ptr + 36));
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/memory_manager.json" for item in manifests)
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

    def _identity_for_base(self, plan, profile_id: str, base: str) -> dict[str, object]:
        identities = [
            item
            for item in self._identities(plan)
            if item.get("profile_id") == profile_id and item.get("base") == base
        ]
        self.assertEqual(1, len(identities))
        return identities[0]
