from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
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

    def test_resolve_page_file_fault_context_role_requires_fault_callees(self) -> None:
        without_callees = self._plan(
            """
__int64 MiResolvePageFileFault(__int64 a1, unsigned __int64 a2)
{
  return *(_QWORD *)a1 + a2;
}
"""
        )
        with_callees = self._plan(
            """
__int64 MiResolvePageFileFault(__int64 a1, unsigned __int64 a2)
{
  __int64 address;
  __int64 support;

  address = *(_QWORD *)(a1 + 88);
  MiComputeFaultNode(a1, 0, &address, 0);
  support = MiAllocateInPageSupport(a2, 0, 0, 0, a1);
  MiReturnFaultCharges(0, 0, 0);
  return support + address;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.resolve_page_file_fault"
                for item in self._identities(without_callees)
            )
        )

        rename_map = {item.old: item.new for item in with_callees.renames if item.apply}
        identity = self._single_identity(
            with_callees,
            "windows.memory_manager.resolve_page_file_fault",
            role="pageFileFaultContext",
        )

        self.assertEqual("pageFileFaultContext", rename_map["a1"])
        self.assertEqual("MI_PAGE_FILE_FAULT_CONTEXT", identity["structure_name"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual([], identity["fields"])

    def test_complete_proto_pte_fault_identifies_pfn_entry_local(self) -> None:
        without_callees = self._plan(
            """
NTSTATUS __fastcall MiCompleteProtoPteFault(__int64 context, __int64 argument1)
{
  ULONG_PTR BugCheckParameter2;

  BugCheckParameter2 = 48 * argument1 - 0x220000000000LL;
  return *(_QWORD *)(BugCheckParameter2 + 16) ? STATUS_SUCCESS : STATUS_PTE_CHANGED;
}
"""
        )
        with_callees = self._plan(
            """
NTSTATUS __fastcall MiCompleteProtoPteFault(__int64 context, __int64 argument1)
{
  ULONG_PTR BugCheckParameter2;
  NTSTATUS status;

  BugCheckParameter2 = 48 * argument1 - 0x220000000000LL;
  if ( MiGetPagingFileOffset(*(_QWORD *)(BugCheckParameter2 + 16)) )
  {
    MiSetPfnModified(BugCheckParameter2, 1);
  }
  status = MiPrivateFixup(context, 0, 0, BugCheckParameter2, 0, 0);
  MiLockAndDecrementShareCount(BugCheckParameter2, 2LL, 0, 0);
  return status;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.memory_manager.complete_proto_pte_fault"
                for item in self._identities(without_callees)
            )
        )

        identity = self._identity_for_base(
            with_callees,
            "windows.memory_manager.complete_proto_pte_fault",
            "BugCheckParameter2",
        )

        self.assertEqual("MMPFN", identity["structure_name"])
        self.assertEqual("pfnEntry", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual([], identity["fields"])

    def test_private_memory_profiles_correct_weak_hexrays_parameter_types(self) -> None:
        samples = [
            (
                """
__int64 __fastcall MiCreateSlabEntry(__int64 a1, __int64 a2, int a3, unsigned __int8 a4)
{
  *(_QWORD *)(a2 + 40) = a1;
  return a3 + a4;
}
""",
                "windows.memory_manager.create_slab_entry",
                [
                    "PMI_SLAB_CONTEXT slabContext",
                    "PMI_SLAB_ENTRY slabEntry",
                    "ULONG slabPageCount",
                    "BOOLEAN zeroInitialize",
                ],
            ),
            (
                """
__int64 __fastcall ST_STORE<SM_TRAITS>::StWorkItemProcess(__int64 a1, unsigned __int64 a2, unsigned __int64 a3)
{
  return *(_QWORD *)(a1 + 24) + a2 + a3;
}
""",
                "windows.memory_manager.store_work_item_process",
                [
                    "PST_STORE_SM_TRAITS store",
                    "PST_WORK_ITEM workItem",
                    "ULONG_PTR workItemContext",
                ],
            ),
            (
                """
__int64 __fastcall MiCreateSharedZeroPages(__int64 a1, __int64 *a2)
{
  *a2 = a1;
  return 0;
}
""",
                "windows.memory_manager.create_shared_zero_pages",
                [
                    "PMI_SHARED_ZERO_PAGE_CONTEXT sharedZeroPageContext",
                    "PMMPFN * sharedZeroPageList",
                ],
            ),
            (
                """
__int64 __fastcall MiPfAllocateMdls(__int64 a1, unsigned int a2, _SLIST_ENTRY *a3, volatile signed __int64 *a4)
{
  return a2 + *a4 + (a3 != 0) + *(_QWORD *)(a1 + 8);
}
""",
                "windows.memory_manager.pf_allocate_mdls",
                [
                    "PMI_PAGEFILE_MDL_CONTEXT pageFileMdlContext",
                    "ULONG mdlCount",
                    "PSLIST_ENTRY mdlSList",
                    "volatile LONG64 * outstandingMdlCount",
                ],
            ),
            (
                """
void __fastcall MiLockPageListAndLastPage(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  *(_QWORD *)(a1 + 40) = a2 + a3 + a4;
}
""",
                "windows.memory_manager.lock_page_list_and_last_page",
                [
                    "PMI_PAGE_LIST_LOCK_CONTEXT pageListLockContext",
                    "PMMPFN lastPage",
                    "PMMPFN pageList",
                    "ULONG_PTR lockFlags",
                ],
            ),
            (
                """
__int64 __fastcall MiValidateAddPhysicalMemoryParameters(ULONG *a1, __int64 *a2, _DWORD *a3, __int64 a4, __int64 a5, __int64 a6)
{
  *(_DWORD *)(a6 + 40) = a4 | 1;
  *(_QWORD *)(a6 + 48) = a1;
  *(_QWORD *)(a6 + 32) = *(_QWORD *)a3 >> 12;
  MiLogAddPhysicalMemory((unsigned __int16 *)a1, a2, (__int64)a3, a4, 0LL);
  return 0;
}
""",
                "windows.memory_manager.validate_add_physical_memory_parameters",
                [
                    "PMMPARTITION partition",
                    "PPHYSICAL_ADDRESS startPhysicalAddress",
                    "PULONGLONG byteCount",
                    "ULONG addFlags",
                    "ULONG_PTR callerContext",
                    "PMI_ADD_PHYSICAL_MEMORY_CONTEXT addMemoryContext",
                ],
            ),
            (
                """
__int64 __fastcall VmpFillGpnRanges(int a1, __int64 a2, __int64 a3, __int64 *a4, __int64 a5, __int64 a6)
{
  __int128 range;
  int count;
  count = 0;
  range = 0;
  VmpConvertPortionVpnRangeToGpnRange(a1, a2, -1, a6, (__int64)&range, (__int64)&count, 0);
  *(_OWORD *)(a3 + 16 * *a4) = range;
  ++*a4;
  return *a4 == a5;
}
""",
                "windows.memory_manager.vmp_fill_gpn_ranges",
                [
                    "ULONG partitionId",
                    "PVMP_VPN_RANGE vpnRange",
                    "PVMP_GPN_RANGE gpnRanges",
                    "PULONG64 gpnRangeCount",
                    "ULONG64 gpnRangeCapacity",
                    "ULONG_PTR conversionContext",
                ],
            ),
            (
                """
__int64 __fastcall VmpFillSlat(__int64 a1, int a2, __int64 a3, _QWORD *a4, _QWORD *a5)
{
  if ( a3 == 512 )
  {
    return HvlMapGpaPages(*(_QWORD *)(a1 + 104), *a4, a2, 1, (__int64)(a4 + 1), (__int64)a5);
  }
  return HvlMapSparseGpaPages(*(_QWORD *)(a1 + 104), a2, a3, (_DWORD)a4, (__int64)a5);
}
""",
                "windows.memory_manager.vmp_fill_slat",
                [
                    "PVMP_CONTEXT vmpContext",
                    "ULONG mapFlags",
                    "ULONG pageCount",
                    "PULONG64 gpaRanges",
                    "PULONG64 mappedPageCount",
                ],
            ),
        ]
        expected_signatures = {
            "windows.memory_manager.create_slab_entry": "NTSTATUS __fastcall MiCreateSlabEntry(",
            "windows.memory_manager.store_work_item_process": "NTSTATUS __fastcall ST_STORE<SM_TRAITS>::StWorkItemProcess(",
            "windows.memory_manager.create_shared_zero_pages": "NTSTATUS __fastcall MiCreateSharedZeroPages(",
            "windows.memory_manager.pf_allocate_mdls": "NTSTATUS __fastcall MiPfAllocateMdls(",
            "windows.memory_manager.lock_page_list_and_last_page": "void __fastcall MiLockPageListAndLastPage(",
            "windows.memory_manager.validate_add_physical_memory_parameters": "NTSTATUS __fastcall MiValidateAddPhysicalMemoryParameters(",
            "windows.memory_manager.vmp_fill_gpn_ranges": "PVOID __fastcall VmpFillGpnRanges(",
            "windows.memory_manager.vmp_fill_slat": "NTSTATUS __fastcall VmpFillSlat(",
        }
        corrected_parameter_expectations = {
            "windows.memory_manager.store_work_item_process": ("store", "ST_STORE_SM_TRAITS", 9),
            "windows.memory_manager.create_shared_zero_pages": (
                "sharedZeroPageContext",
                "MI_SHARED_ZERO_PAGE_CONTEXT",
                8,
            ),
            "windows.memory_manager.pf_allocate_mdls": (
                "pageFileMdlContext",
                "MI_PAGEFILE_MDL_CONTEXT",
                9,
            ),
        }

        for text, profile_id, expected_fragments in samples:
            with self.subTest(profile_id=profile_id):
                capture = capture_from_pseudocode(text, source_path=SOURCE_PATH)
                plan = build_clean_plan(capture)
                rendered = render_cleaned_pseudocode(capture, plan)
                corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]

                self.assertEqual(len(expected_fragments), len(corrections))
                self.assertTrue(all(item.apply_to_preview for item in corrections))
                expected_map = corrected_parameter_expectations.get(profile_id)
                if expected_map:
                    expected_name, expected_structure, expected_field_count = expected_map
                    self.assertEqual(1, len(plan.corrected_parameter_map))
                    self.assertEqual(expected_name, plan.corrected_parameter_map[0].new_name)
                    self.assertEqual(expected_structure, plan.corrected_parameter_map[0].structure)
                    self.assertEqual(expected_field_count, len(plan.corrected_parameter_map[0].fields))
                else:
                    self.assertEqual([], plan.corrected_parameter_map)
                self.assertIn(expected_signatures[profile_id], rendered)
                for fragment in expected_fragments:
                    self.assertIn(fragment, rendered)

    def test_private_memory_profiles_use_validated_layout_rewrite_when_evidence_is_dense(self) -> None:
        samples = [
            (
                """
__int64 __fastcall ST_STORE<SM_TRAITS>::StWorkItemProcess(__int64 a1, unsigned __int64 a2, unsigned __int64 a3)
{
  __int64 total;

  total = *(_QWORD *)(a1 + 24)
        + *(unsigned int *)(a1 + 904)
        + *(_QWORD *)(a1 + 2280)
        + *(unsigned __int8 *)(a1 + 2368);
  total += *(unsigned __int8 *)(a1 + 2370)
        + *(_QWORD *)(a1 + 2376)
        + *(_QWORD *)(a1 + 6800)
        + *(_QWORD *)(a1 + 6808)
        + *(unsigned int *)(a1 + 6816);
  total += *(_QWORD *)(a1 + 24)
        + *(unsigned __int8 *)(a1 + 2368)
        + *(_QWORD *)(a1 + 6800)
        + *(unsigned int *)(a1 + 6816);
  return total + a2 + a3;
}
""",
                "store",
                "field_18",
                "field_1AA0",
                13,
            ),
            (
                """
__int64 __fastcall MiCreateSharedZeroPages(__int64 a1, __int64 *a2)
{
  __int64 total;

  total = *(_QWORD *)(a1 + 8)
        + *(_QWORD *)(a1 + 16)
        + *(_QWORD *)(a1 + 24)
        + *(unsigned int *)(a1 + 32);
  total += *(unsigned int *)(a1 + 36)
        + *(unsigned int *)(a1 + 48)
        + *(_QWORD *)(a1 + 56)
        + *(_QWORD *)(a1 + 64);
  total += *(_QWORD *)(a1 + 8)
        + *(_QWORD *)(a1 + 24)
        + *(unsigned int *)(a1 + 32)
        + *(_QWORD *)(a1 + 56);
  *a2 = total;
  return STATUS_SUCCESS;
}
""",
                "sharedZeroPageContext",
                "field_8",
                "field_40",
                12,
            ),
            (
                """
__int64 __fastcall MiPfAllocateMdls(__int64 a1, unsigned int a2, _SLIST_ENTRY *a3, volatile signed __int64 *a4)
{
  __int64 total;

  total = *(_QWORD *)(a1 + 8)
        + *(_QWORD *)(a1 + 16)
        + *(_QWORD *)(a1 + 24)
        + *(unsigned int *)(a1 + 184);
  total += *(unsigned int *)(a1 + 188)
        + *(unsigned int *)(a1 + 196)
        + *(_QWORD *)(a1 + 200)
        + *(unsigned int *)(a1 + 212)
        + *(_QWORD *)(a1 + 232);
  total += *(_QWORD *)(a1 + 16)
        + *(unsigned int *)(a1 + 184)
        + *(_QWORD *)(a1 + 232);
  return total + a2 + (a3 != 0) + *a4;
}
""",
                "pageFileMdlContext",
                "field_8",
                "field_E8",
                12,
            ),
        ]

        for text, base, first_field, last_field, expected_accesses in samples:
            with self.subTest(base=base):
                capture = capture_from_pseudocode(text, source_path=SOURCE_PATH)
                plan = build_clean_plan(capture)
                ready = [
                    item
                    for item in plan.comments
                    if item.get("kind") == "inferred_offset_rewrite_ready"
                    and item.get("base") == base
                ]
                blockers = [
                    item
                    for item in plan.comments
                    if item.get("kind") == "inferred_offset_rewrite_blockers"
                    and item.get("base") == base
                ]

                self.assertEqual(1, len(plan.corrected_parameter_map))
                self.assertEqual(base, plan.corrected_parameter_map[0].new_name)
                self.assertEqual([], blockers)
                self.assertEqual(1, len(ready))
                self.assertEqual("domain_identity", ready[0]["source_provenance"])

                with tempfile.TemporaryDirectory() as temp_dir:
                    artifacts = write_export_bundle(
                        temp_dir,
                        capture,
                        plan,
                        entrypoint="ida_interactive",
                        apply_validated_layout_rewrites=True,
                    )
                    preview = Path(artifacts["layout_rewrite_preview"]).read_text(encoding="utf-8")
                    metadata = json.loads(
                        Path(artifacts["layout_rewrite_preview_metadata"]).read_text(
                            encoding="utf-8"
                        )
                    )

                self.assertEqual("applied", metadata["canonical_rewrite_status"])
                self.assertEqual([base], metadata["rewritten_bases"])
                self.assertEqual(expected_accesses, metadata["rewritten_accesses"])
                self.assertIn("%s->%s" % (base, first_field), preview)
                self.assertIn("%s->%s" % (base, last_field), preview)

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
