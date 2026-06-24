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
__int64 __fastcall MiCreatePfnTemplate(__int64 a1, __int16 a2, unsigned __int16 a3)
{
  __int64 demandZeroPte;

  *(_OWORD *)a1 = 0LL;
  *(_OWORD *)(a1 + 16) = 0LL;
  *(_OWORD *)(a1 + 32) = 0LL;
  MiSetPfnTbFlushStamp(a1, 0LL, 0);
  MiSetPfnIdentity(a1, 3u);
  demandZeroPte = MiMakeDemandZeroPte(4);
  *(_QWORD *)(a1 + 16) = demandZeroPte;
  MiSetPfnContainingFrame(a1, 0x3FFFFFFFFELL);
  MiSetPageTablePfnBuddy(a1, 0x10000000001LL, 1LL, 0);
  *(_QWORD *)(a1 + 40) = (a3 << 43) ^ (*(_QWORD *)(a1 + 40) ^ (a3 << 43)) & 0xFFE007FFFFFFFFFFuLL;
  return *(_QWORD *)(a1 + 24) + *(unsigned int *)(a1 + 32) + *(_QWORD *)(a1 + 40) + a2;
}
""",
                "windows.memory_manager.create_pfn_template",
                [
                    "PMMPFN pfnTemplate",
                ],
            ),
            (
                """
char __fastcall MiFreePagesFromMdl(ULONG_PTR a1, unsigned int a2, char a3, int a4)
{
  ULONG_PTR *pfnArray;
  ULONG_PTR pageCount;

  if ( _bittest16((const signed __int16 *)(a1 + 10), 9u) )
  {
    MiRetardMdl(a1);
  }
  if ( (*(_BYTE *)(a1 + 10) & 1) != 0 )
  {
    MmUnmapLockedPages(*(PVOID *)(a1 + 24), (PMDL)a1);
  }
  pfnArray = (ULONG_PTR *)(a1 + 48);
  pageCount = (((*(_DWORD *)(a1 + 32) + *(_DWORD *)(a1 + 44)) & 0xFFF)
       + (unsigned __int64)*(unsigned int *)(a1 + 40)
       + 4095) >> 12;
  MiFreeMdlPageRun(*pfnArray, pageCount, a2, a3, 0);
  MiZeroAndReleasePages(0, a2, a3);
  *(_WORD *)(a1 + 10) &= ~2u;
  return a4 != 0;
}
""",
                "windows.memory_manager.free_pages_from_mdl",
                [
                    "PMDL mdl",
                ],
            ),
            (
                """
__int64 __fastcall MiCreateSlabEntry(__int64 a1, __int64 a2, int a3, unsigned __int8 a4)
{
  *(_QWORD *)(a2 + 184) = *(_QWORD *)(a1 + 176);
  *(_DWORD *)(a2 + 17748) = *(_DWORD *)(a1 + 128);
  return *(_DWORD *)(a1 + 136) + a3 + a4;
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
char __fastcall MiChangeSlabEntryIdentity(__int64 a1, __int64 a2)
{
  __int64 listHead;
  __int64 listBlink;
  int flags;

  listHead = *(_QWORD *)(a2 + 24);
  listBlink = *(_QWORD *)(a2 + 32);
  if ( *(_QWORD *)(listHead + 8) != a2 + 24 )
  {
    __fastfail(3u);
  }
  *(_QWORD *)listBlink = listHead;
  MiClearHintSlabEntry(a1, a2);
  flags = *(_DWORD *)(a2 + 92);
  *(_DWORD *)(a2 + 92) = flags | 4;
  return MiSetSlabTypeIdentifiers(
           *(_QWORD *)(a2 + 40),
           LODWORD(MiPageSizes[(*(_DWORD *)(a1 + 136) >> 4) & 3]),
           *(_DWORD *)(a1 + 128),
           flags,
           flags & 1);
}
""",
                "windows.memory_manager.change_slab_entry_identity",
                [
                    "PMI_SLAB_CONTEXT slabContext",
                    "PMI_SLAB_ENTRY slabEntry",
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
  *(_DWORD *)(a1 + 32) |= 0x40000000u;
  *(_QWORD *)(a1 + 40) = *(_QWORD *)(a1 + 24) + a2 + a3 + a4;
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
__int64 __fastcall VmpSplitMemoryRange(PEX_SPIN_LOCK a1, unsigned __int64 a2, __int64 a3)
{
  __int64 lockState;
  __int64 v12;
  unsigned __int64 MemoryRanges;
  __int64 secureHandle;

  lockState = VmpProcessContextLockShared(a1);
  if ( *((_QWORD *)a1 + 13) != a3 )
  {
    VmpProcessContextUnlockShared(a1, lockState);
    return STATUS_CONTEXT_MISMATCH;
  }
  v12 = *((_QWORD *)a1 + 3);
  MemoryRanges = VmpAllocateMemoryRanges(VmpVaRangeNumberOfGpaRanges(v12));
  secureHandle = VmpSecureMemoryForPin(a1, a2 + 1, *(_QWORD *)(v12 + 32) - a2, 0LL);
  lockState = VmpProcessContextLockExclusive(a1);
  *(_QWORD *)(MemoryRanges + 24) = a2 + 1;
  *(_QWORD *)(MemoryRanges + 32) = *(_QWORD *)(v12 + 32);
  *(_QWORD *)(MemoryRanges + 40) = *(_QWORD *)(v12 + 40);
  *(_QWORD *)(MemoryRanges + 56) = secureHandle;
  *(_DWORD *)(MemoryRanges + 72) = *(_DWORD *)(v12 + 72) & 3;
  *(_QWORD *)(v12 + 32) = a2;
  ++*((_QWORD *)a1 + 9);
  RtlRbInsertNodeEx((__int64 *)a1 + 3, 0LL, 0, MemoryRanges);
  VmpProcessContextUnlockExclusive(a1, lockState);
  return 0;
}
""",
                "windows.memory_manager.vmp_split_memory_range",
                [
                    "PVMP_PROCESS_CONTEXT processContext",
                    "ULONG_PTR splitAddress",
                ],
            ),
            (
                """
__int64 __fastcall MiConvertLargeActivePageToChain(__int64 a1)
{
  __int64 v3;
  unsigned int state;

  v3 = a1 + 48 * MiPageSizes[(unsigned int)MiGetPfnPageSizeIndex(a1)];
  v3 -= 48;
  state = *(_DWORD *)(v3 + 32);
  *(_DWORD *)(v3 + 32) = state & 0xFFF8FFFF;
  if ( (unsigned int)MiCanPfnOriginalPteBeLost(v3) )
  {
    *(_QWORD *)(v3 + 16) &= ~4uLL;
  }
  *(_QWORD *)(v3 + 24) &= 0xC000000000000000uLL;
  *(_BYTE *)(v3 + 34) &= 0xF8u;
  *(_DWORD *)(v3 + 36) &= 0xE7FFFFFF;
  *(_QWORD *)(v3 + 40) &= ~0x30000000000uLL;
  if ( (*(_QWORD *)(v3 + 16) & 0x3E0LL) == 0 )
  {
    MiArePageContentsZero((v3 + 0x220000000000LL) / 48);
  }
  return a1;
}
""",
                "windows.memory_manager.convert_large_active_page_to_chain",
                [
                    "PMMPFN largePagePfn",
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
    *(_WORD *)(a1 + 136) |= 1u;
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
            "windows.memory_manager.create_pfn_template": "ULONG_PTR __fastcall MiCreatePfnTemplate(",
            "windows.memory_manager.free_pages_from_mdl": "char __fastcall MiFreePagesFromMdl(",
            "windows.memory_manager.create_slab_entry": "NTSTATUS __fastcall MiCreateSlabEntry(",
            "windows.memory_manager.change_slab_entry_identity": "char __fastcall MiChangeSlabEntryIdentity(",
            "windows.memory_manager.store_work_item_process": "NTSTATUS __fastcall ST_STORE<SM_TRAITS>::StWorkItemProcess(",
            "windows.memory_manager.create_shared_zero_pages": "NTSTATUS __fastcall MiCreateSharedZeroPages(",
            "windows.memory_manager.pf_allocate_mdls": "NTSTATUS __fastcall MiPfAllocateMdls(",
            "windows.memory_manager.lock_page_list_and_last_page": "void __fastcall MiLockPageListAndLastPage(",
            "windows.memory_manager.validate_add_physical_memory_parameters": "NTSTATUS __fastcall MiValidateAddPhysicalMemoryParameters(",
            "windows.memory_manager.vmp_split_memory_range": "NTSTATUS __fastcall VmpSplitMemoryRange(",
            "windows.memory_manager.convert_large_active_page_to_chain": "__int64 __fastcall MiConvertLargeActivePageToChain(",
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
                identities = self._profile_identities(plan, profile_id)
                if profile_id == "windows.memory_manager.create_pfn_template":
                    pfn_template = self._single_identity(plan, profile_id, "pfnTemplate")
                    blockers = [
                        item
                        for item in plan.comments
                        if item.get("kind") == "inferred_offset_rewrite_blockers"
                        and item.get("base") == "pfnTemplate"
                    ]
                    self.assertEqual("MMPFN", pfn_template["structure_name"])
                    self.assertTrue({0x0, 0x10, 0x18, 0x20, 0x28}.issubset(self._field_offsets(pfn_template)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                    self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
                if profile_id == "windows.memory_manager.free_pages_from_mdl":
                    mdl = self._single_identity(plan, profile_id, "mdl")
                    blockers = [
                        item
                        for item in plan.comments
                        if item.get("kind") == "inferred_offset_rewrite_blockers"
                        and item.get("base") == "mdl"
                    ]
                    self.assertEqual("MDL", mdl["structure_name"])
                    self.assertEqual({0xA, 0x18, 0x20, 0x28, 0x2C}, self._field_offsets(mdl))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                    self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
                if profile_id == "windows.memory_manager.create_slab_entry":
                    slab_context = self._single_identity(plan, profile_id, "slabContext")
                    slab_entry = self._single_identity(plan, profile_id, "slabEntry")
                    self.assertTrue({0x80, 0x88, 0xB0}.issubset(self._field_offsets(slab_context)))
                    self.assertTrue({0xB8, 0x4554}.issubset(self._field_offsets(slab_entry)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                if profile_id == "windows.memory_manager.change_slab_entry_identity":
                    slab_context = self._single_identity(plan, profile_id, "slabContext")
                    slab_entry = self._single_identity(plan, profile_id, "slabEntry")
                    self.assertTrue({0x80, 0x88}.issubset(self._field_offsets(slab_context)))
                    self.assertTrue({0x18, 0x28, 0x5C}.issubset(self._field_offsets(slab_entry)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                if profile_id == "windows.memory_manager.lock_page_list_and_last_page":
                    page_lock = self._single_identity(plan, profile_id, "pageListLockContext")
                    self.assertTrue({0x18, 0x20, 0x28}.issubset(self._field_offsets(page_lock)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                if profile_id == "windows.memory_manager.vmp_fill_slat":
                    vmp_context = self._single_identity(plan, profile_id, "vmpContext")
                    self.assertEqual({0x68, 0x88}, self._field_offsets(vmp_context))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                if profile_id == "windows.memory_manager.vmp_split_memory_range":
                    process_context = self._single_identity(plan, profile_id, "processContext")
                    new_range = self._single_identity(plan, profile_id, "newMemoryRange")
                    existing_range = self._single_identity(plan, profile_id, "existingMemoryRange")
                    self.assertTrue({0x18, 0x48, 0x68}.issubset(self._field_offsets(process_context)))
                    self.assertTrue({0x18, 0x20, 0x28, 0x38, 0x48}.issubset(self._field_offsets(new_range)))
                    self.assertTrue({0x20, 0x28, 0x48}.issubset(self._field_offsets(existing_range)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                if profile_id == "windows.memory_manager.convert_large_active_page_to_chain":
                    large_page = self._single_identity(plan, profile_id, "largePagePfn")
                    chain_entry = self._single_identity(plan, profile_id, "chainPfnEntry")
                    expected_offsets = {0x10, 0x18, 0x20, 0x22, 0x24, 0x28}
                    self.assertEqual("MMPFN", large_page["structure_name"])
                    self.assertEqual([], large_page["fields"])
                    self.assertTrue(expected_offsets.issubset(self._field_offsets(chain_entry)))
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
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

    def test_report_only_function_identity_blocks_source_less_local_layout_rewrite(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MiCreateSlabEntry(__int64 a1, __int64 a2, int a3, unsigned __int8 a4)
{
  __int64 SlabEntry;
  int total;

  SlabEntry = MiAllocateSlabEntry(a1);
  if ( SlabEntry )
  {
    *(_DWORD *)(SlabEntry + 84) = a3;
    total = *(_DWORD *)(SlabEntry + 92);
    *(_DWORD *)(SlabEntry + 92) = total | 4;
    *(_QWORD *)(SlabEntry + 40) = a2;
    *(_QWORD *)(SlabEntry + 48) = a2 + a3;
    total += *(_QWORD *)(SlabEntry + 40);
    total += *(_QWORD *)(SlabEntry + 48);
    total += *(_DWORD *)(SlabEntry + 84);
    total += *(_DWORD *)(SlabEntry + 92);
    total += *(_QWORD *)(SlabEntry + 40);
    total += *(_QWORD *)(SlabEntry + 48);
    return total + a4;
  }
  return 0;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        ready = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_ready"
            and item.get("base") == "SlabEntry"
        ]
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "SlabEntry"
        ]

        identities = self._profile_identities(plan, "windows.memory_manager.create_slab_entry")
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertEqual([], ready)
        self.assertTrue(
            any(
                "report-only function identity requires trusted rewrite source"
                in item.get("blockers", [])
                for item in blockers
            )
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                apply_validated_layout_rewrites=True,
            )
            cleaned = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")

        self.assertNotIn("layout_rewrite_preview", artifacts)
        self.assertNotIn("SlabEntry->field_", cleaned)
        self.assertIn("*(_DWORD *)(SlabEntry + 84)", cleaned)

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

    def test_unlink_bad_pages_identifies_computed_pfn_entry_fields_report_only(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall MiUnlinkBadPages(ULONG_PTR BugCheckParameter2, ULONG_PTR argument1)
{
  ULONG_PTR i;
  __int64 v6;
  __int64 v7;
  __int64 v8;
  char lockState;

  for ( i = 48 * BugCheckParameter2 - 0x220000000000LL; BugCheckParameter2 < argument1; i += 48LL )
  {
    lockState = MiSafeLockPage(BugCheckParameter2, v6, v7, v8);
    if ( lockState != 17 )
    {
      *(_DWORD *)(i + 32) &= 0x7FFFFFFF;
      *(_QWORD *)(i + 24) |= 0x4000000000000000uLL;
      *(_QWORD *)(i + 40) >>= 43;
      MiUnlockPage(i, lockState);
    }
  }
  return 0;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.memory_manager.unlink_bad_pages",
            "i",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "i"
        ]

        self.assertEqual("MMPFN", identity["structure_name"])
        self.assertEqual("pfnEntry", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual({0x18, 0x20, 0x28}, self._field_offsets(identity))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "i"
                for item in plan.comments
            )
        )

    def test_wsle_free_adds_report_only_pfn_hot_cluster_identity(self) -> None:
        capture = capture_from_pseudocode(
            """
ULONG_PTR __fastcall MiWsleFree(unsigned __int64 a1, unsigned __int64 a2, char a3, unsigned __int64 a4)
{
  __int64 v9;
  ULONG_PTR result;

  v9 = 48 * ((a4 >> 12) & 0xFFFFFFFFFFLL) - 0x220000000000LL;
  result = *(_QWORD *)(v9 + 8)
         + *(_QWORD *)(v9 + 16)
         + *(_QWORD *)(v9 + 24)
         + *(unsigned int *)(v9 + 32)
         + *(unsigned __int8 *)(v9 + 34)
         + *(unsigned int *)(v9 + 36)
         + *(_QWORD *)(v9 + 40);
  MiInsertPageInFreeOrZeroedList((v9 + 0x220000000000LL) / 48);
  MiInsertPageInList(v9, 4);
  return result + a1 + a2 + a3 + a4;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        identity = self._identity_for_base(
            plan,
            "windows.memory_manager.wsle_free",
            "v9",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "v9"
        ]

        self.assertIn("ULONG_PTR __fastcall MiWsleFree(", rendered)
        self.assertIn("char freeFlags", rendered)
        self.assertIn("unsigned __int64 pteValue", rendered)
        self.assertEqual("MMPFN", identity["structure_name"])
        self.assertEqual("pfnEntry", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual({0x8, 0x10, 0x18, 0x20, 0x22, 0x24, 0x28}, self._field_offsets(identity))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "v9"
                for item in plan.comments
            )
        )

    def test_report_only_direct_parameter_alias_blocks_rewrite(self) -> None:
        plan = self._plan(
            """
ULONG_PTR __fastcall MiLockPageListAndLastPage(__int64 pageListLockContext, __int64 lastPage, __int64 pageList, int lockFlags)
{
  __int64 v5;

  v5 = lastPage;
  return *(_QWORD *)(v5 + 8)
       + *(_QWORD *)(v5 + 16)
       + *(unsigned __int8 *)(v5 + 24)
       + *(_QWORD *)(v5 + 32)
       + *(_QWORD *)(v5 + 40)
       + *(unsigned __int8 *)(v5 + 48)
       + *(_QWORD *)(v5 + 56)
       + *(_QWORD *)(v5 + 64)
       + *(unsigned __int8 *)(v5 + 72)
       + *(_QWORD *)(v5 + 80)
       + *(_QWORD *)(v5 + 88)
       + *(unsigned __int8 *)(v5 + 96)
       + *(_QWORD *)(v5 + 8)
       + *(_QWORD *)(v5 + 16)
       + *(unsigned __int8 *)(v5 + 24)
       + *(_QWORD *)(v5 + 32)
       + *(_QWORD *)(v5 + 40)
       + *(unsigned __int8 *)(v5 + 48)
       + pageListLockContext
       + pageList
       + lockFlags;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.memory_manager.lock_page_list_and_last_page",
            "lastPage",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "v5"
        ]

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertTrue(
            any("source domain identity profile is report-only" in item["blockers"] for item in blockers)
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "v5"
                for item in plan.comments
            )
        )

    def test_prefetch_virtual_memory_preview_signature_only(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall MiPrefetchVirtualMemory(unsigned __int64 a1, __int64 a2, __int64 a3, int a4)
{
  __int64 status;

  if ( a3 == 1 )
  {
    status = 0;
  }
  else
  {
    status = *(_DWORD *)(a3 + 184);
  }
  if ( (a4 & 0x10000) != 0 )
  {
    MiPrefetchPreallocatePages(a1, a2, a3, a4, 0, 0, 0);
  }
  status += MmAccessFault(0, *(_QWORD *)a2, 0, a4);
  MiPfCoalesceAndIssueIOs(a2, a3, 0);
  return status;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        identities = self._profile_identities(
            plan,
            "windows.memory_manager.prefetch_virtual_memory",
        )

        self.assertIn("NTSTATUS __fastcall MiPrefetchVirtualMemory(", rendered)
        self.assertIn("ULONG_PTR rangeCount", rendered)
        self.assertIn("PMEMORY_RANGE_ENTRY memoryRanges", rendered)
        self.assertIn("__int64 partitionOrSentinel", rendered)
        self.assertIn("ULONG prefetchFlags", rendered)
        self.assertEqual(4, len(identities))
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments)
        )

    def test_delete_empty_page_table_commit_marks_vad_local_report_only(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall MiDeleteEmptyPageTableCommit(__int64 *a1, unsigned __int64 a2)
{
  __int64 v4;
  __int64 v5;
  unsigned __int64 leafVa;
  unsigned __int64 endVa;
  unsigned __int64 result;

  v4 = a1[23];
  v5 = *(_QWORD *)(v4 + 80);
  leafVa = MiGetLeafVa(a2);
  if ( leafVa < a1[5] )
  {
    leafVa = a1[5];
  }
  endVa = MiGetLeafVa(a2) - 1;
  if ( leafVa == (*(unsigned int *)(v5 + 24) | ((unsigned __int64)*(unsigned __int8 *)(v5 + 32) << 32)) << 12 )
  {
    MiGetPreviousVad((unsigned __int64 *)v5);
  }
  if ( endVa == (((*(unsigned int *)(v5 + 28) | ((unsigned __int64)*(unsigned __int8 *)(v5 + 33) << 32)) << 12) | 0xFFF) )
  {
    MiGetNextVad(v5);
  }
  result = *(_QWORD *)(v5 + 16)
         + *(_QWORD *)(v5 + 48)
         + *(_QWORD *)(v5 + 64)
         + *(_QWORD *)(v5 + 80)
         + *(_QWORD *)(v5 + 96)
         + *(_QWORD *)(v5 + 112)
         + *(_QWORD *)(v5 + 128);
  MiReturnPageTablePageCommitment(leafVa, endVa, 0, 0, 0, v5, 0);
  return result;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.memory_manager.delete_empty_page_table_commit"
        identities = self._profile_identities(plan, profile_id)
        vad_identity = self._identity_for_base(plan, profile_id, "v5")
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "v5"
        ]

        self.assertIn("ULONG_PTR __fastcall MiDeleteEmptyPageTableCommit(", rendered)
        self.assertIn("PMMSUPPORT_INSTANCE workingSet", rendered)
        self.assertIn("ULONG_PTR virtualAddress", rendered)
        self.assertEqual(3, len(identities))
        self.assertEqual("MMVAD_SHORT", vad_identity["structure_name"])
        self.assertEqual("vadNode", vad_identity["trusted_role"])
        self.assertEqual("report-only", vad_identity["effective_mode"])
        self.assertEqual(
            {0x10, 0x18, 0x1C, 0x20, 0x21, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
            self._field_offsets(vad_identity),
        )
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "v5"
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

    def _field_offsets(self, identity: dict[str, object]) -> set[int]:
        return {
            int(field.get("offset", -1))
            for field in identity.get("fields", []) or []
            if isinstance(field, dict)
        }
