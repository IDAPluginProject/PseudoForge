from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class HandleTableDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_lookup_handle_table_entry_roles(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int *argument0, __int64 argument1)
{
  unsigned __int64 v2;

  v2 = argument1 & 0xFFFFFFFFFFFFFFFCuLL;
  if ( v2 >= *argument0 )
  {
    return 0;
  }
  return *((_QWORD *)argument0 + 1) + 4 * v2;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.handle_table.lookup_handle_table_entry",
            )
        }

        self.assertEqual("HANDLE_TABLE", roles["handleTable"])
        self.assertEqual("HANDLE_VALUE", roles["handleValueOrIndex"])
        self.assertTrue(
            all(
                item["effective_mode"] == "report-only"
                for item in self._profile_identities(plan, "windows.handle_table.lookup_handle_table_entry")
            )
        )

    def test_map_handle_to_pointer_requires_lookup_callee(self) -> None:
        without_callee = self._plan(
            """
signed __int64 *__fastcall ExMapHandleToPointer(__int64 argument0, __int64 argument1)
{
  signed __int64 *v3;
  v3 = 0;
  return v3;
}
"""
        )
        with_callee = self._plan(
            """
signed __int64 *__fastcall ExMapHandleToPointer(__int64 argument0, __int64 argument1)
{
  signed __int64 *v3;

  v3 = (signed __int64 *)ExpLookupHandleTableEntry(argument0, argument1);
  if ( v3 )
  {
    _InterlockedCompareExchange64(v3, *v3 - 1, *v3);
  }
  return v3;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.handle_table.map_handle_to_pointer"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.handle_table.map_handle_to_pointer",
            )
        }

        self.assertEqual("HANDLE_TABLE", roles["handleTable"])
        self.assertEqual("HANDLE_VALUE", roles["handleValue"])
        self.assertEqual("HANDLE_TABLE_ENTRY", roles["lockedHandleEntry"])

    def test_create_handle_ex_requires_critical_region_pair(self) -> None:
        without_callees = self._plan(
            """
__int64 __fastcall ExCreateHandleEx(unsigned int *argument0, __int64 argument1, int argument2, char argument3, __int64 argument4)
{
  return argument1;
}
"""
        )
        with_callees = self._plan(
            """
__int64 __fastcall ExCreateHandleEx(unsigned int *argument0, __int64 argument1, int argument2, char argument3, __int64 argument4)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  KeEnterCriticalRegion();
  ExpUpdateDebugInfo(argument0, currentThread, argument1, 1);
  KeLeaveCriticalRegionThread((__int64)currentThread);
  return argument1;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.handle_table.create_handle_ex"
                for item in self._identities(without_callees)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callees,
                "windows.handle_table.create_handle_ex",
            )
        }

        self.assertEqual("HANDLE_TABLE", roles["handleTable"])
        self.assertEqual("HANDLE_TABLE_ENTRY_PAYLOAD", roles["objectOrHandleInfo"])
        self.assertEqual("ACCESS_MASK", roles["grantedAccess"])
        self.assertEqual("HANDLE_ATTRIBUTES", roles["handleAttributes"])
        self.assertEqual("HANDLE_EXTRA_INFO", roles["extraInfo"])
        self.assertEqual("ETHREAD", roles["currentThread"])

    def test_enum_handle_table_roles(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall ExEnumHandleTable(unsigned int *argument0, __int64 callback, __int64 argument1, __int64 *argument2)
{
  __int64 *v11;

  v11 = (__int64 *)ExpLookupHandleTableEntry(argument0, 4);
  if ( callback(argument0, v11, 4, argument1) )
  {
    *argument2 = 4;
  }
  KeLeaveCriticalRegionThread((__int64)KeGetCurrentThread());
  return 0;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.handle_table.enum_handle_table",
            )
        }

        self.assertEqual("HANDLE_TABLE", roles["handleTable"])
        self.assertEqual("HANDLE_TABLE_ENUMERATE_CALLBACK", roles["enumerationCallback"])
        self.assertEqual("HANDLE_ENUM_CONTEXT", roles["callbackContext"])
        self.assertEqual("HANDLE_VALUE_OUTPUT", roles["foundHandleOutput"])

    def test_cid_lookup_roles(self) -> None:
        process_plan = self._plan(
            """
NTSTATUS __stdcall PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *currentProcess)
{
  unsigned __int64 HandlePointer;

  ExpLookupHandleTableEntry((unsigned int *)PspCidTable, (__int64)ProcessId);
  HandlePointer = ExGetHandlePointer(0);
  *currentProcess = (PEPROCESS)HandlePointer;
  return STATUS_SUCCESS;
}
"""
        )
        thread_plan = self._plan(
            """
NTSTATUS __stdcall PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread)
{
  unsigned __int64 HandlePointer;

  ExpLookupHandleTableEntry((unsigned int *)PspCidTable, (__int64)ThreadId);
  HandlePointer = ExGetHandlePointer(0);
  *Thread = (PETHREAD)HandlePointer;
  return STATUS_SUCCESS;
}
"""
        )

        process_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                process_plan,
                "windows.handle_table.lookup_process_by_process_id",
            )
        }
        thread_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                thread_plan,
                "windows.handle_table.lookup_thread_by_thread_id",
            )
        }

        self.assertEqual("CLIENT_ID_PROCESS", process_roles["processId"])
        self.assertEqual("EPROCESS_OUTPUT", process_roles["processOutput"])
        self.assertEqual("EPROCESS", process_roles["referencedProcess"])
        self.assertEqual("CLIENT_ID_THREAD", thread_roles["threadId"])
        self.assertEqual("ETHREAD_OUTPUT", thread_roles["threadOutput"])
        self.assertEqual("ETHREAD", thread_roles["referencedThread"])

    def test_lookup_process_thread_by_cid_roles(self) -> None:
        plan = self._plan(
            """
NTSTATUS __fastcall PsLookupProcessThreadByCid(PCLIENT_ID client_id_ptr, PEPROCESS *out_obj_ptr, PETHREAD *thread_out_ptr)
{
  PVOID referencedObject;
  void *referenced_obj_ptr;
  NTSTATUS status;

  referencedObject = 0;
  status = PsLookupThreadByThreadId(client_id_ptr->UniqueThread, (PETHREAD *)&referencedObject);
  referenced_obj_ptr = IoThreadToProcess((PETHREAD)referencedObject);
  *out_obj_ptr = (PEPROCESS)referenced_obj_ptr;
  *thread_out_ptr = (PETHREAD)referencedObject;
  return status;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.handle_table.lookup_process_thread_by_cid",
            )
        }

        self.assertEqual("CLIENT_ID", roles["clientId"])
        self.assertEqual("EPROCESS_OUTPUT", roles["processOutput"])
        self.assertEqual("ETHREAD_OUTPUT", roles["threadOutput"])
        self.assertEqual("ETHREAD", roles["referencedThread"])
        self.assertEqual("EPROCESS", roles["referencedProcess"])

    def test_report_only_handle_table_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int *argument0, __int64 argument1)
{
  __int64 probe;

  probe = *(_QWORD *)(argument0 + 16)
        + *(_QWORD *)(argument0 + 24)
        + *(_QWORD *)(argument0 + 32)
        + *(_QWORD *)(argument0 + 40)
        + *(_QWORD *)(argument0 + 48)
        + *(_QWORD *)(argument0 + 56)
        + *(_QWORD *)(argument0 + 64)
        + *(_QWORD *)(argument0 + 72)
        + *(_QWORD *)(argument0 + 16)
        + *(_QWORD *)(argument0 + 24)
        + *(_QWORD *)(argument0 + 32)
        + *(_QWORD *)(argument0 + 40);
  return probe + argument1;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.handle_table.lookup_handle_table_entry",
            "argument0",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "argument0"
        ]

        self.assertEqual("HANDLE_TABLE", identity["structure_name"])
        self.assertEqual("handleTable", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "argument0"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int *argument0, __int64 argument1)
{
  return argument1 ? 1 : 0;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.handle_table.lookup_handle_table_entry",
            role="handleTable",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_handle_table_type(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall ExpLookupHandleTableEntry(int argument0, __int64 argument1)
{
  return argument1 ? argument0 : 0;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.handle_table.lookup_handle_table_entry"
                and item["trusted_role"] == "handleTable"
                for item in self._identities(plan)
            )
        )

    def test_handle_table_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int *argument0, __int64 argument1)
{
  return argument1 ? 1 : 0;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/handle_table.json" for item in manifests)
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
