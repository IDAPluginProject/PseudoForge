from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class RegistryConfigDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_nt_set_value_key_requires_object_reference_and_cm_handoff(self) -> None:
        without_callees = self._plan(
            """
__int64 __fastcall NtSetValueKey(HANDLE Handle, UNICODE_STRING *ValueName, int TitleIndex, int Type, void *Data, size_t DataSize)
{
  return STATUS_SUCCESS;
}
"""
        )
        with_callees = self._plan(
            """
__int64 __fastcall NtSetValueKey(HANDLE Handle, UNICODE_STRING *ValueName, int TitleIndex, int Type, void *Data, size_t DataSize)
{
  PVOID referencedObject;
  __int64 status;

  referencedObject = 0;
  status = CmObReferenceObjectByHandle(Handle, 2, 0, KeGetCurrentThread()->PreviousMode, (__int64)&referencedObject, 0);
  if ( status >= 0 )
  {
    status = CmSetValueKey((__int64)referencedObject, ValueName, TitleIndex, Data, DataSize, Handle, 0);
    ObfDereferenceObject(referencedObject);
  }
  return status;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.registry_config.nt_set_value_key"
                for item in self._identities(without_callees)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callees,
                "windows.registry_config.nt_set_value_key",
            )
        }

        self.assertEqual("HANDLE", roles["keyHandle"])
        self.assertEqual("UNICODE_STRING", roles["valueName"])
        self.assertEqual("REG_VALUE_TYPE", roles["valueType"])
        self.assertEqual("REG_VALUE_DATA", roles["valueData"])
        self.assertEqual("BUFFER_LENGTH", roles["valueDataSize"])
        self.assertEqual("CM_KEY_BODY", roles["referencedKeyObject"])

    def test_cm_set_value_key_roles_are_report_only(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CmSetValueKey(__int64 keyObject, const UNICODE_STRING *valueName, unsigned int titleIndex, void *data, size_t dataSize, __int64 transaction, char virtualized)
{
  CmpFindNameInListWithStatus(keyObject, valueName, &titleIndex);
  return dataSize ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
"""
        )

        identities = self._profile_identities(plan, "windows.registry_config.cm_set_value_key")
        roles = {item["trusted_role"]: item["structure_name"] for item in identities}

        self.assertEqual("CM_KEY_BODY", roles["keyObject"])
        self.assertEqual("UNICODE_STRING", roles["valueName"])
        self.assertEqual("REG_VALUE_TITLE_INDEX", roles["titleIndex"])
        self.assertEqual("REG_VALUE_DATA", roles["valueData"])
        self.assertEqual("BUFFER_LENGTH", roles["valueDataSize"])
        self.assertEqual("REG_TRANSACTION_CONTEXT", roles["transactionContext"])
        self.assertEqual("BOOLEAN", roles["virtualizationFlag"])
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertTrue(all("profile_report_only" in item["blockers"] for item in identities))

    def test_nt_query_value_key_requires_stack_callout(self) -> None:
        without_callout = self._plan(
            """
__int64 __fastcall NtQueryValueKey(HANDLE Handle, UNICODE_STRING *ValueName, unsigned int InfoClass, unsigned __int64 Buffer, unsigned int Length, void *ResultLength)
{
  return STATUS_SUCCESS;
}
"""
        )
        with_callout = self._plan(
            """
__int64 __fastcall NtQueryValueKey(HANDLE Handle, UNICODE_STRING *ValueName, unsigned int InfoClass, unsigned __int64 Buffer, unsigned int Length, void *ResultLength)
{
  PVOID referencedObject;
  __int128 Parameter;

  referencedObject = 0;
  CmObReferenceObjectByHandle(Handle, 1, 0, KeGetCurrentThread()->PreviousMode, (__int64)&referencedObject, 0);
  Parameter = 0;
  return KeExpandKernelStackAndCallout((PEXPAND_STACK_CALLOUT)CmQueryValueKeyCallout, &Parameter, 0x4800);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.registry_config.nt_query_value_key"
                for item in self._identities(without_callout)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callout,
                "windows.registry_config.nt_query_value_key",
            )
        }

        self.assertEqual("HANDLE", roles["keyHandle"])
        self.assertEqual("UNICODE_STRING", roles["valueName"])
        self.assertEqual("KEY_VALUE_INFORMATION_CLASS", roles["keyValueInformationClass"])
        self.assertEqual("KEY_VALUE_INFORMATION_BUFFER", roles["keyValueInformationBuffer"])
        self.assertEqual("BUFFER_LENGTH", roles["keyValueInformationLength"])
        self.assertEqual("ULONG_OUTPUT", roles["resultLengthOutput"])
        self.assertEqual("CM_QUERY_VALUE_KEY_CONTEXT", roles["queryValueCalloutContext"])
        self.assertEqual("CM_KEY_BODY", roles["referencedKeyObject"])

    def test_query_value_key_callout_and_cm_query_value_key_roles(self) -> None:
        callout_plan = self._plan(
            """
void __fastcall CmQueryValueKeyCallout(_OWORD *Parameter)
{
  *(_DWORD *)Parameter = CmQueryValueKey(*((_QWORD *)Parameter + 1), (unsigned __int16 *)&Parameter[1], *((_DWORD *)Parameter + 8), *((_QWORD *)Parameter + 5), *((_DWORD *)Parameter + 12), *((_QWORD *)Parameter + 7));
}
"""
        )
        query_plan = self._plan(
            """
__int64 __fastcall CmQueryValueKey(__int64 keyObject, unsigned __int16 *valueName, int infoClass, size_t buffer, int length, __int64 resultLength)
{
  CmpFindValueByName(keyObject);
  return length;
}
"""
        )

        callout_identity = self._single_identity(
            callout_plan,
            "windows.registry_config.cm_query_value_key_callout",
            role="queryValueCalloutContext",
        )
        query_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                query_plan,
                "windows.registry_config.cm_query_value_key",
            )
        }

        self.assertEqual("CM_QUERY_VALUE_KEY_CONTEXT", callout_identity["structure_name"])
        self.assertEqual("CM_KEY_BODY", query_roles["keyObject"])
        self.assertEqual("UNICODE_STRING", query_roles["valueName"])
        self.assertEqual("KEY_VALUE_INFORMATION_CLASS", query_roles["keyValueInformationClass"])
        self.assertEqual("KEY_VALUE_INFORMATION_BUFFER", query_roles["keyValueInformationBuffer"])
        self.assertEqual("BUFFER_LENGTH", query_roles["keyValueInformationLength"])
        self.assertEqual("ULONG_OUTPUT", query_roles["resultLengthOutput"])

    def test_open_create_and_enumerate_callout_contexts(self) -> None:
        open_plan = self._plan(
            """
void __fastcall CmOpenKeyCallout(PVOID Parameter)
{
  *(_DWORD *)Parameter = CmOpenKey(*((_QWORD *)Parameter + 1), *((_DWORD *)Parameter + 4), *((_QWORD *)Parameter + 3), *((_DWORD *)Parameter + 8), *((_QWORD *)Parameter + 5), *((_BYTE *)Parameter + 48));
}
"""
        )
        create_plan = self._plan(
            """
void __fastcall CmCreateKeyCallout(_QWORD *Parameter)
{
  *(_DWORD *)Parameter = CmCreateKey(Parameter[1], *((unsigned int *)Parameter + 4), Parameter[3], Parameter[4], (__m128i *)Parameter[5], *((int *)Parameter + 12), (_DWORD *)Parameter[7], 0);
}
"""
        )
        enumerate_plan = self._plan(
            """
void __fastcall CmEnumerateKeyCallout(_QWORD *Parameter)
{
  *(_DWORD *)Parameter = CmEnumerateKey(Parameter[1], Parameter[2], *((_DWORD *)Parameter + 6), *((_DWORD *)Parameter + 7), Parameter[4], *((_DWORD *)Parameter + 10), Parameter[6]);
}
"""
        )

        self.assertEqual(
            "CM_OPEN_KEY_CONTEXT",
            self._single_identity(
                open_plan,
                "windows.registry_config.cm_open_key_callout",
                role="openKeyCalloutContext",
            )["structure_name"],
        )
        self.assertEqual(
            "CM_CREATE_KEY_CONTEXT",
            self._single_identity(
                create_plan,
                "windows.registry_config.cm_create_key_callout",
                role="createKeyCalloutContext",
            )["structure_name"],
        )
        self.assertEqual(
            "CM_ENUMERATE_KEY_CONTEXT",
            self._single_identity(
                enumerate_plan,
                "windows.registry_config.cm_enumerate_key_callout",
                role="enumerateKeyCalloutContext",
            )["structure_name"],
        )

    def test_delete_key_delete_value_notify_and_parse_roles(self) -> None:
        delete_key_plan = self._plan(
            """
__int64 __fastcall NtDeleteKey(HANDLE Handle)
{
  PVOID referencedObject;

  referencedObject = 0;
  CmObReferenceObjectByHandle(Handle, 0x10000, 0, KeGetCurrentThread()->PreviousMode, (__int64)&referencedObject, 0);
  return CmDeleteKey((_QWORD *)referencedObject);
}
"""
        )
        delete_value_plan = self._plan(
            """
__int64 __fastcall CmDeleteValueKey(__int64 keyObject, unsigned __int16 *valueName, __int64 transaction, char virtualized)
{
  return CmpFindNameInListWithStatus(keyObject, valueName, &transaction);
}
"""
        )
        notify_plan = self._plan(
            """
__int64 __fastcall CmpNotifyChangeKey(__int64 keyObject, _QWORD *postBlock, int filter, unsigned char watchTree, __int64 event, __int64 apc, __int64 context)
{
  __int64 newProviderRecord;

  newProviderRecord = ExAllocatePool2(0x100, 0x58, 0x626E4D43);
  return CmpIsKeyDeletedForKeyBody(keyObject, 0) ? STATUS_KEY_DELETED : filter;
}
"""
        )
        parse_plan = self._plan(
            """
__int64 __fastcall CmpParseKey(__int64 RegistryNamespaceRootForSilo, POBJECT_TYPE *ObjectType, struct _ACCESS_STATE *AccessState, unsigned __int8 ParseMode, int Attributes, const UNICODE_STRING *RemainingName, __m128i *ObjectName, __int64 ParseObject, __int64 SecurityQos, __int64 ThreadInfo, __int64 *ResultObject)
{
  struct _PRIVILEGE_SET *ParseContext;

  ParseContext = (struct _PRIVILEGE_SET *)CmpAllocateParseContext();
  *ResultObject = 0;
  return ObjectType == CmKeyObjectType ? 0 : STATUS_OBJECT_TYPE_MISMATCH;
}
"""
        )

        delete_key_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                delete_key_plan,
                "windows.registry_config.nt_delete_key",
            )
        }
        delete_value_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                delete_value_plan,
                "windows.registry_config.cm_delete_value_key",
            )
        }
        notify_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                notify_plan,
                "windows.registry_config.cmp_notify_change_key",
            )
        }
        parse_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                parse_plan,
                "windows.registry_config.cmp_parse_key",
            )
        }

        self.assertEqual("HANDLE", delete_key_roles["keyHandle"])
        self.assertEqual("CM_KEY_BODY", delete_key_roles["referencedKeyObject"])
        self.assertEqual("CM_KEY_BODY", delete_value_roles["keyObject"])
        self.assertEqual("UNICODE_STRING", delete_value_roles["valueName"])
        self.assertEqual("REG_TRANSACTION_CONTEXT", delete_value_roles["transactionContext"])
        self.assertEqual("BOOLEAN", delete_value_roles["virtualizationFlag"])
        self.assertEqual("CM_KEY_BODY", notify_roles["keyObject"])
        self.assertEqual("CM_NOTIFY_BLOCK", notify_roles["notifyPostBlock"])
        self.assertEqual("CM_NOTIFY_THREAD_CONTEXT", notify_roles["threadNotifyContext"])
        self.assertEqual("CM_NOTIFY_BLOCK", notify_roles["notifyProviderRecord"])
        self.assertEqual("CM_REGISTRY_NAMESPACE_ROOT", parse_roles["registryNamespaceRoot"])
        self.assertEqual("OBJECT_TYPE", parse_roles["objectType"])
        self.assertEqual("ACCESS_STATE", parse_roles["accessState"])
        self.assertEqual("UNICODE_STRING", parse_roles["remainingName"])
        self.assertEqual("CM_KEY_BODY_OUTPUT", parse_roles["resultObjectOutput"])
        self.assertEqual("CM_PARSE_CONTEXT", parse_roles["parseContext"])

    def test_cmp_do_parse_key_identifies_parse_context_without_layout_inference(self) -> None:
        without_callees = self._plan(
            """
NTSTATUS __fastcall CmpDoParseKey(__int64 a1, struct _ACCESS_STATE *a2, unsigned __int8 a3, __int16 a4, const UNICODE_STRING *a5, __m128i *a6, __int64 a7, int a8, _QWORD *a9)
{
  *(_OWORD *)(a7 + 160) = 0LL;
  *(_QWORD *)(a7 + 208) = 0LL;
  return STATUS_SUCCESS;
}
"""
        )
        with_callees = self._plan(
            """
NTSTATUS __fastcall CmpDoParseKey(__int64 a1, struct _ACCESS_STATE *a2, unsigned __int8 a3, __int16 a4, const UNICODE_STRING *a5, __m128i *a6, __int64 a7, int a8, _QWORD *a9)
{
  __int64 delayDerefContext;

  CmpInitializeDelayDerefContext(&delayDerefContext);
  *(_OWORD *)(a7 + 160) = 0LL;
  *(_OWORD *)(a7 + 176) = 0LL;
  *(_OWORD *)(a7 + 192) = 0LL;
  *(_QWORD *)(a7 + 208) = 0LL;
  memset_0((void *)(a7 + 216), 0, 0xA8uLL);
  if ( (*(_DWORD *)a7 & 2) != 0 )
  {
    CmpRecordParseFailure(a7, 256, STATUS_INVALID_PARAMETER);
  }
  CmpCleanupPathInfo(a7 + 216);
  return STATUS_SUCCESS;
}
"""
        )

        identity = self._single_identity(
            with_callees,
            "windows.registry_config.cmp_do_parse_key",
            role="parseContext",
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.registry_config.cmp_do_parse_key"
                for item in self._identities(without_callees)
            )
        )
        self.assertEqual("CM_PARSE_CONTEXT", identity["structure_name"])
        self.assertEqual("parseContext", self._rename_map(with_callees).get("a7"))
        self.assertTrue(identity["suppress_layout_inference"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_layout"
                and item.get("base") == "parseContext"
                for item in with_callees.comments
            )
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_blockers"
                and item.get("base") == "parseContext"
                for item in with_callees.comments
            )
        )

    def test_cm_register_callback_ex_profile_corrects_generic_parameter_types_in_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
NTSTATUS __stdcall CmRegisterCallbackEx(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  return STATUS_SUCCESS;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.registry_config.cm_register_callback_ex"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identities = self._profile_identities(plan, profile_id)

        self.assertEqual(6, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertIn("PEX_CALLBACK_FUNCTION function", rendered)
        self.assertIn("PCUNICODE_STRING altitude", rendered)
        self.assertIn("PVOID driver", rendered)
        self.assertIn("PVOID context", rendered)
        self.assertIn("PLARGE_INTEGER cookie", rendered)
        self.assertIn("PVOID reserved", rendered)
        self.assertEqual(
            {
                "registryCallbackFunction": "EX_CALLBACK_FUNCTION",
                "callbackAltitude": "UNICODE_STRING",
                "callbackContext": "REGISTRY_CALLBACK_CONTEXT",
                "callbackCookieOutput": "LARGE_INTEGER_OUTPUT",
            },
            {item["trusted_role"]: item["structure_name"] for item in identities},
        )
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_registry_security_descriptor_profile_corrects_hexrays_parameter_types(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall CmpSetSecurityDescriptorInfo(ULONG_PTR a1, _DWORD *a2, size_t a3, ULONG_PTR a4, int a5, __int64 a6, __int64 a7, __int64 a8, __int64 a9)
{
  CmGetKCBCacheSecurity(a1, a7);
  RtlpSetSecurityObject(0, *a2, a3, (unsigned int)&a4, 0, a5, a6, a9);
  return CmpTraceSecurityChanging(a1, a4, *a2, a3, a4);
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.registry_config.cmp_set_security_descriptor_info"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identities = self._profile_identities(plan, profile_id)

        self.assertEqual(9, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertTrue(all(not item.apply_to_idb for item in corrections))
        self.assertIn("PCM_KEY_CONTROL_BLOCK keyControlBlock", rendered)
        self.assertIn("PSECURITY_INFORMATION securityInformation", rendered)
        self.assertIn("PSECURITY_DESCRIPTOR newSecurityDescriptor", rendered)
        self.assertIn("KPROCESSOR_MODE accessMode", rendered)
        self.assertEqual(
            {
                "keyControlBlock": "CM_KEY_CONTROL_BLOCK",
                "securityInformation": "SECURITY_INFORMATION",
                "securityDescriptorLength": "BUFFER_LENGTH",
                "newSecurityDescriptor": "SECURITY_DESCRIPTOR",
                "accessMode": "KPROCESSOR_MODE",
                "genericMapping": "GENERIC_MAPPING",
                "transactionContext": "CM_TRANS",
                "transactionLogEntry": "CM_TRANS_SECURITY_ENTRY",
                "poolTypeContext": "GENERIC_MAPPING_CONTEXT",
            },
            {item["trusted_role"]: item["structure_name"] for item in identities},
        )
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))
        self.assertEqual([], plan.corrected_parameter_map)
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_registry_security_descriptor_build_mismatch_blocks_type_preview(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CmpSetSecurityDescriptorInfo(ULONG_PTR a1, _DWORD *a2, size_t a3, ULONG_PTR a4, int a5, __int64 a6, __int64 a7, __int64 a8, __int64 a9)
{
  CmGetKCBCacheSecurity(a1, a7);
  return RtlpSetSecurityObject(0, *a2, a3, (unsigned int)&a4, 0, a5, a6, a9);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )
        corrections = [
            item
            for item in plan.type_corrections
            if item.profile_id == "windows.registry_config.cmp_set_security_descriptor_info"
        ]

        self.assertEqual(9, len(corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in corrections))
        self.assertTrue(all(not item.apply_to_preview for item in corrections))

    def test_cmp_find_value_by_name_profile_corrects_search_context_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall CmpFindValueByName(ULONG_PTR a1)
{
  return CmpFindNameInListWithStatus(a1, 0, 0);
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.registry_config.cmp_find_value_by_name"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]

        self.assertEqual(1, len(corrections))
        self.assertTrue(corrections[0].apply_to_preview)
        self.assertIn("PCM_KEY_VALUE_SEARCH_CONTEXT valueSearchContext", rendered)
        self.assertEqual([], plan.corrected_parameter_map)

    def test_report_only_registry_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CmQueryValueKey(__int64 keyObject, unsigned __int16 *valueName, int infoClass, size_t buffer, int length, __int64 resultLength)
{
  __int64 probe;

  probe = *(_QWORD *)(keyObject + 16)
        + *(_QWORD *)(keyObject + 24)
        + *(_QWORD *)(keyObject + 32)
        + *(_QWORD *)(keyObject + 40)
        + *(_QWORD *)(keyObject + 48)
        + *(_QWORD *)(keyObject + 56)
        + *(_QWORD *)(keyObject + 64)
        + *(_QWORD *)(keyObject + 72)
        + *(_QWORD *)(keyObject + 16)
        + *(_QWORD *)(keyObject + 24)
        + *(_QWORD *)(keyObject + 32)
        + *(_QWORD *)(keyObject + 40);
  return probe + CmpFindValueByName(keyObject);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.registry_config.cm_query_value_key",
            "keyObject",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "keyObject"
        ]

        self.assertEqual("CM_KEY_BODY", identity["structure_name"])
        self.assertEqual("keyObject", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "keyObject"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CmQueryValueKey(__int64 keyObject, unsigned __int16 *valueName, int infoClass, size_t buffer, int length, __int64 resultLength)
{
  return CmpFindValueByName(keyObject);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.registry_config.cm_query_value_key",
            role="keyObject",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_key_body_type(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CmQueryValueKey(int keyObject, unsigned __int16 *valueName, int infoClass, size_t buffer, int length, __int64 resultLength)
{
  return CmpFindValueByName(keyObject);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.registry_config.cm_query_value_key"
                and item["trusted_role"] == "keyObject"
                for item in self._identities(plan)
            )
        )

    def test_registry_config_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall CmQueryValueKey(__int64 keyObject, unsigned __int16 *valueName, int infoClass, size_t buffer, int length, __int64 resultLength)
{
  return CmpFindValueByName(keyObject);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/registry_config.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _rename_map(self, plan) -> dict[str, str]:
        return {item.old: item.new for item in plan.renames if item.apply}

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
