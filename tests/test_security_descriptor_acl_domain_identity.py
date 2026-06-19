from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class SecurityDescriptorAclDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_security_descriptor_capture_release_and_validation_roles(self) -> None:
        capture_plan = self._plan(
            """
__int64 __fastcall SeCaptureSecurityDescriptor(__int64 SecurityDescriptor, char CaptureMode, int PoolType, char OwnerGroupPresent, _QWORD *CapturedSecurityDescriptor)
{
  __int64 srcSidPtr;
  __int64 srcDacLPtr;
  __int64 srcSaCLPtr;

  srcSidPtr = SecurityDescriptor + 20;
  srcDacLPtr = SecurityDescriptor + 32;
  srcSaCLPtr = SecurityDescriptor + 48;
  *CapturedSecurityDescriptor = ExAllocatePoolWithTag(PoolType, 128, 0x63536553u);
  RtlValidAcl(srcDacLPtr);
  return srcSidPtr + srcSaCLPtr + OwnerGroupPresent + CaptureMode;
}
"""
        )
        release_plan = self._plan(
            """
void __fastcall SeReleaseSecurityDescriptor(void *SecurityDescriptor, char DescriptorType, char Flags)
{
  if ( DescriptorType || Flags )
  {
    ExFreePoolWithTag(SecurityDescriptor, 0);
  }
}
"""
        )
        valid_plan = self._plan(
            """
BOOLEAN __stdcall SeValidSecurityDescriptor(ULONG InputLength, PSECURITY_DESCRIPTOR SecurityDescriptor)
{
  PACL dAclPtr;
  PACL sAclPtr;

  dAclPtr = (PACL)((char *)SecurityDescriptor + 20);
  sAclPtr = (PACL)((char *)SecurityDescriptor + 32);
  return InputLength && RtlValidAcl(dAclPtr) && RtlValidAcl(sAclPtr);
}
"""
        )

        capture_roles = self._roles(capture_plan, "windows.security_descriptor_acl.capture_security_descriptor")
        release_roles = self._roles(release_plan, "windows.security_descriptor_acl.release_security_descriptor")
        valid_roles = self._roles(valid_plan, "windows.security_descriptor_acl.valid_security_descriptor")

        self.assertEqual("SECURITY_DESCRIPTOR", capture_roles["securityDescriptor"])
        self.assertEqual("KPROCESSOR_MODE", capture_roles["captureMode"])
        self.assertEqual("POOL_TYPE", capture_roles["poolType"])
        self.assertEqual("BOOLEAN", capture_roles["ownerGroupPresent"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", capture_roles["capturedSecurityDescriptor"])
        self.assertEqual("SID", capture_roles["sourceSid"])
        self.assertEqual("ACL", capture_roles["sourceAcl"])
        self.assertEqual("SECURITY_DESCRIPTOR", release_roles["securityDescriptor"])
        self.assertEqual("SECURITY_DESCRIPTOR_TYPE", release_roles["descriptorType"])
        self.assertEqual("BUFFER_LENGTH", valid_roles["inputLength"])
        self.assertEqual("SECURITY_DESCRIPTOR", valid_roles["securityDescriptor"])
        self.assertEqual("ACL", valid_roles["acl"])

    def test_sid_and_acl_capture_release_roles(self) -> None:
        capture_sid_plan = self._plan(
            """
__int64 __fastcall SeCaptureSid(_BYTE *SourceSid, char CaptureMode, __int64 ProbeMode, __int64 CaptureLength, int PoolType, char Flags, PSID *CapturedSid)
{
  PVOID PoolWithTag;

  RtlLengthRequiredSid(*SourceSid);
  PoolWithTag = ExAllocatePoolWithTag(PoolType, 64, 0x64695353u);
  *CapturedSid = PoolWithTag;
  RtlValidSid(PoolWithTag);
  return CaptureMode + Flags + ProbeMode + CaptureLength;
}
"""
        )
        release_sid_plan = self._plan(
            """
void __fastcall SeReleaseSid(void *Sid, char IsOwner, char IsGroup)
{
  if ( IsOwner || IsGroup )
  {
    ExFreePoolWithTag(Sid, 0);
  }
}
"""
        )
        capture_acl_plan = self._plan(
            """
__int64 __fastcall SeCaptureAcl(char *SourceAcl, char CaptureMode, __int64 ProbeMode, __int64 CaptureLength, int PoolType, int Flags, PVOID *CapturedAcl, unsigned int *CapturedAclLength)
{
  *CapturedAcl = ExAllocatePoolWithTag(PoolType, *CapturedAclLength, 0x6C634153u);
  SepCheckAcl(SourceAcl, *CapturedAclLength);
  return CaptureMode + ProbeMode + CaptureLength + Flags;
}
"""
        )
        release_acl_plan = self._plan(
            """
void __fastcall SeReleaseAcl(void *Acl, unsigned __int8 FreeFlag)
{
  if ( FreeFlag )
  {
    ExFreePoolWithTag(Acl, 0);
  }
}
"""
        )

        capture_sid_roles = self._roles(capture_sid_plan, "windows.security_descriptor_acl.capture_sid")
        release_sid_roles = self._roles(release_sid_plan, "windows.security_descriptor_acl.release_sid")
        capture_acl_roles = self._roles(capture_acl_plan, "windows.security_descriptor_acl.capture_acl")
        release_acl_roles = self._roles(release_acl_plan, "windows.security_descriptor_acl.release_acl")

        self.assertEqual("SID", capture_sid_roles["sourceSid"])
        self.assertEqual("POOL_TYPE", capture_sid_roles["poolType"])
        self.assertEqual("SID_OUTPUT", capture_sid_roles["capturedSid"])
        self.assertEqual("SID", capture_sid_roles["capturedSidBuffer"])
        self.assertEqual("SID", release_sid_roles["sid"])
        self.assertEqual("ACL", capture_acl_roles["sourceAcl"])
        self.assertEqual("POOL_TYPE", capture_acl_roles["poolType"])
        self.assertEqual("ACL_OUTPUT", capture_acl_roles["capturedAcl"])
        self.assertEqual("ACL_LENGTH_OUTPUT", capture_acl_roles["capturedAclLength"])
        self.assertEqual("ACL", release_acl_roles["acl"])
        self.assertEqual("BOOLEAN", release_acl_roles["freeFlag"])

    def test_object_attribute_qos_and_assign_roles(self) -> None:
        object_attr_plan = self._plan(
            """
__int64 __fastcall SeCaptureObjectAttributeSecurityDescriptorPresent(__int64 ObjectAttributes, char CheckPresentFlag, _BYTE *SecurityDescriptorPresent)
{
  *SecurityDescriptorPresent = ObjectAttributes != 0;
  return CheckPresentFlag;
}
"""
        )
        qos_plan = self._plan(
            """
__int64 __fastcall SeCaptureSecurityQos(__int64 SecurityQos, char CaptureContextFlag, _BYTE *CapturedStatus, __int64 CapturedSecurityQos)
{
  *CapturedStatus = SecurityQos != 0;
  return CapturedSecurityQos + CaptureContextFlag;
}
"""
        )
        assign_plan = self._plan(
            """
NTSTATUS __stdcall SeAssignSecurity(PSECURITY_DESCRIPTOR ParentDescriptor, PSECURITY_DESCRIPTOR ExplicitDescriptor, PSECURITY_DESCRIPTOR *NewDescriptor, BOOLEAN IsDirectoryObject, PSECURITY_SUBJECT_CONTEXT SubjectContext, PGENERIC_MAPPING GenericMapping, POOL_TYPE PoolType)
{
  return RtlpNewSecurityObject(ParentDescriptor, ExplicitDescriptor, NewDescriptor, IsDirectoryObject, SubjectContext, GenericMapping, PoolType);
}
"""
        )
        assign_ex_plan = self._plan(
            """
NTSTATUS __stdcall SeAssignSecurityEx(PSECURITY_DESCRIPTOR ParentDescriptor, PSECURITY_DESCRIPTOR ExplicitDescriptor, PSECURITY_DESCRIPTOR *NewDescriptor, GUID *ObjectTypeGuid, BOOLEAN IsDirectoryObject, ULONG AutoInheritFlags, PSECURITY_SUBJECT_CONTEXT SubjectContext, PGENERIC_MAPPING GenericMapping, POOL_TYPE PoolType)
{
  return SeAssignSecurityEx2(ParentDescriptor, ExplicitDescriptor, NewDescriptor, ObjectTypeGuid, IsDirectoryObject, AutoInheritFlags, SubjectContext, GenericMapping, PoolType);
}
"""
        )
        deassign_plan = self._plan(
            """
NTSTATUS __stdcall SeDeassignSecurity(PSECURITY_DESCRIPTOR *SecurityDescriptorPointer)
{
  PSECURITY_DESCRIPTOR secDesc;

  secDesc = *SecurityDescriptorPointer;
  ExFreePoolWithTag(secDesc, 0);
  *SecurityDescriptorPointer = 0;
  return STATUS_SUCCESS;
}
"""
        )

        object_attr_roles = self._roles(object_attr_plan, "windows.security_descriptor_acl.capture_object_attribute_security_descriptor_present")
        qos_roles = self._roles(qos_plan, "windows.security_descriptor_acl.capture_security_qos")
        assign_roles = self._roles(assign_plan, "windows.security_descriptor_acl.assign_security")
        assign_ex_roles = self._roles(assign_ex_plan, "windows.security_descriptor_acl.assign_security_ex")
        deassign_roles = self._roles(deassign_plan, "windows.security_descriptor_acl.deassign_security")

        self.assertEqual("OBJECT_ATTRIBUTES", object_attr_roles["objectAttributes"])
        self.assertEqual("BOOLEAN_OUTPUT", object_attr_roles["securityDescriptorPresent"])
        self.assertEqual("SECURITY_QUALITY_OF_SERVICE", qos_roles["securityQos"])
        self.assertEqual("BOOLEAN_OUTPUT", qos_roles["capturedStatus"])
        self.assertEqual("SECURITY_QUALITY_OF_SERVICE_OUTPUT", qos_roles["capturedSecurityQos"])
        self.assertEqual("SECURITY_DESCRIPTOR", assign_roles["parentDescriptor"])
        self.assertEqual("SECURITY_DESCRIPTOR", assign_roles["explicitDescriptor"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", assign_roles["newDescriptor"])
        self.assertEqual("SECURITY_SUBJECT_CONTEXT", assign_roles["subjectContext"])
        self.assertEqual("GENERIC_MAPPING", assign_roles["genericMapping"])
        self.assertEqual("SECURITY_DESCRIPTOR", assign_ex_roles["parentDescriptor"])
        self.assertEqual("GUID", assign_ex_roles["objectTypeGuid"])
        self.assertEqual("SECURITY_SUBJECT_CONTEXT", assign_ex_roles["subjectContext"])
        self.assertEqual("GENERIC_MAPPING", assign_ex_roles["genericMapping"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", deassign_roles["securityDescriptorPointer"])
        self.assertEqual("SECURITY_DESCRIPTOR", deassign_roles["securityDescriptor"])

    def test_set_and_query_security_descriptor_roles(self) -> None:
        set_plan = self._plan(
            """
NTSTATUS __stdcall SeSetSecurityDescriptorInfo(PVOID Object, PSECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor, PSECURITY_DESCRIPTOR *ObjectSecurityDescriptor, POOL_TYPE PoolType, PGENERIC_MAPPING GenericMapping)
{
  return RtlpSetSecurityObject(Object, *SecurityInformation, ModificationDescriptor, ObjectSecurityDescriptor, PoolType, GenericMapping);
}
"""
        )
        set_ex_plan = self._plan(
            """
NTSTATUS __stdcall SeSetSecurityDescriptorInfoEx(PVOID Object, PSECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor, PSECURITY_DESCRIPTOR *ObjectSecurityDescriptor, ULONG AutoInheritFlags, POOL_TYPE PoolType, PGENERIC_MAPPING GenericMapping)
{
  return RtlpSetSecurityObject(Object, *SecurityInformation, ModificationDescriptor, ObjectSecurityDescriptor, AutoInheritFlags, PoolType, GenericMapping);
}
"""
        )
        query_plan = self._plan(
            """
NTSTATUS __stdcall SeQuerySecurityDescriptorInfo(PSECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, PULONG InputLength, PSECURITY_DESCRIPTOR *ObjectSecurityDescriptor)
{
  memmove(SecurityDescriptor, *ObjectSecurityDescriptor, *InputLength);
  return *SecurityInformation ? STATUS_SUCCESS : STATUS_SUCCESS;
}
"""
        )
        query_access_plan = self._plan(
            """
int __fastcall SeQuerySecurityAccessMask(int RequestedAccess, int *AccessMask)
{
  *AccessMask = RequestedAccess | 0x20000;
  return *AccessMask;
}
"""
        )
        set_access_plan = self._plan(
            """
int __fastcall SeSetSecurityAccessMask(int RequestedAccess, int *AccessMask)
{
  *AccessMask = RequestedAccess | 0x40000;
  return *AccessMask;
}
"""
        )

        set_roles = self._roles(set_plan, "windows.security_descriptor_acl.set_security_descriptor_info")
        set_ex_roles = self._roles(set_ex_plan, "windows.security_descriptor_acl.set_security_descriptor_info_ex")
        query_roles = self._roles(query_plan, "windows.security_descriptor_acl.query_security_descriptor_info")
        query_access_roles = self._roles(query_access_plan, "windows.security_descriptor_acl.query_security_access_mask")
        set_access_roles = self._roles(set_access_plan, "windows.security_descriptor_acl.set_security_access_mask")

        self.assertEqual("OBJECT_BODY", set_roles["object"])
        self.assertEqual("SECURITY_INFORMATION", set_roles["securityInformation"])
        self.assertEqual("SECURITY_DESCRIPTOR", set_roles["modificationDescriptor"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", set_roles["objectSecurityDescriptor"])
        self.assertEqual("GENERIC_MAPPING", set_roles["genericMapping"])
        self.assertEqual("OBJECT_BODY", set_ex_roles["object"])
        self.assertEqual("SECURITY_INFORMATION", set_ex_roles["securityInformation"])
        self.assertEqual("SECURITY_AUTO_INHERIT_FLAGS", set_ex_roles["autoInheritFlags"])
        self.assertEqual("GENERIC_MAPPING", set_ex_roles["genericMapping"])
        self.assertEqual("SECURITY_INFORMATION", query_roles["securityInformation"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", query_roles["securityDescriptor"])
        self.assertEqual("BUFFER_LENGTH_OUTPUT", query_roles["inputLength"])
        self.assertEqual("SECURITY_DESCRIPTOR", query_roles["objectSecurityDescriptor"])
        self.assertEqual("ACCESS_MASK", query_access_roles["requestedAccess"])
        self.assertEqual("ACCESS_MASK_OUTPUT", query_access_roles["accessMask"])
        self.assertEqual("ACCESS_MASK", set_access_roles["requestedAccess"])
        self.assertEqual("ACCESS_MASK_OUTPUT", set_access_roles["accessMask"])

    def test_internal_acl_and_sid_helper_roles(self) -> None:
        check_acl_plan = self._plan(
            """
char __fastcall SepCheckAcl(__int64 Acl, unsigned int ExpectedAclSize)
{
  __int64 currentAcePtr;

  currentAcePtr = Acl + 8;
  RtlpValidObjectAce(currentAcePtr);
  return ExpectedAclSize != 0;
}
"""
        )
        copy_sd_plan = self._plan(
            """
NTSTATUS __fastcall SepCheckAndCopySelfRelativeSD(__int16 *SecurityDescriptor, PVOID *CapturedSecurityDescriptor, ULONG *InputLength, _BYTE *Flags)
{
  RtlAbsoluteToSelfRelativeSD(SecurityDescriptor, *CapturedSecurityDescriptor, InputLength);
  SepSecurityDescriptorStrictLength(*CapturedSecurityDescriptor, *InputLength);
  return *Flags ? STATUS_SUCCESS : STATUS_SUCCESS;
}
"""
        )
        flatten_plan = self._plan(
            """
__int64 __fastcall SepFlattenAcl(__int64 InputAcl, __int64 *FlattenedAcl, unsigned int *FlattenedAclSize, _WORD *FlattenedAceCount)
{
  *FlattenedAcl = InputAcl;
  *FlattenedAclSize = 32;
  *FlattenedAceCount = 1;
  return STATUS_SUCCESS;
}
"""
        )
        duplicate_sid_plan = self._plan(
            """
__int64 __fastcall SepDuplicateSid(unsigned __int8 *SourceSid, _QWORD *DuplicatedSid)
{
  *DuplicatedSid = ExAllocatePool2(0, 32, 0x64695353u);
  memmove(*DuplicatedSid, SourceSid, 32);
  return STATUS_SUCCESS;
}
"""
        )
        acl_equal_plan = self._plan(
            """
char __fastcall SepIsAclEqual(_WORD *LeftAcl, _WORD *RightAcl)
{
  return RtlCompareMemory(LeftAcl, RightAcl, 16) == 16;
}
"""
        )
        sid_equal_plan = self._plan(
            """
char __fastcall SepIsSidEqual(void *LeftSid, void *RightSid)
{
  return RtlEqualSid(LeftSid, RightSid);
}
"""
        )
        sid_array_plan = self._plan(
            """
__int64 __fastcall SepLengthSidAndAttributesArray(__int64 SidArray, unsigned int SidCount, _DWORD *LengthOut)
{
  SeCaptureSidAndAttributesArray(SidArray, SidCount, KernelMode, 0, 0, LengthOut);
  return *LengthOut;
}
"""
        )

        check_acl_roles = self._roles(check_acl_plan, "windows.security_descriptor_acl.sep_check_acl")
        copy_sd_roles = self._roles(copy_sd_plan, "windows.security_descriptor_acl.sep_check_and_copy_self_relative_sd")
        flatten_roles = self._roles(flatten_plan, "windows.security_descriptor_acl.sep_flatten_acl")
        duplicate_sid_roles = self._roles(duplicate_sid_plan, "windows.security_descriptor_acl.sep_duplicate_sid")
        acl_equal_roles = self._roles(acl_equal_plan, "windows.security_descriptor_acl.sep_is_acl_equal")
        sid_equal_roles = self._roles(sid_equal_plan, "windows.security_descriptor_acl.sep_is_sid_equal")
        sid_array_roles = self._roles(sid_array_plan, "windows.security_descriptor_acl.sep_length_sid_and_attributes_array")

        self.assertEqual("ACL", check_acl_roles["acl"])
        self.assertEqual("ACL_SIZE", check_acl_roles["expectedAclSize"])
        self.assertEqual("ACE_HEADER", check_acl_roles["currentAce"])
        self.assertEqual("SECURITY_DESCRIPTOR", copy_sd_roles["securityDescriptor"])
        self.assertEqual("SECURITY_DESCRIPTOR_OUTPUT", copy_sd_roles["capturedSecurityDescriptor"])
        self.assertEqual("BUFFER_LENGTH_OUTPUT", copy_sd_roles["inputLength"])
        self.assertEqual("ACL", flatten_roles["inputAcl"])
        self.assertEqual("ACL_OUTPUT", flatten_roles["flattenedAcl"])
        self.assertEqual("ACL_SIZE_OUTPUT", flatten_roles["flattenedAclSize"])
        self.assertEqual("ACE_COUNT_OUTPUT", flatten_roles["flattenedAceCount"])
        self.assertEqual("SID", duplicate_sid_roles["sourceSid"])
        self.assertEqual("SID_OUTPUT", duplicate_sid_roles["duplicatedSid"])
        self.assertEqual("ACL", acl_equal_roles["leftAcl"])
        self.assertEqual("ACL", acl_equal_roles["rightAcl"])
        self.assertEqual("SID", sid_equal_roles["leftSid"])
        self.assertEqual("SID", sid_equal_roles["rightSid"])
        self.assertEqual("SID_AND_ATTRIBUTES_ARRAY", sid_array_roles["sidArray"])
        self.assertEqual("SID_COUNT", sid_array_roles["sidCount"])
        self.assertEqual("BUFFER_LENGTH_OUTPUT", sid_array_roles["lengthOut"])

    def test_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall SeValidSecurityDescriptor(ULONG inputLength, __int64 securityDescriptor)
{
  unsigned __int64 probe;

  probe = *(_QWORD *)(securityDescriptor + 16)
        + *(_QWORD *)(securityDescriptor + 24)
        + *(_QWORD *)(securityDescriptor + 32)
        + *(_QWORD *)(securityDescriptor + 40)
        + *(_QWORD *)(securityDescriptor + 48)
        + *(_QWORD *)(securityDescriptor + 56)
        + *(_QWORD *)(securityDescriptor + 64)
        + *(_QWORD *)(securityDescriptor + 72)
        + *(_QWORD *)(securityDescriptor + 80)
        + *(_QWORD *)(securityDescriptor + 88)
        + *(_QWORD *)(securityDescriptor + 96)
        + *(_QWORD *)(securityDescriptor + 104);
  return inputLength != 0 && probe != 0 && RtlValidAcl(securityDescriptor + 16);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.security_descriptor_acl.valid_security_descriptor",
            "securityDescriptor",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "securityDescriptor"
        ]

        self.assertEqual("SECURITY_DESCRIPTOR", identity["structure_name"])
        self.assertEqual("securityDescriptor", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "securityDescriptor"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall SeValidSecurityDescriptor(ULONG InputLength, PSECURITY_DESCRIPTOR SecurityDescriptor)
{
  return InputLength && RtlValidAcl(SecurityDescriptor);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.security_descriptor_acl.valid_security_descriptor",
            role="securityDescriptor",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_acl_type(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall SeCaptureAcl(int SourceAcl, char CaptureMode, __int64 ProbeMode, __int64 CaptureLength, int PoolType, int Flags, PVOID *CapturedAcl, unsigned int *CapturedAclLength)
{
  SepCheckAcl(SourceAcl, *CapturedAclLength);
  return CaptureMode + ProbeMode + CaptureLength + PoolType + Flags;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.security_descriptor_acl.capture_acl"
                and item["trusted_role"] == "sourceAcl"
                for item in self._identities(plan)
            )
        )

    def test_security_descriptor_acl_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
BOOLEAN __stdcall SeValidSecurityDescriptor(ULONG InputLength, PSECURITY_DESCRIPTOR SecurityDescriptor)
{
  return InputLength && RtlValidAcl(SecurityDescriptor);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/security_descriptor_acl.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _roles(self, plan, profile_id: str) -> dict[str, str]:
        return {
            str(item["trusted_role"]): str(item["structure_name"])
            for item in self._profile_identities(plan, profile_id)
        }

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
