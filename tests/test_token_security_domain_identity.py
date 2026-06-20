from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class TokenSecurityDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_capture_subject_context_roles(self) -> None:
        plan = self._plan(
            """
void __fastcall SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)
{
  struct _KTHREAD *currentThread;
  _KPROCESS *currentProcess;

  currentThread = KeGetCurrentThread();
  currentProcess = currentThread->ApcState.Process;
  SubjectContext->ProcessAuditId = currentProcess;
  SubjectContext->PrimaryToken = PsReferencePrimaryTokenWithTag((PEPROCESS)currentProcess, 'tSeS');
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.token_security.capture_subject_context",
            )
        }
        identity = self._single_identity(
            plan,
            "windows.token_security.capture_subject_context",
            role="capturedSubjectContext",
        )

        self.assertEqual("SECURITY_SUBJECT_CONTEXT", roles["capturedSubjectContext"])
        self.assertEqual("ETHREAD", roles["currentThread"])
        self.assertEqual("EPROCESS", roles["currentProcess"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])

    def test_assign_primary_token_requires_subject_context_pair(self) -> None:
        without_callees = self._plan(
            """
NTSTATUS __fastcall SeAssignPrimaryToken(PEPROCESS targetProcess, PACCESS_TOKEN newToken)
{
  SECURITY_SUBJECT_CONTEXT SubjectContext;
  PACCESS_TOKEN primaryToken;

  primaryToken = newToken;
  return STATUS_SUCCESS;
}
"""
        )
        with_callees = self._plan(
            """
NTSTATUS __fastcall SeAssignPrimaryToken(PEPROCESS targetProcess, PACCESS_TOKEN newToken)
{
  SECURITY_SUBJECT_CONTEXT SubjectContext;
  PACCESS_TOKEN primaryToken;

  SeCaptureSubjectContext(&SubjectContext);
  primaryToken = newToken;
  SepAuditAssignPrimaryToken(targetProcess, primaryToken);
  SeReleaseSubjectContext(&SubjectContext);
  return STATUS_SUCCESS;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.token_security.assign_primary_token"
                for item in self._identities(without_callees)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callees,
                "windows.token_security.assign_primary_token",
            )
        }

        self.assertEqual("EPROCESS", roles["targetProcess"])
        self.assertEqual("ACCESS_TOKEN", roles["newPrimaryToken"])
        self.assertEqual("SECURITY_SUBJECT_CONTEXT", roles["auditSubjectContext"])
        self.assertEqual("ACCESS_TOKEN", roles["effectiveAuditToken"])

    def test_access_check_from_state_requires_hint_callee(self) -> None:
        without_callee = self._plan(
            """
BOOLEAN __fastcall SeAccessCheckFromState(PSECURITY_DESCRIPTOR SecurityDescriptor, PTOKEN_ACCESS_INFORMATION PrimaryTokenInformation, PTOKEN_ACCESS_INFORMATION ClientTokenInformation, ACCESS_MASK DesiredAccess, ACCESS_MASK PreviouslyGrantedAccess, PPRIVILEGE_SET *Privileges, PGENERIC_MAPPING GenericMapping, KPROCESSOR_MODE AccessMode, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus)
{
  return FALSE;
}
"""
        )
        with_callee = self._plan(
            """
BOOLEAN __fastcall SeAccessCheckFromState(PSECURITY_DESCRIPTOR SecurityDescriptor, PTOKEN_ACCESS_INFORMATION PrimaryTokenInformation, PTOKEN_ACCESS_INFORMATION ClientTokenInformation, ACCESS_MASK DesiredAccess, ACCESS_MASK PreviouslyGrantedAccess, PPRIVILEGE_SET *Privileges, PGENERIC_MAPPING GenericMapping, KPROCESSOR_MODE AccessMode, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus)
{
  return SeAccessCheckWithHint(SecurityDescriptor, PrimaryTokenInformation, ClientTokenInformation, DesiredAccess, PreviouslyGrantedAccess, Privileges, GenericMapping, AccessMode, GrantedAccess, AccessStatus, 0);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.token_security.access_check_from_state"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.token_security.access_check_from_state",
            )
        }

        self.assertEqual("SECURITY_DESCRIPTOR", roles["securityDescriptor"])
        self.assertEqual("ACCESS_MASK", roles["desiredAccess"])
        self.assertEqual("ACCESS_MASK_OUTPUT", roles["grantedAccessOutput"])
        self.assertEqual("NTSTATUS_OUTPUT", roles["accessStatusOutput"])

    def test_access_check_with_hint_identifies_security_descriptor(self) -> None:
        plan = self._plan(
            """
BOOLEAN __fastcall SeAccessCheckWithHint(__int64 a1, unsigned int a2, int *a3, char a4, unsigned int a5, int a6, _QWORD *a7, _DWORD *a8, char a9, unsigned int *a10, int *a11)
{
  int localStatus;
  __int128 mandatoryState;

  if ( !a1 )
  {
    *a11 = STATUS_ACCESS_DENIED;
    return FALSE;
  }
  if ( !a4 )
  {
    SeLockSubjectContext((PSECURITY_SUBJECT_CONTEXT)a3);
  }
  localStatus = 0;
  if ( *(_BYTE *)(a1 + 1) )
  {
    localStatus = *(_DWORD *)(a1 + 4);
  }
  localStatus |= SepFilterCheck(a1, (unsigned int)&mandatoryState, *(_QWORD *)a3, 0, (__int64)&mandatoryState);
  *a11 = SepMandatoryIntegrityCheck(a8, a1, (__int64)a10, *(_QWORD *)a3, 0, (__int64)&mandatoryState);
  if ( !a4 )
  {
    SeUnlockSubjectContext((PSECURITY_SUBJECT_CONTEXT)a3);
  }
  *a10 = a5 | a6 | localStatus;
  return *a11 >= 0;
}
"""
        )

        identity = self._single_identity(
            plan,
            "windows.token_security.access_check_with_hint",
            role="securityDescriptor",
        )

        self.assertEqual("SECURITY_DESCRIPTOR", identity["structure_name"])
        self.assertEqual("securityDescriptor", self._rename_map(plan).get("a1"))
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertTrue(identity["suppress_layout_inference"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_layout"
                and item.get("base") == "securityDescriptor"
                for item in plan.comments
            )
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_blockers"
                and item.get("base") == "securityDescriptor"
                for item in plan.comments
            )
        )

    def test_sep_common_access_check_ex_roles_and_output_bundle_fields(self) -> None:
        without_callees = self._plan(
            """
BOOLEAN __fastcall SepCommonAccessCheckEx(PSECURITY_SUBJECT_CONTEXT SubjectContext, char a2, __int64 a3, __int64 a4, _DWORD *a5, char a6, char a7)
{
  if ( !SubjectContext || !a3 || !a4 )
  {
    return FALSE;
  }
  return *(_DWORD *)a3 == 56 && *(_DWORD *)a4 == 40;
}
"""
        )
        with_callees = self._plan(
            """
BOOLEAN __fastcall SepCommonAccessCheckEx(PSECURITY_SUBJECT_CONTEXT SubjectContext, char a2, __int64 a3, __int64 a4, _DWORD *a5, char a6, char a7)
{
  __int64 genericMapping;
  __int64 grantedAccessOutput;
  __int64 accessStatusOutput;
  __int64 accessReasonOutput;
  __int64 privilegeSetOutput;

  if ( !SubjectContext || !a3 || !a4 )
  {
    return FALSE;
  }
  if ( *(_DWORD *)a3 != 56 || *(_DWORD *)a4 != 40 )
  {
    *(_DWORD *)(*(_QWORD *)(a4 + 16)) = STATUS_INVALID_PARAMETER;
    return FALSE;
  }
  grantedAccessOutput = *(_QWORD *)(a4 + 8);
  accessStatusOutput = *(_QWORD *)(a4 + 16);
  accessReasonOutput = *(_QWORD *)(a4 + 24);
  privilegeSetOutput = *(_QWORD *)(a4 + 32);
  genericMapping = *(_QWORD *)(a3 + 32);
  *(_DWORD *)grantedAccessOutput = *(_DWORD *)(a3 + 16) | *(_DWORD *)(a3 + 20);
  *(_DWORD *)accessStatusOutput = STATUS_ACCESS_DENIED;
  AuthzBasepMergeAccessReasons(accessReasonOutput, 0, 0);
  SepAccessCheckEx(
      *(_QWORD *)(*(_QWORD *)(a3 + 8) + 8),
      0,
      SubjectContext->PrimaryToken,
      SubjectContext->ClientToken,
      *(_DWORD *)(a3 + 16),
      0,
      0,
      genericMapping,
      *(_DWORD *)(a3 + 20),
      a6,
      grantedAccessOutput,
      0,
      accessStatusOutput,
      privilegeSetOutput,
      0,
      0,
      a7,
      0,
      0,
      0);
  if ( !a2 )
  {
    SeUnlockSubjectContext(SubjectContext);
  }
  return TRUE;
}
"""
        )

        profile_id = "windows.token_security.sep_common_access_check_ex"

        self.assertFalse(
            any(
                item["profile_id"] == profile_id
                for item in self._identities(without_callees)
            )
        )

        roles = self._roles(with_callees, profile_id)
        rename_map = {item.old: item.new for item in with_callees.renames if item.apply}
        access_state_identity = self._identity_for_base(with_callees, profile_id, "accessState")
        outputs_identity = self._identity_for_base(with_callees, profile_id, "accessCheckOutputs")
        access_state_fields = {str(item["name"]): item for item in access_state_identity["fields"]}
        output_fields = {str(item["name"]): item for item in outputs_identity["fields"]}
        blockers = [
            item
            for item in with_callees.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") in {"accessState", "accessCheckOutputs"}
        ]
        blocker_bases = {str(item["base"]) for item in blockers}

        self.assertEqual("SECURITY_SUBJECT_CONTEXT", roles["subjectContext"])
        self.assertEqual("BOOLEAN", roles["subjectContextLocked"])
        self.assertEqual("SEP_ACCESS_STATE", roles["accessState"])
        self.assertEqual("SEP_ACCESS_CHECK_OUTPUTS", roles["accessCheckOutputs"])
        self.assertEqual("KPROCESSOR_MODE", roles["accessMode"])
        self.assertEqual("SE_ACCESS_CHECK_FLAGS", roles["accessCheckFlags"])
        self.assertEqual("subjectContext", rename_map["SubjectContext"])
        self.assertEqual("subjectContextLocked", rename_map["a2"])
        self.assertEqual("accessState", rename_map["a3"])
        self.assertEqual("accessCheckOutputs", rename_map["a4"])
        self.assertEqual("accessMode", rename_map["a6"])
        self.assertEqual("accessCheckFlags", rename_map["a7"])
        self.assertEqual("ACCESS_MASK", access_state_fields["desiredAccess"]["type"])
        self.assertEqual("ACCESS_MASK", access_state_fields["previouslyGrantedAccess"]["type"])
        self.assertEqual("PGENERIC_MAPPING", access_state_fields["genericMapping"]["type"])
        self.assertEqual("PACCESS_MASK", output_fields["grantedAccessOutput"]["type"])
        self.assertEqual("PNTSTATUS", output_fields["accessStatusOutput"]["type"])
        self.assertEqual("PACCESS_REASONS", output_fields["accessReasonOutput"]["type"])
        self.assertEqual("PPRIVILEGE_SET *", output_fields["privilegeSetOutput"]["type"])
        self.assertEqual("report-only", access_state_identity["effective_mode"])
        self.assertEqual("report-only", outputs_identity["effective_mode"])
        self.assertEqual({"accessState", "accessCheckOutputs"}, blocker_bases)
        self.assertTrue(
            all("domain identity profile is report-only" in item["blockers"] for item in blockers)
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") in {"accessState", "accessCheckOutputs"}
                for item in with_callees.comments
            )
        )

    def test_audit_process_creation_requires_audit_record_call(self) -> None:
        without_callee = self._plan(
            """
void __fastcall SeAuditProcessCreation(PRKPROCESS Process, UNICODE_STRING *CommandLine)
{
  SECURITY_SUBJECT_CONTEXT SubjectContext;
  char Src[256];

  SeCaptureSubjectContext(&SubjectContext);
}
"""
        )
        with_callee = self._plan(
            """
void __fastcall SeAuditProcessCreation(PRKPROCESS Process, UNICODE_STRING *CommandLine)
{
  SECURITY_SUBJECT_CONTEXT SubjectContext;
  char Src[256];

  SeCaptureSubjectContext(&SubjectContext);
  SepAdtLogAuditRecord(Src);
  SeReleaseSubjectContext(&SubjectContext);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.token_security.audit_process_creation"
                for item in self._identities(without_callee)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_callee,
                "windows.token_security.audit_process_creation",
            )
        }

        self.assertEqual("EPROCESS", roles["auditedProcess"])
        self.assertEqual("UNICODE_STRING", roles["commandLine"])
        self.assertEqual("SECURITY_SUBJECT_CONTEXT", roles["auditSubjectContext"])
        self.assertEqual("AUDIT_RECORD", roles["auditRecord"])

    def test_release_subject_context_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __fastcall SeReleaseSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)
{
  PACCESS_TOKEN primaryToken;
  PACCESS_TOKEN clientToken;
  __int64 probe;

  primaryToken = SubjectContext->PrimaryToken;
  clientToken = SubjectContext->ClientToken;
  probe = *(_QWORD *)(SubjectContext + 16)
        + *(_QWORD *)(SubjectContext + 24)
        + *(_QWORD *)(SubjectContext + 32)
        + *(_QWORD *)(SubjectContext + 40)
        + *(_QWORD *)(SubjectContext + 48)
        + *(_QWORD *)(SubjectContext + 56)
        + *(_QWORD *)(SubjectContext + 64)
        + *(_QWORD *)(SubjectContext + 72)
        + *(_QWORD *)(SubjectContext + 16)
        + *(_QWORD *)(SubjectContext + 24)
        + *(_QWORD *)(SubjectContext + 32)
        + *(_QWORD *)(SubjectContext + 40);
  if ( probe )
  {
    PsDereferencePrimaryToken(primaryToken);
    ObfDereferenceObject(clientToken);
  }
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.token_security.release_subject_context",
            "subjectContext",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "subjectContext"
        ]

        self.assertEqual("SECURITY_SUBJECT_CONTEXT", identity["structure_name"])
        self.assertEqual("releasedSubjectContext", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "subjectContext"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __fastcall SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)
{
  SubjectContext->PrimaryToken = PsReferencePrimaryTokenWithTag(PsGetCurrentProcess(), 'tSeS');
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.token_security.capture_subject_context",
            role="capturedSubjectContext",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_subject_context_type(self) -> None:
        plan = self._plan(
            """
void __fastcall SeCaptureSubjectContext(int SubjectContext)
{
  SubjectContext = 0;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.token_security.capture_subject_context"
                and item["trusted_role"] == "capturedSubjectContext"
                for item in self._identities(plan)
            )
        )

    def test_token_security_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __fastcall SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)
{
  SubjectContext->PrimaryToken = PsReferencePrimaryTokenWithTag(PsGetCurrentProcess(), 'tSeS');
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/token_security.json" for item in manifests)
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
