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
