from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.domain_identity_summary import (
    domain_identity_summary_payload,
    format_domain_identity_summary,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ObjectManagerDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_dereference_role_only_identity_from_default_pack(self) -> None:
        plan = self._plan(
            """
LONG_PTR __stdcall ObfDereferenceObject(PVOID referencedObject)
{
  return *((volatile LONG_PTR *)referencedObject - 6);
}
"""
        )

        identity = self._single_identity(plan, "windows.object_manager.dereference_object")

        self.assertEqual("object", identity["base"])
        self.assertEqual("OBJECT_BODY", identity["structure_name"])
        self.assertEqual("dereferencedObject", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual(True, identity["role_only"])
        self.assertEqual([], identity["fields"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual("object-manager-v1", identity["profile_version"])
        self.assertEqual("26200.8457", identity["profile_metadata"]["build"])
        self.assertEqual("x64", identity["profile_metadata"]["arch"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_regex_matcher_does_not_overmatch_ob_like_name(self) -> None:
        plan = self._plan(
            """
LONG_PTR __stdcall ObfDereferenceObjectWithTagExtra(PVOID referencedObject, ULONG tag)
{
  return *((volatile LONG_PTR *)referencedObject - 6);
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.object_manager.dereference_object"
                for item in self._identities(plan)
            )
        )

    def test_required_callee_prevents_query_security_false_positive(self) -> None:
        without_callee = self._plan(
            """
NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded)
{
  PVOID referencedObject;
  referencedObject = 0;
  return STATUS_SUCCESS;
}
"""
        )
        with_callee = self._plan(
            """
NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded)
{
  PVOID referencedObject;
  ObReferenceObjectByHandle(Handle, 0, 0, 0, &referencedObject, 0);
  ObfDereferenceObject(referencedObject);
  return STATUS_SUCCESS;
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.object_manager.query_security_object"
                for item in self._identities(without_callee)
            )
        )
        query_identities = [
            item
            for item in self._identities(with_callee)
            if item.get("profile_id") == "windows.object_manager.query_security_object"
        ]

        self.assertTrue(any(item.get("base") == "handle" for item in query_identities))
        self.assertTrue(any(item.get("base") == "referencedObject" for item in query_identities))
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in query_identities))

    def test_register_callbacks_profile_corrects_generic_parameter_types_in_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
NTSTATUS __stdcall ObRegisterCallbacks(__int64 a1, __int64 a2)
{
  return STATUS_SUCCESS;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.object_manager.register_callbacks"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identities = [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

        self.assertEqual(2, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertTrue(all(not item.apply_to_idb for item in corrections))
        self.assertIn(
            "NTSTATUS __stdcall ObRegisterCallbacks(POB_CALLBACK_REGISTRATION callbackRegistration, PVOID * registrationHandle)",
            rendered,
        )
        self.assertEqual(
            {
                "callbackRegistration": "OB_CALLBACK_REGISTRATION",
                "registrationHandleOutput": "OB_CALLBACK_HANDLE_OUTPUT",
            },
            {item["trusted_role"]: item["structure_name"] for item in identities},
        )
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_register_callbacks_build_mismatch_blocks_type_preview(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall ObRegisterCallbacks(__int64 a1, __int64 a2)
{
  return STATUS_SUCCESS;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )
        corrections = [
            item
            for item in plan.type_corrections
            if item.profile_id == "windows.object_manager.register_callbacks"
        ]

        self.assertEqual(2, len(corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in corrections))
        self.assertTrue(all(not item.apply_to_preview for item in corrections))

    def test_free_object_profile_corrects_object_header_signature_preview_only(self) -> None:
        capture = capture_from_pseudocode(
            """
void __fastcall ObpFreeObject(__int64 a1, __int64 a2, __int64 a3)
{
  *(_DWORD *)(a1 + 24) = 0;
  *(_DWORD *)(a1 + 26) = 0;
  *(_QWORD *)(a1 + 32) = 0;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.object_manager.free_object"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identity = self._single_identity(plan, profile_id)

        self.assertEqual(1, len(corrections))
        correction = corrections[0]
        self.assertEqual(0, correction.parameter_index)
        self.assertEqual("a1", correction.old_name)
        self.assertEqual("objectHeader", correction.new_name)
        self.assertEqual("__int64", correction.old_type)
        self.assertEqual("OBJECT_HEADER_LIKE *", correction.canonical_type)
        self.assertTrue(correction.apply_to_preview)
        self.assertFalse(correction.apply_to_idb)
        self.assertEqual([], correction.blockers)
        self.assertIn(
            "void __fastcall ObpFreeObject(OBJECT_HEADER_LIKE * objectHeader, __int64 argument1, __int64 argument2)",
            rendered,
        )
        self.assertIn("objectHeader + 24", rendered)
        self.assertEqual([], plan.corrected_parameter_map)
        self.assertEqual("objectHeader", identity["base"])
        self.assertEqual("OBJECT_HEADER_LIKE", identity["structure_name"])
        self.assertEqual("objectHeader", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready" and item.get("base") == "objectHeader"
                for item in plan.comments
            )
        )

    def test_free_object_build_mismatch_blocks_signature_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
void __fastcall ObpFreeObject(__int64 a1, __int64 a2, __int64 a3)
{
  *(_DWORD *)(a1 + 24) = 0;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.object_manager.free_object"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identity = self._single_identity(plan, profile_id)

        self.assertEqual(1, len(corrections))
        self.assertIn("build_mismatch", corrections[0].blockers)
        self.assertFalse(corrections[0].apply_to_preview)
        self.assertNotIn("OBJECT_HEADER_LIKE * objectHeader", rendered)
        self.assertEqual([], plan.corrected_parameter_map)
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertIn("profile_report_only", identity["blockers"])

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
LONG_PTR __stdcall ObfDereferenceObject(PVOID referencedObject)
{
  return *((volatile LONG_PTR *)referencedObject - 6);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(plan, "windows.object_manager.dereference_object")

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))
        summary = domain_identity_summary_payload(plan)
        summary_text = format_domain_identity_summary(plan)

        self.assertEqual(1, summary["total_hits"])
        self.assertEqual(1, summary["report_only_hits"])
        self.assertEqual(1, summary["blocker_counts"]["build_mismatch"])
        self.assertIn("build_mismatch=1", summary_text)

    def test_source_path_infers_object_manager_profile_context(self) -> None:
        capture = capture_from_pseudocode(
            """
LONG_PTR __stdcall ObfDereferenceObject(PVOID referencedObject)
{
  return *((volatile LONG_PTR *)referencedObject - 6);
}
""",
            source_path=SOURCE_PATH,
        )

        self.assertEqual("ntoskrnl.exe", capture.profile_context["image"])
        self.assertEqual("26200.8457", capture.profile_context["build"])
        self.assertEqual("x64", capture.profile_context["arch"])

    def test_report_only_create_handle_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
NTSTATUS __fastcall ObpCreateHandle(unsigned int argument0, PVOID referencedObject, int argument2, __int64 context, int argument4, int argument5, char argument6, ULONG_PTR inputLength, int argument8, _QWORD *handleOut, __int64 *handleInfoOut)
{
  return *(_DWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_DWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_DWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_DWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_QWORD *)(context + 40);
}
"""
        )

        identity = self._identity_for_base(plan, "windows.object_manager.create_handle", "context")
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers" and item.get("base") == "context"
        ]

        self.assertEqual("ACCESS_STATE", identity["structure_name"])
        self.assertEqual("accessState", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready" and item.get("base") == "context"
                for item in plan.comments
            )
        )

    def test_canonical_object_manager_like_profile_stays_blocked_by_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_temp_object_manager_profile(temp_dir)
            profile_loader.configure_profile_dir(temp_dir)
            plan = self._plan(
                """
NTSTATUS __fastcall ObpCreateHandle(unsigned int argument0, PVOID referencedObject, int argument2, __int64 context, int argument4, int argument5, char argument6, ULONG_PTR inputLength, int argument8, _QWORD *handleOut, __int64 *handleInfoOut)
{
  return *(_BYTE *)(context + 16)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40);
}
"""
            )

        identity = self._identity_for_base(plan, "test.object_manager.canonical", "context")

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("overlay", identity["forced_report_only_reasons"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready" and item.get("base") == "context"
                for item in plan.comments
            )
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _single_identity(self, plan, profile_id: str) -> dict[str, object]:
        identities = [item for item in self._identities(plan) if item.get("profile_id") == profile_id]
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

    def _write_temp_object_manager_profile(self, temp_dir: str) -> None:
        pack_dir = Path(temp_dir, "domain_identity")
        pack_dir.mkdir()
        payload = {
            "schema": "domain_identity_profiles_v1",
            "profile_version": "test-object-manager",
            "metadata": {
                "image": "ntoskrnl.exe",
                "arch": "x64",
                "build": "26200.8457",
            },
            "profiles": [
                {
                    "id": "test.object_manager.canonical",
                    "function_names": ["ObpCreateHandle"],
                    "parameters": [
                        {
                            "parameter_index": 3,
                            "role": "accessState",
                            "structure": "ACCESS_STATE",
                            "mode": "canonical-rewrite-eligible",
                            "confidence": 0.92,
                            "accepted_types": ["__int64"],
                            "force_report_only_on": ["overlay", "base_stability"],
                            "fields": [
                                {
                                    "offset": "0x10",
                                    "name": "Flags",
                                    "type": "ULONG",
                                    "size": 4,
                                    "confidence": 0.96,
                                    "source": "test profile",
                                    "provenance": "test profile",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        Path(pack_dir, "object_manager.json").write_text(
            json.dumps(payload, ensure_ascii=True),
            encoding="utf-8",
        )
