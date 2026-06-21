from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.field_layout_hints import field_layout_comments
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


class DomainIdentityProfileFrameworkTests(unittest.TestCase):
    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_isolated_pack_loader_matches_build_bound_profile_and_emits_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, _pack_payload(function_names=["DomainProfileTarget"]))
            profile_loader.configure_profile_dir(temp_dir)

            comments = field_layout_comments(
                _domain_layout_sample("DomainProfileTarget", body_call="RequiredCallee();"),
                profile_context=_matching_context(),
            )

        identity = self._single_identity(comments)
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual("test.domain_profile", identity["matched_profile_id"])
        self.assertEqual("TEST_DOMAIN_CONTEXT", identity["structure_name"])
        self.assertEqual("domainContext", identity["trusted_role"])
        self.assertEqual("canonical-rewrite-eligible", identity["effective_mode"])
        self.assertEqual([], identity["blockers"])
        self.assertEqual("v1-test", identity["profile_version"])
        self.assertEqual("ntoskrnl.exe", identity["profile_metadata"]["image"])
        self.assertTrue(any(field.get("name") == "flags" for field in identity["fields"]))
        self.assertTrue(all(field.get("source") == "test-profile" for field in identity["fields"]))
        self.assertEqual(1, len(ready))
        self.assertEqual("domain_identity", ready[0]["source_provenance"])
        self.assertEqual([], blockers)

    def test_build_mismatch_is_report_only_and_does_not_promote_rewrite_or_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, _pack_payload(rename_to="domainContext"))
            profile_loader.configure_profile_dir(temp_dir)

            text = _domain_layout_sample("DomainProfileTarget")
            comments = field_layout_comments(text, profile_context={**_matching_context(), "build": "99999.1"})
            capture = capture_from_pseudocode(
                text,
                profile_context={**_matching_context(), "build": "99999.1"},
            )
            plan = build_clean_plan(capture)

        identity = self._single_identity(comments)
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertEqual([], ready)
        self.assertEqual([], aliases)
        self.assertNotEqual("domainContext", rename_map.get("a2"))

    def test_missing_profile_context_fails_closed_for_build_bound_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, _pack_payload())
            profile_loader.configure_profile_dir(temp_dir)

            comments = field_layout_comments(_domain_layout_sample("DomainProfileTarget"))

        identity = self._single_identity(comments)
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("missing_source_identity", identity["forced_report_only_reasons"])
        self.assertIn("missing_source_identity", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertEqual([], ready)

    def test_profile_backed_type_correction_uses_canonical_type_in_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, _type_correction_pack_payload())
            profile_loader.configure_profile_dir(temp_dir)

            capture = capture_from_pseudocode(
                """
__int64 __fastcall IopExample(__int64 a1, __int64 a2)
{
  return a1 + a2;
}
""",
                profile_context=_matching_context(),
            )
            plan = build_clean_plan(capture)
            rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(2, len(plan.type_corrections))
        self.assertTrue(all(item.apply_to_preview for item in plan.type_corrections))
        self.assertEqual("__int64", plan.type_corrections[0].old_type)
        self.assertEqual("PDEVICE_OBJECT", plan.type_corrections[0].canonical_type)
        self.assertEqual("PIRP", plan.type_corrections[1].canonical_type)
        self.assertIn("__int64 __fastcall IopExample(PDEVICE_OBJECT deviceObject, PIRP irp)", rendered)
        self.assertNotIn("__int64 deviceObject", rendered)

    def test_type_correction_build_mismatch_is_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, _type_correction_pack_payload())
            profile_loader.configure_profile_dir(temp_dir)

            capture = capture_from_pseudocode(
                """
__int64 __fastcall IopExample(__int64 a1, __int64 a2)
{
  return a1 + a2;
}
""",
                profile_context={**_matching_context(), "build": "99999.1"},
            )
            plan = build_clean_plan(capture)
            rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(2, len(plan.type_corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in plan.type_corrections))
        self.assertFalse(any(item.apply_to_preview for item in plan.type_corrections))
        self.assertIn("__int64 __fastcall IopExample(__int64 argument0, __int64 argument1)", rendered)
        self.assertIn("Parameter type corrections: 0 applied, 2 blocked.", rendered)
        self.assertIn("build_mismatch=2", rendered)

    def test_invalid_canonical_type_is_reported_without_rendering(self) -> None:
        payload = _type_correction_pack_payload(canonical_type0="PDEVICE_OBJECT[bad]")
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, payload)
            profile_loader.configure_profile_dir(temp_dir)

            capture = capture_from_pseudocode(
                """
__int64 __fastcall IopExample(__int64 a1, __int64 a2)
{
  return a1 + a2;
}
""",
                profile_context=_matching_context(),
            )
            plan = build_clean_plan(capture)
            rendered = render_cleaned_pseudocode(capture, plan)

        blocked = [item for item in plan.type_corrections if "invalid_canonical_type" in item.blockers]
        self.assertEqual(1, len(blocked))
        self.assertFalse(blocked[0].apply_to_preview)
        self.assertIn("__int64 __fastcall IopExample(__int64 deviceObject, PIRP irp)", rendered)
        self.assertIn("invalid_canonical_type=1", rendered)

    def test_ambiguous_type_correction_leaves_signature_unchanged(self) -> None:
        first = _type_correction_profile("test.type.a", "PDEVICE_OBJECT", "deviceObject")
        second = _type_correction_profile("test.type.b", "PVOID", "object")
        payload = _type_correction_pack_payload(profiles=[first, second])
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, payload)
            profile_loader.configure_profile_dir(temp_dir)

            capture = capture_from_pseudocode(
                """
__int64 __fastcall IopExample(__int64 a1, __int64 a2)
{
  return a1 + a2;
}
""",
                profile_context=_matching_context(),
            )
            plan = build_clean_plan(capture)
            rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(1, len(plan.type_corrections))
        self.assertEqual("ambiguous", plan.type_corrections[0].profile_id)
        self.assertIn("ambiguous_profile_match", plan.type_corrections[0].blockers)
        self.assertIn("__int64 __fastcall IopExample(__int64 argument0, __int64 argument1)", rendered)

    def test_image_hash_constraint_can_match_context_alias(self) -> None:
        profile = _pack_payload()
        profile["metadata"].pop("pdb_guid_age")
        profile["metadata"]["image_sha256"] = "AABBCC001122"
        context = dict(_matching_context())
        context.pop("pdb_guid_age")
        context["image_hash"] = "aabbcc001122"
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, profile)
            profile_loader.configure_profile_dir(temp_dir)

            comments = field_layout_comments(
                _domain_layout_sample("DomainProfileTarget"),
                profile_context=context,
            )

        identity = self._single_identity(comments)

        self.assertEqual("canonical-rewrite-eligible", identity["effective_mode"])
        self.assertEqual([], identity["blockers"])

    def test_profile_context_participates_in_input_fingerprint(self) -> None:
        text = _domain_layout_sample("DomainProfileTarget")
        first = capture_from_pseudocode(text, profile_context={**_matching_context(), "build": "26200.8457"})
        second = capture_from_pseudocode(text, profile_context={**_matching_context(), "build": "99999.1"})

        self.assertNotEqual(first.input_fingerprint(), second.input_fingerprint())

    def test_regex_and_required_callee_matchers_are_required(self) -> None:
        profile = _pack_payload(
            function_names=[],
            function_regex=["^DomainRegex.*$"],
            required_calls=["RequiredCallee"],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, profile)
            profile_loader.configure_profile_dir(temp_dir)

            without_callee = field_layout_comments(
                _domain_layout_sample("DomainRegexTarget"),
                profile_context=_matching_context(),
            )
            with_callee = field_layout_comments(
                _domain_layout_sample("DomainRegexTarget", body_call="RequiredCallee();"),
                profile_context=_matching_context(),
            )

        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in without_callee))
        self.assertEqual("test.domain_profile", self._single_identity(with_callee)["profile_id"])

    def test_body_identity_match_requires_explicit_allow_and_body_evidence(self) -> None:
        no_body_match_profile = _pack_payload(function_names=[])
        no_body_match_profile["profiles"][0]["required_body_regex"] = [
            r"\bRequiredBodyEvidence\s*\(",
        ]
        allowed_profile = _pack_payload(function_names=[])
        allowed_profile["profiles"][0]["allow_body_identity_match"] = True
        allowed_profile["profiles"][0]["required_body_regex"] = [
            r"\bRequiredBodyEvidence\s*\(",
        ]
        with tempfile.TemporaryDirectory() as blocked_dir:
            self._write_isolated_pack(blocked_dir, no_body_match_profile)
            profile_loader.configure_profile_dir(blocked_dir)

            blocked_comments = field_layout_comments(
                _domain_layout_sample("UnexpectedBodyTarget", body_call="RequiredBodyEvidence();"),
                profile_context=_matching_context(),
            )

        with tempfile.TemporaryDirectory() as allowed_dir:
            self._write_isolated_pack(allowed_dir, allowed_profile)
            profile_loader.configure_profile_dir(allowed_dir)

            missing_body_comments = field_layout_comments(
                _domain_layout_sample("UnexpectedBodyTarget"),
                profile_context=_matching_context(),
            )
            matched_comments = field_layout_comments(
                _domain_layout_sample("UnexpectedBodyTarget", body_call="RequiredBodyEvidence();"),
                profile_context=_matching_context(),
            )

        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in blocked_comments))
        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in missing_body_comments))
        self.assertEqual("test.domain_profile", self._single_identity(matched_comments)["profile_id"])

    def test_local_name_hint_can_match_non_parameter_base(self) -> None:
        profile = _pack_payload(function_names=["DomainLocalHintTarget"])
        profile["profiles"][0]["parameters"][0].pop("parameter_index")
        profile["profiles"][0]["parameters"][0]["local_names"] = ["domainLocal"]
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, profile)
            profile_loader.configure_profile_dir(temp_dir)

            comments = field_layout_comments(
                _domain_local_layout_sample("DomainLocalHintTarget"),
                profile_context=_matching_context(),
            )

        identity = self._single_identity(comments)

        self.assertEqual("domainLocal", identity["base"])
        self.assertEqual(-1, identity["parameter_index"])
        self.assertEqual("TEST_DOMAIN_CONTEXT", identity["structure"])

    def test_overlay_blocker_is_propagated_as_structured_blocker(self) -> None:
        profile = _pack_payload(force_report_only_on=["overlay", "type_conflict"])
        with tempfile.TemporaryDirectory() as temp_dir:
            self._write_isolated_pack(temp_dir, profile)
            profile_loader.configure_profile_dir(temp_dir)

            comments = field_layout_comments(
                _domain_layout_sample("DomainProfileTarget", mixed_width=True),
                profile_context=_matching_context(),
            )

        identity = self._single_identity(comments)
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("overlay", identity["forced_report_only_reasons"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], ready)
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))

    def _write_isolated_pack(self, temp_dir: str, payload: dict[str, object]) -> None:
        pack_dir = Path(temp_dir, "domain_identity")
        pack_dir.mkdir()
        Path(pack_dir, "kernel-test.json").write_text(json.dumps(payload), encoding="utf-8")

    def _single_identity(self, comments: list[dict[str, object]]) -> dict[str, object]:
        identities = [item for item in comments if item.get("kind") == "domain_structure_identity"]
        self.assertEqual(1, len(identities))
        return identities[0]


def _matching_context() -> dict[str, str]:
    return {
        "image": "ntoskrnl.exe",
        "arch": "amd64",
        "build": "26200.8457",
        "pdb_guid_age": "ABCDEF0123456789-1",
    }


def _pack_payload(
    function_names: list[str] | None = None,
    function_regex: list[str] | None = None,
    required_calls: list[str] | None = None,
    rename_to: str = "domainContext",
    force_report_only_on: list[str] | None = None,
) -> dict[str, object]:
    profile: dict[str, object] = {
        "id": "test.domain_profile",
        "source": "test-profile",
        "parameter_count": 2,
        "parameters": [
            {
                "parameter_index": 1,
                "rename_to": rename_to,
                "role": "domainContext",
                "structure": "TEST_DOMAIN_CONTEXT",
                "mode": "canonical-rewrite-eligible",
                "confidence": 0.91,
                "rename_confidence": 0.95,
                "accepted_types": ["__int64", "TEST_DOMAIN_CONTEXT *"],
                "force_report_only_on": force_report_only_on or [],
                "fields": [
                    {"offset": "0x10", "name": "flags", "type": "ULONG", "size": 4, "confidence": 0.98},
                    {"offset": "0x18", "name": "object", "type": "PVOID", "size": 8, "confidence": 0.94},
                    {"offset": "0x20", "name": "count", "type": "ULONG", "size": 4, "confidence": 0.93},
                    {"offset": "0x28", "name": "state", "type": "ULONG", "size": 4, "confidence": 0.93},
                    {"offset": "0x30", "name": "link", "type": "LIST_ENTRY", "size": 16, "confidence": 0.91},
                    {"offset": "0x38", "name": "owner", "type": "PVOID", "size": 8, "confidence": 0.90},
                    {"offset": "0x40", "name": "cookie", "type": "ULONG64", "size": 8, "confidence": 0.90},
                    {"offset": "0x48", "name": "generation", "type": "ULONG", "size": 4, "confidence": 0.90},
                ],
            }
        ],
    }
    if function_names is None:
        function_names = ["DomainProfileTarget"]
    if function_names:
        profile["function_names"] = function_names
    if function_regex:
        profile["function_regex"] = function_regex
    if required_calls:
        profile["required_calls"] = required_calls
    return {
        "schema": "domain_identity_profiles_v1",
        "profile_version": "v1-test",
        "metadata": {
            "image": "ntoskrnl.exe",
            "arch": "x64",
            "build": "26200.8457",
            "pdb_guid_age": "abcdef0123456789-1",
        },
        "profiles": [profile],
    }


def _type_correction_pack_payload(
    canonical_type0: str = "PDEVICE_OBJECT",
    profiles: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if profiles is None:
        profiles = [
            _type_correction_profile("test.type.device", canonical_type0, "deviceObject"),
            {
                **_type_correction_profile("test.type.irp", "PIRP", "irp"),
                "parameters": [
                    {
                        **_type_correction_profile("test.type.irp", "PIRP", "irp")["parameters"][0],
                        "parameter_index": 1,
                    }
                ],
            },
        ]
    return {
        "schema": "domain_identity_profiles_v1",
        "profile_version": "v1-test",
        "metadata": {
            "image": "ntoskrnl.exe",
            "arch": "x64",
            "build": "26200.8457",
            "pdb_guid_age": "abcdef0123456789-1",
        },
        "profiles": profiles,
    }


def _type_correction_profile(
    profile_id: str,
    canonical_type: str,
    canonical_name: str,
) -> dict[str, object]:
    return {
        "id": profile_id,
        "source": "type-correction-test",
        "function_names": ["IopExample"],
        "parameter_count": 2,
        "parameters": [
            {
                "parameter_index": 0,
                "rename_to": canonical_name,
                "role": canonical_name,
                "structure": "TEST_TYPE",
                "mode": "report-only",
                "confidence": 0.91,
                "accepted_types": ["__int64", "_QWORD"],
                "canonical_type": canonical_type,
                "canonical_name": canonical_name,
                "type_source": "unit-test-profile",
                "type_confidence": 0.93,
            }
        ],
    }


def _domain_layout_sample(
    function_name: str,
    body_call: str = "",
    mixed_width: bool = False,
) -> str:
    first_access = "*(_BYTE *)(a2 + 16)" if mixed_width else "*(_QWORD *)(a2 + 16)"
    call_line = ("  " + body_call + "\n") if body_call else ""
    return f"""
__int64 __fastcall {function_name}(__int64 a1, __int64 a2)
{{
{call_line}  return {first_access}
       + *(_QWORD *)(a2 + 24)
       + *(_QWORD *)(a2 + 32)
       + *(_QWORD *)(a2 + 40)
       + *(_QWORD *)(a2 + 48)
       + *(_QWORD *)(a2 + 56)
       + *(_QWORD *)(a2 + 64)
       + *(_QWORD *)(a2 + 72)
       + *(_QWORD *)(a2 + 16)
       + *(_QWORD *)(a2 + 24)
       + *(_QWORD *)(a2 + 32)
       + *(_QWORD *)(a2 + 40);
}}
"""


def _domain_local_layout_sample(function_name: str) -> str:
    return f"""
__int64 __fastcall {function_name}()
{{
  __int64 domainLocal;

  domainLocal = GetDomainContext();
  return *(_QWORD *)(domainLocal + 16)
       + *(_QWORD *)(domainLocal + 24)
       + *(_QWORD *)(domainLocal + 32)
       + *(_QWORD *)(domainLocal + 40)
       + *(_QWORD *)(domainLocal + 48)
       + *(_QWORD *)(domainLocal + 56)
       + *(_QWORD *)(domainLocal + 64)
       + *(_QWORD *)(domainLocal + 72)
       + *(_QWORD *)(domainLocal + 16)
       + *(_QWORD *)(domainLocal + 24)
       + *(_QWORD *)(domainLocal + 32)
       + *(_QWORD *)(domainLocal + 40);
}}
"""
