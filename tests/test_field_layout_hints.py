from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.field_layout_hints import (
    _LayoutEvidence,
    _field_rewrite_threshold_blockers,
    _field_rewrite_threshold_policy,
    field_layout_comments,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


class FieldLayoutHintTests(unittest.TestCase):
    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def _configure_domain_profiles(self, temp_dir: str, profiles: list[dict[str, object]]) -> None:
        payload = {
            "schema": "domain_identity_profiles_v1",
            "profiles": profiles,
        }
        Path(temp_dir, "domain_identity.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        profile_loader.configure_profile_dir(temp_dir)

    def test_repeated_typed_offset_accesses_emit_layout_comment(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "a1",
                                "new": "sessionSpace",
                                "confidence": 0.95,
                                "reason": "base pointer with repeated typed offsets",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(
            """
__int64 __fastcall FieldLayoutSample(__int64 a1)
{
  unsigned int v1;
  __int64 v2;

  v1 = *(_DWORD *)(a1 + 16);
  v2 = *(_QWORD *)(a1 + 24);
  if ( *(_BYTE *)(a1 + 32) )
    return *(_DWORD *)(a1 + 40) + *(_WORD *)(a1 + 48) + v1;
  return v1 + v2;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        comments = [item for item in plan.comments if item.get("kind") == "inferred_offset_layout"]
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(1, len(comments))
        self.assertIn("sessionSpace", comments[0]["text"])
        self.assertIn("+0x10", comments[0]["text"])
        self.assertIn("+0x18", comments[0]["text"])
        self.assertIn("+0x20", comments[0]["text"])
        self.assertIn("inferred_offset_layout", rendered)
        self.assertIn("Offset layout hint: sessionSpace", rendered)
        self.assertIn("inferred_offset_field_preview", rendered)
        self.assertIn("Preview fields for sessionSpace", rendered)
        self.assertIn("inferred_offset_field_aliases", rendered)
        self.assertIn("Alias map for sessionSpace", rendered)
        self.assertIn("inferred_offset_rewrite_blockers", rendered)
        self.assertIn("rewrite offset threshold requires at least 8 offsets", rendered)
        self.assertIn("rewrite access threshold requires at least 12 accesses", rendered)

    def test_sparse_offset_accesses_do_not_emit_layout_comment(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SparseLayout(__int64 a1)
{
  return *(_DWORD *)(a1 + 16) + *(_DWORD *)(a1 + 24);
}
"""
        )

        self.assertEqual([], comments)

    def test_domain_identity_no_profile_keeps_argument_identity_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall DomainNoProfileLayout(__int64 argument0)
{
  return *(_QWORD *)(argument0 + 16)
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
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in comments))
        self.assertEqual(1, len(blockers))
        self.assertIn("base name is unresolved argument identity", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_domain_identity_report_only_profile_emits_identity_before_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._configure_domain_profiles(
                temp_dir,
                [
                    _domain_identity_profile(
                        "test.report_only",
                        "DomainReportOnlyLayout",
                        "report-only",
                    )
                ],
            )
            comments = field_layout_comments(_domain_identity_sample("DomainReportOnlyLayout"))

        kinds = [str(item.get("kind", "")) for item in comments]
        identities = [item for item in comments if item.get("kind") == "domain_structure_identity"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(identities))
        self.assertLess(kinds.index("domain_structure_identity"), kinds.index("inferred_offset_field_aliases"))
        self.assertEqual("test.report_only", identities[0]["profile_id"])
        self.assertEqual("domainContext", identities[0]["role"])
        self.assertEqual("TEST_DOMAIN_CONTEXT", identities[0]["structure"])
        self.assertEqual("report-only", identities[0]["effective_mode"])
        self.assertEqual("flags", identities[0]["fields"][0]["name"])
        self.assertEqual(1, len(aliases))
        self.assertIn("flags=+0x10 ULONG", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertIn("domain identity profile is report-only", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_domain_identity_can_suppress_role_only_layout_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._configure_domain_profiles(
                temp_dir,
                [
                    _domain_identity_profile(
                        "test.role_only_suppressed",
                        "DomainRoleOnlySuppressedLayout",
                        "report-only",
                        suppress_layout_inference=True,
                    )
                ],
            )
            capture = capture_from_pseudocode(_domain_identity_sample("DomainRoleOnlySuppressedLayout"))
            plan = build_clean_plan(capture)

        identities = [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]
        layout_comments = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_layout"
            and item.get("base") == "argument0"
        ]
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "argument0"
        ]
        aliases = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_field_aliases"
            and item.get("base") == "argument0"
        ]

        self.assertEqual(1, len(identities))
        self.assertEqual("test.role_only_suppressed", identities[0]["profile_id"])
        self.assertEqual("domainContext", identities[0]["role"])
        self.assertTrue(identities[0]["suppress_layout_inference"])
        self.assertEqual([], layout_comments)
        self.assertEqual([], blockers)
        self.assertEqual([], aliases)

    def test_domain_identity_canonical_profile_can_satisfy_argument_identity_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._configure_domain_profiles(
                temp_dir,
                [
                    _domain_identity_profile(
                        "test.canonical",
                        "DomainCanonicalLayout",
                        "canonical-rewrite-eligible",
                    )
                ],
            )
            comments = field_layout_comments(_domain_identity_sample("DomainCanonicalLayout"))

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("domain_identity", ready[0]["source_provenance"])
        self.assertEqual("test.canonical", ready[0]["domain_profile_id"])
        self.assertEqual("domainContext", ready[0]["domain_role"])
        self.assertEqual(1, len(previews))
        self.assertEqual("domain_identity", previews[0]["source_provenance"])
        self.assertIn("flags", previews[0]["text"])

    def test_domain_identity_ambiguous_profile_match_stays_report_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._configure_domain_profiles(
                temp_dir,
                [
                    _domain_identity_profile(
                        "test.ambiguous.a",
                        "DomainAmbiguousLayout",
                        "canonical-rewrite-eligible",
                    ),
                    _domain_identity_profile(
                        "test.ambiguous.b",
                        "DomainAmbiguousLayout",
                        "canonical-rewrite-eligible",
                    ),
                ],
            )
            comments = field_layout_comments(_domain_identity_sample("DomainAmbiguousLayout"))

        identities = [item for item in comments if item.get("kind") == "domain_structure_identity"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(identities))
        self.assertEqual("ambiguous", identities[0]["profile_id"])
        self.assertEqual(
            ["test.ambiguous.a", "test.ambiguous.b"],
            identities[0]["ambiguous_profile_ids"],
        )
        self.assertEqual(1, len(blockers))
        self.assertIn("domain identity profile is ambiguous", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_domain_identity_profile_forces_report_only_on_overlay_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._configure_domain_profiles(
                temp_dir,
                [
                    _domain_identity_profile(
                        "test.overlay_blocked",
                        "DomainOverlayBlockedLayout",
                        "canonical-rewrite-eligible",
                        force_report_only_on=["overlay", "type_conflict"],
                    )
                ],
            )
            comments = field_layout_comments(
                """
__int64 __fastcall DomainOverlayBlockedLayout(__int64 argument0)
{
  return *(_BYTE *)(argument0 + 16)
       + *(_QWORD *)(argument0 + 16)
       + *(_QWORD *)(argument0 + 24)
       + *(_QWORD *)(argument0 + 32)
       + *(_QWORD *)(argument0 + 40)
       + *(_QWORD *)(argument0 + 48)
       + *(_QWORD *)(argument0 + 56)
       + *(_QWORD *)(argument0 + 64)
       + *(_QWORD *)(argument0 + 72)
       + *(_QWORD *)(argument0 + 24)
       + *(_QWORD *)(argument0 + 32)
       + *(_QWORD *)(argument0 + 40);
}
"""
            )

        identities = [item for item in comments if item.get("kind") == "domain_structure_identity"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(identities))
        self.assertEqual("report-only", identities[0]["effective_mode"])
        self.assertEqual(["overlay"], identities[0]["forced_report_only_reasons"])
        self.assertEqual(1, len(blockers))
        self.assertIn("domain identity profile is report-only", blockers[0]["blockers"])
        self.assertIn("one or more offsets mix irregular field access widths", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_rtlp_copy_legacy_context_profile_renames_context_parameters(self) -> None:
        capture = capture_from_pseudocode(_rtlp_copy_legacy_context_sample())
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        identities = [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]
        blockers = [item for item in plan.comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        aliases = [item for item in plan.comments if item.get("kind") == "inferred_offset_field_aliases"]
        unaligned = [item for item in plan.comments if item.get("kind") == "inferred_offset_unaligned_subfields"]

        self.assertEqual("destinationContext", rename_map["a2"])
        self.assertEqual("sourceContext", rename_map["a4"])
        self.assertIn("RtlpCopyLegacyContext(__int64 argument0, __int64 destinationContext", rendered)
        self.assertIn("__int64 sourceContext)", rendered)
        self.assertEqual(
            ["destinationContext", "sourceContext"],
            [item.get("base") for item in identities],
        )
        self.assertTrue(all(item.get("structure") == "CONTEXT" for item in identities))
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))
        self.assertTrue(all("unaligned" in item.get("forced_report_only_reasons", []) for item in identities))
        self.assertTrue(any("ContextFlags=+0x30 DWORD" in item["text"] for item in aliases))
        self.assertTrue(
            any(
                field.get("name") == "Rip" and field.get("offset") == 0xF8
                for item in aliases
                for field in item.get("fields", [])
            )
        )
        self.assertEqual(2, len(unaligned))
        self.assertTrue(all("CONTEXT subfield alignment evidence" in item["text"] for item in unaligned))
        self.assertTrue(any("Rax uses _OWORD" in item["text"] for item in unaligned))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_rtlp_copy_legacy_context_profile_can_be_canonical_when_layout_is_clean(self) -> None:
        capture = capture_from_pseudocode(_rtlp_copy_legacy_context_aligned_sample())
        plan = build_clean_plan(capture)
        ready = [item for item in plan.comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in plan.comments if item.get("kind") == "inferred_offset_rewrite_preview"]
        blockers = [item for item in plan.comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertFalse(blockers)
        self.assertEqual(2, len(ready))
        self.assertTrue(all(item.get("source_provenance") == "domain_identity" for item in ready))
        self.assertTrue(all(item.get("domain_profile_id") == "windows.x64_context.rtlp_copy_legacy_context" for item in ready))
        self.assertEqual(2, len(previews))
        self.assertTrue(any("ContextFlags" in item["text"] for item in previews))
        self.assertIn("destinationContext + 48", rendered)
        self.assertIn("sourceContext + 48", rendered)

    def test_context_profile_does_not_apply_to_unrelated_function(self) -> None:
        capture = capture_from_pseudocode(
            _rtlp_copy_legacy_context_sample().replace(
                "RtlpCopyLegacyContext",
                "UnrelatedContextCopy",
                1,
            )
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertNotEqual("destinationContext", rename_map.get("a2"))
        self.assertNotEqual("sourceContext", rename_map.get("a4"))
        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in plan.comments))

    def test_devpropkey_profile_renames_property_key_and_annotates_guid_parts(self) -> None:
        capture = capture_from_pseudocode(_cm_get_device_mapped_property_sample())
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        identities = [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

        self.assertEqual("propertyKey", rename_map["a4"])
        self.assertIn("__int64 propertyKey,", rendered)
        self.assertEqual(1, len(identities))
        self.assertEqual("propertyKey", identities[0]["base"])
        self.assertEqual("propertyKey", identities[0]["role"])
        self.assertEqual("DEVPROPKEY", identities[0]["structure"])
        self.assertEqual("windows.devpropkey.cm_get_device_mapped_property_from_composite", identities[0]["profile_id"])
        self.assertTrue(any(field.get("name") == "fmtidHighPart" for field in identities[0]["fields"]))
        self.assertTrue(any(field.get("name") == "pid" for field in identities[0]["fields"]))
        self.assertIn("+0x8 ULONGLONG fmtidHighPart", rendered)
        self.assertIn("DEVPROPKEY property identifier at +0x10", rendered)
        self.assertIn("propertyKey is DEVPROPKEY: +0x10 is pid / DEVPROPID, +0x8 is fmtidHighPart", rendered)
        self.assertIn("direct _QWORD loads from propertyKey are fmtidLowPart review aliases", rendered)
        self.assertIn("Observed DEVPKEY_* comparisons, for example DEVPKEY_Device_InstanceId", rendered)
        self.assertIn("DEVPKEY_Device_InstanceId.fmtid.Data1", rendered)

    def test_devpropkey_profile_handles_partial_guid_high_access_honestly(self) -> None:
        capture = capture_from_pseudocode(_cm_get_device_mapped_property_partial_guid_sample())
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        identities = [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

        self.assertEqual(1, len(identities))
        self.assertEqual("DEVPROPKEY", identities[0]["structure"])
        self.assertIn("fmtidHighPart", rendered)
        self.assertIn("require both halves before treating them as a full GUID match", rendered)
        self.assertNotIn("fmtidLowPart review aliases", rendered)
        self.assertNotIn("full DEVPROPKEY equality", rendered)

    def test_devpropkey_profile_does_not_apply_to_unrelated_guid_buffer(self) -> None:
        capture = capture_from_pseudocode(
            _cm_get_device_mapped_property_sample().replace(
                "CmGetDeviceMappedPropertyFromComposite",
                "UnrelatedGuidBufferHelper",
                1,
            )
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotEqual("propertyKey", rename_map.get("a4"))
        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in plan.comments))
        self.assertNotIn("propertyKey->fmtidHighPart", rendered)

    def test_etw_store_event_builder_profile_renames_builder_and_emits_append_hint(self) -> None:
        capture = capture_from_pseudocode(_smst_etw_fill_store_event_sample())
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        identities = [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]
        append_hints = [
            item
            for item in plan.comments
            if item.get("kind") == "domain_event_builder_append_pattern"
        ]
        aliases = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_field_aliases" and item.get("base") == "eventBuilder"
        ]
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers" and item.get("base") == "eventBuilder"
        ]

        self.assertEqual("eventBuilder", rename_map["a2"])
        self.assertIn("SmStEtwFillStoreEvent(__int64 argument0, __int64 eventBuilder)", rendered)
        self.assertEqual(1, len(identities))
        self.assertEqual("windows.etw.smst_fill_store_event_builder", identities[0]["profile_id"])
        self.assertEqual("eventBuilder", identities[0]["base"])
        self.assertEqual("eventBuilder", identities[0]["role"])
        self.assertEqual("SMST_ETW_EVENT_BUILDER", identities[0]["structure"])
        self.assertEqual("report-only", identities[0]["effective_mode"])
        self.assertEqual(["threshold"], identities[0]["forced_report_only_reasons"])
        self.assertTrue(any(field.get("name") == "descriptorTable" for field in identities[0]["fields"]))
        self.assertTrue(any(field.get("name") == "payloadBuffer" for field in identities[0]["fields"]))
        self.assertTrue(any(field.get("name") == "itemCount" for field in identities[0]["fields"]))
        self.assertTrue(any(field.get("name") == "payloadWriteOffset" for field in identities[0]["fields"]))
        self.assertEqual(1, len(append_hints))
        self.assertEqual(1, append_hints[0]["payload_buffer_targets"])
        self.assertEqual(1, append_hints[0]["descriptor_table_slots"])
        self.assertEqual(1, append_hints[0]["item_count_updates"])
        self.assertEqual(1, append_hints[0]["payload_offset_updates"])
        self.assertIn("payloadBuffer target(s)=1", append_hints[0]["text"])
        self.assertEqual(1, len(aliases))
        self.assertIn("descriptorTable=+0x0 SMKM_EVENT_DESCRIPTOR *", aliases[0]["text"])
        self.assertIn("payloadWriteOffset=+0x18 ULONG", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertIn("domain identity profile is report-only", blockers[0]["blockers"])
        self.assertIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))
        self.assertIn("eventBuilder is SMST_ETW_EVENT_BUILDER", rendered)
        self.assertIn("Repeated append pattern on eventBuilder writes payload data", rendered)

    def test_etw_store_event_builder_profile_does_not_apply_to_unrelated_hot_cluster(self) -> None:
        capture = capture_from_pseudocode(
            _smst_etw_fill_store_event_sample().replace(
                "SmStEtwFillStoreEvent",
                "UnrelatedStoreEventHelper",
                1,
            )
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotEqual("eventBuilder", rename_map.get("a2"))
        self.assertFalse(any(item.get("kind") == "domain_structure_identity" for item in plan.comments))
        self.assertFalse(any(item.get("kind") == "domain_event_builder_append_pattern" for item in plan.comments))
        self.assertNotIn("SMST_ETW_EVENT_BUILDER", rendered)
        self.assertNotIn("eventBuilder is SMST_ETW_EVENT_BUILDER", rendered)

    def test_registry_delete_value_profile_reports_roles_without_field_rewrite(self) -> None:
        capture = capture_from_pseudocode(_cm_delete_value_key_registry_sample())
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        roles = [
            item
            for item in plan.comments
            if item.get("kind") == "registry_domain_role_evidence"
        ]
        by_role = {str(item.get("role")): item for item in roles}

        self.assertEqual("keyBody", rename_map["a1"])
        self.assertEqual("status", rename_map["started"])
        self.assertEqual("kcb", rename_map["v7"])
        self.assertEqual("transactionUow", rename_map["v6"])
        self.assertEqual(
            {
                "hiveCellLikePointer",
                "kcbLikePointer",
                "keyBodyLikePointer",
                "statusCarrier",
                "transactionUnitOfWork",
            },
            set(by_role),
        )
        self.assertTrue(all(item.get("mode") == "report-only" for item in roles))
        self.assertTrue(all("no registry structure field rewrite is enabled by this profile" in item["blockers"] for item in roles))
        self.assertIn("boolean-like source name is weaker than NTSTATUS evidence", by_role["statusCarrier"]["blockers"])
        self.assertIn("KCB field names remain unresolved", by_role["kcbLikePointer"]["blockers"])
        self.assertIn("hive/cell role is expression-level only", by_role["hiveCellLikePointer"]["blockers"])
        self.assertIn("UoW structure fields are not recovered", by_role["transactionUnitOfWork"]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))
        self.assertIn("CmDeleteValueKey(__int64 keyBody", rendered)
        self.assertIn("status = CmpStartKcbStackForTopLayerKcb", rendered)
        self.assertIn("transactionUow is transactionUnitOfWork", rendered)
        self.assertIn("CmpTransEnlistUowInCmTrans(UnitOfWork", rendered)
        self.assertIn("Registry domain role for CmDeleteValueKey", rendered)

    def test_registry_delete_value_profile_does_not_apply_to_unrelated_cm_helper(self) -> None:
        capture = capture_from_pseudocode(
            _cm_delete_value_key_registry_sample().replace("CmDeleteValueKey", "CmOtherValueHelper", 1)
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertNotEqual("keyBody", rename_map.get("a1"))
        self.assertNotEqual("transactionUow", rename_map.get("v6"))
        self.assertFalse(any(item.get("kind") == "registry_domain_role_evidence" for item in plan.comments))

    def test_generic_temp_base_requires_stronger_layout_evidence(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall GenericTempLayout(__int64 v14)
{
  if ( *(_BYTE *)(v14 + 1) )
    return *(_DWORD *)(v14 + 4) + *(_QWORD *)(v14 + 32);
  return *(_DWORD *)(v14 + 40);
}
"""
        )

        self.assertEqual([], comments)

    def test_named_layout_with_dense_offsets_emits_preview_only_fields(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall NamedLayout(__int64 sessionSpace)
{
  return *(_DWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_BYTE *)(sessionSpace + 32)
       + *(_WORD *)(sessionSpace + 40)
       + *(_DWORD *)(sessionSpace + 48);
}
"""
        )
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(previews))
        self.assertEqual("sessionSpace", previews[0]["base"])
        self.assertEqual("named", previews[0]["base_kind"])
        self.assertEqual(5, len(previews[0]["fields"]))
        self.assertIn("+0x10 _DWORD field_10", previews[0]["text"])
        self.assertIn("Preview only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        self.assertEqual(1, len(aliases))
        self.assertEqual("sessionSpace", aliases[0]["base"])
        self.assertEqual("named", aliases[0]["base_kind"])
        self.assertEqual(0.73, aliases[0]["confidence"])
        self.assertIn("field_10=+0x10 _DWORD", aliases[0]["text"])
        self.assertIn("review-only shorthand", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertEqual("sessionSpace", blockers[0]["base"])
        self.assertEqual("named", blockers[0]["base_kind"])
        self.assertIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])

    def test_named_layout_threshold_blockers_are_split_by_evidence_type(self) -> None:
        offset_limited = field_layout_comments(
            """
__int64 __fastcall OffsetLimitedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24);
}
"""
        )
        access_limited = field_layout_comments(
            """
__int64 __fastcall AccessLimitedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72);
}
"""
        )

        offset_blockers = [
            item for item in offset_limited if item.get("kind") == "inferred_offset_rewrite_blockers"
        ]
        access_blockers = [
            item for item in access_limited if item.get("kind") == "inferred_offset_rewrite_blockers"
        ]
        offset_near_ready = [
            item for item in offset_limited if item.get("kind") == "inferred_offset_rewrite_near_ready"
        ]
        access_near_ready = [
            item for item in access_limited if item.get("kind") == "inferred_offset_rewrite_near_ready"
        ]

        self.assertEqual(1, len(offset_blockers))
        self.assertIn("rewrite offset threshold requires at least 8 offsets", offset_blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", offset_blockers[0]["blockers"])
        self.assertEqual(1, len(offset_near_ready))
        self.assertEqual("offset", offset_near_ready[0]["missing_threshold"])
        self.assertEqual(5, offset_near_ready[0]["offset_count"])
        self.assertEqual(12, offset_near_ready[0]["access_count"])
        self.assertIn("missing offset threshold only", offset_near_ready[0]["text"])
        self.assertEqual(1, len(access_blockers))
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", access_blockers[0]["blockers"])
        self.assertIn("rewrite access threshold requires at least 12 accesses", access_blockers[0]["blockers"])
        self.assertEqual(1, len(access_near_ready))
        self.assertEqual("access", access_near_ready[0]["missing_threshold"])
        self.assertEqual(8, access_near_ready[0]["offset_count"])
        self.assertEqual(8, access_near_ready[0]["access_count"])
        self.assertIn("missing access threshold only", access_near_ready[0]["text"])

    def test_named_layout_threshold_grace_promotes_near_ready_candidates(self) -> None:
        offset_grace = field_layout_comments(
            """
__int64 __fastcall OffsetGraceLayout(__int64 deviceObject)
{
  return *(_QWORD *)(deviceObject + 16)
       + *(_QWORD *)(deviceObject + 24)
       + *(_QWORD *)(deviceObject + 32)
       + *(_QWORD *)(deviceObject + 40)
       + *(_QWORD *)(deviceObject + 48)
       + *(_QWORD *)(deviceObject + 56)
       + *(_QWORD *)(deviceObject + 16)
       + *(_QWORD *)(deviceObject + 24)
       + *(_QWORD *)(deviceObject + 32)
       + *(_QWORD *)(deviceObject + 40)
       + *(_QWORD *)(deviceObject + 48)
       + *(_QWORD *)(deviceObject + 56);
}
"""
        )
        access_grace = field_layout_comments(
            """
__int64 __fastcall AccessGraceLayout(__int64 Irp)
{
  return *(_QWORD *)(Irp + 16)
       + *(_QWORD *)(Irp + 24)
       + *(_QWORD *)(Irp + 32)
       + *(_QWORD *)(Irp + 40)
       + *(_QWORD *)(Irp + 48)
       + *(_QWORD *)(Irp + 56)
       + *(_QWORD *)(Irp + 64)
       + *(_QWORD *)(Irp + 72)
       + *(_QWORD *)(Irp + 16)
       + *(_QWORD *)(Irp + 24);
}
"""
        )

        offset_ready = [
            item for item in offset_grace if item.get("kind") == "inferred_offset_rewrite_ready"
        ]
        access_ready = [
            item for item in access_grace if item.get("kind") == "inferred_offset_rewrite_ready"
        ]

        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in offset_grace))
        self.assertEqual(1, len(offset_ready))
        self.assertEqual("named_threshold_grace", offset_ready[0]["threshold_policy"])
        self.assertIn("Threshold policy named_threshold_grace", offset_ready[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in access_grace))
        self.assertEqual(1, len(access_ready))
        self.assertEqual("named_threshold_grace", access_ready[0]["threshold_policy"])

    def test_generic_layout_does_not_use_named_threshold_grace(self) -> None:
        layout = _LayoutEvidence(base="context", access_count=12)
        for offset in (16, 24, 32, 40, 48, 56):
            layout.offsets[offset] = {"_QWORD"}

        self.assertEqual("", _field_rewrite_threshold_policy(layout))
        self.assertEqual(
            ["rewrite offset threshold requires at least 8 offsets"],
            _field_rewrite_threshold_blockers(layout),
        )

    def test_strong_temp_base_is_marked_as_temporary_low_confidence_hint(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongTempLayout(__int64 v14)
{
  return *(_QWORD *)(v14 + 16)
       + *(_QWORD *)(v14 + 24)
       + *(_QWORD *)(v14 + 32)
       + *(_QWORD *)(v14 + 40)
       + *(_QWORD *)(v14 + 48)
       + *(_QWORD *)(v14 + 56)
       + *(_QWORD *)(v14 + 64)
       + *(_QWORD *)(v14 + 72)
       + *(_QWORD *)(v14 + 80)
       + *(_QWORD *)(v14 + 88)
       + *(_QWORD *)(v14 + 96)
       + *(_QWORD *)(v14 + 104);
}
"""
        )

        self.assertEqual(4, len(comments))
        self.assertEqual("temp", comments[0]["base_kind"])
        self.assertEqual(0.74, comments[0]["confidence"])
        self.assertIn("temporary base", comments[0]["text"])
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        self.assertEqual(1, len(previews))
        self.assertEqual("v14", previews[0]["base"])
        self.assertEqual("temp", previews[0]["base_kind"])
        self.assertEqual(0.7, previews[0]["confidence"])
        self.assertIn("Review fields for v14 (temporary base)", previews[0]["text"])
        self.assertIn("Review only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        self.assertEqual(1, len(aliases))
        self.assertEqual("v14", aliases[0]["base"])
        self.assertEqual("temp", aliases[0]["base_kind"])
        self.assertEqual(0.66, aliases[0]["confidence"])
        self.assertIn("Review aliases for v14 (temporary base)", aliases[0]["text"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertEqual("v14", blockers[0]["base"])
        self.assertEqual("temp", blockers[0]["base_kind"])
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_decompiler_argument_parameter_base_with_strong_layout_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall DirectArgumentLayout(__int64 a1)
{
  return *(_QWORD *)(a1 + 16)
       + *(_QWORD *)(a1 + 24)
       + *(_QWORD *)(a1 + 32)
       + *(_QWORD *)(a1 + 40)
       + *(_QWORD *)(a1 + 48)
       + *(_QWORD *)(a1 + 56)
       + *(_QWORD *)(a1 + 64)
       + *(_QWORD *)(a1 + 72)
       + *(_QWORD *)(a1 + 80)
       + *(_QWORD *)(a1 + 88)
       + *(_QWORD *)(a1 + 16)
       + *(_QWORD *)(a1 + 24)
       + *(_QWORD *)(a1 + 32)
       + *(_QWORD *)(a1 + 40)
       + *(_QWORD *)(a1 + 48)
       + *(_QWORD *)(a1 + 56);
}
"""
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("a1", ready[0]["base"])
        self.assertEqual("temp", ready[0]["base_kind"])
        self.assertEqual("a1", ready[0]["source"])
        self.assertEqual("argument", ready[0]["source_kind"])
        self.assertEqual("decompiler_parameter_trust", ready[0]["source_provenance"])
        self.assertEqual("parameter", ready[0]["source_rhs_kind"])
        self.assertEqual("standard", ready[0]["source_threshold_policy"])
        self.assertIn("Source provenance decompiler_parameter_trust from a1", ready[0]["text"])
        self.assertEqual(1, len(previews))
        self.assertEqual("decompiler_parameter_trust", previews[0]["source_provenance"])

    def test_decompiler_argument_parameter_trust_rejects_medium_evidence(self) -> None:
        lines = []
        offsets = list(range(16, 96, 8))
        for index, offset in enumerate(offsets + offsets[:3]):
            prefix = "  return " if index == 0 else "       + "
            lines.append("%s*(_QWORD *)(a1 + %d)" % (prefix, offset))
        comments = field_layout_comments(
            """
__int64 __fastcall MediumArgumentLayout(__int64 a1)
{
%s;
}
"""
            % "\n".join(lines)
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_decompiler_argument_parameter_trust_requires_signature_parameter(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall LocalArgumentLikeLayout(__int64 input)
{
  __int64 a1;

  a1 = input ^ 8;
  return *(_QWORD *)(a1 + 16)
       + *(_QWORD *)(a1 + 24)
       + *(_QWORD *)(a1 + 32)
       + *(_QWORD *)(a1 + 40)
       + *(_QWORD *)(a1 + 48)
       + *(_QWORD *)(a1 + 56)
       + *(_QWORD *)(a1 + 64)
       + *(_QWORD *)(a1 + 72)
       + *(_QWORD *)(a1 + 80)
       + *(_QWORD *)(a1 + 88)
       + *(_QWORD *)(a1 + 16)
       + *(_QWORD *)(a1 + 24)
       + *(_QWORD *)(a1 + 32)
       + *(_QWORD *)(a1 + 40)
       + *(_QWORD *)(a1 + 48)
       + *(_QWORD *)(a1 + 56);
}
"""
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_stable_argument_source_reports_source_hint(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableTempSourceLayout(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("temp", sources[0]["base_kind"])
        self.assertEqual("argument2", sources[0]["source"])
        self.assertEqual("argument", sources[0]["source_kind"])
        self.assertEqual("direct_argument_alias", sources[0]["source_provenance"])
        self.assertEqual("none", sources[0]["source_rhs_kind"])
        self.assertEqual(8, sources[0]["offset_count"])
        self.assertEqual(12, sources[0]["access_count"])
        self.assertIn(
            "Stable base source for v4: argument2 (argument source, direct_argument_alias)",
            sources[0]["text"],
        )
        self.assertIn("source identity evidence", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("v4", ready[0]["base"])
        self.assertEqual("temp", ready[0]["base_kind"])
        self.assertEqual("argument2", ready[0]["source"])
        self.assertEqual("argument", ready[0]["source_kind"])
        self.assertEqual("direct_argument_alias", ready[0]["source_provenance"])
        self.assertEqual("none", ready[0]["source_rhs_kind"])
        self.assertIn("Source provenance direct_argument_alias from argument2", ready[0]["text"])
        self.assertEqual(1, len(previews))
        self.assertEqual("v4", previews[0]["base"])
        self.assertEqual("direct_argument_alias", previews[0]["source_provenance"])
        self.assertEqual(12, previews[0]["access_count"])
        self.assertEqual(8, previews[0]["field_count"])
        self.assertIn("field_10", previews[0]["text"])
        self.assertIn("Preview artifact only", previews[0]["text"])

    def test_temp_base_with_back_container_parameter_source_reports_source_hint(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall BackContainerSourceLayout(__int64 completionApc)
{
  __int64 v6;

  v6 = completionApc - 120;
  return *(_QWORD *)(v6 + 16)
       + *(_QWORD *)(v6 + 24)
       + *(_QWORD *)(v6 + 32)
       + *(_QWORD *)(v6 + 40)
       + *(_QWORD *)(v6 + 48)
       + *(_QWORD *)(v6 + 56)
       + *(_QWORD *)(v6 + 64)
       + *(_QWORD *)(v6 + 72)
       + *(_QWORD *)(v6 + 16)
       + *(_QWORD *)(v6 + 24)
       + *(_QWORD *)(v6 + 32)
       + *(_QWORD *)(v6 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v6", sources[0]["base"])
        self.assertEqual("completionApc", sources[0]["source"])
        self.assertEqual("parameter", sources[0]["source_kind"])
        self.assertEqual("parameter_back_container_alias", sources[0]["source_provenance"])
        self.assertEqual("parameter_back_container", sources[0]["source_rhs_kind"])
        self.assertEqual("-0x78", sources[0]["source_offset"])
        self.assertEqual("0x78", sources[0]["source_container_offset"])
        self.assertIn("parameter_back_container_alias", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("completionApc", ready[0]["source"])
        self.assertEqual("parameter_back_container_alias", ready[0]["source_provenance"])
        self.assertEqual("parameter_back_container", ready[0]["source_rhs_kind"])
        self.assertEqual(1, len(previews))
        self.assertEqual("parameter_back_container_alias", previews[0]["source_provenance"])

    def test_back_container_alias_does_not_inherit_source_domain_identity(self) -> None:
        comments = field_layout_comments(
            """
void __fastcall IopCompleteRequest(__int64 completionApc, __int64 a2, _QWORD *a3, ULONG_PTR *a4, _QWORD *a5)
{
  __int64 v6;
  __int64 result;

  result = *(_QWORD *)(completionApc + 8);
  v6 = completionApc - 120;
  result += *(_QWORD *)(v6 + 16)
       + *(_QWORD *)(v6 + 24)
       + *(_QWORD *)(v6 + 32)
       + *(_QWORD *)(v6 + 40)
       + *(_QWORD *)(v6 + 48)
       + *(_QWORD *)(v6 + 56)
       + *(_QWORD *)(v6 + 64)
       + *(_QWORD *)(v6 + 72)
       + *(_QWORD *)(v6 + 16)
       + *(_QWORD *)(v6 + 24)
       + *(_QWORD *)(v6 + 32)
       + *(_QWORD *)(v6 + 40);
  IopProcessBufferedIoCompletion();
  KeInsertQueueApc();
}
""",
            profile_context={"arch": "x64", "build": "26200.8457", "image": "ntoskrnl.exe"},
        )
        identities = [
            item
            for item in comments
            if item.get("kind") == "domain_structure_identity" and item.get("base") == "v6"
        ]
        sources = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_stable_base_source" and item.get("base") == "v6"
        ]
        blockers = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_blockers" and item.get("base") == "v6"
        ]
        ready = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_ready" and item.get("base") == "v6"
        ]

        self.assertEqual([], identities)
        self.assertEqual(1, len(sources))
        self.assertEqual("completionApc", sources[0]["source"])
        self.assertEqual("parameter_back_container_alias", sources[0]["source_provenance"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_back_container_alias", ready[0]["source_provenance"])

    def test_temp_base_with_parameter_indirect_source_reports_source_hint(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall ParameterIndirectSourceLayout(__int64 *a1)
{
  __int64 v4;

  v4 = *a1;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("a1", sources[0]["source"])
        self.assertEqual("argument", sources[0]["source_kind"])
        self.assertEqual("parameter_indirect_pointer_alias", sources[0]["source_provenance"])
        self.assertEqual("parameter_pointer_deref", sources[0]["source_rhs_kind"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_indirect_pointer_alias", ready[0]["source_provenance"])
        self.assertEqual("parameter_pointer_deref", ready[0]["source_rhs_kind"])
        self.assertEqual(1, len(previews))
        self.assertEqual("parameter_indirect_pointer_alias", previews[0]["source_provenance"])

    def test_temp_base_with_cast_parameter_indirect_source_reports_source_type(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall CastParameterIndirectSourceLayout(void *P)
{
  __int64 v4;

  v4 = *(_QWORD *)P;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(sources))
        self.assertEqual("P", sources[0]["source"])
        self.assertEqual("parameter", sources[0]["source_kind"])
        self.assertEqual("parameter_indirect_pointer_alias", sources[0]["source_provenance"])
        self.assertEqual("_QWORD", sources[0]["source_type"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_indirect_pointer_alias", ready[0]["source_provenance"])

    def test_temp_base_with_parameter_indirect_source_rejects_local_pointer(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall LocalIndirectSourceLayout(__int64 input)
{
  __int64 *local;
  __int64 v4;

  local = (__int64 *)input;
  v4 = *local;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_stable_base_source" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_indexed_expression_source_reports_review_evidence(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall IndexedExpressionSourceLayout(__int64 input)
{
  _QWORD *holder;
  __int64 v4;

  holder = (_QWORD *)input;
  v4 = holder[3];
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        expression_sources = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_stable_expression_source"
        ]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(expression_sources))
        self.assertEqual("v4", expression_sources[0]["base"])
        self.assertEqual("holder[3]", expression_sources[0]["source"])
        self.assertEqual("indexed_pointer", expression_sources[0]["source_expression_kind"])
        self.assertEqual("holder", expression_sources[0]["source_parent"])
        self.assertEqual(3, expression_sources[0]["source_index"])
        self.assertEqual("temporary_only", expression_sources[0]["blocker_profile"])
        self.assertEqual("standard", expression_sources[0]["threshold_policy"])
        self.assertIn("rewrite remains blocked", expression_sources[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_field_expression_source_reports_review_evidence(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall FieldExpressionSourceLayout(__int64 input)
{
  __int64 node;
  __int64 v4;

  node = input;
  v4 = *(_QWORD *)(node + 24);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        expression_sources = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_stable_expression_source"
        ]

        self.assertEqual(1, len(expression_sources))
        self.assertEqual("*(_QWORD *)(node + 24)", expression_sources[0]["source"])
        self.assertEqual("field_pointer_deref", expression_sources[0]["source_expression_kind"])
        self.assertEqual("node", expression_sources[0]["source_parent"])
        self.assertEqual("0x18", expression_sources[0]["source_offset"])
        self.assertEqual("_QWORD", expression_sources[0]["source_type"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_expression_source_with_extra_blockers_stays_hidden(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UnalignedExpressionSourceLayout(__int64 input)
{
  _QWORD *holder;
  __int64 v4;

  holder = (_QWORD *)input;
  v4 = holder[3];
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 18)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 18)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertIn("one or more typed offsets are not naturally aligned", blockers[0]["blockers"])
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_stable_expression_source" for item in comments)
        )
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_named_call_result_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableNamedCallSourceLayout(__int64 source)
{
  __int64 list;
  __int64 v16;

  list = AllocateLayoutSource(source);
  v16 = list;
  return *(_QWORD *)(v16 + 16)
       + *(_QWORD *)(v16 + 24)
       + *(_QWORD *)(v16 + 32)
       + *(_QWORD *)(v16 + 40)
       + *(_QWORD *)(v16 + 48)
       + *(_QWORD *)(v16 + 56)
       + *(_QWORD *)(v16 + 64)
       + *(_QWORD *)(v16 + 72)
       + *(_QWORD *)(v16 + 16)
       + *(_QWORD *)(v16 + 24)
       + *(_QWORD *)(v16 + 32)
       + *(_QWORD *)(v16 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v16", sources[0]["base"])
        self.assertEqual("list", sources[0]["source"])
        self.assertEqual("named", sources[0]["source_kind"])
        self.assertEqual("named_call_result_alias", sources[0]["source_provenance"])
        self.assertEqual("call_result", sources[0]["source_rhs_kind"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("v16", ready[0]["base"])
        self.assertEqual("temp", ready[0]["base_kind"])
        self.assertEqual("list", ready[0]["source"])
        self.assertEqual("named", ready[0]["source_kind"])
        self.assertEqual("named_call_result_alias", ready[0]["source_provenance"])
        self.assertEqual("call_result", ready[0]["source_rhs_kind"])
        self.assertIn("Source provenance named_call_result_alias from list", ready[0]["text"])
        self.assertEqual(1, len(previews))
        self.assertEqual("v16", previews[0]["base"])
        self.assertEqual("named_call_result_alias", previews[0]["source_provenance"])
        self.assertEqual(12, previews[0]["access_count"])
        self.assertEqual(8, previews[0]["field_count"])
        self.assertIn("Source provenance named_call_result_alias from list", previews[0]["text"])

    def test_temp_base_with_parameter_field_pointer_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableFieldPointerSourceLayout(__int64 context)
{
  __int64 v4;

  v4 = *(_QWORD *)(context + 8);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("context", sources[0]["source"])
        self.assertEqual("generic", sources[0]["source_kind"])
        self.assertEqual("parameter_field_pointer_alias", sources[0]["source_provenance"])
        self.assertEqual("field_pointer", sources[0]["source_rhs_kind"])
        self.assertEqual("0x8", sources[0]["source_offset"])
        self.assertEqual("_QWORD", sources[0]["source_type"])
        self.assertIn("parameter_field_pointer_alias", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_field_pointer_alias", ready[0]["source_provenance"])
        self.assertEqual("context", ready[0]["source"])
        self.assertEqual(1, len(previews))
        self.assertEqual("parameter_field_pointer_alias", previews[0]["source_provenance"])

    def test_temp_base_with_named_parameter_direct_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableNamedParameterSourceLayout(ULONG_PTR inputLength)
{
  __int64 v4;

  v4 = inputLength;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("inputLength", sources[0]["source"])
        self.assertEqual("parameter", sources[0]["source_kind"])
        self.assertEqual("parameter_direct_alias", sources[0]["source_provenance"])
        self.assertEqual("direct_parameter", sources[0]["source_rhs_kind"])
        self.assertIn("parameter_direct_alias", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("inputLength", ready[0]["source"])
        self.assertEqual("parameter", ready[0]["source_kind"])
        self.assertEqual("parameter_direct_alias", ready[0]["source_provenance"])
        self.assertEqual("direct_parameter", ready[0]["source_rhs_kind"])
        self.assertIn("Source provenance parameter_direct_alias from inputLength", ready[0]["text"])
        self.assertEqual(1, len(previews))
        self.assertEqual("parameter_direct_alias", previews[0]["source_provenance"])

    def test_temp_base_with_named_parameter_direct_alias_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableNamedParameterDirectAliasLayout(__int64 context)
{
  __int64 holder;
  __int64 v4;

  holder = context;
  v4 = holder;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("context", sources[0]["source"])
        self.assertEqual("holder", sources[0]["source_alias"])
        self.assertEqual("parameter", sources[0]["source_kind"])
        self.assertEqual("named_parameter_direct_alias", sources[0]["source_provenance"])
        self.assertEqual("direct_parameter_alias", sources[0]["source_rhs_kind"])
        self.assertIn("named_parameter_direct_alias", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("context", ready[0]["source"])
        self.assertEqual("holder", ready[0]["source_alias"])
        self.assertEqual("named_parameter_direct_alias", ready[0]["source_provenance"])
        self.assertEqual("direct_parameter_alias", ready[0]["source_rhs_kind"])
        self.assertEqual(1, len(previews))
        self.assertEqual("named_parameter_direct_alias", previews[0]["source_provenance"])

    def test_temp_base_with_temporary_parameter_direct_alias_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableTemporaryParameterDirectAliasLayout(__int64 context)
{
  __int64 v214;
  __int64 v4;

  v214 = context;
  v4 = v214;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("context", sources[0]["source"])
        self.assertEqual("v214", sources[0]["source_alias"])
        self.assertEqual("parameter", sources[0]["source_kind"])
        self.assertEqual("temporary_parameter_direct_alias", sources[0]["source_provenance"])
        self.assertEqual("direct_parameter_alias", sources[0]["source_rhs_kind"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("context", ready[0]["source"])
        self.assertEqual("v214", ready[0]["source_alias"])
        self.assertEqual("temporary_parameter_direct_alias", ready[0]["source_provenance"])
        self.assertEqual("direct_parameter_alias", ready[0]["source_rhs_kind"])
        self.assertEqual(1, len(previews))
        self.assertEqual("temporary_parameter_direct_alias", previews[0]["source_provenance"])

    def test_temp_hot_cluster_inherits_domain_identity_from_temporary_parameter_alias(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SepCommonAccessCheckEx(
        __int64 subjectContext,
        char subjectContextLocked,
        __int64 accessState,
        __int64 accessCheckOutputs,
        __int64 argument4,
        char accessMode,
        int accessCheckFlags)
{
  __int64 v214;
  __int64 v29;
  __int64 result;

  v214 = accessState;
  result = *(_DWORD *)(accessState + 16) + *(_QWORD *)(accessState + 8);
  v29 = v214;
  result += *(_DWORD *)(v29 + 16);
  result += *(_DWORD *)(v29 + 16);
  result += *(_DWORD *)(v29 + 16);
  result += *(_DWORD *)(v29 + 16);
  result += *(_BYTE *)(v29 + 16);
  result += *(_BYTE *)(v29 + 16);
  result += *(_BYTE *)(v29 + 16);
  result += *(_BYTE *)(v29 + 16);
  result += *(_QWORD *)(v29 + 8);
  result += *(_QWORD *)(v29 + 8);
  result += *(_QWORD *)(v29 + 8);
  result += *(_QWORD *)(v29 + 8);
  result += *(_QWORD *)(v29 + 8);
  result += *(_QWORD *)(v29 + 8);
  result += *(_DWORD *)(v29 + 20);
  result += *(_BYTE *)(v29 + 20);
  result += *(_DWORD *)(v29 + 32);
  SepAccessCheckEx();
  SeUnlockSubjectContext(subjectContext);
  return result;
}
""",
            profile_context={"arch": "x64", "build": "26200.8457", "image": "ntoskrnl.exe"},
        )
        identities = [
            item
            for item in comments
            if item.get("kind") == "domain_structure_identity" and item.get("base") == "v29"
        ]
        aliases = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_field_aliases" and item.get("base") == "v29"
        ]
        blockers = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_blockers" and item.get("base") == "v29"
        ]
        sources = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_stable_base_source" and item.get("base") == "v29"
        ]
        hot_clusters = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_field_hot_cluster" and item.get("base") == "v29"
        ]

        self.assertEqual(1, len(identities))
        self.assertEqual("SEP_ACCESS_STATE", identities[0]["structure"])
        self.assertIn("via stable source accessState through v214", identities[0]["text"])
        self.assertEqual(1, len(aliases))
        alias_names = {item["name"] for item in aliases[0]["fields"]}
        self.assertIn("objectTypeInfo", alias_names)
        self.assertIn("desiredAccess", alias_names)
        self.assertIn("previouslyGrantedAccess", alias_names)
        self.assertIn("genericMapping", alias_names)
        self.assertEqual(1, len(blockers))
        self.assertIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertEqual(1, len(sources))
        self.assertEqual("accessState", sources[0]["source"])
        self.assertEqual("v214", sources[0]["source_alias"])
        self.assertEqual("temporary_parameter_direct_alias", sources[0]["source_provenance"])
        self.assertEqual([], hot_clusters)

    def test_temp_base_with_non_parameter_local_direct_alias_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UntrustedLocalDirectAliasLayout(__int64 context)
{
  __int64 root;
  __int64 holder;
  __int64 v4;

  root = *(_QWORD *)(context + 8);
  holder = root;
  v4 = holder;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(sources))
        self.assertEqual("named_direct_alias", sources[0]["source_provenance"])
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_reassigned_named_parameter_alias_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall ReassignedNamedParameterDirectAliasLayout(__int64 context)
{
  __int64 holder;
  __int64 v4;

  holder = context;
  v4 = holder;
  holder = context + 8;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(sources))
        self.assertEqual("named_multi_assignment_alias", sources[0]["source_provenance"])
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_reassigned_parameter_direct_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall ReassignedParameterDirectAliasLayout(__int64 context)
{
  __int64 v4;

  context = context + 8;
  v4 = context;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_bugcheck_parameter_direct_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall BugCheckParameterDirectAliasLayout(__int64 BugCheckParameter2)
{
  __int64 v4;

  v4 = BugCheckParameter2;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_untrusted_field_pointer_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UntrustedFieldPointerSourceLayout(__int64 context)
{
  __int64 holder;
  __int64 v4;

  holder = *(_QWORD *)(context + 8);
  v4 = *(_QWORD *)(holder + 8);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_direct_call_result_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableDirectCallResultSourceLayout(__int64 context)
{
  __int64 v4;

  v4 = GetStableContext(context);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("GetStableContext(context)", sources[0]["source"])
        self.assertEqual("call_result", sources[0]["source_kind"])
        self.assertEqual("direct_call_result_alias", sources[0]["source_provenance"])
        self.assertEqual("call_result", sources[0]["source_rhs_kind"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("direct_call_result_alias", ready[0]["source_provenance"])

    def test_temp_base_with_indirect_dispatch_call_result_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall IndirectDispatchCallResultSourceLayout(__int64 context)
{
  __int64 v4;

  v4 = guard_dispatch_icall_no_overrides(context);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])

    def test_temp_base_with_named_branch_call_result_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableNamedBranchCallResultSourceLayout(__int64 hive, int usePaged)
{
  __int64 cell;
  __int64 v12;

  if ( usePaged )
  {
    cell = HvpGetCellPaged(hive, 16, 0LL);
  }
  else
  {
    cell = HvpGetCellFlat(hive, 16, 0LL);
  }
  v12 = cell;
  return *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40)
       + *(_QWORD *)(v12 + 48)
       + *(_QWORD *)(v12 + 56)
       + *(_QWORD *)(v12 + 64)
       + *(_QWORD *)(v12 + 72)
       + *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v12", sources[0]["base"])
        self.assertEqual("cell", sources[0]["source"])
        self.assertEqual("named", sources[0]["source_kind"])
        self.assertEqual("named_branch_call_result_alias", sources[0]["source_provenance"])
        self.assertEqual("call_result", sources[0]["source_rhs_kind"])
        self.assertEqual(
            ["HvpGetCellPaged(hive, 16, 0LL)", "HvpGetCellFlat(hive, 16, 0LL)"],
            sources[0]["source_calls"],
        )
        self.assertEqual(["HvpGetCellPaged", "HvpGetCellFlat"], sources[0]["source_call_names"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("cell", ready[0]["source"])
        self.assertEqual("named_branch_call_result_alias", ready[0]["source_provenance"])
        self.assertEqual(1, len(previews))
        self.assertEqual("named_branch_call_result_alias", previews[0]["source_provenance"])

    def test_temp_base_with_guarded_named_branch_call_result_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall GuardedNamedBranchCallResultSourceLayout(__int64 hive, int usePaged)
{
  __int64 cell;
  __int64 v12;

  if ( usePaged )
  {
    cell = guard_dispatch_icall_no_overrides(hive, 16, 0LL);
  }
  else
  {
    cell = HvpGetCellFlat(hive, 16, 0LL);
  }
  v12 = cell;
  return *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40)
       + *(_QWORD *)(v12 + 48)
       + *(_QWORD *)(v12 + 56)
       + *(_QWORD *)(v12 + 64)
       + *(_QWORD *)(v12 + 72)
       + *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(sources))
        self.assertEqual("named_multi_assignment_alias", sources[0]["source_provenance"])
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_post_alias_named_branch_source_assignment_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall PostAliasNamedBranchCallResultSourceLayout(__int64 hive)
{
  __int64 cell;
  __int64 v12;

  cell = HvpGetCellFlat(hive, 16, 0LL);
  v12 = cell;
  cell = HvpGetCellPaged(hive, 24, 0LL);
  return *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40)
       + *(_QWORD *)(v12 + 48)
       + *(_QWORD *)(v12 + 56)
       + *(_QWORD *)(v12 + 64)
       + *(_QWORD *)(v12 + 72)
       + *(_QWORD *)(v12 + 16)
       + *(_QWORD *)(v12 + 24)
       + *(_QWORD *)(v12 + 32)
       + *(_QWORD *)(v12 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(sources))
        self.assertEqual("named_multi_assignment_alias", sources[0]["source_provenance"])
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_temporary_call_result_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableTemporaryCallResultSourceLayout(__int64 context)
{
  __int64 v3;
  __int64 v4;

  v3 = CreateStableContext(context);
  v4 = v3;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("v3", sources[0]["source"])
        self.assertEqual("temporary", sources[0]["source_kind"])
        self.assertEqual("temporary_call_result_alias", sources[0]["source_provenance"])
        self.assertEqual("call_result", sources[0]["source_rhs_kind"])
        self.assertEqual("CreateStableContext(context)", sources[0]["source_call"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("v3", ready[0]["source"])
        self.assertEqual("temporary_call_result_alias", ready[0]["source_provenance"])
        self.assertEqual("CreateStableContext(context)", ready[0]["source_call"])
        self.assertEqual(1, len(previews))
        self.assertEqual("temporary_call_result_alias", previews[0]["source_provenance"])

    def test_temp_base_with_multi_assignment_temporary_call_result_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MultiAssignmentTemporaryCallResultSourceLayout(__int64 context)
{
  __int64 v3;
  __int64 v4;

  v3 = 0LL;
  v3 = CreateStableContext(context);
  v4 = v3;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_indirect_temporary_call_result_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall IndirectTemporaryCallResultSourceLayout(__int64 context)
{
  __int64 v3;
  __int64 v4;

  v3 = guard_dispatch_icall_no_overrides(context);
  v4 = v3;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_local_out_parameter_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableOutParameterSourceLayout(__int64 context)
{
  int status;
  __int64 v4;
  __int64 v8;

  v8 = 0LL;
  status = CreateLayout(context, &v8);
  if ( status < 0 )
    return status;
  v4 = v8;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("v8", sources[0]["source"])
        self.assertEqual("out_parameter", sources[0]["source_kind"])
        self.assertEqual("local_out_parameter_alias", sources[0]["source_provenance"])
        self.assertEqual("out_parameter_call", sources[0]["source_rhs_kind"])
        self.assertEqual("CreateLayout", sources[0]["source_call"])
        self.assertIn("local_out_parameter_alias", sources[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("v8", ready[0]["source"])
        self.assertEqual("out_parameter", ready[0]["source_kind"])
        self.assertEqual("local_out_parameter_alias", ready[0]["source_provenance"])
        self.assertEqual("out_parameter_call", ready[0]["source_rhs_kind"])
        self.assertEqual("CreateLayout", ready[0]["source_call"])
        self.assertEqual(1, len(previews))
        self.assertEqual("local_out_parameter_alias", previews[0]["source_provenance"])

    def test_temp_base_with_out_parameter_call_after_alias_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall LateOutParameterSourceLayout(__int64 context)
{
  __int64 v4;
  __int64 v8;

  v8 = 0LL;
  v4 = v8;
  CreateLayout(context, &v8);
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_multiple_out_parameter_calls_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall AmbiguousOutParameterSourceLayout(__int64 context)
{
  __int64 v4;
  __int64 v8;

  v8 = 0LL;
  ProbeLayout(context, &v8);
  CreateLayout(context, &v8);
  v4 = v8;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_temp_base_with_parameter_subobject_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableParameterSubobjectSourceLayout(__int64 context)
{
  __int64 v4;

  v4 = context + 680;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("context", sources[0]["source"])
        self.assertEqual("generic", sources[0]["source_kind"])
        self.assertEqual("parameter_subobject_pointer_alias", sources[0]["source_provenance"])
        self.assertEqual("parameter_pointer_arithmetic", sources[0]["source_rhs_kind"])
        self.assertEqual("0x2A8", sources[0]["source_offset"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_subobject_pointer_alias", ready[0]["source_provenance"])

    def test_temp_base_with_parameter_indexed_source_is_audit_ready(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableParameterIndexedSourceLayout(_QWORD *argument0)
{
  __int64 v4;

  v4 = argument0[2200];
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(sources))
        self.assertEqual("v4", sources[0]["base"])
        self.assertEqual("argument0", sources[0]["source"])
        self.assertEqual("argument", sources[0]["source_kind"])
        self.assertEqual("parameter_indexed_pointer_alias", sources[0]["source_provenance"])
        self.assertEqual("parameter_indexed_pointer", sources[0]["source_rhs_kind"])
        self.assertEqual(2200, sources[0]["source_index"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("parameter_indexed_pointer_alias", ready[0]["source_provenance"])

    def test_temp_base_with_local_subobject_source_remains_blocked(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UntrustedSubobjectSourceLayout(__int64 context)
{
  __int64 holder;
  __int64 v4;

  holder = context + 680;
  v4 = holder + 24;
  return *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40)
       + *(_QWORD *)(v4 + 48)
       + *(_QWORD *)(v4 + 56)
       + *(_QWORD *)(v4 + 64)
       + *(_QWORD *)(v4 + 72)
       + *(_QWORD *)(v4 + 16)
       + *(_QWORD *)(v4 + 24)
       + *(_QWORD *)(v4 + 32)
       + *(_QWORD *)(v4 + 40);
}
"""
        )
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual([], sources)
        self.assertEqual(1, len(blockers))
        self.assertIn("base is a decompiler temporary", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_generic_argument_and_bugcheck_parameter_bases_are_skipped(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall GenericArgumentLayout(__int64 argument0, __int64 BugCheckParameter2)
{
  if ( *(_DWORD *)(argument0 + 48) )
    return *(_QWORD *)(argument0 + 72) + *(_DWORD *)(argument0 + 48);
  return *(_DWORD *)(BugCheckParameter2 + 56)
       + *(_QWORD *)(BugCheckParameter2 + 64)
       + *(_DWORD *)(BugCheckParameter2 + 144)
       + *(_DWORD *)(BugCheckParameter2 + 148)
       + *(_DWORD *)(BugCheckParameter2 + 152)
       + *(_QWORD *)(BugCheckParameter2 + 160)
       + *(_QWORD *)(BugCheckParameter2 + 232)
       + *(_DWORD *)(BugCheckParameter2 + 280);
}
"""
        )

        self.assertEqual([], comments)

    def test_hot_context_field_cluster_emits_review_only_pressure_evidence(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall HotContextLayout(__int64 context)
{
  return *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 32)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 40)
       + *(_DWORD *)(context + 34)
       + *(_DWORD *)(context + 34)
       + *(_DWORD *)(context + 34)
       + *(_QWORD *)(context + 8)
       + *(_DWORD *)(context + 35);
}
"""
        )
        hot_clusters = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_field_hot_cluster"
        ]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(hot_clusters))
        self.assertEqual([], previews)
        self.assertEqual([], blockers)
        self.assertEqual("context", hot_clusters[0]["base"])
        self.assertEqual("generic", hot_clusters[0]["base_kind"])
        self.assertEqual(27, hot_clusters[0]["access_count"])
        self.assertEqual(6, hot_clusters[0]["offset_count"])
        self.assertEqual("field_20", hot_clusters[0]["fields"][0]["name"])
        self.assertEqual(10, hot_clusters[0]["fields"][0]["access_count"])
        self.assertIn("Hot field cluster for context (generic base)", hot_clusters[0]["text"])
        self.assertIn("Review-only access-pressure evidence", hot_clusters[0]["text"])

    def test_hot_argument_identity_field_cluster_stays_review_only(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall HotArgumentLayout(__int64 argument3)
{
  return *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 16)
       + *(_DWORD **)(argument3 + 8)
       + *(_DWORD **)(argument3 + 8)
       + *(_DWORD **)(argument3 + 8)
       + *(_DWORD **)(argument3 + 8)
       + *(_QWORD *)(argument3 + 24)
       + *(_QWORD *)(argument3 + 24)
       + *(_QWORD *)(argument3 + 24)
       + *(_QWORD **)(argument3 + 32)
       + *(_QWORD **)(argument3 + 32)
       + *(_DWORD *)(argument3 + 4);
}
"""
        )
        hot_clusters = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_field_hot_cluster"
        ]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(hot_clusters))
        self.assertEqual([], ready)
        self.assertEqual("argument3", hot_clusters[0]["base"])
        self.assertEqual("argument", hot_clusters[0]["base_kind"])
        self.assertEqual(5, hot_clusters[0]["offset_count"])
        self.assertIn("argument identity base", hot_clusters[0]["text"])
        self.assertIn("no structure type or body rewrite was inferred", hot_clusters[0]["text"])

    def test_strong_argument_identity_base_emits_review_only_layout(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongArgumentLayout(__int64 argument0)
{
  return *(_QWORD *)(argument0 + 16)
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
}
"""
        )
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(previews))
        self.assertEqual("argument0", previews[0]["base"])
        self.assertEqual("argument", previews[0]["base_kind"])
        self.assertEqual(0.72, previews[0]["confidence"])
        self.assertIn("argument identity base", previews[0]["text"])
        self.assertEqual(1, len(aliases))
        self.assertEqual("argument", aliases[0]["base_kind"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertEqual("argument", blockers[0]["base_kind"])
        self.assertIn("base name is unresolved argument identity", blockers[0]["blockers"])
        self.assertEqual([], ready)

    def test_strong_bugcheck_parameter_base_emits_review_only_layout(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongBugcheckLayout(__int64 BugCheckParameter2)
{
  return *(_QWORD *)(BugCheckParameter2 + 16)
       + *(_QWORD *)(BugCheckParameter2 + 24)
       + *(_QWORD *)(BugCheckParameter2 + 32)
       + *(_QWORD *)(BugCheckParameter2 + 40)
       + *(_QWORD *)(BugCheckParameter2 + 48)
       + *(_QWORD *)(BugCheckParameter2 + 56)
       + *(_QWORD *)(BugCheckParameter2 + 64)
       + *(_QWORD *)(BugCheckParameter2 + 72)
       + *(_QWORD *)(BugCheckParameter2 + 16)
       + *(_QWORD *)(BugCheckParameter2 + 24)
       + *(_QWORD *)(BugCheckParameter2 + 32)
       + *(_QWORD *)(BugCheckParameter2 + 40);
}
"""
        )
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]
        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(previews))
        self.assertEqual("BugCheckParameter2", previews[0]["base"])
        self.assertEqual("bugcheck", previews[0]["base_kind"])
        self.assertEqual(0.70, previews[0]["confidence"])
        self.assertIn("bugcheck parameter base", previews[0]["text"])
        self.assertEqual(1, len(aliases))
        self.assertEqual("bugcheck", aliases[0]["base_kind"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        self.assertEqual(1, len(blockers))
        self.assertEqual("bugcheck", blockers[0]["base_kind"])
        self.assertIn("base name is unresolved bugcheck parameter identity", blockers[0]["blockers"])
        self.assertEqual([], ready)

    def test_full_layout_evidence_does_not_emit_hot_cluster(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongContextLayout(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40);
}
"""
        )
        hot_clusters = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_field_hot_cluster"
        ]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_field_preview"]

        self.assertEqual([], hot_clusters)
        self.assertEqual(1, len(previews))

    def test_generic_named_context_uses_grace_only_for_strong_layout_evidence(self) -> None:
        weak_comments = field_layout_comments(
            """
__int64 __fastcall WeakContextLayout(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_WORD *)(context + 56)
       + *(_BYTE *)(context + 64)
       + *(_BYTE *)(context + 66)
       + *(_BYTE *)(context + 69)
       + *(_QWORD *)(context + 72);
}
"""
        )
        strong_comments = field_layout_comments(
            """
__int64 __fastcall StrongContextLayout(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88)
       + *(_QWORD *)(context + 104)
       + *(_QWORD *)(context + 112)
       + *(_QWORD *)(context + 120)
       + *(_QWORD *)(context + 128)
       + *(_QWORD *)(context + 136);
}
"""
        )

        self.assertEqual([], weak_comments)
        self.assertEqual(6, len(strong_comments))
        self.assertEqual("generic", strong_comments[0]["base_kind"])
        self.assertEqual(0.78, strong_comments[0]["confidence"])
        self.assertIn("generic base", strong_comments[0]["text"])
        self.assertIn("context", strong_comments[0]["text"])
        previews = [item for item in strong_comments if item.get("kind") == "inferred_offset_field_preview"]
        self.assertEqual(1, len(previews))
        self.assertEqual("context", previews[0]["base"])
        self.assertEqual("generic", previews[0]["base_kind"])
        self.assertEqual(0.74, previews[0]["confidence"])
        self.assertIn("Review fields for context (generic base)", previews[0]["text"])
        self.assertIn("Review only; no IDB type or pseudocode rewrite was applied", previews[0]["text"])
        aliases = [item for item in strong_comments if item.get("kind") == "inferred_offset_field_aliases"]
        self.assertEqual(1, len(aliases))
        self.assertEqual("context", aliases[0]["base"])
        self.assertEqual("generic", aliases[0]["base_kind"])
        self.assertEqual(0.7, aliases[0]["confidence"])
        self.assertIn("Review aliases for context (generic base)", aliases[0]["text"])
        self.assertIn("do not treat as a recovered structure type", aliases[0]["text"])
        candidates = [
            item
            for item in strong_comments
            if item.get("kind") == "inferred_offset_generic_base_trust_candidate"
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual("context", candidates[0]["base"])
        self.assertEqual("generic", candidates[0]["base_kind"])
        self.assertEqual("generic_only", candidates[0]["blocker_profile"])
        self.assertEqual("generic_parameter_offset_grace", candidates[0]["threshold_policy"])
        self.assertEqual(12, candidates[0]["offset_count"])
        self.assertEqual(12, candidates[0]["access_count"])
        blockers = [item for item in strong_comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual([], blockers)
        ready = [item for item in strong_comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        self.assertEqual(1, len(ready))
        self.assertEqual("generic_parameter_trust", ready[0]["source_provenance"])
        self.assertEqual("generic_parameter_offset_grace", ready[0]["source_threshold_policy"])

    def test_generic_parameter_base_with_generic_only_blocker_emits_trust_candidate(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongParameterContext(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88);
}
"""
        )

        candidates = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_generic_base_trust_candidate"
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual("context", candidates[0]["base"])
        self.assertEqual("generic", candidates[0]["base_kind"])
        self.assertEqual("parameter", candidates[0]["source_kind"])
        self.assertEqual("generic_only", candidates[0]["blocker_profile"])
        self.assertEqual(10, candidates[0]["offset_count"])
        self.assertEqual(20, candidates[0]["access_count"])
        self.assertEqual(0.76, candidates[0]["confidence"])
        self.assertIn("Generic base trust candidate for context", candidates[0]["text"])
        self.assertIn("parameter source", candidates[0]["text"])
        self.assertIn("explicit validation-gated export", candidates[0]["text"])
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual([], blockers)
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]
        self.assertEqual(1, len(ready))
        self.assertEqual("generic_parameter_trust", ready[0]["source_provenance"])
        self.assertEqual("context", ready[0]["source"])
        self.assertEqual("standard", ready[0]["source_threshold_policy"])
        self.assertEqual(1, len(previews))
        self.assertEqual("generic_parameter_trust", previews[0]["source_provenance"])
        self.assertIn("Source provenance generic_parameter_trust from context", previews[0]["text"])

    def test_generic_parameter_trust_uses_offset_grace_for_many_offsets(self) -> None:
        accesses = []
        for index, offset in enumerate(range(16, 112, 8)):
            prefix = "  return " if index == 0 else "       + "
            accesses.append("%s*(_QWORD *)(context + %d)" % (prefix, offset))
        comments = field_layout_comments(
            """
__int64 __fastcall OffsetGraceParameterContext(__int64 context)
{
%s;
}
"""
            % "\n".join(accesses)
        )

        candidates = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_generic_base_trust_candidate"
        ]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(candidates))
        self.assertEqual("generic_parameter_offset_grace", candidates[0]["threshold_policy"])
        self.assertEqual(12, candidates[0]["offset_count"])
        self.assertEqual(12, candidates[0]["access_count"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("generic_parameter_trust", ready[0]["source_provenance"])
        self.assertEqual("generic_parameter_offset_grace", ready[0]["source_threshold_policy"])

    def test_generic_parameter_trust_uses_access_grace_for_hot_base(self) -> None:
        lines = []
        for repeat_index in range(3):
            for offset_index, offset in enumerate(range(16, 80, 8)):
                prefix = "  return " if repeat_index == 0 and offset_index == 0 else "       + "
                lines.append("%s*(_QWORD *)(context + %d)" % (prefix, offset))
        comments = field_layout_comments(
            """
__int64 __fastcall AccessGraceParameterContext(__int64 context)
{
%s;
}
"""
            % "\n".join(lines)
        )

        candidates = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_generic_base_trust_candidate"
        ]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(candidates))
        self.assertEqual("generic_parameter_access_grace", candidates[0]["threshold_policy"])
        self.assertEqual(8, candidates[0]["offset_count"])
        self.assertEqual(24, candidates[0]["access_count"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("generic_parameter_access_grace", ready[0]["source_threshold_policy"])

    def test_generic_parameter_trust_grace_rejects_medium_evidence(self) -> None:
        lines = []
        offsets = list(range(16, 96, 8))
        for index, offset in enumerate(offsets + offsets[:3]):
            prefix = "  return " if index == 0 else "       + "
            lines.append("%s*(_QWORD *)(context + %d)" % (prefix, offset))
        comments = field_layout_comments(
            """
__int64 __fastcall MediumEvidenceGenericContext(__int64 context)
{
%s;
}
"""
            % "\n".join(lines)
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertIn("base name is generic", blockers[0]["blockers"])
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_generic_base_trust_candidate" for item in comments)
        )
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_generic_base_evidence_profiles_other_blockers(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MixedGenericContext(__int64 context)
{
  return *(_DWORD *)(context + 16)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88)
       + *(_QWORD *)(context + 96);
}
"""
        )

        generic_evidence = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_generic_base_evidence"
        ]
        self.assertEqual(1, len(generic_evidence))
        self.assertEqual("generic_with_other_blockers", generic_evidence[0]["blocker_profile"])
        self.assertEqual(0.7, generic_evidence[0]["confidence"])
        self.assertIn("generic_with_other_blockers", generic_evidence[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_generic_base_trust_candidate" for item in comments))
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        self.assertEqual(1, len(blockers))
        self.assertIn("base name is generic", blockers[0]["blockers"])
        self.assertIn("one or more offsets mix wide overlay access widths", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_generic_parameter_type_blocker_reports_partial_rewrite_opportunity(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall PartialGenericContext(__int64 context)
{
  return *(_DWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40)
       + *(_QWORD *)(context + 0x48)
       + *(_QWORD *)(context + 0x50)
       + *(_QWORD *)(context + 0x58)
       + *(_QWORD *)(context + 0x60)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        partial = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_partial_opportunity"
        ]

        self.assertEqual(1, len(blockers))
        self.assertIn("base name is generic", blockers[0]["blockers"])
        self.assertIn("one or more offsets mix wide overlay access widths", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_preview" for item in comments))
        self.assertEqual(1, len(partial))
        self.assertEqual("context", partial[0]["base"])
        self.assertEqual("generic", partial[0]["base_kind"])
        self.assertEqual("generic_parameter_trust", partial[0]["source_provenance"])
        self.assertEqual("context", partial[0]["source"])
        self.assertEqual(9, partial[0]["safe_offset_count"])
        self.assertEqual(14, partial[0]["safe_access_count"])
        self.assertEqual(1, partial[0]["excluded_offset_count"])
        self.assertEqual(2, partial[0]["excluded_access_count"])
        self.assertEqual([0x10], partial[0]["excluded_offsets"])
        self.assertIn("Source provenance generic_parameter_trust from context", partial[0]["text"])

    def test_generic_parameter_partial_rewrite_uses_offset_grace_when_accesses_are_strong(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall PartialGenericContextOffsetGrace(__int64 context)
{
  return *(_DWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x12)
       + *(_QWORD *)(context + 0x14)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40)
       + *(_QWORD *)(context + 0x48)
       + *(_QWORD *)(context + 0x50)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40);
}
"""
        )
        partial = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_partial_opportunity"
        ]

        self.assertEqual(1, len(partial))
        self.assertEqual("context", partial[0]["base"])
        self.assertEqual("generic_parameter_trust", partial[0]["source_provenance"])
        self.assertEqual("partial_offset_grace", partial[0]["threshold_policy"])
        self.assertEqual(7, partial[0]["safe_offset_count"])
        self.assertEqual(12, partial[0]["safe_access_count"])
        self.assertEqual(3, partial[0]["excluded_offset_count"])
        self.assertEqual(4, partial[0]["excluded_access_count"])
        self.assertEqual([0x10, 0x12, 0x14], partial[0]["excluded_offsets"])

    def test_generic_parameter_partial_rewrite_offset_grace_still_requires_access_strength(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall PartialGenericContextWeakOffsetGrace(__int64 context)
{
  return *(_DWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x12)
       + *(_QWORD *)(context + 0x14)
       + *(_QWORD *)(context + 0x16)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40)
       + *(_QWORD *)(context + 0x48)
       + *(_QWORD *)(context + 0x50)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_rewrite_partial_opportunity" for item in comments)
        )

    def test_untrusted_generic_expression_source_does_not_report_partial_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UntrustedGenericContext(__int64 a1)
{
  __int64 context;

  context = *(_QWORD *)(a1 + 8);
  return *(_DWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40)
       + *(_QWORD *)(context + 0x48)
       + *(_QWORD *)(context + 0x50)
       + *(_QWORD *)(context + 0x58)
       + *(_QWORD *)(context + 0x60)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x30)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_rewrite_partial_opportunity" for item in comments)
        )

    def test_named_layout_without_negative_evidence_has_no_rewrite_blocker(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StrongNamedLayout(__int64 sessionSpace)
{
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_field_aliases" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]
        self.assertEqual(1, len(ready))
        self.assertEqual("sessionSpace", ready[0]["base"])
        self.assertEqual("named", ready[0]["base_kind"])
        self.assertEqual(8, ready[0]["offset_count"])
        self.assertEqual(12, ready[0]["access_count"])
        self.assertIn("no rewrite blockers found", ready[0]["text"])
        self.assertIn("Audit only; body rewrite was not applied", ready[0]["text"])
        self.assertEqual(1, len(previews))
        self.assertEqual("sessionSpace", previews[0]["base"])
        self.assertEqual("none", previews[0]["source_provenance"])
        self.assertEqual(12, previews[0]["access_count"])
        self.assertEqual(8, previews[0]["field_count"])
        self.assertIn("field_10", previews[0]["text"])

    def test_stable_one_time_base_alias_assignment_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableAliasLayout(__int64 a1)
{
  __int64 sessionSpace;

  sessionSpace = a1;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertTrue(any(item.get("kind") == "inferred_offset_field_aliases" for item in comments))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_terminal_base_reassignment_after_layout_access_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall TerminalBaseReassignmentLayout(__int64 sessionSpace, __int64 nextSessionSpace)
{
  __int64 result;

  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
  sessionSpace = nextSessionSpace;
  return result;
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("sessionSpace", ready[0]["base"])
        self.assertEqual(8, ready[0]["offset_count"])
        self.assertEqual(12, ready[0]["access_count"])

    def test_named_layout_rewrite_blocker_reports_mixed_type_and_base_mutation(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MutatedNamedLayout(__int64 sessionSpace, __int64 nextSessionSpace)
{
  result = *(_DWORD *)(sessionSpace + 16);
  result += *(_QWORD *)(sessionSpace + 16);
  result += *(_QWORD *)(sessionSpace + 24);
  result += *(_QWORD *)(sessionSpace + 32);
  result += *(_QWORD *)(sessionSpace + 40);
  result += *(_QWORD *)(sessionSpace + 48);
  result += *(_QWORD *)(sessionSpace + 56);
  result += *(_QWORD *)(sessionSpace + 64);
  result += *(_QWORD *)(sessionSpace + 72);
  result += *(_QWORD *)(sessionSpace + 80);
  result += *(_QWORD *)(sessionSpace + 88);
  result += *(_QWORD *)(sessionSpace + 96);
  sessionSpace = nextSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 104);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]
        narrow = [item for item in comments if item.get("kind") == "inferred_offset_narrow_subfields"]
        bitfield_aliases = [item for item in comments if item.get("kind") == "inferred_offset_bitfield_aliases"]

        self.assertEqual(1, len(overlays))
        self.assertEqual("sessionSpace", overlays[0]["base"])
        self.assertEqual("named", overlays[0]["base_kind"])
        self.assertEqual(1, len(overlays[0]["overlays"]))
        self.assertEqual(16, overlays[0]["overlays"][0]["offset"])
        self.assertEqual([4, 8], overlays[0]["overlays"][0]["sizes"])
        self.assertEqual("dword_qword", overlays[0]["overlays"][0]["size_class"])
        self.assertEqual("wide_overlay", overlays[0]["overlays"][0]["policy_class"])
        self.assertEqual("union_overlay_candidate", overlays[0]["overlays"][0]["interpretation"])
        self.assertIn("Subfield overlay evidence for sessionSpace", overlays[0]["text"])
        self.assertIn(
            "+0x10 field_10 uses 4/8-byte accesses (_DWORD/_QWORD) [union_overlay_candidate]",
            overlays[0]["text"],
        )
        self.assertEqual([], narrow)
        self.assertEqual([], bitfield_aliases)
        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets mix wide overlay access widths", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix narrow subfield access widths", blockers[0]["blockers"])
        self.assertIn("base is reassigned after layout access", blockers[0]["blockers"])
        self.assertNotIn("rewrite offset threshold requires at least 8 offsets", blockers[0]["blockers"])
        self.assertNotIn("rewrite access threshold requires at least 12 accesses", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_narrow_subfield_overlay_reports_narrow_policy_blocker(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall NarrowSubfieldLayout(__int64 currentThread)
{
  return *(_BYTE *)(currentThread + 0x206)
       + *(_WORD *)(currentThread + 0x206)
       + *(_QWORD *)(currentThread + 0x10)
       + *(_QWORD *)(currentThread + 0x18)
       + *(_QWORD *)(currentThread + 0x20)
       + *(_QWORD *)(currentThread + 0x28)
       + *(_QWORD *)(currentThread + 0x30)
       + *(_QWORD *)(currentThread + 0x38)
       + *(_QWORD *)(currentThread + 0x40)
       + *(_QWORD *)(currentThread + 0x48)
       + *(_QWORD *)(currentThread + 0x10)
       + *(_QWORD *)(currentThread + 0x18);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]
        narrow = [item for item in comments if item.get("kind") == "inferred_offset_narrow_subfields"]
        bitfield_aliases = [item for item in comments if item.get("kind") == "inferred_offset_bitfield_aliases"]

        self.assertEqual(1, len(overlays))
        self.assertEqual("currentThread", overlays[0]["base"])
        self.assertEqual(1, len(overlays[0]["overlays"]))
        self.assertEqual(0x206, overlays[0]["overlays"][0]["offset"])
        self.assertEqual([1, 2], overlays[0]["overlays"][0]["sizes"])
        self.assertEqual("byte_word", overlays[0]["overlays"][0]["size_class"])
        self.assertEqual("narrow_subfield", overlays[0]["overlays"][0]["policy_class"])
        self.assertEqual("packed_field_candidate", overlays[0]["overlays"][0]["interpretation"])
        self.assertEqual(1, len(narrow))
        self.assertEqual("currentThread", narrow[0]["base"])
        self.assertEqual("named", narrow[0]["base_kind"])
        self.assertEqual(1, len(narrow[0]["fields"]))
        self.assertEqual(0x206, narrow[0]["fields"][0]["offset"])
        self.assertEqual("byte_word", narrow[0]["fields"][0]["size_class"])
        self.assertEqual("narrow_subfield", narrow[0]["fields"][0]["policy_class"])
        self.assertEqual("packed_field_candidate", narrow[0]["fields"][0]["interpretation"])
        self.assertIn("Narrow subfield candidates for currentThread", narrow[0]["text"])
        self.assertIn(
            "+0x206 field_206 uses 1/2-byte accesses (_BYTE/_WORD) [packed_field_candidate]",
            narrow[0]["text"],
        )
        self.assertIn("body rewrite remains disabled", narrow[0]["text"])
        self.assertEqual([], bitfield_aliases)
        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets mix narrow subfield access widths", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix wide overlay access widths", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_bitwise_narrow_subfield_reports_bitfield_interpretation(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall BitfieldSubfieldLayout(__int64 currentThread)
{
  if ( (*(_BYTE *)(currentThread + 0x206) & 0xF) != 0 )
    *(_WORD *)(currentThread + 0x206) &= 0xFFF0u;
  *(_WORD *)(currentThread + 0x206) &= 0xF00Fu;
  return *(_QWORD *)(currentThread + 0x10)
       + *(_QWORD *)(currentThread + 0x18)
       + *(_QWORD *)(currentThread + 0x20)
       + *(_QWORD *)(currentThread + 0x28)
       + *(_QWORD *)(currentThread + 0x30)
       + *(_QWORD *)(currentThread + 0x38)
       + *(_QWORD *)(currentThread + 0x40)
       + *(_QWORD *)(currentThread + 0x48)
       + *(_QWORD *)(currentThread + 0x10)
       + *(_QWORD *)(currentThread + 0x18);
}
"""
        )
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]
        narrow = [item for item in comments if item.get("kind") == "inferred_offset_narrow_subfields"]
        bitfield_aliases = [item for item in comments if item.get("kind") == "inferred_offset_bitfield_aliases"]

        self.assertEqual(1, len(overlays))
        self.assertEqual("bitfield_candidate", overlays[0]["overlays"][0]["interpretation"])
        self.assertEqual(["0xF", "0xF00F", "0xFFF0"], overlays[0]["overlays"][0]["bit_masks"])
        self.assertEqual(["test_mask", "clear_mask"], overlays[0]["overlays"][0]["bit_operations"])
        self.assertEqual(
            ["low_nibble", "preserve_outer_nibbles", "clear_low_nibble"],
            overlays[0]["overlays"][0]["mask_families"],
        )
        self.assertIn(
            "[bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]",
            overlays[0]["text"],
        )
        self.assertEqual(1, len(narrow))
        self.assertEqual("bitfield_candidate", narrow[0]["fields"][0]["interpretation"])
        self.assertEqual(["0xF", "0xF00F", "0xFFF0"], narrow[0]["fields"][0]["bit_masks"])
        self.assertEqual(["test_mask", "clear_mask"], narrow[0]["fields"][0]["bit_operations"])
        self.assertEqual(
            ["low_nibble", "preserve_outer_nibbles", "clear_low_nibble"],
            narrow[0]["fields"][0]["mask_families"],
        )
        self.assertIn(
            "[bitfield_candidate masks=0xF,0xF00F,0xFFF0 ops=test_mask,clear_mask families=low_nibble,preserve_outer_nibbles,clear_low_nibble]",
            narrow[0]["text"],
        )
        self.assertEqual(1, len(bitfield_aliases))
        self.assertEqual("currentThread", bitfield_aliases[0]["base"])
        self.assertEqual("named", bitfield_aliases[0]["base_kind"])
        self.assertEqual(1, len(bitfield_aliases[0]["fields"]))
        self.assertEqual(0x206, bitfield_aliases[0]["fields"][0]["offset"])
        self.assertEqual(
            ["bitfield_low_nibble", "bitfield_preserve_outer_nibbles", "bitfield_clear_low_nibble"],
            bitfield_aliases[0]["fields"][0]["aliases"],
        )
        self.assertIn("Bitfield aliases for currentThread", bitfield_aliases[0]["text"])
        self.assertIn(
            "field_206=+0x206 bitfield_low_nibble/bitfield_preserve_outer_nibbles/bitfield_clear_low_nibble masks=0xF,0xF00F,0xFFF0",
            bitfield_aliases[0]["text"],
        )
        self.assertIn("body rewrite remains disabled", bitfield_aliases[0]["text"])

    def test_same_width_type_aliases_do_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SameWidthAliasLayout(__int64 sessionSpace)
{
  return *(_DWORD *)(sessionSpace + 16)
       + *(unsigned int *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(aliases))
        self.assertIn("field_10=+0x10 mixed(_DWORD/unsigned int)", aliases[0]["text"])
        self.assertEqual([], overlays)
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))

    def test_unsigned_int8_alias_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall ByteAliasLayout(__int64 sessionSpace)
{
  return *(unsigned __int8 *)(sessionSpace + 0x20)
       + *(_BYTE *)(sessionSpace + 0x21)
       + *(unsigned __int8 *)(sessionSpace + 0x21)
       + *(_BYTE *)(sessionSpace + 0x22)
       + *(_QWORD *)(sessionSpace + 0x28)
       + *(_DWORD *)(sessionSpace + 0x30)
       + *(_DWORD *)(sessionSpace + 0x34)
       + *(_QWORD *)(sessionSpace + 0x38)
       + *(_QWORD *)(sessionSpace + 0x40)
       + *(_QWORD *)(sessionSpace + 0x48)
       + *(_QWORD *)(sessionSpace + 0x50)
       + *(_QWORD *)(sessionSpace + 0x58);
}
"""
        )

        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]
        previews = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_preview"]

        self.assertEqual(1, len(aliases))
        self.assertIn("field_21=+0x21 mixed(_BYTE/unsigned __int8)", aliases[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual(1, len(previews))

    def test_signed_fixed_width_aliases_do_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SignedFixedWidthAliasLayout(__int64 sessionSpace)
{
  return *(signed __int16 *)(sessionSpace + 0x20)
       + *(_WORD *)(sessionSpace + 0x20)
       + *(signed __int32 *)(sessionSpace + 0x24)
       + *(_DWORD *)(sessionSpace + 0x24)
       + *(signed __int64 *)(sessionSpace + 0x28)
       + *(_QWORD *)(sessionSpace + 0x28)
       + *(_QWORD *)(sessionSpace + 0x30)
       + *(_QWORD *)(sessionSpace + 0x38)
       + *(_QWORD *)(sessionSpace + 0x40)
       + *(_QWORD *)(sessionSpace + 0x48)
       + *(_QWORD *)(sessionSpace + 0x50)
       + *(_QWORD *)(sessionSpace + 0x58);
}
"""
        )

        aliases = [item for item in comments if item.get("kind") == "inferred_offset_field_aliases"]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(aliases))
        self.assertIn("field_20=+0x20 mixed(_WORD/signed __int16)", aliases[0]["text"])
        self.assertIn("field_24=+0x24 mixed(_DWORD/signed __int32)", aliases[0]["text"])
        self.assertIn("field_28=+0x28 mixed(_QWORD/signed __int64)", aliases[0]["text"])
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))

    def test_signed_fixed_width_alignment_still_blocks_unsafe_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall SignedFixedWidthUnalignedLayout(__int64 sessionSpace)
{
  return *(signed __int32 *)(sessionSpace + 0x22)
       + *(_QWORD *)(sessionSpace + 0x28)
       + *(_QWORD *)(sessionSpace + 0x30)
       + *(_QWORD *)(sessionSpace + 0x38)
       + *(_QWORD *)(sessionSpace + 0x40)
       + *(_QWORD *)(sessionSpace + 0x48)
       + *(_QWORD *)(sessionSpace + 0x50)
       + *(_QWORD *)(sessionSpace + 0x58)
       + *(_QWORD *)(sessionSpace + 0x60)
       + *(_QWORD *)(sessionSpace + 0x68)
       + *(_QWORD *)(sessionSpace + 0x70)
       + *(_QWORD *)(sessionSpace + 0x78);
}
"""
        )

        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual(1, len(blockers))
        self.assertIn("one or more typed offsets are not naturally aligned", blockers[0]["blockers"])
        self.assertEqual([], ready)

    def test_unknown_type_class_conflicts_are_reported_separately(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall UnknownTypeConflictLayout(__int64 sessionSpace)
{
  return *(_FOO *)(sessionSpace + 16)
       + *(_BAR *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        overlays = [item for item in comments if item.get("kind") == "inferred_offset_subfield_overlays"]

        self.assertEqual([], overlays)
        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets have incompatible access type classes", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix narrow subfield access widths", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix wide overlay access widths", blockers[0]["blockers"])
        self.assertNotIn("one or more offsets mix irregular field access widths", blockers[0]["blockers"])

    def test_compound_base_assignment_blocks_rewrite_even_before_first_access(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall CompoundAliasLayout(__int64 sessionSpace)
{
  sessionSpace += 8;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base uses compound assignment", blockers[0]["blockers"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_stable_same_rhs_reload_after_layout_access_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableReloadLayout(__int64 a1)
{
  __int64 sessionSpace;
  __int64 result;

  sessionSpace = a1;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = a1;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_stable_saved_alias_reload_after_layout_access_does_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall StableSavedAliasReloadLayout(__int64 a1)
{
  __int64 sessionSpace;
  __int64 savedSessionSpace;
  __int64 result;

  sessionSpace = a1;
  savedSessionSpace = sessionSpace;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = savedSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )

        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_blockers" for item in comments))
        self.assertTrue(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_mutated_saved_alias_reload_after_layout_access_blocks_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MutatedSavedAliasReloadLayout(__int64 a1, __int64 a2)
{
  __int64 sessionSpace;
  __int64 savedSessionSpace;
  __int64 result;

  sessionSpace = a1;
  savedSessionSpace = sessionSpace;
  savedSessionSpace = a2;
  result = *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32);
  sessionSpace = savedSessionSpace;
  return result + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        stability = [item for item in comments if item.get("kind") == "inferred_offset_base_stability"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base is reassigned after layout access", blockers[0]["blockers"])
        self.assertEqual(1, len(stability))
        self.assertEqual("sessionSpace", stability[0]["base"])
        self.assertEqual(1, stability[0]["pre_access_assignment_count"])
        self.assertEqual(1, stability[0]["distinct_pre_access_rhs_count"])
        self.assertEqual(["a1"], stability[0]["distinct_pre_access_rhs"])
        self.assertEqual(1, stability[0]["post_access_assignment_count"])
        self.assertEqual(1, stability[0]["risky_post_access_assignment_count"])
        self.assertIn("Base stability evidence for sessionSpace", stability[0]["text"])
        self.assertIn("1 followed by later layout access", stability[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_multiple_different_initializers_before_layout_access_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall MultiInitializerLayout(__int64 a1, __int64 a2)
{
  __int64 sessionSpace;

  sessionSpace = a1;
  sessionSpace = a2;
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        sources = [item for item in comments if item.get("kind") == "inferred_offset_stable_base_source"]
        stability = [item for item in comments if item.get("kind") == "inferred_offset_base_stability"]

        self.assertEqual(1, len(blockers))
        self.assertIn("base has multiple initializers before layout access", blockers[0]["blockers"])
        self.assertEqual([], sources)
        self.assertEqual(1, len(stability))
        self.assertEqual("sessionSpace", stability[0]["base"])
        self.assertEqual(2, stability[0]["pre_access_assignment_count"])
        self.assertEqual(2, stability[0]["distinct_pre_access_rhs_count"])
        self.assertEqual(["a1", "a2"], stability[0]["distinct_pre_access_rhs"])
        self.assertEqual(0, stability[0]["post_access_assignment_count"])
        self.assertEqual(0, stability[0]["risky_post_access_assignment_count"])
        self.assertIn("a1; a2", stability[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in comments))

    def test_cast_equivalent_initializers_before_layout_access_do_not_block_rewrite(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall CastEquivalentInitializerLayout(__int64 a1)
{
  __int64 sessionSpace;

  sessionSpace = a1;
  sessionSpace = (__int64)a1;
  sessionSpace = (unsigned __int64)(a1);
  return *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(sessionSpace + 48)
       + *(_QWORD *)(sessionSpace + 56)
       + *(_QWORD *)(sessionSpace + 64)
       + *(_QWORD *)(sessionSpace + 72)
       + *(_QWORD *)(sessionSpace + 16)
       + *(_QWORD *)(sessionSpace + 24)
       + *(_QWORD *)(sessionSpace + 32)
       + *(_QWORD *)(sessionSpace + 40);
}
"""
        )
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]
        ready = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_ready"]

        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("sessionSpace", ready[0]["base"])
        self.assertEqual(8, ready[0]["offset_count"])
        self.assertEqual(12, ready[0]["access_count"])

    def test_type_blocked_named_layout_reports_partial_rewrite_opportunity(self) -> None:
        comments = field_layout_comments(
            """
__int64 __fastcall PartialTypeBlockedLayout(__int64 sessionSpace)
{
  return *(_BYTE *)(sessionSpace + 0x206)
       + *(_WORD *)(sessionSpace + 0x206)
       + *(_QWORD *)(sessionSpace + 0x10)
       + *(_QWORD *)(sessionSpace + 0x18)
       + *(_QWORD *)(sessionSpace + 0x20)
       + *(_QWORD *)(sessionSpace + 0x28)
       + *(_QWORD *)(sessionSpace + 0x30)
       + *(_QWORD *)(sessionSpace + 0x38)
       + *(_QWORD *)(sessionSpace + 0x40)
       + *(_QWORD *)(sessionSpace + 0x48)
       + *(_QWORD *)(sessionSpace + 0x10)
       + *(_QWORD *)(sessionSpace + 0x18)
       + *(_QWORD *)(sessionSpace + 0x20)
       + *(_QWORD *)(sessionSpace + 0x28);
}
"""
        )
        partial = [
            item
            for item in comments
            if item.get("kind") == "inferred_offset_rewrite_partial_opportunity"
        ]
        blockers = [item for item in comments if item.get("kind") == "inferred_offset_rewrite_blockers"]

        self.assertEqual(1, len(blockers))
        self.assertIn("one or more offsets mix narrow subfield access widths", blockers[0]["blockers"])
        self.assertEqual(1, len(partial))
        self.assertEqual("sessionSpace", partial[0]["base"])
        self.assertEqual("named", partial[0]["base_kind"])
        self.assertEqual(8, partial[0]["safe_offset_count"])
        self.assertEqual(12, partial[0]["safe_access_count"])
        self.assertEqual(1, partial[0]["excluded_offset_count"])
        self.assertEqual(2, partial[0]["excluded_access_count"])
        self.assertEqual(
            ["one or more offsets mix narrow subfield access widths"],
            partial[0]["excluded_reasons"],
        )
        self.assertEqual(8, len(partial[0]["safe_fields"]))
        self.assertEqual(1, len(partial[0]["excluded_fields"]))
        self.assertEqual(0x206, partial[0]["excluded_fields"][0]["offset"])
        self.assertEqual([0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48], partial[0]["safe_offsets"])
        self.assertEqual([0x206], partial[0]["excluded_offsets"])
        self.assertIn("safe fields field_10", partial[0]["text"])
        self.assertIn("Safe offsets +0x10, +0x18, +0x20", partial[0]["text"])
        self.assertIn("excluded offsets +0x206", partial[0]["text"])
        self.assertIn("canonical body rewrite remains disabled", partial[0]["text"])
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_preview" for item in comments))


def _domain_identity_profile(
    profile_id: str,
    function_name: str,
    mode: str,
    force_report_only_on: list[str] | None = None,
    suppress_layout_inference: bool = False,
) -> dict[str, object]:
    return {
        "id": profile_id,
        "function_names": [function_name],
        "parameters": [
            {
                "parameter_index": 0,
                "role": "domainContext",
                "structure": "TEST_DOMAIN_CONTEXT",
                "mode": mode,
                "confidence": 0.88,
                "force_report_only_on": force_report_only_on or [],
                "suppress_layout_inference": suppress_layout_inference,
                "fields": [
                    {"offset": "0x10", "name": "flags", "type": "ULONG", "size": 4, "confidence": 0.90},
                    {"offset": "0x18", "name": "objectPointer", "type": "PVOID", "size": 8, "confidence": 0.86},
                    {"offset": "0x20", "name": "descriptor", "type": "PVOID", "size": 8, "confidence": 0.84},
                    {"offset": "0x28", "name": "count", "type": "ULONG64", "size": 8, "confidence": 0.82},
                    {"offset": "0x30", "name": "length", "type": "ULONG64", "size": 8, "confidence": 0.82},
                    {"offset": "0x38", "name": "state", "type": "ULONG64", "size": 8, "confidence": 0.80},
                    {"offset": "0x40", "name": "owner", "type": "PVOID", "size": 8, "confidence": 0.80},
                    {"offset": "0x48", "name": "next", "type": "PVOID", "size": 8, "confidence": 0.78},
                ],
            }
        ],
    }


def _domain_identity_sample(function_name: str) -> str:
    return """
__int64 __fastcall %s(__int64 argument0)
{
  return *(_QWORD *)(argument0 + 16)
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
}
""" % function_name


def _rtlp_copy_legacy_context_sample() -> str:
    return """
void __fastcall RtlpCopyLegacyContext(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  *(_DWORD *)(a2 + 48) = a3 & 0x67FFFFFF;
  *(_DWORD *)(a2 + 52) = *(_DWORD *)(a4 + 52);
  *(_WORD *)(a2 + 56) = *(_WORD *)(a4 + 56);
  *(_WORD *)(a2 + 58) = *(_WORD *)(a4 + 58);
  *(_WORD *)(a2 + 60) = *(_WORD *)(a4 + 60);
  *(_WORD *)(a2 + 62) = *(_WORD *)(a4 + 62);
  *(_WORD *)(a2 + 64) = *(_WORD *)(a4 + 64);
  *(_WORD *)(a2 + 66) = *(_WORD *)(a4 + 66);
  *(_DWORD *)(a2 + 68) = *(_DWORD *)(a4 + 68);
  *(_QWORD *)(a2 + 152) = *(_QWORD *)(a4 + 152);
  *(_QWORD *)(a2 + 248) = *(_QWORD *)(a4 + 248);
  *(_OWORD *)(a2 + 120) = *(_OWORD *)(a4 + 120);
  *(_OWORD *)(a2 + 1200) = *(_OWORD *)(a4 + 1200);
  *(_OWORD *)(a2 + 1216) = *(_OWORD *)(a4 + 1216);
}
"""


def _rtlp_copy_legacy_context_aligned_sample() -> str:
    return """
void __fastcall RtlpCopyLegacyContext(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  *(_DWORD *)(a2 + 48) = *(_DWORD *)(a4 + 48);
  *(_DWORD *)(a2 + 52) = *(_DWORD *)(a4 + 52);
  *(_WORD *)(a2 + 56) = *(_WORD *)(a4 + 56);
  *(_WORD *)(a2 + 58) = *(_WORD *)(a4 + 58);
  *(_WORD *)(a2 + 60) = *(_WORD *)(a4 + 60);
  *(_WORD *)(a2 + 62) = *(_WORD *)(a4 + 62);
  *(_WORD *)(a2 + 64) = *(_WORD *)(a4 + 64);
  *(_WORD *)(a2 + 66) = *(_WORD *)(a4 + 66);
  *(_DWORD *)(a2 + 68) = *(_DWORD *)(a4 + 68);
  *(_QWORD *)(a2 + 72) = *(_QWORD *)(a4 + 72);
  *(_QWORD *)(a2 + 80) = *(_QWORD *)(a4 + 80);
  *(_QWORD *)(a2 + 88) = *(_QWORD *)(a4 + 88);
}
"""


def _cm_get_device_mapped_property_sample() -> str:
    return """
__int64 __fastcall CmGetDeviceMappedPropertyFromComposite(
        _QWORD *a1,
        WCHAR *a2,
        void *a3,
        __int64 a4,
        int *a5,
        wchar_t *a6,
        ULONG a7,
        int *a8,
        int a9)
{
  unsigned int v1;
  __int64 v2;

  v1 = *(_DWORD *)(a4 + 16);
  v2 = *(_QWORD *)a4 - *(_QWORD *)&DEVPKEY_Device_InstanceId.fmtid.Data1;
  if ( *(_QWORD *)a4 == *(_QWORD *)&DEVPKEY_Device_InstanceId.fmtid.Data1 )
    v2 = *(_QWORD *)(a4 + 8) - *(_QWORD *)DEVPKEY_Device_InstanceId.fmtid.Data4;
  if ( !v2 && v1 == 3 )
    return PnpGetObjectProperty(a1, a2, 1u, a3, 0LL, (__int64)&DEVPKEY_Device_InstanceId, a5, a6, a7, (__int64)a8, a9);
  return v1;
}
"""


def _cm_get_device_mapped_property_partial_guid_sample() -> str:
    return """
__int64 __fastcall CmGetDeviceMappedPropertyFromComposite(
        _QWORD *a1,
        WCHAR *a2,
        void *a3,
        __int64 a4,
        int *a5,
        wchar_t *a6,
        ULONG a7,
        int *a8,
        int a9)
{
  unsigned int v1;
  __int64 v2;

  v1 = *(_DWORD *)(a4 + 16);
  v2 = *(_QWORD *)(a4 + 8) - *(_QWORD *)DEVPKEY_Device_ProblemCode.fmtid.Data4;
  if ( !v2 && v1 == 4 )
    return PnpGetObjectProperty(a1, a2, 1u, a3, 0LL, (__int64)&DEVPKEY_Device_ProblemCode, a5, a6, a7, (__int64)a8, a9);
  return v1;
}
"""


def _smst_etw_fill_store_event_sample() -> str:
    return """
_QWORD *__fastcall SMKM_STORE<SM_TRAITS>::SmStEtwFillStoreEvent(__int64 a1, __int64 a2)
{
  unsigned int v3;
  _QWORD *v4;
  _QWORD *v5;

  v3 = *(unsigned int *)(a2 + 24);
  v4 = (_QWORD *)(*(_QWORD *)(a2 + 8) + v3);
  *v4 = a1;
  v5 = (_QWORD *)(*(_QWORD *)a2 + 16LL * *(unsigned int *)(a2 + 16));
  *v5 = v4;
  v5[1] = 8LL;
  ++*(_DWORD *)(a2 + 16);
  *(_DWORD *)(a2 + 24) += 8;
  return v5;
}
"""


def _cm_delete_value_key_registry_sample() -> str:
    return """
__int64 __fastcall CmDeleteValueKey(__int64 a1, unsigned __int16 *a2, __int64 a3, char a4)
{
  int started;
  __int64 v5;
  ULONG_PTR v7;
  _QWORD *v6;
  _QWORD *UnitOfWork;
  _QWORD *v75;
  __int64 v13;
  __int64 v81;
  __int64 v86;
  unsigned int v76;
  char v70;

  v5 = a1;
  v7 = 0LL;
  v7 = *(_QWORD *)(v5 + 8);
  if ( (*(_DWORD *)(*(_QWORD *)(v7 + 32) + 160LL) & 0x100000) != 0 )
  {
    started = STATUS_ACCESS_DENIED;
  }
  started = CmpStartKcbStackForTopLayerKcb(&v81, v7);
  if ( started < 0 )
  {
    return (unsigned int)started;
  }
  if ( (unsigned __int8)CmpIsKeyDeletedForKeyBody(v5, 0LL) )
  {
    return (unsigned int)started;
  }
  started = CmpTransSearchAddTransFromKeyBody(v5, &v13);
  UnitOfWork = (_QWORD *)CmpAllocateUnitOfWork(v13);
  v75 = UnitOfWork;
  v6 = UnitOfWork;
  CmpTransEnlistUowInKcb(UnitOfWork, v7);
  started = CmpTransEnlistUowInCmTrans(v6, v13);
  CmpLockIXLockIntent(v7 + 248, v6);
  CmpLockIXLockExclusive(v7 + 264, v6, 1LL);
  started = CmpCloneKCBValueListForTrans(v7, v13, &v70);
  HvLockHiveFlusherShared(*(_QWORD *)(v7 + 32));
  HvpGetCellFlat(*(_QWORD *)(v7 + 32), v76);
  HvpReleaseCellFlat(*(_QWORD *)(v7 + 32), &v86);
  HvFreeCell(*(_QWORD *)(v7 + 32), v76);
  if ( (*(_DWORD *)(v7 + 8) & 8) != 0 )
  {
    *(_WORD *)(v7 + 8) &= ~8u;
  }
  CmpRundownUnitOfWork((ULONG_PTR)v6);
  ExFreePoolWithTag(v6, POOL_TAG('C', 'M', 'U', 'w'));
  SeAdtRegistryValueChangedAuditAlarm(0LL, 0LL, 0LL, a2, v5, a3, 0LL, 2);
  return (unsigned int)started;
}
"""


if __name__ == "__main__":
    unittest.main()
