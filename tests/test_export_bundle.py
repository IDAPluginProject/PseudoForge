from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.layout_rewrite_preview import build_layout_rewrite_preview_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import (
    CleanPlan,
    CorrectedParameterField,
    CorrectedParameterMapEntry,
)
from ida_pseudoforge.core.render import write_export_bundle as legacy_render_write_export_bundle
from ida_pseudoforge.profiles import loader as profile_loader


SAMPLE = """
__int64 __fastcall ExportBundleSample(int a1)
{
  int status;

  status = 0;
  if ( a1 )
  {
    status = -1073741823;
  }
  return status;
}
"""


STATUS_OBJECT_EXPORT_SAMPLE = """
__int64 __fastcall StatusObjectExportSample()
{
  int ObjectProperty;
  int ObjectList;
  int status;

  ObjectProperty = QueryObjectProperty();
  if ( ObjectProperty == STATUS_BUFFER_TOO_SMALL )
  {
    status = ObjectProperty;
  }
  ObjectList = STATUS_MORE_PROCESSING_REQUIRED;
  if ( ObjectList < 0 )
  {
    return ObjectList;
  }
  return status;
}
"""


OBJECT_DOMAIN_EXPORT_SAMPLE = """
LONG_PTR __stdcall ObfDereferenceObject(PVOID referencedObject)
{
  return *((volatile LONG_PTR *)referencedObject - 6);
}
"""


IO_DELETE_TYPE_EXPORT_SAMPLE = """
void __stdcall IoDeleteDevice(__int64 a1)
{
  IopCompleteUnloadOrDelete((ULONG_PTR)a1);
}
"""


LIVE_IN_REGISTER_EXPORT_SAMPLE = """
__int64 __fastcall LiveInRegisterExportSample()
{
  int v1; // r8d

  EtwpEventWriteFull(v1);
  return 0;
}
"""


class ExportBundleTests(unittest.TestCase):
    def test_write_export_bundle_includes_parity_artifacts(self) -> None:
        profile_loader.clear_profile_caches()
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
                plan = build_clean_plan(capture)
                self.assertTrue(profile_loader.get_status_name(-1073741823))

                artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

                for key in (
                    "cleaned_pseudocode",
                    "switch_outline",
                    "rename_map",
                    "flow_report",
                    "rule_report",
                    "raw_pseudocode",
                    "warnings",
                    "raw_vs_cleaned_diff",
                    "summary",
                ):
                    self.assertIn(key, artifacts)
                    self.assertTrue(Path(artifacts[key]).exists(), key)

                self.assertEqual(
                    Path(artifacts["raw_pseudocode"]).read_text(encoding="utf-8"),
                    capture.pseudocode.rstrip() + "\n",
                )
                diff_text = Path(artifacts["raw_vs_cleaned_diff"]).read_text(encoding="utf-8")
                self.assertTrue(diff_text.startswith("--- raw/ExportBundleSample.cpp\n"))
                self.assertIn("+++ cleaned/ExportBundleSample.cpp\n", diff_text)
                self.assertIsInstance(json.loads(Path(artifacts["warnings"]).read_text(encoding="utf-8")), list)

                summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
                self.assertEqual(summary["mode"], "ida_interactive")
                self.assertEqual(summary["function"], "ExportBundleSample")
                self.assertEqual(summary["function_ea"], "0x140001000")
                self.assertEqual(summary["source_path"], "sample.bin")
                self.assertIn("raw_vs_cleaned_diff", summary["artifacts"])
                self.assertIn("warning_diagnostics", summary["artifacts"])
                self.assertEqual(artifacts["summary"], summary["artifacts"]["summary"])
                self.assertEqual(summary["profile_root"], profile_loader.active_profile_root())
                self.assertIn("status_codes.json", summary["active_profiles"])
                self.assertTrue(
                    any(item["name"] == "status_codes.json" for item in summary["profile_manifests"])
                )
            finally:
                profile_loader.clear_profile_caches()

    def test_write_export_bundle_hides_resolved_status_carrier_display_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                STATUS_OBJECT_EXPORT_SAMPLE,
                ea=0x140002000,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)
            self.assertIn("Downgraded object-style status carrier name", "\n".join(plan.warnings))

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            warning_payload = json.loads(Path(artifacts["warnings"]).read_text(encoding="utf-8"))
            rename_payload = json.loads(Path(artifacts["rename_map"]).read_text(encoding="utf-8"))
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))

            self.assertEqual(warning_payload, [])
            self.assertEqual(summary["warnings"], 0)
            self.assertIn(
                "Downgraded object-style status carrier name",
                "\n".join(str(item) for item in rename_payload["warnings"]),
            )

    def test_write_export_bundle_allows_summary_suffix_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_free_offline",
                summary_suffix="ida-free-summary",
            )

            summary_path = Path(artifacts["summary"])
            self.assertEqual("ExportBundleSample.ida-free-summary.json", summary_path.name)
            self.assertTrue(summary_path.exists())
            self.assertFalse((Path(temp_dir) / "ExportBundleSample.summary.json").exists())

    def test_write_export_bundle_emits_warning_diagnostics_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                LIVE_IN_REGISTER_EXPORT_SAMPLE,
                ea=0x140003000,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            warnings = json.loads(Path(artifacts["warnings"]).read_text(encoding="utf-8"))
            diagnostics = json.loads(Path(artifacts["warning_diagnostics"]).read_text(encoding="utf-8"))
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))

            self.assertIsInstance(warnings, list)
            self.assertTrue(any("live-in register value (r8d)" in item for item in warnings))
            self.assertEqual(1, len(diagnostics))
            self.assertEqual("unassigned_local_live_in_register", diagnostics[0]["kind"])
            self.assertEqual("v1", diagnostics[0]["symbol"])
            self.assertEqual("call_argument", diagnostics[0]["usage_class"])
            self.assertEqual("r8d", diagnostics[0]["register"])
            self.assertEqual("abi_argument", diagnostics[0]["register_class"])
            self.assertEqual("caller_parameter_gap_candidate", diagnostics[0]["candidate_action"])
            self.assertEqual("parameter_gap_candidate", diagnostics[0]["legacy_candidate_action"])
            self.assertEqual("EtwpEventWriteFull", diagnostics[0]["callee_name"])
            self.assertEqual(0, diagnostics[0]["argument_index"])
            self.assertEqual(artifacts["warning_diagnostics"], summary["artifacts"]["warning_diagnostics"])
            self.assertEqual(1, summary["warning_diagnostics"])

    def test_write_export_bundle_limits_long_artifact_stems(self) -> None:
        long_name = (
            "?BTreeRedistribute@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY@?"
            "$SMKM_STORE_MGR@USM_TRAITS@@@@$0BAAA@UB_TREE_DUMMY_NODE_POOL@@"
            "U?$B_TREE_KEY_COMPARATOR@T_SM_PAGE_KEY@@@@@@SAPEAUNODE@?"
            "$B_TREE_HEADER@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY@?"
            "$SMKM_STORE_MGR@USM_TRAITS@@@@@@PEAU1@PEAUSEARCH_RESULT@1@@Z"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                SAMPLE,
                name=long_name,
                ea=0x140291E88,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            cleaned_path = Path(artifacts["cleaned_pseudocode"])
            artifact_stem = cleaned_path.name[: -len(".cleaned.cpp")]
            self.assertLessEqual(len(artifact_stem), 96)
            self.assertRegex(artifact_stem, r"_[0-9a-f]{12}$")
            for path in artifacts.values():
                self.assertTrue(Path(path).exists(), path)

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(long_name, summary["function"])

    def test_write_export_bundle_includes_rule_diagnostics_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)
            plan.rule_report = {
                "matched_rules": [{"rule_id": "one"}, {"rule_id": "two"}],
                "rewrite_emissions": [
                    {"kind": "call_arg_rewrite", "status": "applied"},
                    {"kind": "text_rewrite", "status": "rejected"},
                ],
                "load_errors": [{"path": "project/broken.json", "error": "invalid json"}],
                "validation_errors": [{"path": "project/invalid.json", "error": "bad phase"}],
            }

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            diagnostics = summary["rule_diagnostics"]
            self.assertEqual(2, diagnostics["matched_rules"])
            self.assertEqual(2, diagnostics["rewrite_emissions"]["total"])
            self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["applied"])
            self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["rejected"])
            self.assertEqual(1, diagnostics["load_errors"])
            self.assertEqual(1, diagnostics["validation_errors"])
            self.assertEqual("project/broken.json", summary["rule_load_errors"][0]["path"])
            self.assertEqual("project/invalid.json", summary["rule_validation_errors"][0]["path"])

    def test_write_export_bundle_includes_domain_identity_summary(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                capture = capture_from_pseudocode(
                    OBJECT_DOMAIN_EXPORT_SAMPLE,
                    ea=0x140003000,
                    source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe.i64",
                )
                plan = build_clean_plan(capture)

                artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

                summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
                domain_summary = summary["domain_identity_summary"]
                rename_payload = json.loads(Path(artifacts["rename_map"]).read_text(encoding="utf-8"))

                self.assertEqual(1, domain_summary["total_hits"])
                self.assertEqual(1, domain_summary["report_only_hits"])
                self.assertEqual(1, domain_summary["blocker_counts"]["profile_report_only"])
                self.assertIn("windows.object_manager.dereference_object", domain_summary["top_profile_ids"])
                self.assertTrue(
                    any(
                        item.get("kind") == "domain_structure_identity"
                        for item in rename_payload["comments"]
                    )
                )
        finally:
            profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_write_export_bundle_includes_parameter_type_corrections(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                capture = capture_from_pseudocode(
                    IO_DELETE_TYPE_EXPORT_SAMPLE,
                    ea=0x140004000,
                    source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe.i64",
                )
                plan = build_clean_plan(capture)

                artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

                summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
                rename_payload = json.loads(Path(artifacts["rename_map"]).read_text(encoding="utf-8"))
                cleaned = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")

                self.assertEqual("D:\\bin\\os\\26200.8457\\ntoskrnl.exe.i64", summary["source_context"]["source_path"])
                self.assertEqual("26200.8457", summary["source_context"]["profile_context"]["build"])
                self.assertEqual(1, len(summary["function_identity_candidates"]))
                self.assertEqual(
                    "windows.io_manager.delete_device",
                    summary["function_identity_candidates"][0]["profile_id"],
                )
                self.assertIn("report_only_profile", summary["function_identity_candidates"][0]["blockers"])
                self.assertEqual(1, len(summary["parameter_type_corrections"]))
                self.assertEqual("PDEVICE_OBJECT", summary["parameter_type_corrections"][0]["canonical_type"])
                self.assertFalse(summary["parameter_type_corrections"][0]["apply_to_idb"])
                self.assertEqual([], summary["corrected_parameter_map"])
                self.assertEqual(0, summary["body_canonical_rewrite_summary"]["rewrite_ready"])
                self.assertEqual(1, len(rename_payload["type_corrections"]))
                self.assertIn("Function identities: 1 candidate(s)", cleaned)
                self.assertIn("Applied corrections: a1->deviceObject __int64->PDEVICE_OBJECT", cleaned)
                self.assertIn("IoDeleteDevice(PDEVICE_OBJECT deviceObject)", cleaned)
        finally:
            profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_write_export_bundle_includes_corrected_parameter_map_and_body_rewrite_summary(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall BodyRewriteEvidence(__int64 context)
{
  return *(_QWORD *)(context + 16);
}
""",
            name="BodyRewriteEvidence",
            ea=0x140005000,
            source_path="sample.bin",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            corrected_parameter_map=[
                CorrectedParameterMapEntry(
                    parameter_index=0,
                    old_name="a1",
                    new_name="context",
                    old_type="__int64",
                    canonical_type="PTEST_CONTEXT",
                    display_type="PTEST_CONTEXT",
                    profile_id="test.corrected_body",
                    role="context",
                    structure="TEST_CONTEXT",
                    effective_mode="canonical-rewrite-eligible",
                    confidence=0.86,
                    provenance="test corrected map",
                    source="test profile",
                    body_canonical_rewrite=True,
                    fields=[
                        CorrectedParameterField(
                            offset=0x10,
                            name="Flags",
                            type_text="ULONG",
                            size=4,
                            confidence=0.86,
                            source="test profile",
                            provenance="test field",
                        )
                    ],
                )
            ],
            comments=[
                {
                    "kind": "inferred_offset_rewrite_ready",
                    "base": "context",
                    "source_provenance": "corrected_parameter_map",
                    "domain_profile_id": "test.corrected_body",
                    "text": "Offset field rewrite candidate for context.",
                    "confidence": 0.86,
                },
                {
                    "kind": "inferred_offset_rewrite_blockers",
                    "base": "blockedContext",
                    "source_provenance": "corrected_parameter_map",
                    "domain_profile_id": "test.blocked_body",
                    "blockers": ["overlay", "build_mismatch"],
                    "text": "Offset field rewrite blocked for blockedContext.",
                    "confidence": 0.80,
                },
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))

        corrected_map = summary["corrected_parameter_map"]
        body_summary = summary["body_canonical_rewrite_summary"]
        self.assertEqual(1, len(corrected_map))
        self.assertEqual("test.corrected_body", corrected_map[0]["profile_id"])
        self.assertEqual("Flags", corrected_map[0]["fields"][0]["name"])
        self.assertEqual(1, body_summary["rewrite_ready"])
        self.assertEqual(1, body_summary["rewrite_blockers"])
        self.assertEqual({"build_mismatch": 1, "overlay": 1}, body_summary["blocker_counts"])
        self.assertEqual({"corrected_parameter_map": 2}, body_summary["source_provenance_counts"])
        self.assertEqual(["blockedContext", "context"], body_summary["bases"])

    def test_write_export_bundle_includes_layout_rewrite_preview_artifacts(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for v4: 2 typed dereference(s) across 2 offset(s), no rewrite blockers found. Source provenance direct_argument_alias from argument2. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v4: 2 dereference(s) can map to 2 field alias(es) field_10, field_18. Source provenance direct_argument_alias from argument2. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreview(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_DWORD *)(v4 + 16) + *(_QWORD *)(v4 + 24);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreview(__int64 argument2)
{
  return argument2;
}
""",
                name="LayoutPreview",
                ea=0x140002000,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
            )

            for key in (
                "layout_rewrite_preview",
                "layout_rewrite_preview_diff",
                "layout_rewrite_preview_metadata",
            ):
                self.assertIn(key, artifacts)
                self.assertTrue(Path(artifacts[key]).exists(), key)
            self.assertEqual(cleaned_text, Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8"))
            preview_text = Path(artifacts["layout_rewrite_preview"]).read_text(encoding="utf-8")
            self.assertIn("Canonical cleaned output was not modified", preview_text)
            self.assertIn("v4->field_10 /* _DWORD +0x10 */", preview_text)
            self.assertIn("v4->field_18 /* _QWORD +0x18 */", preview_text)
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual("layout_rewrite_preview_v2", preview_metadata["schema"])
            self.assertFalse(preview_metadata["canonical_rewrite_requested"])
            self.assertFalse(preview_metadata["canonical_cleaned_output_modified"])
            self.assertEqual("not_requested", preview_metadata["canonical_rewrite_status"])
            self.assertEqual(2, preview_metadata["rewritten_accesses"])
            self.assertEqual(2, preview_metadata["rewritten_fields"])
            self.assertEqual(["v4"], preview_metadata["rewritten_bases"])
            self.assertEqual(2, preview_metadata["rewrite_results"]["v4"]["rewritten_accesses"])
            self.assertEqual(2, preview_metadata["rewrite_results"]["v4"]["rewritten_fields"])
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual([], preview_metadata["validation"]["errors"])
            self.assertTrue(preview_metadata["validation"]["checks"]["advertised_access_counts_match"])
            self.assertTrue(preview_metadata["validation"]["checks"]["advertised_field_counts_match"])
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(artifacts["layout_rewrite_preview"], summary["artifacts"]["layout_rewrite_preview"])

    def test_layout_rewrite_preview_metadata_reports_validation_failure(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v4: 3 dereference(s) can map to 2 field alias(es) field_10, field_18. Source provenance direct_argument_alias from argument2. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreviewMismatch(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_DWORD *)(v4 + 16) + *(_QWORD *)(v4 + 24);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreviewMismatch(__int64 argument2)
{
  return argument2;
}
""",
                name="LayoutPreviewMismatch",
                ea=0x140002100,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
            )

            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual("failed", preview_metadata["validation"]["status"])
            self.assertFalse(preview_metadata["validation"]["checks"]["advertised_access_counts_match"])
            self.assertTrue(preview_metadata["validation"]["checks"]["advertised_field_counts_match"])
            self.assertIn("v4 advertised 3 access(es) but rewrote 2", preview_metadata["validation"]["errors"])

    def test_validated_layout_rewrite_can_update_canonical_cleaned_output(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for v4: 2 typed dereference(s) across 2 offset(s), no rewrite blockers found. Source provenance direct_argument_alias from argument2. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v4: 2 dereference(s) can map to 2 field alias(es) field_10, field_18. Source provenance direct_argument_alias from argument2. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreviewApply(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_DWORD *)(v4 + 16) + *(_QWORD *)(v4 + 24);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreviewApply(__int64 argument2)
{
  return argument2;
}
""",
                name="LayoutPreviewApply",
                ea=0x140002200,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_text = Path(artifacts["layout_rewrite_preview"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertIn("v4->field_10 /* _DWORD +0x10 */", cleaned_output)
            self.assertIn("v4->field_18 /* _QWORD +0x18 */", cleaned_output)
            self.assertNotIn("*(_DWORD *)(v4 + 16)", cleaned_output)
            self.assertIn("Validated layout rewrite applied to canonical cleaned output.", cleaned_output)
            self.assertNotIn("Audit only; body rewrite was not applied.", cleaned_output)
            self.assertNotIn("Preview artifact only; body rewrite was not applied.", cleaned_output)
            self.assertIn("Canonical cleaned output was modified by validated opt-in rewrite.", preview_text)
            self.assertTrue(preview_metadata["canonical_rewrite_requested"])
            self.assertTrue(preview_metadata["canonical_cleaned_output_modified"])
            self.assertEqual("applied", preview_metadata["canonical_rewrite_status"])
            self.assertEqual([], preview_metadata["canonical_rewrite_errors"])
            self.assertEqual("passed", preview_metadata["validation"]["status"])

    def test_validated_layout_rewrite_survives_header_insight_limit(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall HeaderLimitLayout(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_DWORD *)(v4 + 16) + *(_QWORD *)(v4 + 24);
}
""",
            name="HeaderLimitLayout",
            ea=0x140002280,
            source_path="sample.bin",
        )
        plan = build_clean_plan(capture)
        plan.comments = [
            {
                "kind": "filler_%d" % index,
                "text": "filler %d" % index,
                "confidence": 0.5,
            }
            for index in range(24)
        ]
        plan.comments.extend(
            [
                {
                    "kind": "inferred_offset_rewrite_ready",
                    "text": (
                        "Offset field rewrite candidate for v4: 2 typed dereference(s) across 2 offset(s), "
                        "no rewrite blockers found. Source provenance direct_argument_alias from argument2. "
                        "Audit only; body rewrite was not applied."
                    ),
                    "confidence": 0.78,
                },
                {
                    "kind": "inferred_offset_rewrite_preview",
                    "text": (
                        "Offset field rewrite preview for v4: 2 dereference(s) can map to 2 field alias(es) "
                        "field_10, field_18. Source provenance direct_argument_alias from argument2. "
                        "Preview artifact only; body rewrite was not applied."
                    ),
                    "confidence": 0.78,
                },
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))

        self.assertIn("layout_rewrite_preview", artifacts)
        self.assertIn("v4->field_10 /* _DWORD +0x10 */", cleaned_output)
        self.assertIn("v4->field_18 /* _QWORD +0x18 */", cleaned_output)
        self.assertEqual("applied", preview_metadata["canonical_rewrite_status"])

    def test_validated_layout_rewrite_handles_advertised_address_casts(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for context: 2 typed dereference(s) across 2 offset(s), no rewrite blockers found. Source provenance generic_parameter_trust from context. Audit only; body rewrite was not applied. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for context: 2 dereference(s) can map to 2 field alias(es) field_8, field_90. Source provenance generic_parameter_trust from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreviewAddressCast(__int64 context)
{
  int *v21;

  v21 = (int *)(context + 144);
  if ( v21 == (int *)(context + 160) )
    return 0;
  return *(_QWORD *)(context + 8);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreviewAddressCast(__int64 context)
{
  return context;
}
""",
                name="LayoutPreviewAddressCast",
                ea=0x140002250,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertIn("context->field_8 /* _QWORD +0x8 */", cleaned_output)
            self.assertIn("(int *)&context->field_90 /* address +0x90 */", cleaned_output)
            self.assertIn("(int *)(context + 160)", cleaned_output)
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual("applied", preview_metadata["canonical_rewrite_status"])
            self.assertEqual(2, preview_metadata["rewritten_accesses"])
            self.assertEqual(2, preview_metadata["rewritten_fields"])
            self.assertEqual([0x8, 0x90], preview_metadata["preview_plans"][0]["advertised_offsets"])

    def test_validated_layout_rewrite_keeps_canonical_output_when_validation_fails(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v4: 3 dereference(s) can map to 2 field alias(es) field_10, field_18. Source provenance direct_argument_alias from argument2. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreviewBlocked(__int64 argument2)
{
  __int64 v4;

  v4 = argument2;
  return *(_DWORD *)(v4 + 16) + *(_QWORD *)(v4 + 24);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreviewBlocked(__int64 argument2)
{
  return argument2;
}
""",
                name="LayoutPreviewBlocked",
                ea=0x140002300,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual(cleaned_text, cleaned_output)
            self.assertTrue(preview_metadata["canonical_rewrite_requested"])
            self.assertFalse(preview_metadata["canonical_cleaned_output_modified"])
            self.assertEqual("blocked_by_validation", preview_metadata["canonical_rewrite_status"])
            self.assertIn("v4 advertised 3 access(es) but rewrote 2", preview_metadata["canonical_rewrite_errors"])

    def test_partial_layout_rewrite_can_update_canonical_allowed_offsets(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for currentThread: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_20, field_40, field_48, field_74, field_78, field_C3, field_233, field_24C. Safe offsets +0x20, +0x40, +0x48, +0x74, +0x78, +0xC3, +0x233, +0x24C; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall LayoutPartialPreview(__int64 currentThread)
{
  return *(_QWORD *)(currentThread + 0x20)
       + *(_QWORD *)(currentThread + 0x40)
       + *(_QWORD *)(currentThread + 0x48)
       + *(_DWORD *)(currentThread + 0x74)
       + *(_DWORD *)(currentThread + 0x78)
       + *(char *)(currentThread + 0xC3)
       + *(char *)(currentThread + 0x233)
       + *(_DWORD *)(currentThread + 0x24C)
       + *(_QWORD *)(currentThread + 0x20)
       + *(_QWORD *)(currentThread + 0x40)
       + *(_QWORD *)(currentThread + 0x48)
       + *(_DWORD *)(currentThread + 0x74)
       + *(_BYTE *)(currentThread + 0x206)
       + *(_WORD *)(currentThread + 0x206);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPartialPreview(__int64 currentThread)
{
  return currentThread;
}
""",
                name="LayoutPartialPreview",
                ea=0x140002350,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_text = Path(artifacts["layout_rewrite_preview"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertNotEqual(cleaned_text, cleaned_output)
            self.assertIn("currentThread->field_20 /* _QWORD +0x20 */", cleaned_output)
            self.assertIn("currentThread->field_24C /* _DWORD +0x24C */", cleaned_output)
            self.assertIn("*(_BYTE *)(currentThread + 0x206)", cleaned_output)
            self.assertIn("*(_WORD *)(currentThread + 0x206)", cleaned_output)
            self.assertIn("Validated partial layout rewrite applied to canonical cleaned output.", cleaned_output)
            self.assertNotIn("canonical body rewrite remains disabled", cleaned_output)
            self.assertIn("currentThread->field_20 /* _QWORD +0x20 */", preview_text)
            self.assertIn("currentThread->field_24C /* _DWORD +0x24C */", preview_text)
            self.assertIn("*(_BYTE *)(currentThread + 0x206)", preview_text)
            self.assertIn("*(_WORD *)(currentThread + 0x206)", preview_text)
            self.assertTrue(preview_metadata["canonical_rewrite_requested"])
            self.assertTrue(preview_metadata["canonical_cleaned_output_modified"])
            self.assertEqual("applied_partial", preview_metadata["canonical_rewrite_status"])
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual([], preview_metadata["validation"]["errors"])
            self.assertEqual(12, preview_metadata["rewritten_accesses"])
            self.assertEqual(8, preview_metadata["rewritten_fields"])
            self.assertEqual("partial", preview_metadata["preview_plans"][0]["plan_kind"])
            self.assertEqual([0x20, 0x40, 0x48, 0x74, 0x78, 0xC3, 0x233, 0x24C], preview_metadata["preview_plans"][0]["allowed_offsets"])
            self.assertEqual([0x206], preview_metadata["preview_plans"][0]["excluded_offsets"])
            self.assertEqual(2, preview_metadata["preview_plans"][0]["excluded_access_count"])
            self.assertTrue(
                preview_metadata["validation"]["checks"]["preview_has_no_raw_offset_derefs_for_rewrite_scope"]
            )

    def test_report_only_partial_opportunity_does_not_become_canonical_rewrite(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for sessionSpace: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for sessionSpace: 12 dereference(s) can map to 8 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Preview artifact only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for resource: 12 safe dereference(s) across 8 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_20, field_28, field_30, field_38, field_40, field_48, field_50, field_58. Safe offsets +0x20, +0x28, +0x30, +0x38, +0x40, +0x48, +0x50, +0x58; excluded offsets +0x10. Excluded reasons one or more offsets mix wide overlay access widths. Source provenance domain_identity_report_only from resource. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall MixedReportOnly(__int64 sessionSpace, __int64 resource)
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
       + *(_QWORD *)(sessionSpace + 40)
       + *(_QWORD *)(resource + 32)
       + *(_QWORD *)(resource + 40)
       + *(_QWORD *)(resource + 48)
       + *(_QWORD *)(resource + 56)
       + *(_QWORD *)(resource + 64)
       + *(_QWORD *)(resource + 72)
       + *(_QWORD *)(resource + 80)
       + *(_QWORD *)(resource + 88)
       + *(_DWORD *)(resource + 16)
       + *(_QWORD *)(resource + 16);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "MixedReportOnly",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        self.assertIsNotNone(bundle.canonical_text)
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(1, len(bundle.metadata["preview_plans"]))
        self.assertEqual("sessionSpace", bundle.metadata["preview_plans"][0]["base"])
        self.assertIn("sessionSpace->field_10 /* _QWORD +0x10 */", canonical_text)
        self.assertIn("*(_QWORD *)(resource + 32)", canonical_text)
        self.assertIn(
            "Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented.",
            canonical_text,
        )
        self.assertNotIn(
            "Validated partial layout rewrite applied to canonical cleaned output.",
            canonical_text,
        )

    def test_validated_layout_rewrite_handles_pointer_indexed_dereferences(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for context: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Source provenance generic_parameter_trust from context. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for context: 12 dereference(s) can map to 8 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Source provenance generic_parameter_trust from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall PointerIndexedLayout(__int64 context)
{
  return *((_QWORD *)context + 2)
       + *((_QWORD *)context + 3)
       + *((_QWORD *)context + 4)
       + *((_QWORD *)context + 5)
       + *((_QWORD *)context + 6)
       + *((_QWORD *)context + 7)
       + *((_QWORD *)context + 8)
       + *((_QWORD *)context + 9)
       + *((_QWORD *)context + 2)
       + *((_QWORD *)context + 3)
       + *((_QWORD *)context + 4)
       + *((_QWORD *)context + 5);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "PointerIndexedLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(12, bundle.metadata["rewritten_accesses"])
        self.assertIn("context->field_10 /* _QWORD +0x10 */", canonical_text)
        self.assertIn("context->field_48 /* _QWORD +0x48 */", canonical_text)
        self.assertNotIn("*((_QWORD *)context + 2)", canonical_text)

    def test_validated_layout_rewrite_handles_advertised_direct_base_field_zero(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for context: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Source provenance domain_identity from context. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for context: 14 dereference(s) can map to 9 field alias(es) field_0, field_8, field_10, field_18, field_20, field_28, field_30, field_38, field_40. Source provenance domain_identity from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall DirectBaseFieldZeroLayout(__int64 context)
{
  return *(_DWORD *)context
       + *(_DWORD *)context
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 40)
       + *(_DWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_QWORD *)(context + 56);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "DirectBaseFieldZeroLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(14, bundle.metadata["rewritten_accesses"])
        self.assertEqual(9, bundle.metadata["rewrite_results"]["context"]["rewritten_fields"])
        self.assertIn("context->field_0 /* _DWORD +0x0 */", canonical_text)
        self.assertNotIn("*(_DWORD *)context", canonical_text)

    def test_validated_layout_rewrite_keeps_unadvertised_direct_base_raw(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for context: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Source provenance domain_identity from context. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for context: 12 dereference(s) can map to 8 field alias(es) field_8, field_10, field_18, field_20, field_28, field_30, field_38, field_40. Source provenance domain_identity from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall DirectBaseUnadvertisedLayout(__int64 context)
{
  return *(_DWORD *)context
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_DWORD *)(context + 40)
       + *(_DWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 24)
       + *(_DWORD *)(context + 32)
       + *(_QWORD *)(context + 56);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "DirectBaseUnadvertisedLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(12, bundle.metadata["rewritten_accesses"])
        self.assertIn("*(_DWORD *)context", canonical_text)
        self.assertNotIn("context->field_0", canonical_text)

    def test_validated_partial_layout_rewrite_handles_advertised_direct_base_field_zero(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for context: 13 safe dereference(s) across 9 safe offset(s), 1 excluded dereference(s) across 1 excluded offset(s), safe fields field_0, field_8, field_10, field_18, field_28, field_30, field_38, field_40, field_48. Safe offsets +0x0, +0x8, +0x10, +0x18, +0x28, +0x30, +0x38, +0x40, +0x48; excluded offsets +0x20. Excluded reasons one or more offsets mix wide overlay access widths. Source provenance generic_parameter_trust from context. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall PartialDirectBaseFieldZeroLayout(__int64 context)
{
  return *(_DWORD *)context
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_OWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 48)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 8)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 40);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "PartialDirectBaseFieldZeroLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied_partial", bundle.metadata["canonical_rewrite_status"])
        self.assertIn("context->field_0 /* _DWORD +0x0 */", canonical_text)
        self.assertIn("*(_OWORD *)(context + 32)", canonical_text)
        self.assertNotIn("*(_DWORD *)context", canonical_text)

    def test_validated_layout_rewrite_extends_to_direct_source_alias_offsets(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for v6: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Source provenance parameter_direct_alias from context. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v6: 12 dereference(s) can map to 8 field alias(es) field_7C, field_88, field_8C, field_B0, field_240, field_248, field_25C, field_264. Source provenance parameter_direct_alias from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
unsigned __int64 __fastcall SourceAliasLayout(ULONG_PTR context)
{
  ULONG_PTR v6;

  v6 = context;
  return *(_QWORD *)(context + 176)
       + *(_QWORD *)(context + 576)
       + *(_QWORD *)(context + 176)
       + *(_DWORD *)(context + 604)
       + *(_DWORD *)(v6 + 124)
       + *(_DWORD *)(v6 + 136)
       + *(unsigned __int16 *)(v6 + 140)
       + *(_QWORD *)(v6 + 176)
       + *(_QWORD *)(v6 + 576)
       + *(_QWORD *)(v6 + 584)
       + *(_DWORD *)(v6 + 604)
       + *(_DWORD *)(v6 + 612);
}
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "SourceAliasLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(["context", "v6"], bundle.metadata["rewritten_bases"])
        self.assertEqual(12, bundle.metadata["rewritten_accesses"])
        self.assertEqual(8, bundle.metadata["rewrite_results"]["v6"]["rewritten_fields"])
        self.assertEqual(12, bundle.metadata["rewrite_results"]["v6"]["rewritten_accesses"])
        self.assertEqual(
            {"v6": ["context"]},
            bundle.metadata["source_aliases_by_result_base"],
        )
        self.assertIn("context->field_B0 /* _QWORD +0xB0 */", canonical_text)
        self.assertIn("context->field_240 /* _QWORD +0x240 */", canonical_text)
        self.assertIn("context->field_25C /* _DWORD +0x25C */", canonical_text)
        self.assertIn("v6->field_7C /* _DWORD +0x7C */", canonical_text)
        self.assertNotIn("*(_QWORD *)(context + 176)", canonical_text)
        self.assertNotIn("*(_DWORD *)(context + 604)", canonical_text)

    def test_validated_layout_rewrite_keeps_field_pointer_source_alias_raw(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for v16: 12 typed dereference(s) across 8 offset(s), no rewrite blockers found. Source provenance parameter_field_pointer_alias from objectHeader. Audit only; body rewrite was not applied. confidence=0.78
      - inferred_offset_rewrite_preview: Offset field rewrite preview for v16: 12 dereference(s) can map to 8 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48. Source provenance parameter_field_pointer_alias from objectHeader. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall FieldPointerAliasLayout(__int64 objectHeader)
{
  __int64 v16;

  v16 = *(_QWORD *)(objectHeader + 48);
  return *(_QWORD *)(objectHeader + 16)
       + *(_QWORD *)(v16 + 16)
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
""".lstrip()
        bundle = build_layout_rewrite_preview_bundle(
            cleaned_text,
            "FieldPointerAliasLayout",
            apply_validated_body_rewrite=True,
        )

        self.assertIsNotNone(bundle)
        assert bundle is not None
        canonical_text = bundle.canonical_text or ""
        self.assertEqual("applied", bundle.metadata["canonical_rewrite_status"])
        self.assertEqual(["v16"], bundle.metadata["rewritten_bases"])
        self.assertEqual({}, bundle.metadata["source_aliases_by_result_base"])
        self.assertIn("v16->field_10 /* _QWORD +0x10 */", canonical_text)
        self.assertIn("*(_QWORD *)(objectHeader + 16)", canonical_text)

    def test_validated_layout_rewrite_normalizes_post_render_advertised_counts(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_ready: Offset field rewrite candidate for context: 13 typed dereference(s) across 10 offset(s), no rewrite blockers found. Source provenance generic_parameter_trust from context. Audit only; body rewrite was not applied. confidence=0.80
      - inferred_offset_rewrite_preview: Offset field rewrite preview for context: 13 dereference(s) can map to 10 field alias(es) field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48, .... Source provenance generic_parameter_trust from context. Preview artifact only; body rewrite was not applied. confidence=0.78
*/
__int64 __fastcall LayoutPreviewNormalize(__int64 context)
{
  return *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32)
       + *(_QWORD *)(context + 40)
       + *(_QWORD *)(context + 56)
       + *(_QWORD *)(context + 64)
       + *(_QWORD *)(context + 72)
       + *(_QWORD *)(context + 80)
       + *(_QWORD *)(context + 88)
       + *(_QWORD *)(context + 16)
       + *(_QWORD *)(context + 24)
       + *(_QWORD *)(context + 32);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPreviewNormalize(__int64 context)
{
  return context;
}
""",
                name="LayoutPreviewNormalize",
                ea=0x140002400,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual("applied", preview_metadata["canonical_rewrite_status"])
            self.assertEqual(1, len(preview_metadata["advertisement_normalizations"]))
            self.assertEqual(
                {
                    "base": "context",
                    "original_accesses": 13,
                    "original_fields": 10,
                    "normalized_accesses": 12,
                    "normalized_fields": 9,
                },
                preview_metadata["advertisement_normalizations"][0],
            )
            self.assertEqual(12, preview_metadata["preview_plans"][0]["advertised_access_count"])
            self.assertEqual(9, preview_metadata["preview_plans"][0]["advertised_field_count"])
            self.assertIn("context->field_58 /* _QWORD +0x58 */", cleaned_output)
            self.assertIn("12 typed dereference(s) across 9 offset(s)", cleaned_output)
            self.assertIn("12 dereference(s) can map to 9 field alias(es)", cleaned_output)
            self.assertNotIn("field_30,", cleaned_output)

    def test_partial_layout_rewrite_normalizes_post_render_advertised_counts(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for context: 13 safe dereference(s) across 10 safe offset(s), 2 excluded dereference(s) across 1 excluded offset(s), safe fields field_10, field_18, field_20, field_28, field_30, field_38, field_40, field_48, .... Safe offsets +0x10, +0x18, +0x20, +0x28, +0x30, +0x38, +0x40, +0x48, +0x50, +0x58; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall LayoutPartialPreviewNormalize(__int64 context)
{
  return *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x18)
       + *(_QWORD *)(context + 0x20)
       + *(_QWORD *)(context + 0x28)
       + *(_QWORD *)(context + 0x38)
       + *(_QWORD *)(context + 0x40)
       + *(_QWORD *)(context + 0x48)
       + *(_QWORD *)(context + 0x50)
       + *(_QWORD *)(context + 0x58)
       + *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x18)
       + *(_QWORD *)(context + 0x20)
       + *(_BYTE *)(context + 0x206)
       + *(_WORD *)(context + 0x206);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPartialPreviewNormalize(__int64 context)
{
  return context;
}
""",
                name="LayoutPartialPreviewNormalize",
                ea=0x140002450,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual("applied_partial", preview_metadata["canonical_rewrite_status"])
            self.assertEqual(1, len(preview_metadata["advertisement_normalizations"]))
            self.assertEqual(
                {
                    "base": "context",
                    "plan_kind": "partial",
                    "original_accesses": 13,
                    "original_fields": 10,
                    "normalized_accesses": 12,
                    "normalized_fields": 9,
                    "original_allowed_offsets": [0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58],
                    "normalized_allowed_offsets": [0x10, 0x18, 0x20, 0x28, 0x38, 0x40, 0x48, 0x50, 0x58],
                },
                preview_metadata["advertisement_normalizations"][0],
            )
            self.assertEqual(12, preview_metadata["preview_plans"][0]["advertised_access_count"])
            self.assertEqual(9, preview_metadata["preview_plans"][0]["advertised_field_count"])
            self.assertEqual(
                [0x10, 0x18, 0x20, 0x28, 0x38, 0x40, 0x48, 0x50, 0x58],
                preview_metadata["preview_plans"][0]["allowed_offsets"],
            )
            self.assertIn("12 safe dereference(s) across 9 safe offset(s)", cleaned_output)
            self.assertIn("Safe offsets +0x10, +0x18, +0x20, +0x28, +0x38", cleaned_output)
            self.assertNotIn("context->field_30", cleaned_output)
            self.assertIn("*(_BYTE *)(context + 0x206)", cleaned_output)

    def test_partial_layout_rewrite_handles_pointer_to_pointer_accesses(self) -> None:
        cleaned_text = """
/*
    Kernel insights:
      - inferred_offset_rewrite_partial_opportunity: Offset field partial rewrite opportunity for context: 12 safe dereference(s) across 8 safe offset(s), 1 excluded dereference(s) across 1 excluded offset(s), safe fields field_10, field_18, field_20, field_28, field_40, field_48, field_50, field_58. Safe offsets +0x10, +0x18, +0x20, +0x28, +0x40, +0x48, +0x50, +0x58; excluded offsets +0x206. Excluded reasons one or more offsets mix narrow subfield access widths. Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented. confidence=0.77
*/
__int64 __fastcall LayoutPointerPreviewNormalize(__int64 context)
{
  return *(_QWORD *)(context + 0x10)
       + *(_QWORD *)(context + 0x18)
       + *(_DWORD *)(context + 0x20)
       + *(_DWORD *)(context + 0x28)
       + *(_BYTE *)(context + 0x40)
       + **(_DWORD **)(context + 0x48)
       + *(_QWORD **)(context + 0x50)
       + *(_QWORD *)(context + 0x58)
       + *(_QWORD *)(context + 0x10)
       + **(_DWORD **)(context + 0x48)
       + *(_QWORD **)(context + 0x50)
       + *(_QWORD *)(context + 0x58)
       + *(_BYTE *)(context + 0x206);
}
""".lstrip()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                """
__int64 __fastcall LayoutPointerPreviewNormalize(__int64 context)
{
  return context;
}
""",
                name="LayoutPointerPreviewNormalize",
                ea=0x140002460,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                cleaned_text=cleaned_text,
                apply_validated_layout_rewrites=True,
            )

            cleaned_output = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            preview_metadata = json.loads(Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8"))
            self.assertEqual("passed", preview_metadata["validation"]["status"])
            self.assertEqual("applied_partial", preview_metadata["canonical_rewrite_status"])
            self.assertEqual([], preview_metadata["canonical_rewrite_errors"])
            self.assertIn("*context->field_48 /* _DWORD * +0x48 */", cleaned_output)
            self.assertIn("context->field_50 /* _QWORD * +0x50 */", cleaned_output)
            self.assertIn("*(_BYTE *)(context + 0x206)", cleaned_output)

    def test_legacy_render_export_import_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = legacy_render_write_export_bundle(temp_dir, capture, plan)

            self.assertTrue(Path(artifacts["cleaned_pseudocode"]).exists())
            self.assertTrue(Path(artifacts["summary"]).exists())


if __name__ == "__main__":
    unittest.main()
