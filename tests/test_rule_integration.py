from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tests.rule_test_helpers import (
    _call_arg_rewrite_rule,
    _rename_rule,
    _rule_pack,
)


RESOURCE_PAIR_SAMPLE = r"""
__int64 __fastcall RuleIntegrationResourceSample(void *Resource)
{
  ExAcquireResourceExclusiveLite(Resource, 1u);
  ExReleaseResourceLite(Resource);
  return 0;
}
"""


class RuleIntegrationTests(unittest.TestCase):
    def test_build_clean_plan_reports_v2_call_arg_rewrites_without_plan_conversion(self) -> None:
        sample = """
__int64 __fastcall ProjectCallArgReportSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  return 0;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            rules_dir = temp_path / "pseudoforge_rules"
            rules_dir.mkdir()
            (rules_dir / "call_arg_report.json").write_text(
                json.dumps(_rule_pack([_call_arg_rewrite_rule()], schema_version=2)),
                encoding="utf-8",
            )
            capture = capture_from_pseudocode(sample, source_path=str(temp_path / "sample.cpp"))
            plan = build_clean_plan(capture, rule_dirs=[rules_dir])

            rewrites = plan.rule_report["rewrite_emissions"]
            self.assertEqual(1, len(rewrites))
            self.assertEqual("applied", rewrites[0]["status"])
            self.assertEqual("call_arg_rewrite", rewrites[0]["kind"])
            self.assertTrue(rewrites[0]["preview_only"])
            self.assertEqual("ProbeForRead", rewrites[0]["payload"]["function_name"])
            self.assertFalse(any(item.source == "rule" for item in plan.renames))
            self.assertFalse(any("Deterministic rule emission rejected" in warning for warning in plan.warnings))
            rendered = render_cleaned_pseudocode(capture, plan)
            self.assertIn("ProbeForRead(inputBuffer, 8, 1);", rendered)
            self.assertNotIn("sizeof(*inputBuffer)", rendered)

    def test_builtin_call_arg_rewrite_report_mirrors_boolean_kernel_api_cleanup(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall BuiltinCallArgReportSample(void *NotifyRoutine)
{
  PsSetCreateProcessNotifyRoutine(NotifyRoutine, 1u);
  PspSetCreateProcessNotifyRoutine(NotifyRoutine, 0u);
  return 0;
}
"""
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        rewrites = [
            item
            for item in plan.rule_report["rewrite_emissions"]
            if str(item.get("rule_id", "")).startswith("builtin.call_arg.ps")
        ]
        reported = {
            (item["payload"]["function_name"], item["payload"]["replacement"], item["status"])
            for item in rewrites
        }

        self.assertEqual(
            {
                ("PsSetCreateProcessNotifyRoutine", "TRUE", "applied"),
                ("PspSetCreateProcessNotifyRoutine", "FALSE", "applied"),
            },
            reported,
        )
        self.assertIn("PsSetCreateProcessNotifyRoutine(NotifyRoutine, TRUE);", rendered)
        self.assertIn("PspSetCreateProcessNotifyRoutine(NotifyRoutine, FALSE);", rendered)
        self.assertFalse(any("Deterministic rule emission rejected" in warning for warning in plan.warnings))

    def test_rule_rename_source_cannot_spoof_kernel_status(self) -> None:
        sample = """
__int64 __fastcall RuleSourceSpoofSample()
{
  unsigned int v1;

  v1 = 3221225485;
  return v1;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            rule_path = Path(temp_dir) / "spoof_rule.json"
            rule_path.write_text(
                json.dumps(
                    _rule_pack(
                        [
                            _rename_rule(
                                rule_id="project.spoof.status",
                                pattern=r"\b(?P<dst>v1)\s*=\s*3221225485\b",
                                new_name="status",
                                source="kernel-status",
                                scope_text="v1 = 3221225485",
                            )
                        ]
                    )
                ),
                encoding="utf-8",
            )
            capture = capture_from_pseudocode(sample)
            plan = build_clean_plan(capture, rule_dirs=[temp_dir])
            rename = next(item for item in plan.renames if item.old == "v1" and item.apply)
            rendered = render_cleaned_pseudocode(capture, plan)

            self.assertEqual(rename.source, "rule")
            self.assertIn("unsigned int status;", rendered)
            self.assertNotIn("NTSTATUS status;", rendered)

    def test_builtin_rule_comments_are_deduped_with_existing_kernel_comments(self) -> None:
        capture = capture_from_pseudocode(RESOURCE_PAIR_SAMPLE)
        plan = build_clean_plan(capture)
        comments = [(item.get("kind"), item.get("text")) for item in plan.comments]

        self.assertEqual(
            comments.count(("resource", "ERESOURCE exclusive acquisition with common release tail")),
            1,
        )
        self.assertTrue(plan.rule_report["matched_rules"])

    def test_project_local_rule_directory_can_add_rename_without_core_code_change(self) -> None:
        sample = """
__int64 __fastcall ProjectRuleSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            rule_path = Path(temp_dir) / "project_rule.json"
            rule_path.write_text(
                json.dumps(
                    _rule_pack(
                        [
                            _rename_rule(
                                rule_id="project.rename.v1",
                                pattern=r"\b(?P<dst>v1)\s*=\s*a1\b",
                                new_name="projectInput",
                            )
                        ]
                    )
                ),
                encoding="utf-8",
            )
            capture = capture_from_pseudocode(sample)
            plan = build_clean_plan(capture, rule_dirs=[temp_dir])
            rename_map = {item.old: item.new for item in plan.renames if item.apply}

            self.assertEqual(rename_map["v1"], "projectInput")
            self.assertTrue(
                any(item["rule_id"] == "project.rename.v1" for item in plan.rule_report["matched_rules"])
            )
            self.assertNotIn(temp_dir, json.dumps(plan.rule_report))

    def test_project_rule_directory_is_resolved_from_capture_source_path(self) -> None:
        sample = """
__int64 __fastcall SourcePathRuleSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            rules_dir = temp_path / "pseudoforge_rules"
            rules_dir.mkdir()
            (rules_dir / "source_path_rule.json").write_text(
                json.dumps(
                    _rule_pack(
                        [
                            _rename_rule(
                                rule_id="source.path.rename.v1",
                                pattern=r"\b(?P<dst>v1)\s*=\s*a1\b",
                                new_name="sourcePathInput",
                            )
                        ]
                    )
                ),
                encoding="utf-8",
            )
            capture = capture_from_pseudocode(sample, source_path=str(temp_path / "sample.cpp"))
            plan = build_clean_plan(capture)
            rename_map = {item.old: item.new for item in plan.renames if item.apply}

            self.assertEqual(rename_map["v1"], "sourcePathInput")
            self.assertTrue(
                any(item.get("source") == "project/source_path_rule.json" for item in plan.rule_report["matched_rules"])
            )

    def test_duplicate_project_rule_directory_is_loaded_once(self) -> None:
        sample = """
__int64 __fastcall DuplicateRuleDirSample(int a1)
{
  int v1;

  v1 = a1;
  return v1;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            rules_dir = temp_path / "pseudoforge_rules"
            rules_dir.mkdir()
            (rules_dir / "duplicate_dir_rule.json").write_text(
                json.dumps(
                    _rule_pack(
                        [
                            _rename_rule(
                                rule_id="duplicate.dir.rename.v1",
                                pattern=r"\b(?P<dst>v1)\s*=\s*a1\b",
                                new_name="dedupedInput",
                            )
                        ]
                    )
                ),
                encoding="utf-8",
            )
            capture = capture_from_pseudocode(sample, source_path=str(temp_path / "sample.cpp"))
            plan = build_clean_plan(capture, rule_dirs=[rules_dir])
            matched = [
                item
                for item in plan.rule_report["matched_rules"]
                if item.get("rule_id") == "duplicate.dir.rename.v1"
            ]

            self.assertEqual(len(matched), 1)
            self.assertFalse(plan.rule_report["rejected_emissions"])


if __name__ == "__main__":
    unittest.main()
