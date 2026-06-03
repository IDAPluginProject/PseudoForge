from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.deterministic.validators import validate_rule_pack_data
from tools import pseudoforge_rule_author


SAMPLE = """
__int64 __fastcall RuleAuthoringSample(void *inputBuffer)
{
  int v1;

  v1 = ProbeForRead(inputBuffer, 8, 1);
  return v1;
}
"""


class RuleAuthoringTests(unittest.TestCase):
    def test_authoring_facts_command_dumps_rule_context_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "sample.cpp"
            input_path.write_text(SAMPLE, encoding="utf-8")

            result = _run_authoring(["facts", str(input_path)])

            self.assertEqual(0, result.exit_code)
            payload = json.loads(result.stdout)
            self.assertEqual("RuleAuthoringSample", payload["function"]["name"])
            self.assertTrue(any(item["name"] == "ProbeForRead" for item in payload["call_sites"]))
            self.assertTrue(any(item["target"] == "v1" for item in payload["assignments"]))

    def test_authoring_run_command_reports_matches_misses_and_redacted_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "sample.cpp"
            rules_path = temp_path / "rules.json"
            input_path.write_text(SAMPLE, encoding="utf-8")
            rules_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "id": "test.authoring",
                        "description": "authoring test rules",
                        "rules": [
                            {
                                "id": "test.rename.typed",
                                "phase": "rename",
                                "priority": 100,
                                "confidence": 0.93,
                                "scope": {"call_site": {"function_name": "ProbeForRead"}},
                                "match": {"assignment": {"rhs_call_name": "ProbeForRead"}},
                                "emit": {
                                    "kind": "rename",
                                    "rename_kind": "lvar",
                                    "target": "$assignment_target",
                                    "new_name": "probeStatus",
                                },
                            },
                            {
                                "id": "test.rename.missed",
                                "phase": "rename",
                                "priority": 100,
                                "confidence": 0.93,
                                "scope": {"lvar": {"name": "missingLocal"}},
                                "match": {"lvar": {"name": "missingLocal"}},
                                "emit": {
                                    "kind": "rename",
                                    "rename_kind": "lvar",
                                    "target": "$lvar",
                                    "new_name": "missingRole",
                                },
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = _run_authoring(["run", str(input_path), "--rules", str(rules_path), "--phase", "rename", "--explain"])

            self.assertEqual(0, result.exit_code)
            payload = json.loads(result.stdout)
            self.assertEqual([("v1", "probeStatus")], [(item["payload"]["target"], item["payload"]["new_name"]) for item in payload["emissions"]])
            self.assertTrue(any(item["rule_id"] == "test.rename.missed" for item in payload["rule_report"]["missed_rules"]))
            self.assertNotIn(temp_dir, json.dumps(payload))
            self.assertIn("external/rules.json", json.dumps(payload))

    def test_authoring_run_command_preserves_file_and_directory_source_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "sample.cpp"
            first_rules_path = temp_path / "first.json"
            second_rules_dir = temp_path / "pseudoforge_rules"
            second_rules_dir.mkdir()
            second_rules_path = second_rules_dir / "second.json"
            input_path.write_text(SAMPLE, encoding="utf-8")
            first_rules_path.write_text(
                json.dumps(_rename_pack("z.file", "fileName")),
                encoding="utf-8",
            )
            second_rules_path.write_text(
                json.dumps(_rename_pack("a.dir", "dirName")),
                encoding="utf-8",
            )

            result = _run_authoring(
                [
                    "run",
                    str(input_path),
                    "--rules",
                    str(first_rules_path),
                    "--rules",
                    str(second_rules_dir),
                    "--phase",
                    "rename",
                ]
            )

            self.assertEqual(0, result.exit_code)
            payload = json.loads(result.stdout)
            self.assertEqual("dirName", payload["emissions"][0]["payload"]["new_name"])

    def test_authoring_scaffold_command_prints_valid_rule_pack(self) -> None:
        result = _run_authoring(["scaffold", "assignment-rename", "--pack-id", "project.generated"])

        self.assertEqual(0, result.exit_code)
        payload = json.loads(result.stdout)
        self.assertEqual("project.generated", payload["id"])
        self.assertEqual([], validate_rule_pack_data(payload))

    def test_authoring_scaffold_command_can_write_utf8_rule_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "pseudoforge_rules" / "generated.json"

            result = _run_authoring(["scaffold", "semantic-comment", "--out", str(output_path)])

            self.assertEqual(0, result.exit_code)
            self.assertTrue(output_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual([], validate_rule_pack_data(payload))
            self.assertIn(str(output_path), result.stdout)


class _CliResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def _run_authoring(argv: list[str]) -> _CliResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = pseudoforge_rule_author.main(argv)
    return _CliResult(exit_code, stdout.getvalue(), stderr.getvalue())


def _rename_pack(rule_id: str, new_name: str) -> dict:
    return {
        "schema_version": 2,
        "id": "test.authoring.order",
        "description": "authoring source order test",
        "rules": [
            {
                "id": rule_id,
                "phase": "rename",
                "priority": 100,
                "confidence": 0.90,
                "scope": {"lvar": {"name": "v1"}},
                "match": {"lvar": {"name": "v1"}},
                "emit": {
                    "kind": "rename",
                    "rename_kind": "lvar",
                    "target": "$lvar",
                    "new_name": new_name,
                },
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
