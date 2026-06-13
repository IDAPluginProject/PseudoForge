from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder, query
from tools.kernel_corpus.answer_eval import (
    ANSWER_EVAL_CASES_SCHEMA_VERSION,
    ANSWER_EVAL_REPORT_SCHEMA_VERSION,
    DEFAULT_CASES_PATH,
    run_answer_eval,
    write_report,
)
from tools.kernel_corpus.errors import QueryError


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusAnswerEvalTests(unittest.TestCase):
    def test_default_case_manifest_contains_required_seed_topics(self) -> None:
        payload = json.loads(DEFAULT_CASES_PATH.read_text(encoding="utf-8"))
        cases = payload["cases"]
        case_ids = {case["id"] for case in cases}

        self.assertEqual(ANSWER_EVAL_CASES_SCHEMA_VERSION, payload["schema"])
        self.assertGreaterEqual(len(cases), 10)
        self.assertTrue(
            {
                "process_object_lifecycle",
                "thread_object_lifecycle",
                "remote_process_access",
                "file_object_lifecycle",
                "image_load_visibility",
                "registry_callback_notify",
                "pool_allocation_tag_tracking",
                "irp_cancellation",
                "driver_load_unload",
                "token_impersonation",
            }.issubset(case_ids)
        )
        for case in cases:
            self.assertIn("expected_canonical_topic_ids", case)
            self.assertIn("allowed_fallback_tools", case)
            self.assertIn("required_function_name_regexes", case)
            self.assertIn("required_citation_fields", payload["defaults"])

    def test_eval_passes_fixture_plan_and_answer(self) -> None:
        with _built_pack() as pack_root:
            topic = _write_canonical_topic(
                pack_root,
                topic_id="process_object_lifecycle",
                question="Explain process object lifecycle.",
                functions=["0x140001000", "0x140002000"],
            )
            cases_path = _write_cases(
                pack_root,
                [
                    _case(
                        "process_case",
                        "Explain process object lifecycle.",
                        ["process_object_lifecycle"],
                        ["^NtCreateUserProcess$", "^PspAllocateProcess$"],
                    )
                ],
            )
            answers_dir = pack_root / "answers"
            answers_dir.mkdir()
            first, second = topic["evidence_pack"]["functions"]
            (answers_dir / "process_case.md").write_text(
                "\n".join(
                    [
                        "Major functions:",
                        "- `%s` `%s`: entry. Artifact: `%s`. Inference: confirmed corpus evidence."
                        % (first["ea"], first["name"], first["artifacts"]["summary"]),
                        "- `%s` `%s`: allocation. Artifact: `%s`. Inference: confirmed corpus evidence."
                        % (second["ea"], second["name"], second["artifacts"]["summary"]),
                    ]
                ),
                encoding="utf-8",
            )

            report = run_answer_eval(pack_root, cases_path=cases_path, answers_dir=answers_dir)

            self.assertEqual(ANSWER_EVAL_REPORT_SCHEMA_VERSION, report["schema"])
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["pass_count"])
            self.assertEqual("pass", report["cases"][0]["status"])
            self.assertEqual(["process_object_lifecycle"], report["cases"][0]["plan"]["selected_canonical_topic_ids"])

    def test_missing_ea_function_or_artifact_citation_fails(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_topic(
                pack_root,
                topic_id="process_object_lifecycle",
                question="Explain process object lifecycle.",
                functions=["0x140001000", "0x140002000"],
            )
            cases_path = _write_cases(
                pack_root,
                [
                    _case(
                        "process_case",
                        "Explain process object lifecycle.",
                        ["process_object_lifecycle"],
                        ["^NtCreateUserProcess$", "^PspAllocateProcess$"],
                    )
                ],
            )
            answers_dir = pack_root / "answers"
            answers_dir.mkdir()
            (answers_dir / "process_case.md").write_text(
                "Major functions:\n- NtCreateUserProcess creates a process without corpus evidence.\n",
                encoding="utf-8",
            )

            report = run_answer_eval(pack_root, cases_path=cases_path, answers_dir=answers_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(1, report["fail_count"])
            codes = _failure_codes(report["cases"][0])
            self.assertIn("answer_harness_warnings", codes)
            self.assertIn("missing_answer_ea", codes)
            self.assertIn("missing_answer_artifact_path", codes)
            self.assertIn("forbidden_answer_pattern", codes)

    def test_degraded_canonical_answer_without_caveat_fails(self) -> None:
        with _built_pack() as pack_root:
            topic = _write_canonical_topic(
                pack_root,
                topic_id="remote_process_access_flow",
                question="Explain remote process access through PspAllocateProcess.",
                functions=["0x140002000"],
                priority="P1",
                status="degraded",
                score=62,
                gap_count=1,
            )
            cases_path = _write_cases(
                pack_root,
                [
                    _case(
                        "remote_case",
                        "Explain remote process access through PspAllocateProcess.",
                        ["remote_process_access_flow"],
                        ["^PspAllocateProcess$"],
                        allow_degraded=True,
                        stale_degraded="must_caveat",
                    )
                ],
            )
            answers_dir = pack_root / "answers"
            answers_dir.mkdir()
            function = topic["evidence_pack"]["functions"][0]
            (answers_dir / "remote_case.md").write_text(
                "\n".join(
                    [
                        "Major functions:",
                        "- `%s` `%s`: remote access claim. Artifact: `%s`. Inference: confirmed corpus evidence."
                        % (function["ea"], function["name"], function["artifacts"]["summary"]),
                        "",
                        "Gaps:",
                        "- None.",
                    ]
                ),
                encoding="utf-8",
            )

            report = run_answer_eval(pack_root, cases_path=cases_path, answers_dir=answers_dir)

            self.assertFalse(report["ok"])
            self.assertIn("low_quality_or_stale_without_caveat", _failure_codes(report["cases"][0]))

    def test_unknown_topic_routes_to_live_retrieval_without_false_canonical_match(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_topic(
                pack_root,
                topic_id="process_object_lifecycle",
                question="Explain process object lifecycle.",
                functions=["0x140001000", "0x140002000"],
            )
            cases_path = _write_cases(
                pack_root,
                [
                    {
                        "id": "unknown_case",
                        "question": "Explain GPU scheduler DMA remapping policy.",
                        "expected_canonical_topic_ids": [],
                        "allowed_fallback_tools": ["corpus_status", "search_functions"],
                        "required_function_name_regexes": [],
                        "required_citation_fields": ["ea", "function_name", "artifact_path"],
                        "forbidden_answer_patterns": [],
                        "expected_gap_behavior": "optional",
                        "stale_degraded_handling_expectation": "none",
                    }
                ],
            )

            report = run_answer_eval(pack_root, cases_path=cases_path)
            case = report["cases"][0]

            self.assertTrue(report["ok"])
            self.assertEqual(0, report["fail_count"])
            self.assertEqual([], case["plan"]["selected_canonical_topic_ids"])
            self.assertIn("search_functions", case["plan"]["live_tools"])

    def test_report_ordering_and_output_path_are_stable_and_bounded(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_topic(
                pack_root,
                topic_id="process_object_lifecycle",
                question="Explain process object lifecycle.",
                functions=["0x140001000", "0x140002000"],
            )
            cases_path = _write_cases(
                pack_root,
                [
                    _case("z_case", "Explain process object lifecycle.", ["process_object_lifecycle"], ["^NtCreateUserProcess$"]),
                    _case("a_case", "Explain process object lifecycle.", ["process_object_lifecycle"], ["^NtCreateUserProcess$"]),
                ],
            )
            report = run_answer_eval(pack_root, cases_path=cases_path)
            output_path = pack_root / "answer-eval" / "answer-eval-report.md"
            written = write_report(report, output_path, requested_format="markdown")

            self.assertEqual(["a_case", "z_case"], [case["case_id"] for case in report["cases"]])
            self.assertEqual(str(output_path.resolve()), written)
            self.assertTrue(output_path.is_file())
            self.assertLess(output_path.stat().st_size, 20000)
            with self.assertRaises(QueryError):
                write_report(report, pack_root.parent / "outside.md", requested_format="markdown")


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _write_cases(pack_root: Path, cases: list[dict[str, Any]]) -> Path:
    path = pack_root / "answer-eval-cases.json"
    path.write_text(
        json.dumps(
            {
                "schema": ANSWER_EVAL_CASES_SCHEMA_VERSION,
                "defaults": {
                    "required_citation_fields": ["ea", "function_name", "artifact_path"],
                    "expected_gap_behavior": "require_gap_section_when_gaps_present",
                    "stale_degraded_handling_expectation": "exclude_or_caveat",
                    "forbidden_answer_patterns": ["without corpus evidence"],
                },
                "cases": cases,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _case(
    case_id: str,
    question: str,
    topic_ids: list[str],
    required_functions: list[str],
    *,
    allow_degraded: bool = False,
    stale_degraded: str = "exclude_or_caveat",
) -> dict[str, Any]:
    return {
        "id": case_id,
        "question": question,
        "expected_canonical_topic_ids": topic_ids,
        "allowed_fallback_tools": [
            "corpus_status",
            "get_canonical_answer",
            "find_canonical_answers",
            "trace_lifecycle",
            "get_atlas_page",
            "search_functions",
            "build_evidence_pack",
        ],
        "required_function_name_regexes": required_functions,
        "required_citation_fields": ["ea", "function_name", "artifact_path"],
        "forbidden_answer_patterns": ["without corpus evidence"],
        "expected_gap_behavior": "require_gap_section_when_gaps_present",
        "stale_degraded_handling_expectation": stale_degraded,
        "allow_degraded_canonical": allow_degraded,
    }


def _write_canonical_topic(
    pack_root: Path,
    *,
    topic_id: str,
    question: str,
    functions: list[str],
    priority: str = "P0",
    status: str = "pass",
    score: int = 95,
    gap_count: int = 0,
) -> dict[str, Any]:
    canonical_root = pack_root / "canonical-answers"
    topic_dir = canonical_root / priority / topic_id
    topic_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = topic_dir / "evidence-pack.json"
    evidence_pack = query.build_evidence_pack(pack_root, functions, topic_id, output_path=evidence_path)
    if gap_count:
        evidence_pack["gaps"] = ["fixture degraded gap"]
        evidence_path.write_text(json.dumps(evidence_pack, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    pack_manifest = json.loads((pack_root / "manifest.json").read_text(encoding="utf-8"))
    source_hash = str(pack_manifest.get("source_index_sha256", ""))
    pack_generated_at = str(pack_manifest.get("generated_at", ""))
    selected_functions = [function["name"] for function in evidence_pack.get("functions", [])]
    edges = evidence_pack.get("edges", [])

    (topic_dir / "answer.md").write_text("# %s\n\nFixture answer.\n" % topic_id, encoding="utf-8")
    (topic_dir / "quality.md").write_text("# Quality\n\nstatus=%s\n" % status, encoding="utf-8")
    (topic_dir / "gaps.md").write_text("- fixture gap\n" if gap_count else "- none\n", encoding="utf-8")
    (topic_dir / "source-map.md").write_text("- fixture source\n", encoding="utf-8")
    (topic_dir / "trace.json").write_text(
        json.dumps({"schema": "kernel_corpus_canonical_trace_v1", "selected_candidates": evidence_pack.get("functions", [])}, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (topic_dir / "validation.json").write_text(
        json.dumps({"passed": status != "fail", "warning_count": 0}, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    quality = {
        "topic_id": topic_id,
        "priority": priority,
        "mode": "focused",
        "directory": str(topic_dir.resolve()),
        "status": status,
        "score": score,
        "selected_function_count": len(selected_functions),
        "edge_count": len(edges),
        "validation_warning_count": 0,
        "gap_count": gap_count,
    }
    (topic_dir / "quality.json").write_text(json.dumps(quality, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    (topic_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_artifact_v1",
                "topic": {
                    "id": topic_id,
                    "priority": priority,
                    "title": topic_id.replace("_", " ").title(),
                    "mode": "focused",
                    "question": question,
                },
                "source_index_sha256": source_hash,
                "pack_generated_at": pack_generated_at,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    topics = [
        {
            "id": topic_id,
            "priority": priority,
            "mode": "focused",
            "directory": str(topic_dir.resolve()),
        }
    ]
    report_topics = [quality]
    if (canonical_root / "index.json").is_file():
        existing_index = json.loads((canonical_root / "index.json").read_text(encoding="utf-8"))
        topics = [item for item in existing_index.get("topics", []) if item.get("id") != topic_id] + topics
    if (canonical_root / "quality-report.json").is_file():
        existing_report = json.loads((canonical_root / "quality-report.json").read_text(encoding="utf-8"))
        report_topics = [item for item in existing_report.get("topics", []) if item.get("topic_id") != topic_id] + report_topics
    canonical_root.mkdir(parents=True, exist_ok=True)
    (canonical_root / "index.json").write_text(
        json.dumps({"schema": "kernel_corpus_canonical_answer_run_v1", "topics": topics}, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (canonical_root / "quality-report.json").write_text(
        json.dumps({"schema": "kernel_corpus_canonical_quality_report_v1", "topics": report_topics}, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (canonical_root / "quality-report.md").write_text("# Fixture Quality\n", encoding="utf-8")
    return {
        "topic_dir": topic_dir,
        "evidence_pack": evidence_pack,
    }


def _failure_codes(case: dict[str, Any]) -> set[str]:
    return {failure["code"] for failure in case["failures"]}


if __name__ == "__main__":
    unittest.main()
