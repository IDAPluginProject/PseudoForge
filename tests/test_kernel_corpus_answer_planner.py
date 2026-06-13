from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder
from tools.kernel_corpus.answer_planner import ANSWER_PLAN_SCHEMA_VERSION, build_answer_plan, write_plan
from tools.kernel_corpus.errors import QueryError
from tools.kernel_corpus.mcp_server import KernelCorpusMcpServer

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusAnswerPlannerTests(unittest.TestCase):
    def test_korean_process_lifecycle_question_routes_to_canonical_topic(self) -> None:
        with _built_minimal_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            payload = build_answer_plan(
                pack_root,
                "이 커널에서 프로세스 오브젝트가 생성되고 사라질 때까지 주요 함수 기준으로 설명해줘",
            )

            self.assertEqual(ANSWER_PLAN_SCHEMA_VERSION, payload["schema"])
            self.assertEqual("process_object_lifecycle", payload["canonical_candidates"][0]["topic_id"])
            self.assertEqual("pass", payload["canonical_candidates"][0]["quality"]["status"])
            self.assertIn("process_object", payload["routing"]["lifecycle_topics"])
            self.assertIn("process_lifecycle", payload["routing"]["korean_mappings"])
            self.assertNotIn("thread_lifecycle", payload["routing"]["korean_mappings"])
            self.assertIn("get_canonical_answer", _step_tools(payload))
            self.assertIn("trace_lifecycle", _step_tools(payload))
            self.assertTrue(any("canonical topic id" in item for item in payload["citation_contract"]["required"]))

    def test_remote_process_question_uses_degraded_gate_and_live_function_search(self) -> None:
        functions = [
            _function("0x140010000", "NtOpenProcess", ["process_thread", "security"], ["remote process open"], []),
            _function("0x140011000", "MmCopyVirtualMemory", ["memory", "process_thread"], ["copy virtual memory"], []),
        ]
        with _built_custom_pack(functions) as pack_root:
            _write_canonical_fixture(pack_root)

            default_payload = build_answer_plan(
                pack_root,
                "Explain remote process access through NtOpenProcess and MmCopyVirtualMemory.",
            )
            allowed_payload = build_answer_plan(
                pack_root,
                "Explain remote process access through NtOpenProcess and MmCopyVirtualMemory.",
                allow_degraded=True,
            )

            self.assertNotIn(
                "remote_process_access_flow",
                [topic["topic_id"] for topic in default_payload["canonical_candidates"]],
            )
            self.assertIn(
                "remote_process_access_flow",
                [topic["topic_id"] for topic in default_payload["excluded_canonical_candidates"]],
            )
            self.assertEqual("remote_process_access_flow", allowed_payload["canonical_candidates"][0]["topic_id"])
            self.assertEqual("degraded", allowed_payload["canonical_candidates"][0]["quality"]["status"])
            found_names = {
                function["name"]
                for step in allowed_payload["live_retrieval_steps"]
                for function in step.get("found_functions", [])
            }
            self.assertTrue({"NtOpenProcess", "MmCopyVirtualMemory"}.issubset(found_names))
            self.assertIn("build_evidence_pack", _step_tools(allowed_payload))

    def test_unknown_topic_returns_live_retrieval_plan(self) -> None:
        with _built_minimal_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            payload = build_answer_plan(pack_root, "Explain GPU scheduler DMA remapping policy.")

            self.assertEqual([], payload["canonical_candidates"])
            self.assertIn("search_functions", _step_tools(payload))
            self.assertIn("No selected passing canonical topic", " ".join(payload["stop_conditions"]))
            self.assertGreaterEqual(len(payload["live_retrieval_steps"]), 2)

    def test_degraded_canonical_topics_are_included_only_when_requested(self) -> None:
        with _built_minimal_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            default_payload = build_answer_plan(pack_root, "remote process access flow")
            allowed_payload = build_answer_plan(pack_root, "remote process access flow", allow_degraded=True)

            self.assertNotIn("remote_process_access_flow", [item["topic_id"] for item in default_payload["canonical_candidates"]])
            self.assertIn("remote_process_access_flow", [item["topic_id"] for item in default_payload["excluded_canonical_candidates"]])
            self.assertIn("remote_process_access_flow", [item["topic_id"] for item in allowed_payload["canonical_candidates"]])
            self.assertTrue(any("Degraded canonical topic excluded" in warning for warning in default_payload["warnings"]))

    def test_output_ordering_truncation_and_plan_out_are_stable(self) -> None:
        with _built_minimal_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            first = build_answer_plan(pack_root, "process", max_topics=1)
            second = build_answer_plan(pack_root, "process", max_topics=1)
            output_path = pack_root / "answer-plans" / "process.md"
            written_path = write_plan(first, output_path, requested_format="markdown")

            self.assertEqual([item["topic_id"] for item in first["canonical_candidates"]], [item["topic_id"] for item in second["canonical_candidates"]])
            self.assertEqual(1, len(first["canonical_candidates"]))
            self.assertTrue(first["canonical_candidates_truncated"])
            self.assertEqual("process_object_lifecycle", first["canonical_candidates"][0]["topic_id"])
            self.assertEqual(str(output_path.resolve()), written_path)
            self.assertTrue(output_path.is_file())
            self.assertIn("# Kernel Answer Plan", output_path.read_text(encoding="utf-8"))
            with self.assertRaises(QueryError):
                write_plan(first, pack_root.parent / "outside.md", requested_format="markdown")

    def test_mcp_plan_kernel_answer_returns_compact_plan(self) -> None:
        with _built_minimal_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            payload = server.call_tool(
                "plan_kernel_answer",
                {
                    "question": "process object lifecycle",
                    "max_topics": 1,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual(ANSWER_PLAN_SCHEMA_VERSION, payload["schema_version"])
            self.assertEqual("process_object_lifecycle", payload["canonical_candidates"][0]["topic_id"])
            self.assertIn("live_retrieval_steps", payload)
            self.assertNotIn("answer", payload)


@contextlib.contextmanager
def _built_minimal_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


@contextlib.contextmanager
def _built_custom_pack(functions: list[dict[str, Any]]):
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        corpus_root = root / "corpus"
        pack_root = root / "pack"
        _write_corpus(corpus_root, functions)
        builder.build_pack(corpus_root, pack_root)
        yield pack_root


def _write_canonical_fixture(pack_root: Path) -> None:
    root = pack_root / "canonical-answers"
    specs = [
        {
            "topic_id": "process_object_lifecycle",
            "priority": "P0",
            "mode": "lifecycle",
            "title": "Process Object Lifecycle",
            "question": "Explain process object lifecycle from canonical evidence.",
            "status": "pass",
            "score": 94,
            "warnings": 0,
            "functions": ["NtCreateUserProcess", "PspAllocateProcess", "PspProcessDelete"],
        },
        {
            "topic_id": "process_identity_lookup",
            "priority": "P1",
            "mode": "focused",
            "title": "Process Identity Lookup",
            "question": "Explain process identity lookup functions.",
            "status": "pass",
            "score": 82,
            "warnings": 0,
            "functions": ["PsLookupProcessByProcessId", "PsGetProcessId"],
        },
        {
            "topic_id": "remote_process_access_flow",
            "priority": "P1",
            "mode": "focused",
            "title": "Remote Process Access Flow",
            "question": "Explain remote process access through NtOpenProcess and memory operations.",
            "status": "degraded",
            "score": 70,
            "warnings": 0,
            "functions": ["NtOpenProcess", "MmCopyVirtualMemory"],
        },
        {
            "topic_id": "p2_review_topic",
            "priority": "P2",
            "mode": "focused",
            "title": "P2 Review Topic",
            "question": "Explain a broad P2 review topic.",
            "status": "fail",
            "score": 45,
            "warnings": 1,
            "functions": ["EtwWrite"],
        },
    ]
    topics = []
    report_topics = []
    for spec in specs:
        topic_dir = root / str(spec["priority"]) / str(spec["topic_id"])
        _write_canonical_topic(topic_dir, spec)
        topics.append(
            {
                "id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
            }
        )
        report_topics.append(
            {
                "topic_id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
                "status": spec["status"],
                "score": spec["score"],
                "selected_function_count": len(spec["functions"]),
                "edge_count": max(0, len(spec["functions"]) - 1),
                "validation_warning_count": spec["warnings"],
                "gap_count": 1,
            }
        )
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_run_v1",
                "source_index_sha256": "fixture-source",
                "pack_generated_at": "2026-06-13T00:00:00+00:00",
                "topics": list(reversed(topics)),
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "quality-report.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_quality_report_v1",
                "topics": report_topics,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "quality-report.md").write_text("# Canonical Quality Report\n", encoding="utf-8")


def _write_canonical_topic(topic_dir: Path, spec: dict[str, Any]) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    topic_id = str(spec["topic_id"])
    functions = [
        {
            "ea": "0x%X" % (0x140000000 + (index * 0x1000)),
            "name": name,
            "tags": ["process_thread"],
            "artifact_paths": {"cleaned": str((topic_dir / "answer.md").resolve())},
        }
        for index, name in enumerate(spec["functions"], start=1)
    ]
    edges = [
        {"src_ea": functions[index]["ea"], "dst_ea": functions[index + 1]["ea"], "edge_kind": "callee"}
        for index in range(max(0, len(functions) - 1))
    ]
    (topic_dir / "answer.md").write_text("# %s\n\nfixture answer\n" % spec["title"], encoding="utf-8")
    (topic_dir / "quality.md").write_text("# Quality\n\nstatus=%s\n" % spec["status"], encoding="utf-8")
    (topic_dir / "gaps.md").write_text("- fixture gap\n", encoding="utf-8")
    (topic_dir / "source-map.md").write_text("- fixture source\n", encoding="utf-8")
    (topic_dir / "evidence-pack.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": topic_id,
                "summary": {
                    "selected_function_count": len(functions),
                    "edge_count": len(edges),
                },
                "functions": functions,
                "edges": edges,
                "gaps": ["fixture gap"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "trace.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_trace_v1",
                "selected_candidates": functions,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "validation.json").write_text(
        json.dumps(
            {
                "passed": int(spec["warnings"]) == 0,
                "warning_count": spec["warnings"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "quality.json").write_text(
        json.dumps(
            {
                "topic_id": topic_id,
                "priority": spec["priority"],
                "mode": spec["mode"],
                "status": spec["status"],
                "score": spec["score"],
                "selected_function_count": len(functions),
                "edge_count": len(edges),
                "validation_warning_count": spec["warnings"],
                "gap_count": 1,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_artifact_v1",
                "topic": {
                    "id": topic_id,
                    "priority": spec["priority"],
                    "title": spec["title"],
                    "mode": spec["mode"],
                    "question": spec["question"],
                },
                "source_index_sha256": "fixture-source",
                "pack_generated_at": "2026-06-13T00:00:00+00:00",
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_corpus(corpus_root: Path, functions: list[dict[str, Any]]) -> None:
    (corpus_root / "functions").mkdir(parents=True)
    index = {
        "schema": "pseudoforge_corpus_index_v1",
        "pseudoforge_version": "test",
        "generated_at": "2026-06-13T00:00:00+00:00",
        "functions": [],
        "overview": {"functions": len(functions), "report_status_counts": {"ok": len(functions)}},
        "metadata": {"target_path": "synthetic.i64"},
        "report_summary": {"status_counts": {"ok": len(functions)}},
    }
    for function in functions:
        item = dict(function)
        stem = "%016x_%s" % (int(str(item["ea"]), 0), item["name"])
        function_dir = corpus_root / "functions" / stem
        function_dir.mkdir(parents=True)
        cleaned = function_dir / "function.cleaned.cpp"
        raw = function_dir / "function.raw.cpp"
        summary = function_dir / "function.ida-batch-summary.json"
        cleaned.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        raw.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        summary.write_text(json.dumps({"ea": item["ea"], "name": item["name"]}, ensure_ascii=True), encoding="utf-8")
        item["directory"] = str(Path("functions") / stem)
        item["summary_path"] = str(Path("functions") / stem / "function.ida-batch-summary.json")
        item["artifacts"] = {
            "cleaned_pseudocode": str(Path("functions") / stem / "function.cleaned.cpp"),
            "raw_pseudocode": str(Path("functions") / stem / "function.raw.cpp"),
            "summary": str(Path("functions") / stem / "function.ida-batch-summary.json"),
        }
        index["functions"].append(item)
    (corpus_root / "pseudoforge-corpus-index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )


def _function(ea: str, name: str, tags: list[str], terms: list[str], callees: list[str]) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "tags": tags,
        "terms": terms,
        "mode": "synthetic",
        "counts": {"warnings": 0, "buffer_contracts": 0},
        "llm_status": "ok",
        "callee_eas": callees,
        "caller_eas": [],
        "imports_called": [],
        "strings_referenced": [],
        "interesting_lines": terms,
        "cleaned_excerpt": "%s synthetic evidence: %s" % (name, " ".join(terms)),
    }


def _step_tools(payload: dict[str, Any]) -> set[str]:
    return {step["mcp_tool"] for step in payload["live_retrieval_steps"]}


if __name__ == "__main__":
    unittest.main()
