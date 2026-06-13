from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.errors import QueryError
from tools.kernel_corpus.knowledge_graph import (
    KNOWLEDGE_GRAPH_SCHEMA_VERSION,
    build_knowledge_graph,
    function_topics,
    list_topics,
    render_markdown_graph,
    shared_functions,
    topic_functions,
    topic_path,
    topic_subgraph,
    write_graph,
)
from tools.kernel_corpus.mcp_server import KernelCorpusMcpServer


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusKnowledgeGraphTests(unittest.TestCase):
    def test_graph_exports_topic_function_phase_tag_import_string_and_artifact_relationships(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            _write_lifecycle_pack(pack_root)
            _write_atlas_page(pack_root)

            first = build_knowledge_graph(
                pack_root,
                priority="P0",
                include_atlas=True,
                include_lifecycle=True,
                max_functions_per_topic=3,
                max_edges=10,
            )
            second = build_knowledge_graph(
                pack_root,
                priority="P0",
                include_atlas=True,
                include_lifecycle=True,
                max_functions_per_topic=3,
                max_edges=10,
            )

            self.assertEqual(KNOWLEDGE_GRAPH_SCHEMA_VERSION, first["schema"])
            self.assertEqual(
                [node["id"] for node in first["nodes"]],
                [node["id"] for node in second["nodes"]],
            )
            self.assertEqual(
                [edge["id"] for edge in first["edges"]],
                [edge["id"] for edge in second["edges"]],
            )
            node_types = {node["type"] for node in first["nodes"]}
            edge_types = {edge["type"] for edge in first["edges"]}
            self.assertTrue(
                {
                    "topic",
                    "function",
                    "phase",
                    "tag",
                    "import",
                    "string",
                    "atlas_page",
                    "artifact",
                }.issubset(node_types)
            )
            self.assertTrue(
                {
                    "topic_selects_function",
                    "topic_has_phase",
                    "function_in_phase",
                    "function_calls_function",
                    "function_has_tag",
                    "function_references_import",
                    "function_references_string",
                    "atlas_page_mentions_function",
                    "function_has_artifact",
                }.issubset(edge_types)
            )
            self.assertEqual("minimal.i64", first["pack"]["target_path"])
            self.assertEqual(2, first["summary"]["edge_type_counts"]["function_references_import"])
            self.assertEqual(1, first["summary"]["edge_type_counts"]["function_references_string"])

    def test_query_helpers_report_topics_roles_shared_functions_and_paths(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            graph = build_knowledge_graph(pack_root, max_functions_per_topic=3, max_edges=10)

            topics = list_topics(graph)
            process_functions = topic_functions(graph, "process_object_lifecycle")
            function_roles = function_topics(graph, "PspAllocateProcess")
            shared = shared_functions(graph)
            paths = topic_path(graph, "process_object_lifecycle", "remote_process_access_flow")

            self.assertEqual(
                ["process_object_lifecycle", "remote_process_access_flow"],
                [topic["id"] for topic in topics],
            )
            self.assertIn("PspAllocateProcess", [function["name"] for function in process_functions])
            self.assertEqual(
                ["process_object_lifecycle", "remote_process_access_flow"],
                [role["topic_id"] for role in function_roles],
            )
            self.assertEqual("PspAllocateProcess", shared[0]["name"])
            self.assertEqual(2, shared[0]["topic_count"])
            self.assertTrue(paths)
            self.assertEqual("topic:process_object_lifecycle", paths[0]["nodes"][0]["id"])

    def test_bounds_and_output_path_safety(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            graph = build_knowledge_graph(pack_root, max_functions_per_topic=1, max_edges=1)
            path = write_graph(graph, "reports\\knowledge-graph.md", requested_format="markdown")
            subgraph = topic_subgraph(graph, "process_object_lifecycle", max_nodes=2, max_edges=1)

            self.assertTrue(graph["warnings"])
            self.assertIn("functions truncated", " ".join(graph["warnings"]))
            self.assertEqual(1, graph["summary"]["edge_type_counts"].get("function_calls_function", 0))
            self.assertEqual(str((pack_root / "reports" / "knowledge-graph.md").resolve()), path)
            self.assertIn("# Kernel Knowledge Graph", Path(path).read_text(encoding="utf-8"))
            self.assertLessEqual(subgraph["node_count"], 2)
            with self.assertRaises(QueryError):
                write_graph(graph, pack_root.parent / "outside.md", requested_format="markdown")

    def test_missing_optional_inputs_degrade_with_warnings(self) -> None:
        with _built_pack() as pack_root:
            graph = build_knowledge_graph(pack_root, include_atlas=True, include_lifecycle=True)

            self.assertTrue(graph["ok"])
            self.assertEqual([], list_topics(graph))
            warnings = " ".join(graph["warnings"])
            self.assertIn("Canonical answer root does not exist", warnings)
            self.assertIn("Atlas directory does not exist", warnings)
            self.assertIn("Lifecycle evidence-pack directory is missing", warnings)

    def test_markdown_summary_mentions_shared_functions_and_evidence_boundary(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            graph = build_knowledge_graph(pack_root)

            markdown = render_markdown_graph(graph)

            self.assertIn("## Most Shared Functions", markdown)
            self.assertIn("PspAllocateProcess", markdown)
            self.assertIn("Treat graph centrality as navigation", markdown)

    def test_mcp_knowledge_graph_tools_return_bounded_payloads(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            subgraph = server.call_tool(
                "get_topic_graph",
                {
                    "topic_id": "process_object_lifecycle",
                    "max_nodes": 20,
                    "max_edges": 20,
                },
            )
            paths = server.call_tool(
                "find_topic_paths",
                {
                    "source_topic": "process_object_lifecycle",
                    "target_topic": "remote_process_access_flow",
                },
            )
            roles = server.call_tool(
                "get_function_roles",
                {
                    "ea_or_name": "PspAllocateProcess",
                },
            )

            self.assertTrue(subgraph["ok"])
            self.assertEqual("kernel_corpus_knowledge_graph_v1_subgraph", subgraph["schema_version"])
            self.assertGreater(subgraph["node_count"], 0)
            self.assertTrue(paths["ok"])
            self.assertGreaterEqual(paths["path_count"], 1)
            self.assertTrue(roles["ok"])
            self.assertEqual(2, roles["role_count"])


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _write_canonical_fixture(pack_root: Path) -> None:
    root = pack_root / "canonical-answers"
    specs = [
        {
            "topic_id": "process_object_lifecycle",
            "priority": "P0",
            "mode": "lifecycle",
            "title": "Process Object Lifecycle",
            "status": "pass",
            "score": 94,
            "warnings": 0,
            "gap_count": 0,
            "phases": [
                ("entry", [_function("0x140001000", "NtCreateUserProcess", "entry")]),
                ("allocate", [_function("0x140002000", "PspAllocateProcess", "allocate")]),
                ("delete", [_function("0x140003000", "PspProcessDelete", "delete")]),
            ],
            "edges": [
                ("0x140001000", "0x140002000"),
                ("0x140002000", "0x140003000"),
            ],
        },
        {
            "topic_id": "remote_process_access_flow",
            "priority": "P1",
            "mode": "focused",
            "title": "Remote Process Access Flow",
            "status": "pass",
            "score": 80,
            "warnings": 0,
            "gap_count": 1,
            "functions": [
                _function("0x140002000", "PspAllocateProcess", "focused"),
            ],
            "edges": [],
        },
    ]
    report_topics = []
    index_topics = []
    root.mkdir(parents=True, exist_ok=True)
    for spec in specs:
        topic_dir = root / spec["priority"] / spec["topic_id"]
        _write_canonical_topic(topic_dir, spec)
        index_topics.append(
            {
                "id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
            }
        )
        report_topics.append(_quality_payload(topic_dir, spec))
    (root / "index.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_run_v1",
                "topics": index_topics,
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


def _write_canonical_topic(topic_dir: Path, spec: dict[str, object]) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    functions = list(spec.get("functions", []))
    phases = []
    for phase_id, phase_functions in spec.get("phases", []):
        functions.extend(phase_functions)
        phases.append(
            {
                "id": phase_id,
                "functions": phase_functions,
            }
        )
    edges = [
        {
            "src_ea": src,
            "dst_ea": dst,
            "edge_kind": "calls",
        }
        for src, dst in spec["edges"]
    ]
    (topic_dir / "answer.md").write_text("# %s\n\nfixture answer\n" % spec["title"], encoding="utf-8")
    (topic_dir / "quality.md").write_text("# Quality\n\nstatus=%s\n" % spec["status"], encoding="utf-8")
    (topic_dir / "gaps.md").write_text("- fixture gap\n", encoding="utf-8")
    (topic_dir / "source-map.md").write_text("- fixture source\n", encoding="utf-8")
    (topic_dir / "evidence-pack.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": spec["topic_id"],
                "summary": {
                    "selected_function_count": len(functions),
                    "edge_count": len(edges),
                },
                "functions": functions,
                "phases": phases,
                "edges": edges,
                "gaps": ["fixture gap"] * int(spec["gap_count"]),
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
        json.dumps({"passed": spec["status"] == "pass", "warning_count": spec["warnings"]}, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    (topic_dir / "quality.json").write_text(
        json.dumps(_quality_payload(topic_dir, spec), indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (topic_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_artifact_v1",
                "topic": {
                    "id": spec["topic_id"],
                    "priority": spec["priority"],
                    "title": spec["title"],
                    "mode": spec["mode"],
                    "question": "Explain %s." % spec["title"],
                },
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_lifecycle_pack(pack_root: Path) -> None:
    evidence_root = pack_root / "evidence-packs"
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "process_object.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": "process_object",
                "summary": {"selected_function_count": 2, "edge_count": 1},
                "phases": [
                    {
                        "id": "entry",
                        "functions": [_function("0x140001000", "NtCreateUserProcess", "entry")],
                    },
                    {
                        "id": "allocate",
                        "functions": [_function("0x140002000", "PspAllocateProcess", "allocate")],
                    },
                ],
                "edges": [{"src_ea": "0x140001000", "dst_ea": "0x140002000", "edge_kind": "calls"}],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_atlas_page(pack_root: Path) -> None:
    atlas_root = pack_root / "reports" / "atlas"
    atlas_root.mkdir(parents=True, exist_ok=True)
    (atlas_root / "process.md").write_text(
        "# Process Subsystem Atlas\n\n"
        "## Corpus Identity\n\n"
        "- Function: `0x140001000` `NtCreateUserProcess`\n"
        "- Function: `0x140002000` `PspAllocateProcess`\n\n"
        "## Review Rule\n",
        encoding="utf-8",
    )


def _function(ea: str, name: str, phase: str) -> dict[str, object]:
    return {
        "ea": ea,
        "name": name,
        "phase": phase,
        "role": "%s role" % phase,
        "tags": ["process_thread"],
    }


def _quality_payload(topic_dir: Path, spec: dict[str, object]) -> dict[str, object]:
    functions = list(spec.get("functions", []))
    for _phase_id, phase_functions in spec.get("phases", []):
        functions.extend(phase_functions)
    return {
        "topic_id": spec["topic_id"],
        "priority": spec["priority"],
        "mode": spec["mode"],
        "directory": str(topic_dir.resolve()),
        "status": spec["status"],
        "score": spec["score"],
        "selected_function_count": len(functions),
        "edge_count": len(spec["edges"]),
        "validation_warning_count": spec["warnings"],
        "gap_count": spec["gap_count"],
    }


if __name__ == "__main__":
    unittest.main()
