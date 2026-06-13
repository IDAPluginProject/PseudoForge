from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.atlas import get_atlas_page, list_atlas_pages  # noqa: E402
from tools.kernel_corpus.canonical_store import (  # noqa: E402
    MAX_TOPICS as MAX_CANONICAL_TOPICS,
    PRIORITY_ORDER,
    list_canonical_answers,
)
from tools.kernel_corpus.ea import normalize_ea  # noqa: E402
from tools.kernel_corpus.errors import KernelCorpusError, QueryError  # noqa: E402
from tools.kernel_corpus.query import corpus_status  # noqa: E402
from tools.kernel_corpus.schema import SQLITE_FILENAME  # noqa: E402
from tools.kernel_corpus.store import connect_database  # noqa: E402

KNOWLEDGE_GRAPH_SCHEMA_VERSION = "kernel_corpus_knowledge_graph_v1"
DEFAULT_MAX_FUNCTIONS_PER_TOPIC = 24
MAX_FUNCTIONS_PER_TOPIC = 200
DEFAULT_MAX_EDGES = 600
MAX_EDGES = 5000
DEFAULT_MAX_NODES = 300
MAX_NODES = 3000
DEFAULT_MAX_PATHS = 5
MAX_PATHS = 20
MAX_VALUES_PER_FUNCTION = 8
MAX_ARTIFACTS_PER_FUNCTION = 5
ATLAS_FUNCTION_LIMIT = 24
SUPPORTED_FORMATS = ("json", "markdown")
SAFE_TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9_:.-]*$")
EA_RE = re.compile(r"0x[0-9a-fA-F]+")


def main(argv: list[str] | None = None) -> int:
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    try:
        if raw_args and raw_args[0] in _query_commands():
            payload = _run_query_command(raw_args)
            print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
        else:
            args = _build_export_parser().parse_args(raw_args)
            payload = build_knowledge_graph(
                args.pack_root,
                priority=args.priority or "",
                include_atlas=bool(args.include_atlas),
                include_lifecycle=bool(args.include_lifecycle),
                max_functions_per_topic=args.max_functions_per_topic,
                max_edges=args.max_edges,
            )
            if args.output:
                payload["output"] = write_graph(payload, args.output, requested_format=args.format)
            if args.format == "markdown":
                print(render_markdown_graph(payload))
            else:
                print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print("Kernel knowledge graph failed: %s" % exc, file=sys.stderr)
        return 1
    return 0


def build_knowledge_graph(
    pack_root: str | Path,
    *,
    priority: str = "",
    include_atlas: bool = False,
    include_lifecycle: bool = False,
    max_functions_per_topic: int = DEFAULT_MAX_FUNCTIONS_PER_TOPIC,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> dict[str, Any]:
    priority_filter = str(priority or "").strip().upper()
    if priority_filter and priority_filter not in PRIORITY_ORDER:
        raise QueryError("Unsupported priority filter: %s" % priority)
    function_limit = _bounded_int(max_functions_per_topic, DEFAULT_MAX_FUNCTIONS_PER_TOPIC, MAX_FUNCTIONS_PER_TOPIC)
    edge_limit = _bounded_int(max_edges, DEFAULT_MAX_EDGES, MAX_EDGES)
    root = Path(pack_root)
    status = corpus_status(root)
    graph = _new_graph(root, status, priority_filter, include_atlas, include_lifecycle, function_limit, edge_limit)

    _add_canonical_topics(graph, root, priority_filter=priority_filter, max_functions_per_topic=function_limit)
    if include_lifecycle:
        _add_lifecycle_packs(graph, root, max_functions_per_topic=function_limit)
    if include_atlas:
        _add_atlas_pages(graph, root)

    selected_eas = _selected_function_eas(graph)
    _enrich_selected_functions(graph, root, selected_eas)
    _add_call_edges(graph, root, selected_eas, max_edges=edge_limit)
    _finalize_graph(graph)
    return graph


def write_graph(payload: dict[str, Any], output: str | Path, *, requested_format: str = "json") -> str:
    pack_root = Path(str(payload.get("pack_root", "") or ""))
    path = Path(output)
    if not path.is_absolute():
        path = pack_root / path
    resolved = path.resolve()
    _require_inside(resolved, pack_root, "Knowledge graph output")
    fmt = _format_from_path(resolved, requested_format)
    if fmt == "markdown":
        text = render_markdown_graph(payload)
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(text, encoding="utf-8")
    return str(resolved)


def render_markdown_graph(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    pack = payload.get("pack", {}) if isinstance(payload.get("pack"), dict) else {}
    lines = [
        "# Kernel Knowledge Graph",
        "",
        "- Schema: `%s`" % payload.get("schema", ""),
        "- Generated: `%s`" % payload.get("generated_at", ""),
        "- Pack root: `%s`" % payload.get("pack_root", ""),
        "- Target: `%s`" % pack.get("target_path", ""),
        "- Functions: `%s`" % pack.get("function_count", ""),
        "- Skipped: `%s`" % pack.get("skipped_count", ""),
        "- Nodes: `%s`; edges: `%s`" % (summary.get("node_count", 0), summary.get("edge_count", 0)),
        "",
        "## Topic Coverage",
        "",
    ]
    topics = list_topics(payload)
    if not topics:
        lines.append("- No topic nodes were generated.")
    for topic in topics:
        lines.append(
            "- `%s` `%s` priority=`%s` quality=`%s` functions=`%s`"
            % (
                topic.get("id", ""),
                topic.get("label", ""),
                topic.get("priority", ""),
                topic.get("quality_status", ""),
                topic.get("selected_function_count", 0),
            )
        )
    lines.extend(["", "## Most Shared Functions", ""])
    shared = shared_functions(payload, max_functions=12)
    if not shared:
        lines.append("- No functions are shared by multiple topics.")
    for item in shared:
        lines.append(
            "- `%s` `%s` topics=%s artifacts=%s"
            % (
                item.get("ea", ""),
                item.get("name", ""),
                _inline_code_list(item.get("topics", [])),
                _inline_code_list(item.get("artifacts", [])[:2]),
            )
        )
    lines.extend(["", "## Bridge Functions", ""])
    bridges = summary.get("bridge_functions", []) if isinstance(summary.get("bridge_functions"), list) else []
    if not bridges:
        lines.append("- No bridge functions detected in the bounded graph.")
    for item in bridges[:12]:
        lines.append(
            "- `%s` `%s` degree=`%s` topics=%s"
            % (
                item.get("ea", ""),
                item.get("name", ""),
                item.get("degree", 0),
                _inline_code_list(item.get("topics", [])),
            )
        )
    lines.extend(["", "## Topic Clusters", ""])
    clusters = summary.get("topic_clusters", []) if isinstance(summary.get("topic_clusters"), list) else []
    if not clusters:
        lines.append("- No topic clusters were produced.")
    for item in clusters[:20]:
        lines.append(
            "- `%s`: functions=%s tags=%s"
            % (
                item.get("topic_id", ""),
                _inline_code_list(item.get("functions", [])[:6]),
                _inline_code_list(item.get("tags", [])[:6]),
            )
        )
    warnings = [str(item) for item in payload.get("warnings", [])]
    lines.extend(["", "## Missing Quality And Gap Warnings", ""])
    if not warnings:
        lines.append("- No graph-generation warnings were emitted.")
    for warning in warnings:
        lines.append("- %s" % warning)
    lines.extend(
        [
            "",
            "## Evidence Boundary",
            "",
            "- Treat graph centrality as navigation, not proof.",
            "- Important claims still require EA, function name, and artifact path citations.",
            "- Rebuild the graph after regenerating packs, canonical answers, lifecycle traces, or atlas pages.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def list_topics(graph: dict[str, Any]) -> list[dict[str, Any]]:
    selected_counts = _topic_function_counts(graph)
    topics = []
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("type") != "topic":
            continue
        props = node.get("properties", {}) if isinstance(node.get("properties"), dict) else {}
        topics.append(
            {
                "id": props.get("topic_id", _node_key(node.get("id", ""))),
                "node_id": node.get("id", ""),
                "label": node.get("label", ""),
                "source": props.get("source", ""),
                "priority": props.get("priority", ""),
                "mode": props.get("mode", ""),
                "quality_status": props.get("quality_status", ""),
                "selected_function_count": selected_counts.get(str(node.get("id", "")), 0),
            }
        )
    topics.sort(key=lambda item: (_priority_rank(item.get("priority", "")), str(item.get("id", ""))))
    return topics


def topic_functions(graph: dict[str, Any], topic_id: str, *, max_functions: int = DEFAULT_MAX_FUNCTIONS_PER_TOPIC) -> list[dict[str, Any]]:
    topic_node = _find_topic_node(graph, topic_id)
    if not topic_node:
        return []
    limit = _bounded_int(max_functions, DEFAULT_MAX_FUNCTIONS_PER_TOPIC, MAX_FUNCTIONS_PER_TOPIC)
    node_by_id = _nodes_by_id(graph)
    functions = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("type") != "topic_selects_function" or edge.get("source") != topic_node["id"]:
            continue
        target = node_by_id.get(str(edge.get("target", "")))
        if not target:
            continue
        functions.append(_function_query_payload(target, edge))
    functions.sort(key=lambda item: (str(item.get("phase", "")), str(item.get("name", "")), str(item.get("ea", ""))))
    return functions[:limit]


def function_topics(graph: dict[str, Any], ea_or_name: str, *, max_topics: int = DEFAULT_MAX_FUNCTIONS_PER_TOPIC) -> list[dict[str, Any]]:
    function_node = _find_function_node(graph, ea_or_name)
    if not function_node:
        return []
    limit = _bounded_int(max_topics, DEFAULT_MAX_FUNCTIONS_PER_TOPIC, MAX_FUNCTIONS_PER_TOPIC)
    node_by_id = _nodes_by_id(graph)
    topics = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("type") != "topic_selects_function" or edge.get("target") != function_node["id"]:
            continue
        source = node_by_id.get(str(edge.get("source", "")))
        if source:
            props = source.get("properties", {}) if isinstance(source.get("properties"), dict) else {}
            topics.append(
                {
                    "topic_id": props.get("topic_id", _node_key(source.get("id", ""))),
                    "label": source.get("label", ""),
                    "source": props.get("source", ""),
                    "priority": props.get("priority", ""),
                    "phase": edge.get("properties", {}).get("phase", "") if isinstance(edge.get("properties"), dict) else "",
                    "role": edge.get("properties", {}).get("role", "") if isinstance(edge.get("properties"), dict) else "",
                }
            )
    topics.sort(key=lambda item: (_priority_rank(item.get("priority", "")), str(item.get("topic_id", ""))))
    return topics[:limit]


def shared_functions(graph: dict[str, Any], *, max_functions: int = DEFAULT_MAX_FUNCTIONS_PER_TOPIC) -> list[dict[str, Any]]:
    limit = _bounded_int(max_functions, DEFAULT_MAX_FUNCTIONS_PER_TOPIC, MAX_FUNCTIONS_PER_TOPIC)
    node_by_id = _nodes_by_id(graph)
    topics_by_function: dict[str, set[str]] = {}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("type") != "topic_selects_function":
            continue
        topics_by_function.setdefault(str(edge.get("target", "")), set()).add(str(edge.get("source", "")))
    result = []
    for function_id, topic_ids in topics_by_function.items():
        if len(topic_ids) < 2:
            continue
        function = node_by_id.get(function_id)
        if not function:
            continue
        props = function.get("properties", {}) if isinstance(function.get("properties"), dict) else {}
        topic_labels = []
        for topic_node_id in sorted(topic_ids):
            topic_node = node_by_id.get(topic_node_id)
            if topic_node:
                topic_props = topic_node.get("properties", {}) if isinstance(topic_node.get("properties"), dict) else {}
                topic_labels.append(str(topic_props.get("topic_id", _node_key(topic_node_id))))
        result.append(
            {
                "ea": props.get("ea", _node_key(function_id)),
                "name": function.get("label", ""),
                "topic_count": len(topic_ids),
                "topics": topic_labels,
                "artifacts": props.get("artifact_paths", []),
            }
        )
    result.sort(key=lambda item: (-int(item.get("topic_count", 0)), str(item.get("name", "")), str(item.get("ea", ""))))
    return result[:limit]


def topic_path(
    graph: dict[str, Any],
    source_topic: str,
    target_topic: str,
    *,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> list[dict[str, Any]]:
    source = _find_topic_node(graph, source_topic)
    target = _find_topic_node(graph, target_topic)
    if not source or not target:
        return []
    limit = _bounded_int(max_paths, DEFAULT_MAX_PATHS, MAX_PATHS)
    adjacency = _topic_path_adjacency(graph)
    paths = []
    queue: deque[list[str]] = deque([[source["id"]]])
    while queue and len(paths) < limit:
        path = queue.popleft()
        current = path[-1]
        if current == target["id"]:
            paths.append(_graph_path_payload(graph, path))
            continue
        if len(path) >= 7:
            continue
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor in path:
                continue
            queue.append(path + [neighbor])
    return paths


def topic_subgraph(
    graph: dict[str, Any],
    topic_id: str,
    *,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> dict[str, Any]:
    topic = _find_topic_node(graph, topic_id)
    if not topic:
        raise QueryError("Topic was not found in knowledge graph: %s" % topic_id)
    node_limit = _bounded_int(max_nodes, DEFAULT_MAX_NODES, MAX_NODES)
    edge_limit = _bounded_int(max_edges, DEFAULT_MAX_EDGES, MAX_EDGES)
    included = {str(topic["id"])}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("source") in included or edge.get("target") in included:
            included.add(str(edge.get("source", "")))
            included.add(str(edge.get("target", "")))
        if len(included) >= node_limit:
            break
    nodes = [node for node in graph.get("nodes", []) if isinstance(node, dict) and str(node.get("id", "")) in included][:node_limit]
    node_ids = {str(node.get("id", "")) for node in nodes}
    edges = [
        edge
        for edge in graph.get("edges", [])
        if isinstance(edge, dict) and edge.get("source") in node_ids and edge.get("target") in node_ids
    ][:edge_limit]
    return {
        "schema": "%s_subgraph" % KNOWLEDGE_GRAPH_SCHEMA_VERSION,
        "topic_id": topic_id,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes_truncated": len(included) > len(nodes),
        "edges_truncated": len(edges) >= edge_limit,
    }


def _run_query_command(argv: list[str]) -> dict[str, Any]:
    parser = _build_query_parser()
    args = parser.parse_args(argv)
    graph = build_knowledge_graph(
        args.pack_root,
        priority=getattr(args, "priority", "") or "",
        include_atlas=bool(getattr(args, "include_atlas", False)),
        include_lifecycle=bool(getattr(args, "include_lifecycle", False)),
        max_functions_per_topic=getattr(args, "max_functions_per_topic", DEFAULT_MAX_FUNCTIONS_PER_TOPIC),
        max_edges=getattr(args, "max_edges", DEFAULT_MAX_EDGES),
    )
    if args.command == "list-topics":
        return {"ok": True, "schema": "%s_query_v1" % KNOWLEDGE_GRAPH_SCHEMA_VERSION, "topics": list_topics(graph)}
    if args.command == "topic-functions":
        return {
            "ok": True,
            "schema": "%s_query_v1" % KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "topic_id": args.topic,
            "functions": topic_functions(graph, args.topic, max_functions=args.max_functions_per_topic),
        }
    if args.command == "function-topics":
        return {
            "ok": True,
            "schema": "%s_query_v1" % KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "function": args.function,
            "topics": function_topics(graph, args.function, max_topics=args.max_topics),
        }
    if args.command == "shared-functions":
        return {
            "ok": True,
            "schema": "%s_query_v1" % KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "functions": shared_functions(graph, max_functions=args.max_functions),
        }
    if args.command == "topic-path":
        return {
            "ok": True,
            "schema": "%s_query_v1" % KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "source_topic": args.source_topic,
            "target_topic": args.target_topic,
            "paths": topic_path(graph, args.source_topic, args.target_topic, max_paths=args.max_paths),
        }
    raise QueryError("Unsupported knowledge graph query command: %s" % args.command)


def _build_export_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a bounded Kernel Corpus knowledge graph artifact.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--priority", default="", choices=("", "P0", "P1", "P2"), help="Optional canonical priority filter.")
    parser.add_argument("--include-atlas", action="store_true", help="Include existing atlas pages as graph sources.")
    parser.add_argument("--include-lifecycle", action="store_true", help="Include existing lifecycle evidence packs under <pack-root>\\evidence-packs.")
    parser.add_argument("--max-functions-per-topic", type=int, default=DEFAULT_MAX_FUNCTIONS_PER_TOPIC, help="Maximum selected functions per topic-like source.")
    parser.add_argument("--max-edges", type=int, default=DEFAULT_MAX_EDGES, help="Maximum selected call edges to include.")
    parser.add_argument("--format", default="json", choices=SUPPORTED_FORMATS, help="Output format.")
    parser.add_argument("--output", default="", help="Optional output path under the pack root.")
    return parser


def _build_query_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query a bounded Kernel Corpus knowledge graph.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in _query_commands():
        subparser = subparsers.add_parser(name, help=name.replace("-", " "))
        _add_graph_args(subparser)
        if name == "topic-functions":
            subparser.add_argument("--topic", required=True, help="Topic id.")
        elif name == "function-topics":
            subparser.add_argument("--function", required=True, help="Function EA or name.")
            subparser.add_argument("--max-topics", type=int, default=DEFAULT_MAX_FUNCTIONS_PER_TOPIC, help="Maximum topics to return.")
        elif name == "shared-functions":
            subparser.add_argument("--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS_PER_TOPIC, help="Maximum functions to return.")
        elif name == "topic-path":
            subparser.add_argument("--source-topic", required=True, help="Source topic id.")
            subparser.add_argument("--target-topic", required=True, help="Target topic id.")
            subparser.add_argument("--max-paths", type=int, default=DEFAULT_MAX_PATHS, help="Maximum paths to return.")
    return parser


def _add_graph_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--priority", default="", choices=("", "P0", "P1", "P2"), help="Optional canonical priority filter.")
    parser.add_argument("--include-atlas", action="store_true", help="Include existing atlas pages.")
    parser.add_argument("--include-lifecycle", action="store_true", help="Include existing lifecycle evidence packs.")
    parser.add_argument("--max-functions-per-topic", type=int, default=DEFAULT_MAX_FUNCTIONS_PER_TOPIC, help="Maximum functions per topic.")
    parser.add_argument("--max-edges", type=int, default=DEFAULT_MAX_EDGES, help="Maximum call edges.")


def _query_commands() -> set[str]:
    return {"list-topics", "topic-functions", "function-topics", "topic-path", "shared-functions"}


def _new_graph(
    pack_root: Path,
    status: dict[str, Any],
    priority: str,
    include_atlas: bool,
    include_lifecycle: bool,
    max_functions_per_topic: int,
    max_edges: int,
) -> dict[str, Any]:
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    return {
        "schema": KNOWLEDGE_GRAPH_SCHEMA_VERSION,
        "ok": True,
        "generated_at": _utc_now(),
        "pack_root": _path_payload(pack_root),
        "pack": {
            "schema_version": status.get("schema_version", ""),
            "target_path": str(manifest.get("target_path", "")),
            "source_corpus_root": str(manifest.get("source_corpus_root", "")),
            "source_index_path": str(manifest.get("source_index_path", "")),
            "source_index_sha256": str(manifest.get("source_index_sha256", "")),
            "function_count": _int_value(manifest.get("function_count"), 0),
            "skipped_count": _int_value(manifest.get("skipped_count"), 0),
            "generated_at": str(manifest.get("generated_at", "")),
        },
        "filters": {
            "priority": priority,
            "include_atlas": include_atlas,
            "include_lifecycle": include_lifecycle,
            "max_functions_per_topic": max_functions_per_topic,
            "max_edges": max_edges,
        },
        "nodes": [],
        "edges": [],
        "warnings": _coerce_warnings(status),
        "_node_ids": set(),
        "_edge_ids": set(),
        "_function_sources": {},
    }


def _add_canonical_topics(graph: dict[str, Any], pack_root: Path, *, priority_filter: str, max_functions_per_topic: int) -> None:
    try:
        catalog = list_canonical_answers(pack_root, priority=priority_filter, max_topics=MAX_CANONICAL_TOPICS)
    except KernelCorpusError as exc:
        graph["warnings"].append("Canonical answers could not be loaded: %s" % exc)
        return
    graph["warnings"].extend(_coerce_warnings(catalog))
    topics = [item for item in catalog.get("topics", []) if isinstance(item, dict)]
    if not topics:
        graph["warnings"].append("No canonical topics were available for the knowledge graph.")
        return
    for metadata in topics:
        topic_id = str(metadata.get("topic_id", "") or "")
        if not topic_id:
            continue
        quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
        topic_node_id = _topic_node_id(topic_id)
        _add_node(
            graph,
            topic_node_id,
            "topic",
            str(metadata.get("title", "") or topic_id),
            {
                "topic_id": topic_id,
                "source": "canonical",
                "priority": str(metadata.get("priority", "")),
                "mode": str(metadata.get("mode", "")),
                "quality_status": str(quality.get("status", "missing")),
                "quality_score": quality.get("score", None),
                "validation_warning_count": _int_value(quality.get("validation_warning_count"), 0),
                "gap_count": _int_value(quality.get("gap_count"), 0),
                "paths": metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {},
            },
        )
        if str(quality.get("status", "missing")) in {"degraded", "fail", "missing"}:
            graph["warnings"].append("Canonical topic %s quality status is %s." % (topic_id, quality.get("status", "missing")))
        evidence = _read_topic_evidence(metadata, graph)
        _add_topic_evidence(graph, topic_node_id, topic_id, evidence, max_functions=max_functions_per_topic, source="canonical")


def _add_lifecycle_packs(graph: dict[str, Any], pack_root: Path, *, max_functions_per_topic: int) -> None:
    evidence_root = pack_root / "evidence-packs"
    if not evidence_root.is_dir():
        graph["warnings"].append("Lifecycle evidence-pack directory is missing: %s" % evidence_root)
        return
    files = sorted(evidence_root.glob("*.json"), key=lambda item: item.name.lower())
    if not files:
        graph["warnings"].append("No lifecycle evidence-pack JSON files were found: %s" % evidence_root)
        return
    for path in files:
        data = _read_json_object(path, graph["warnings"], "lifecycle evidence pack")
        if not data:
            continue
        topic_id = str(data.get("topic", "") or path.stem)
        if not _safe_topic_like(topic_id):
            graph["warnings"].append("Skipping lifecycle topic with unsafe id: %s" % topic_id)
            continue
        node_topic_id = "lifecycle:%s" % topic_id
        topic_node_id = _topic_node_id(node_topic_id)
        summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
        _add_node(
            graph,
            topic_node_id,
            "topic",
            topic_id,
            {
                "topic_id": node_topic_id,
                "source": "lifecycle",
                "priority": "",
                "mode": "lifecycle",
                "quality_status": "generated",
                "selected_function_count": summary.get("selected_function_count", 0),
                "edge_count": summary.get("edge_count", 0),
                "path": _path_payload(path),
            },
        )
        _add_topic_evidence(graph, topic_node_id, node_topic_id, data, max_functions=max_functions_per_topic, source="lifecycle")


def _add_atlas_pages(graph: dict[str, Any], pack_root: Path) -> None:
    try:
        atlas = list_atlas_pages(pack_root)
    except KernelCorpusError as exc:
        graph["warnings"].append("Atlas pages could not be listed: %s" % exc)
        return
    graph["warnings"].extend(_coerce_warnings(atlas))
    pages = [item for item in atlas.get("pages", []) if isinstance(item, dict)]
    if not pages:
        graph["warnings"].append("No atlas pages were available for the knowledge graph.")
        return
    for page in pages:
        filename = str(page.get("filename", "") or "")
        if not filename:
            continue
        page_node_id = _atlas_node_id(filename)
        _add_node(
            graph,
            page_node_id,
            "atlas_page",
            filename,
            {
                "filename": filename,
                "path": str(page.get("path", "")),
                "size": page.get("size", 0),
            },
        )
        try:
            payload = get_atlas_page(pack_root, filename, max_chars=50000)
        except KernelCorpusError as exc:
            graph["warnings"].append("Atlas page could not be read: %s" % exc)
            continue
        eas = _unique_strings([_normalize_ea_text(match) for match in EA_RE.findall(str(payload.get("markdown", "")))])
        for ea in eas[:ATLAS_FUNCTION_LIMIT]:
            function_node_id = _function_node_id(ea)
            _mark_function_source(graph, ea, {"source": "atlas", "atlas_page": filename})
            _add_node(
                graph,
                function_node_id,
                "function",
                ea,
                {
                    "ea": ea,
                    "name": "",
                    "source_status": "atlas_pending_db_enrichment",
                },
            )
            _add_edge(
                graph,
                "atlas_page_mentions_function",
                page_node_id,
                function_node_id,
                {
                    "atlas_page": filename,
                },
            )


def _read_topic_evidence(metadata: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    paths = metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {}
    evidence_path = Path(str(paths.get("evidence_pack", "") or ""))
    if not evidence_path.is_file():
        graph["warnings"].append("Canonical evidence pack is missing for topic %s: %s" % (metadata.get("topic_id", ""), evidence_path))
        return {}
    return _read_json_object(evidence_path, graph["warnings"], "canonical evidence pack")


def _add_topic_evidence(
    graph: dict[str, Any],
    topic_node_id: str,
    topic_id: str,
    evidence: dict[str, Any],
    *,
    max_functions: int,
    source: str,
) -> None:
    if not evidence:
        return
    function_items = _functions_from_evidence(evidence)
    limited = function_items[:max_functions]
    if len(function_items) > len(limited):
        graph["warnings"].append("Topic %s functions truncated from %d to %d." % (topic_id, len(function_items), len(limited)))
    for item in limited:
        ea = _normalize_ea_text(item.get("ea", ""))
        name = str(item.get("name", "") or ea)
        if not ea:
            continue
        function_node_id = _function_node_id(ea)
        phase = str(item.get("phase", "") or "selected")
        role = str(item.get("role", "") or "")
        _mark_function_source(
            graph,
            ea,
            {
                "source": source,
                "topic_id": topic_id,
                "phase": phase,
                "role": role,
                "name": name,
            },
        )
        _add_node(
            graph,
            function_node_id,
            "function",
            name,
            {
                "ea": ea,
                "name": name,
                "source_status": "selected_pending_db_enrichment",
            },
        )
        _add_edge(
            graph,
            "topic_selects_function",
            topic_node_id,
            function_node_id,
            {
                "topic_id": topic_id,
                "phase": phase,
                "role": role,
                "source": source,
            },
        )
        if phase:
            phase_node_id = _phase_node_id(topic_id, phase)
            _add_node(
                graph,
                phase_node_id,
                "phase",
                "%s:%s" % (topic_id, phase),
                {
                    "topic_id": topic_id,
                    "phase": phase,
                    "source": source,
                },
            )
            _add_edge(graph, "topic_has_phase", topic_node_id, phase_node_id, {"topic_id": topic_id, "phase": phase})
            _add_edge(graph, "function_in_phase", function_node_id, phase_node_id, {"topic_id": topic_id, "phase": phase})


def _enrich_selected_functions(graph: dict[str, Any], pack_root: Path, selected_eas: set[str]) -> None:
    if not selected_eas:
        return
    sqlite_path = Path(str(corpus_status(pack_root).get("sqlite_path", pack_root / SQLITE_FILENAME)))
    with connect_database(sqlite_path) as connection:
        rows = _function_rows(connection, selected_eas)
        for ea in sorted(selected_eas, key=_ea_sort_key):
            node_id = _function_node_id(ea)
            row = rows.get(ea)
            if row is None:
                graph["warnings"].append("Selected function was not found in SQLite: %s" % ea)
                continue
            artifacts = _artifact_paths_from_row(row)
            props = {
                "ea": ea,
                "name": str(row["name"]),
                "mode": str(row["mode"] or ""),
                "llm_status": str(row["llm_status"] or ""),
                "warning_count": int(row["warning_count"] or 0),
                "buffer_contract_count": int(row["buffer_contract_count"] or 0),
                "artifact_paths": artifacts,
                "source_status": "db_enriched",
            }
            _add_node(graph, node_id, "function", str(row["name"]), props)
            for tag in _values_for_ea(connection, "function_tags", "tag", ea)[:MAX_VALUES_PER_FUNCTION]:
                tag_node_id = _tag_node_id(tag)
                _add_node(graph, tag_node_id, "tag", tag, {"tag": tag})
                _add_edge(graph, "function_has_tag", node_id, tag_node_id, {"tag": tag})
            for import_name in _values_for_ea(connection, "function_imports", "import_name", ea)[:MAX_VALUES_PER_FUNCTION]:
                import_node_id = _import_node_id(import_name)
                _add_node(graph, import_node_id, "import", import_name, {"import": import_name})
                _add_edge(graph, "function_references_import", node_id, import_node_id, {"import": import_name})
            for value in _values_for_ea(connection, "function_strings", "string_value", ea)[:MAX_VALUES_PER_FUNCTION]:
                string_node_id = _string_node_id(value)
                _add_node(graph, string_node_id, "string", _short_label(value, 80), {"value": value})
                _add_edge(graph, "function_references_string", node_id, string_node_id, {"value": value})
            for path in artifacts[:MAX_ARTIFACTS_PER_FUNCTION]:
                artifact_node_id = _artifact_node_id(path)
                _add_node(graph, artifact_node_id, "artifact", Path(path).name or path, {"path": path})
                _add_edge(graph, "function_has_artifact", node_id, artifact_node_id, {"path": path})


def _add_call_edges(graph: dict[str, Any], pack_root: Path, selected_eas: set[str], *, max_edges: int) -> None:
    if len(selected_eas) < 2:
        return
    sqlite_path = Path(str(corpus_status(pack_root).get("sqlite_path", pack_root / SQLITE_FILENAME)))
    with connect_database(sqlite_path) as connection:
        placeholders = ",".join("?" for _ in selected_eas)
        params = tuple(sorted(selected_eas, key=_ea_sort_key))
        rows = list(
            connection.execute(
                """
                SELECT src_ea, dst_ea, edge_kind
                FROM call_edges
                WHERE src_ea IN (%s) AND dst_ea IN (%s)
                ORDER BY src_ea, dst_ea, edge_kind
                LIMIT ?
                """ % (placeholders, placeholders),
                params + params + (max_edges,),
            )
        )
    for row in rows:
        src = _normalize_ea_text(row["src_ea"])
        dst = _normalize_ea_text(row["dst_ea"])
        _add_edge(
            graph,
            "function_calls_function",
            _function_node_id(src),
            _function_node_id(dst),
            {
                "src_ea": src,
                "dst_ea": dst,
                "edge_kind": str(row["edge_kind"] or "calls"),
            },
        )
    if len(rows) >= max_edges:
        graph["warnings"].append("Function call edges reached max_edges limit: %d." % max_edges)


def _finalize_graph(graph: dict[str, Any]) -> None:
    graph["nodes"].sort(key=lambda item: (str(item.get("type", "")), str(item.get("id", ""))))
    graph["edges"].sort(key=lambda item: (str(item.get("type", "")), str(item.get("id", ""))))
    graph["summary"] = _summary_payload(graph)
    for key in ("_node_ids", "_edge_ids", "_function_sources"):
        graph.pop(key, None)


def _summary_payload(graph: dict[str, Any]) -> dict[str, Any]:
    type_counts: dict[str, int] = {}
    for node in graph.get("nodes", []):
        type_name = str(node.get("type", ""))
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
    edge_type_counts: dict[str, int] = {}
    for edge in graph.get("edges", []):
        type_name = str(edge.get("type", ""))
        edge_type_counts[type_name] = edge_type_counts.get(type_name, 0) + 1
    return {
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "node_type_counts": type_counts,
        "edge_type_counts": edge_type_counts,
        "topic_count": type_counts.get("topic", 0),
        "function_count": type_counts.get("function", 0),
        "shared_functions": shared_functions(graph, max_functions=20),
        "bridge_functions": _bridge_functions(graph, max_functions=20),
        "topic_clusters": _topic_clusters(graph),
    }


def _topic_clusters(graph: dict[str, Any]) -> list[dict[str, Any]]:
    node_by_id = _nodes_by_id(graph)
    functions_by_topic: dict[str, list[str]] = {}
    tags_by_topic: dict[str, set[str]] = {}
    function_tags: dict[str, set[str]] = {}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("type") == "function_has_tag":
            function_tags.setdefault(str(edge.get("source", "")), set()).add(_node_key(str(edge.get("target", ""))))
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("type") != "topic_selects_function":
            continue
        topic_id = str(edge.get("source", ""))
        function_id = str(edge.get("target", ""))
        function = node_by_id.get(function_id)
        if not function:
            continue
        functions_by_topic.setdefault(topic_id, []).append(str(function.get("label", "")))
        tags_by_topic.setdefault(topic_id, set()).update(function_tags.get(function_id, set()))
    result = []
    for topic_node_id in sorted(functions_by_topic):
        topic_node = node_by_id.get(topic_node_id, {})
        props = topic_node.get("properties", {}) if isinstance(topic_node.get("properties"), dict) else {}
        result.append(
            {
                "topic_id": props.get("topic_id", _node_key(topic_node_id)),
                "functions": _unique_strings(functions_by_topic.get(topic_node_id, []))[:16],
                "tags": sorted(tags_by_topic.get(topic_node_id, set()))[:16],
            }
        )
    return result


def _bridge_functions(graph: dict[str, Any], *, max_functions: int) -> list[dict[str, Any]]:
    node_by_id = _nodes_by_id(graph)
    degree: dict[str, int] = {}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("type") == "function_calls_function":
            degree[str(edge.get("source", ""))] = degree.get(str(edge.get("source", "")), 0) + 1
            degree[str(edge.get("target", ""))] = degree.get(str(edge.get("target", "")), 0) + 1
    result = []
    for function in shared_functions(graph, max_functions=MAX_FUNCTIONS_PER_TOPIC):
        node = _find_function_node(graph, str(function.get("ea", "")))
        if not node:
            continue
        result.append(
            {
                "ea": function.get("ea", ""),
                "name": function.get("name", ""),
                "degree": degree.get(str(node.get("id", "")), 0),
                "topic_count": function.get("topic_count", 0),
                "topics": function.get("topics", []),
            }
        )
    result.sort(key=lambda item: (-int(item.get("topic_count", 0)), -int(item.get("degree", 0)), str(item.get("name", ""))))
    return result[:max_functions]


def _topic_function_counts(graph: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in graph.get("edges", []):
        if isinstance(edge, dict) and edge.get("type") == "topic_selects_function":
            source = str(edge.get("source", ""))
            counts[source] = counts.get(source, 0) + 1
    return counts


def _functions_from_evidence(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if isinstance(evidence.get("functions"), list):
        result.extend(dict(item) for item in evidence["functions"] if isinstance(item, dict))
    if isinstance(evidence.get("phases"), list):
        for phase in evidence["phases"]:
            if not isinstance(phase, dict):
                continue
            phase_id = str(phase.get("id", "") or phase.get("phase", "") or "")
            for function in phase.get("functions", []) if isinstance(phase.get("functions"), list) else []:
                if not isinstance(function, dict):
                    continue
                item = dict(function)
                item.setdefault("phase", phase_id)
                result.append(item)
    seen = set()
    deduped = []
    for item in result:
        ea = _normalize_ea_text(item.get("ea", ""))
        if not ea or ea in seen:
            continue
        item["ea"] = ea
        seen.add(ea)
        deduped.append(item)
    return deduped


def _function_rows(connection: sqlite3.Connection, eas: set[str]) -> dict[str, sqlite3.Row]:
    if not eas:
        return {}
    placeholders = ",".join("?" for _ in eas)
    return {
        _normalize_ea_text(row["ea"]): row
        for row in connection.execute(
            "SELECT * FROM functions WHERE ea IN (%s)" % placeholders,
            tuple(sorted(eas, key=_ea_sort_key)),
        )
    }


def _values_for_ea(connection: sqlite3.Connection, table: str, column: str, ea: str) -> list[str]:
    return [
        str(row[column])
        for row in connection.execute(
            "SELECT DISTINCT %s FROM %s WHERE ea = ? ORDER BY %s" % (column, table, column),
            (ea,),
        )
    ]


def _artifact_paths_from_row(row: sqlite3.Row) -> list[str]:
    values = [
        str(row["directory"] or ""),
        str(row["summary_path"] or ""),
        str(row["cleaned_path"] or ""),
        str(row["raw_path"] or ""),
        str(row["diff_path"] or ""),
    ]
    return [item for item in values if item]


def _selected_function_eas(graph: dict[str, Any]) -> set[str]:
    result = set()
    for node in graph.get("nodes", []):
        if isinstance(node, dict) and node.get("type") == "function":
            props = node.get("properties", {}) if isinstance(node.get("properties"), dict) else {}
            ea = _normalize_ea_text(props.get("ea", _node_key(str(node.get("id", "")))))
            if ea:
                result.add(ea)
    return result


def _mark_function_source(graph: dict[str, Any], ea: str, source: dict[str, Any]) -> None:
    normalized = _normalize_ea_text(ea)
    if not normalized:
        return
    sources = graph.setdefault("_function_sources", {}).setdefault(normalized, [])
    sources.append(source)


def _add_node(graph: dict[str, Any], node_id: str, node_type: str, label: str, properties: dict[str, Any]) -> None:
    node_ids: set[str] = graph["_node_ids"]
    if node_id in node_ids:
        for node in graph["nodes"]:
            if node["id"] == node_id:
                node["label"] = label or node["label"]
                merged = dict(node.get("properties", {}))
                merged.update({key: value for key, value in properties.items() if value not in (None, "", [], {})})
                node["properties"] = merged
                return
    node_ids.add(node_id)
    graph["nodes"].append(
        {
            "id": node_id,
            "type": node_type,
            "label": label,
            "properties": properties,
        }
    )


def _add_edge(graph: dict[str, Any], edge_type: str, source: str, target: str, properties: dict[str, Any] | None = None) -> None:
    edge_id = _edge_id(edge_type, source, target, properties or {})
    edge_ids: set[str] = graph["_edge_ids"]
    if edge_id in edge_ids:
        return
    edge_ids.add(edge_id)
    graph["edges"].append(
        {
            "id": edge_id,
            "type": edge_type,
            "source": source,
            "target": target,
            "properties": properties or {},
        }
    )


def _topic_path_adjacency(graph: dict[str, Any]) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {}
    allowed = {"topic_selects_function", "function_calls_function"}
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("type") not in allowed:
            continue
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set()).add(source)
    return adjacency


def _graph_path_payload(graph: dict[str, Any], path: list[str]) -> dict[str, Any]:
    node_by_id = _nodes_by_id(graph)
    return {
        "length": len(path),
        "nodes": [
            {
                "id": node_id,
                "type": node_by_id.get(node_id, {}).get("type", ""),
                "label": node_by_id.get(node_id, {}).get("label", ""),
            }
            for node_id in path
        ],
    }


def _find_topic_node(graph: dict[str, Any], topic_id: str) -> dict[str, Any] | None:
    candidates = {str(topic_id), _topic_node_id(str(topic_id))}
    if not str(topic_id).startswith("lifecycle:"):
        candidates.add(_topic_node_id("lifecycle:%s" % topic_id))
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("type") != "topic":
            continue
        props = node.get("properties", {}) if isinstance(node.get("properties"), dict) else {}
        if node.get("id") in candidates or props.get("topic_id") == topic_id:
            return node
    return None


def _find_function_node(graph: dict[str, Any], ea_or_name: str) -> dict[str, Any] | None:
    query = str(ea_or_name or "").strip()
    query_ea = _normalize_ea_text(query)
    query_lower = query.lower()
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("type") != "function":
            continue
        props = node.get("properties", {}) if isinstance(node.get("properties"), dict) else {}
        if query_ea and props.get("ea") == query_ea:
            return node
        if str(props.get("name", node.get("label", ""))).lower() == query_lower:
            return node
    return None


def _function_query_payload(function: dict[str, Any], edge: dict[str, Any]) -> dict[str, Any]:
    props = function.get("properties", {}) if isinstance(function.get("properties"), dict) else {}
    edge_props = edge.get("properties", {}) if isinstance(edge.get("properties"), dict) else {}
    return {
        "ea": props.get("ea", _node_key(function.get("id", ""))),
        "name": props.get("name", function.get("label", "")),
        "phase": edge_props.get("phase", ""),
        "role": edge_props.get("role", ""),
        "tags": props.get("tags", []),
        "artifacts": props.get("artifact_paths", []),
    }


def _nodes_by_id(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(node.get("id", "")): node for node in graph.get("nodes", []) if isinstance(node, dict)}


def _topic_node_id(topic_id: str) -> str:
    return "topic:%s" % _safe_id_component(topic_id)


def _function_node_id(ea: str) -> str:
    return "function:%s" % _normalize_ea_text(ea)


def _phase_node_id(topic_id: str, phase: str) -> str:
    return "phase:%s:%s" % (_safe_id_component(topic_id), _safe_id_component(phase))


def _tag_node_id(tag: str) -> str:
    return "tag:%s" % _safe_id_component(tag.lower())


def _import_node_id(import_name: str) -> str:
    return "import:%s" % _safe_id_component(import_name.lower())


def _string_node_id(value: str) -> str:
    return "string:%s" % _stable_hash(value)


def _atlas_node_id(filename: str) -> str:
    return "atlas_page:%s" % _safe_id_component(filename.lower())


def _artifact_node_id(path: str) -> str:
    return "artifact:%s" % _stable_hash(path.lower())


def _edge_id(edge_type: str, source: str, target: str, properties: dict[str, Any]) -> str:
    discriminator = ""
    for key in ("topic_id", "phase", "edge_kind", "tag", "import", "value", "path", "atlas_page"):
        if properties.get(key) not in (None, ""):
            discriminator += "|%s=%s" % (key, properties.get(key))
    return "edge:%s:%s" % (edge_type, _stable_hash("%s|%s|%s%s" % (edge_type, source, target, discriminator)))


def _node_key(node_id: str) -> str:
    return str(node_id).split(":", 1)[1] if ":" in str(node_id) else str(node_id)


def _safe_id_component(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value or "").strip())
    text = text.strip("_")
    return text or _stable_hash(value)


def _safe_topic_like(topic_id: str) -> bool:
    return bool(SAFE_TOPIC_RE.match(str(topic_id or "")))


def _stable_hash(value: str) -> str:
    return hashlib.sha1(str(value).encode("utf-8", errors="replace")).hexdigest()[:16]


def _format_from_path(path: Path, requested_format: str) -> str:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        return "markdown"
    requested = str(requested_format or "json").lower()
    return "markdown" if requested == "markdown" else "json"


def _require_inside(path: Path, root: Path, label: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise QueryError("%s must stay under pack_root: %s" % (label, path)) from exc


def _inline_code_list(values: Any) -> str:
    strings = _strings(values)
    if not strings:
        return "`none`"
    return ", ".join("`%s`" % item for item in strings)


def _coerce_warnings(payload: dict[str, Any]) -> list[str]:
    values = payload.get("warnings", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values]


def _read_json_object(path: Path, warnings: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        warnings.append("%s is missing: %s" % (label, path))
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append("%s could not be read: %s" % (label, exc))
        return {}
    if not isinstance(data, dict):
        warnings.append("%s JSON is not an object: %s" % (label, path))
        return {}
    return data


def _path_payload(path: Path) -> str:
    return str(path.resolve()) if path.exists() else str(path)


def _short_label(value: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _normalize_ea_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return normalize_ea(value)
    except (TypeError, ValueError):
        return ""


def _ea_sort_key(value: str) -> tuple[int, str]:
    try:
        return (0, "%016X" % int(str(value), 0))
    except (TypeError, ValueError):
        return (1, str(value))


def _priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(str(priority or "").upper(), 99)


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def _unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
