from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import QueryError
from tools.kernel_corpus.query import find_functions_by_name, get_function, search_functions
from tools.kernel_corpus.schema import MANIFEST_FILENAME, SQLITE_FILENAME
from tools.kernel_corpus.store import connect_database


VECTOR_INDEX_SCHEMA = "kernel_corpus_vector_recall_index_v1"
VECTOR_QUERY_SCHEMA = "kernel_corpus_vector_recall_query_v1"
MERGED_QUERY_SCHEMA = "kernel_corpus_vector_recall_merge_v1"
DEFAULT_VECTOR_LIMIT = 20
MAX_VECTOR_LIMIT = 200
DEFAULT_MERGE_LIMIT = 20
MAX_MERGE_LIMIT = 200
DEFAULT_MIN_SCORE = 0.65
DEFAULT_DIMENSION = 512
DEFAULT_INDEX_DIR = Path("experimental") / "vector_recall"
TEXT_KIND_LIMITS = {
    "name": 256,
    "tags": 512,
    "terms": 1200,
    "interesting_lines": 1600,
    "cleaned_excerpt": 2000,
}
TEXT_KIND_RANK = {kind: index for index, kind in enumerate(TEXT_KIND_LIMITS)}


class EmbeddingBackend(Protocol):
    name: str
    version: str
    dimension: int

    def embed(self, text: str) -> list[float]:
        ...


class TokenHashEmbeddingBackend:
    name = "token_hash"
    version = "v1"

    def __init__(self, dimension: int = DEFAULT_DIMENSION) -> None:
        self.dimension = max(8, int(dimension or DEFAULT_DIMENSION))

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        for token in _tokens(text):
            digest = hashlib.blake2b(token.encode("utf-8", errors="ignore"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % self.dimension
            sign = -1.0 if digest[4] & 1 else 1.0
            vector[bucket] += sign
        return _normalize(vector)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    backend = TokenHashEmbeddingBackend(dimension=args.dimension)
    try:
        payload = _run_command(args, backend)
    except (OSError, QueryError, ValueError) as exc:
        print("Kernel corpus vector recall experiment failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def build_vector_index(
    pack_root: str | Path,
    *,
    index_root: str | Path | None = None,
    backend: EmbeddingBackend | None = None,
    max_functions: int = 0,
) -> dict[str, Any]:
    backend = backend or TokenHashEmbeddingBackend()
    paths = _pack_paths(pack_root)
    index_dir = _index_dir(paths["pack_root"], index_root)
    index_dir.mkdir(parents=True, exist_ok=True)
    documents = []
    indexed_eas = set()
    with connect_database(paths["sqlite_path"]) as connection:
        fts_rows = _fts_rows(connection)
        for row in connection.execute("SELECT * FROM functions ORDER BY ea"):
            if max_functions > 0 and len(indexed_eas) >= max_functions:
                break
            ea = str(row["ea"])
            indexed_eas.add(ea)
            tags = _tags_for_ea(connection, ea)
            fts = fts_rows.get(ea, {})
            for kind, text in _bounded_texts(row, tags, fts):
                vector = backend.embed(text)
                if len(vector) != backend.dimension:
                    raise ValueError("Embedding backend returned unexpected dimension for %s" % kind)
                documents.append(
                    {
                        "doc_id": "%s::%s" % (ea, kind),
                        "ea": ea,
                        "source_text_kind": kind,
                        "text_sha256": _sha256_text(text),
                        "text_length": len(text),
                        "vector_format": "sparse_pairs",
                        "vector": _sparse_vector(vector),
                    }
                )
    manifest = _read_json(paths["manifest_path"])
    payload = {
        "schema": VECTOR_INDEX_SCHEMA,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "pack_root": str(paths["pack_root"]),
        "source_index_sha256": str(manifest.get("source_index_sha256", "")),
        "backend": _backend_payload(backend),
        "bounds": dict(TEXT_KIND_LIMITS),
        "function_count": len(indexed_eas),
        "document_count": len(documents),
        "documents": documents,
        "notes": [
            "Experimental secondary recall only.",
            "Documents store bounded text hashes and vectors, not full source text.",
            "Every result must resolve back to SQLite function metadata before use.",
        ],
    }
    index_path = index_dir / "vector-index.json"
    index_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    return {
        "ok": True,
        "schema": VECTOR_INDEX_SCHEMA,
        "pack_root": str(paths["pack_root"]),
        "index_root": str(index_dir.resolve()),
        "index_path": str(index_path.resolve()),
        "backend": payload["backend"],
        "function_count": payload["function_count"],
        "document_count": payload["document_count"],
        "bounds": payload["bounds"],
    }


def query_vector_recall(
    pack_root: str | Path,
    query: str,
    *,
    index_root: str | Path | None = None,
    backend: EmbeddingBackend | None = None,
    limit: int = DEFAULT_VECTOR_LIMIT,
    min_score: float = DEFAULT_MIN_SCORE,
) -> dict[str, Any]:
    backend = backend or TokenHashEmbeddingBackend()
    paths = _pack_paths(pack_root)
    index = _load_index(paths["pack_root"], index_root)
    _validate_backend(index, backend)
    bounded_limit = _bounded_limit(limit, DEFAULT_VECTOR_LIMIT, MAX_VECTOR_LIMIT)
    query_text = str(query or "").strip()
    if not query_text:
        raise QueryError("Vector query text is required")
    query_vector = backend.embed(query_text)
    query_sparse = _sparse_vector(query_vector)
    scored = []
    for document in index.get("documents", []):
        if not isinstance(document, dict):
            continue
        score = _cosine_document(query_vector, query_sparse, document, backend.dimension)
        if score < min_score:
            continue
        scored.append(
            {
                "ea": str(document.get("ea", "")),
                "score": round(score, 6),
                "source_text_kind": str(document.get("source_text_kind", "")),
                "doc_id": str(document.get("doc_id", "")),
                "text_sha256": str(document.get("text_sha256", "")),
            }
        )
    best_by_ea = _best_vector_hits(scored)
    results = []
    for hit in best_by_ea[:bounded_limit]:
        function = get_function(paths["pack_root"], hit["ea"], include_excerpt=False, include_artifacts=True)
        results.append(
            {
                "ea": hit["ea"],
                "vector_score": hit["score"],
                "source_text_kind": hit["source_text_kind"],
                "doc_id": hit["doc_id"],
                "function": function,
            }
        )
    return {
        "ok": True,
        "schema": VECTOR_QUERY_SCHEMA,
        "mode": "vector",
        "pack_root": str(paths["pack_root"]),
        "index_path": str(_index_path(paths["pack_root"], index_root).resolve()),
        "query": query_text,
        "backend": _backend_payload(backend),
        "limit": bounded_limit,
        "min_score": float(min_score),
        "results": results,
        "warnings": _index_warnings(paths, index, backend),
    }


def merge_recall(
    pack_root: str | Path,
    query: str,
    *,
    tags: list[str] | tuple[str, ...] | None = None,
    index_root: str | Path | None = None,
    backend: EmbeddingBackend | None = None,
    limit: int = DEFAULT_MERGE_LIMIT,
    vector_limit: int = DEFAULT_VECTOR_LIMIT,
    vector_min_score: float = DEFAULT_MIN_SCORE,
) -> dict[str, Any]:
    paths = _pack_paths(pack_root)
    query_text = str(query or "").strip()
    tag_values = [str(tag) for tag in (tags or []) if str(tag)]
    bounded_limit = _bounded_limit(limit, DEFAULT_MERGE_LIMIT, MAX_MERGE_LIMIT)
    candidates: dict[str, dict[str, Any]] = {}

    if query_text:
        for function in find_functions_by_name(paths["pack_root"], query_text, limit=bounded_limit):
            _merge_candidate(candidates, function, "exact_name", 3.0)
        for function in search_functions(paths["pack_root"], query=query_text, limit=bounded_limit):
            _merge_candidate(candidates, function, "fts", 1.0)
    for tag in tag_values:
        for function in search_functions(paths["pack_root"], tags=[tag], limit=bounded_limit):
            _merge_candidate(candidates, function, "tag:%s" % tag, 1.4)

    vector_payload = query_vector_recall(
        paths["pack_root"],
        query_text,
        index_root=index_root,
        backend=backend,
        limit=vector_limit,
        min_score=vector_min_score,
    )
    for item in vector_payload["results"]:
        function = item["function"]
        score = float(item.get("vector_score", 0.0) or 0.0)
        _merge_candidate(
            candidates,
            function,
            "vector:%s" % item.get("source_text_kind", ""),
            score,
            vector_score=score,
            vector_source_text_kind=str(item.get("source_text_kind", "")),
        )

    ordered = sorted(
        candidates.values(),
        key=lambda item: (-float(item["rerank_score"]), -float(item.get("vector_score", 0.0)), int(str(item["ea"]), 0)),
    )[:bounded_limit]
    results = []
    for item in ordered:
        results.append(
            {
                "ea": item["ea"],
                "rerank_score": round(float(item["rerank_score"]), 6),
                "vector_score": round(float(item.get("vector_score", 0.0)), 6),
                "vector_source_text_kind": str(item.get("vector_source_text_kind", "")),
                "sources": sorted(item["sources"]),
                "function": get_function(paths["pack_root"], item["ea"], include_excerpt=False, include_artifacts=True),
            }
        )
    return {
        "ok": True,
        "schema": MERGED_QUERY_SCHEMA,
        "mode": "merged",
        "pack_root": str(paths["pack_root"]),
        "query": query_text,
        "tags": tag_values,
        "limit": bounded_limit,
        "vector_limit": _bounded_limit(vector_limit, DEFAULT_VECTOR_LIMIT, MAX_VECTOR_LIMIT),
        "vector_min_score": float(vector_min_score),
        "results": results,
        "warnings": vector_payload.get("warnings", []),
    }


def default_index_root(pack_root: str | Path) -> Path:
    return Path(pack_root) / DEFAULT_INDEX_DIR


def _run_command(args: argparse.Namespace, backend: EmbeddingBackend) -> dict[str, Any]:
    if args.command == "build-index":
        return build_vector_index(
            args.pack_root,
            index_root=args.index_root or None,
            backend=backend,
            max_functions=args.max_functions,
        )
    if args.command == "query":
        return query_vector_recall(
            args.pack_root,
            args.query,
            index_root=args.index_root or None,
            backend=backend,
            limit=args.limit,
            min_score=args.min_score,
        )
    if args.command == "merge":
        return merge_recall(
            args.pack_root,
            args.query,
            tags=args.tag,
            index_root=args.index_root or None,
            backend=backend,
            limit=args.limit,
            vector_limit=args.vector_limit,
            vector_min_score=args.vector_min_score,
        )
    raise QueryError("Unsupported command: %s" % args.command)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Experimental secondary vector recall for Kernel Corpus packs.")
    parser.add_argument("--dimension", type=int, default=DEFAULT_DIMENSION, help="Token-hash embedding dimension.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build-index", help="Build an experimental vector index outside repo state by default.")
    _add_common_paths(build)
    build.add_argument("--max-functions", type=int, default=0, help="Optional bounded build for smoke experiments.")

    query = subparsers.add_parser("query", help="Return vector candidate EAs resolved through SQLite.")
    _add_common_paths(query)
    query.add_argument("--query", required=True, help="Semantic query text.")
    query.add_argument("--limit", type=int, default=DEFAULT_VECTOR_LIMIT)
    query.add_argument("--min-score", type=float, default=DEFAULT_MIN_SCORE)

    merge = subparsers.add_parser("merge", help="Merge exact, tag, FTS, and vector candidates.")
    _add_common_paths(merge)
    merge.add_argument("--query", required=True, help="Query text used for exact, FTS, and vector recall.")
    merge.add_argument("--tag", action="append", default=[], help="Optional required tag source. Can be repeated.")
    merge.add_argument("--limit", type=int, default=DEFAULT_MERGE_LIMIT)
    merge.add_argument("--vector-limit", type=int, default=DEFAULT_VECTOR_LIMIT)
    merge.add_argument("--vector-min-score", type=float, default=DEFAULT_MIN_SCORE)
    return parser


def _add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--index-root", default="", help="Vector index root. Default is <pack-root>\\experimental\\vector_recall.")


def _pack_paths(pack_root: str | Path) -> dict[str, Path]:
    root = Path(pack_root)
    if not root.exists() or not root.is_dir():
        raise QueryError("Pack root does not exist: %s" % root)
    sqlite_path = root / SQLITE_FILENAME
    manifest_path = root / MANIFEST_FILENAME
    if not sqlite_path.is_file():
        raise QueryError("Pack SQLite database is missing: %s" % sqlite_path)
    if not manifest_path.is_file():
        raise QueryError("Pack manifest is missing: %s" % manifest_path)
    return {
        "pack_root": root.resolve(),
        "sqlite_path": sqlite_path.resolve(),
        "manifest_path": manifest_path.resolve(),
    }


def _index_dir(pack_root: Path, index_root: str | Path | None) -> Path:
    if index_root is None:
        return default_index_root(pack_root).resolve()
    return Path(index_root).resolve()


def _index_path(pack_root: Path, index_root: str | Path | None) -> Path:
    return _index_dir(pack_root, index_root) / "vector-index.json"


def _load_index(pack_root: Path, index_root: str | Path | None) -> dict[str, Any]:
    path = _index_path(pack_root, index_root)
    if not path.is_file():
        raise QueryError("Vector index is missing; run build-index first: %s" % path)
    data = _read_json(path)
    if str(data.get("schema", "")) != VECTOR_INDEX_SCHEMA:
        raise QueryError("Unsupported vector index schema: %s" % data.get("schema", ""))
    return data


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QueryError("JSON file could not be read: %s" % exc) from exc
    if not isinstance(data, dict):
        raise QueryError("JSON file is not an object: %s" % path)
    return data


def _fts_rows(connection: Any) -> dict[str, dict[str, str]]:
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'function_fts'").fetchone() is None:
        return {}
    rows = {}
    for row in connection.execute("SELECT ea, terms, interesting_lines FROM function_fts"):
        rows[str(row["ea"])] = {
            "terms": str(row["terms"] or ""),
            "interesting_lines": str(row["interesting_lines"] or ""),
        }
    return rows


def _bounded_texts(row: Any, tags: list[str], fts: dict[str, str]) -> list[tuple[str, str]]:
    values = {
        "name": str(row["name"] or ""),
        "tags": " ".join(tags),
        "terms": str(fts.get("terms", "")),
        "interesting_lines": str(fts.get("interesting_lines", "")),
        "cleaned_excerpt": str(row["cleaned_excerpt"] or ""),
    }
    result = []
    for kind, limit in TEXT_KIND_LIMITS.items():
        text = _collapse_ws(values.get(kind, ""))[:limit].strip()
        if text:
            result.append((kind, text))
    return result


def _tags_for_ea(connection: Any, ea: str) -> list[str]:
    return [
        str(row["tag"])
        for row in connection.execute("SELECT tag FROM function_tags WHERE ea = ? ORDER BY tag", (ea,))
    ]


def _best_vector_hits(scored: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for item in scored:
        ea = str(item.get("ea", ""))
        if not ea:
            continue
        current = best.get(ea)
        if current is None or _vector_sort_key(item) < _vector_sort_key(current):
            best[ea] = item
    return sorted(best.values(), key=_vector_sort_key)


def _vector_sort_key(item: dict[str, Any]) -> tuple[float, int, int]:
    kind = str(item.get("source_text_kind", ""))
    return (
        -float(item.get("score", 0.0) or 0.0),
        int(TEXT_KIND_RANK.get(kind, len(TEXT_KIND_RANK))),
        int(str(item.get("ea", "0x0")), 0),
    )


def _merge_candidate(
    candidates: dict[str, dict[str, Any]],
    function: dict[str, Any],
    source: str,
    score: float,
    *,
    vector_score: float = 0.0,
    vector_source_text_kind: str = "",
) -> None:
    ea = str(function.get("ea", ""))
    if not ea:
        return
    item = candidates.setdefault(
        ea,
        {
            "ea": ea,
            "rerank_score": 0.0,
            "vector_score": 0.0,
            "vector_source_text_kind": "",
            "sources": set(),
        },
    )
    item["rerank_score"] = float(item["rerank_score"]) + float(score)
    item["sources"].add(source)
    if vector_score > float(item.get("vector_score", 0.0)):
        item["vector_score"] = vector_score
        item["vector_source_text_kind"] = vector_source_text_kind


def _validate_backend(index: dict[str, Any], backend: EmbeddingBackend) -> None:
    metadata = index.get("backend", {}) if isinstance(index.get("backend"), dict) else {}
    index_dimension = int(metadata.get("dimension", 0) or 0)
    if index_dimension != backend.dimension:
        raise QueryError("Vector index dimension does not match backend: %s != %s" % (index_dimension, backend.dimension))


def _index_warnings(paths: dict[str, Path], index: dict[str, Any], backend: EmbeddingBackend) -> list[str]:
    warnings = []
    manifest = _read_json(paths["manifest_path"])
    if str(index.get("source_index_sha256", "")) != str(manifest.get("source_index_sha256", "")):
        warnings.append("Vector index source hash differs from current pack manifest; rebuild the vector index.")
    if str(index.get("pack_root", "")) != str(paths["pack_root"]):
        warnings.append("Vector index was built for a different pack root.")
    metadata = index.get("backend", {}) if isinstance(index.get("backend"), dict) else {}
    if str(metadata.get("name", "")) != str(backend.name) or str(metadata.get("version", "")) != str(backend.version):
        warnings.append("Vector backend name/version differs from the index metadata; rebuild before trusting scores.")
    return warnings


def _backend_payload(backend: EmbeddingBackend) -> dict[str, Any]:
    return {
        "name": str(backend.name),
        "version": str(backend.version),
        "dimension": int(backend.dimension),
    }


def _bounded_limit(value: int, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def _cosine_document(
    query_vector: list[float],
    query_sparse: list[list[float]],
    document: dict[str, Any],
    dimension: int,
) -> float:
    values = document.get("vector", [])
    if isinstance(values, list) and values and all(isinstance(item, list) and len(item) == 2 for item in values):
        return _cosine_sparse(query_sparse, values, dimension)
    return _cosine(query_vector, _document_vector(document, dimension))


def _cosine_sparse(left_pairs: list[list[float]], right_pairs: list[list[float]], dimension: int) -> float:
    if not left_pairs or not right_pairs:
        return 0.0
    left = _sparse_dict(left_pairs, dimension)
    right = _sparse_dict(right_pairs, dimension)
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    dot = sum(value * right.get(index, 0.0) for index, value in left.items())
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def _sparse_vector(vector: list[float]) -> list[list[float]]:
    result = []
    for index, value in enumerate(vector):
        if abs(value) > 0.00000001:
            result.append([index, round(float(value), 8)])
    return result


def _sparse_dict(values: list[list[float]], dimension: int) -> dict[int, float]:
    result = {}
    for item in values:
        try:
            index = int(item[0])
            value = float(item[1])
        except (IndexError, TypeError, ValueError):
            continue
        if 0 <= index < dimension:
            result[index] = value
    return result


def _document_vector(document: dict[str, Any], dimension: int) -> list[float]:
    values = document.get("vector", [])
    if not isinstance(values, list):
        return []
    if values and all(isinstance(item, list) and len(item) == 2 for item in values):
        dense = [0.0] * dimension
        for item in values:
            try:
                index = int(item[0])
                value = float(item[1])
            except (TypeError, ValueError):
                continue
            if 0 <= index < dimension:
                dense[index] = value
        return dense
    return [float(value) for value in values]


def _normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm <= 0.0:
        return vector
    return [value / norm for value in vector]


def _tokens(text: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[A-Za-z0-9_]+", text) if token]


def _collapse_ws(text: str) -> str:
    return " ".join(str(text or "").split())


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
