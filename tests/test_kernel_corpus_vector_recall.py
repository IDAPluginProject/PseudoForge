from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.experimental.vector_recall import (
    VECTOR_INDEX_SCHEMA,
    build_vector_index,
    default_index_root,
    merge_recall,
    query_vector_recall,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class TinyFakeEmbeddingBackend:
    name = "tiny_fake"
    version = "test"
    dimension = 4

    def embed(self, text: str) -> list[float]:
        lowered = text.lower()
        vector = [0.0, 0.0, 0.0, 0.0]
        if "create" in lowered or "user" in lowered:
            vector[0] += 1.0
        if "alloc" in lowered or "pool" in lowered or "memory" in lowered:
            vector[1] += 1.0
        if "delete" in lowered or "dereference" in lowered:
            vector[2] += 1.0
        if "process" in lowered:
            vector[3] += 0.5
        return vector


class KernelCorpusVectorRecallTests(unittest.TestCase):
    def test_build_index_stores_bounded_metadata_under_pack_root_by_default(self) -> None:
        backend = TinyFakeEmbeddingBackend()
        with _built_pack() as pack_root:
            report = build_vector_index(pack_root, backend=backend)
            index_root = default_index_root(pack_root)
            index_path = index_root / "vector-index.json"
            data = json.loads(index_path.read_text(encoding="utf-8"))

            self.assertTrue(Path(report["index_path"]).is_file())
            self.assertEqual(str(index_root.resolve()), report["index_root"])
            self.assertEqual(VECTOR_INDEX_SCHEMA, data["schema"])
            self.assertEqual("tiny_fake", data["backend"]["name"])
            self.assertGreaterEqual(data["document_count"], 3)
            for document in data["documents"]:
                self.assertNotIn("text", document)
                self.assertIn(document["source_text_kind"], data["bounds"])
                self.assertLessEqual(document["text_length"], data["bounds"][document["source_text_kind"]])
                self.assertEqual("sparse_pairs", document["vector_format"])
                for index, value in document["vector"]:
                    self.assertGreaterEqual(index, 0)
                    self.assertLess(index, backend.dimension)
                    self.assertIsInstance(value, float)

    def test_vector_query_returns_score_kind_and_resolved_function_payload(self) -> None:
        backend = TinyFakeEmbeddingBackend()
        with _built_pack() as pack_root:
            build_vector_index(pack_root, backend=backend)

            payload = query_vector_recall(pack_root, "pool allocation", backend=backend, limit=3)

            self.assertEqual("kernel_corpus_vector_recall_query_v1", payload["schema"])
            self.assertEqual("vector", payload["mode"])
            self.assertEqual("PspAllocateProcess", payload["results"][0]["function"]["name"])
            self.assertGreater(payload["results"][0]["vector_score"], 0.0)
            self.assertIn(payload["results"][0]["source_text_kind"], {"name", "tags", "terms", "interesting_lines", "cleaned_excerpt"})
            self.assertTrue(Path(payload["results"][0]["function"]["artifacts"]["summary"]).is_file())

    def test_merge_recall_combines_exact_tag_fts_and_vector_sources(self) -> None:
        backend = TinyFakeEmbeddingBackend()
        with _built_pack() as pack_root:
            build_vector_index(pack_root, backend=backend)

            payload = merge_recall(pack_root, "PspAllocateProcess", tags=["memory"], backend=backend, limit=5)

            first = payload["results"][0]
            self.assertEqual("kernel_corpus_vector_recall_merge_v1", payload["schema"])
            self.assertEqual("PspAllocateProcess", first["function"]["name"])
            self.assertIn("exact_name", first["sources"])
            self.assertIn("tag:memory", first["sources"])
            self.assertTrue(any(source.startswith("vector:") for source in first["sources"]))
            self.assertGreater(first["rerank_score"], first["vector_score"])


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


if __name__ == "__main__":
    unittest.main()
