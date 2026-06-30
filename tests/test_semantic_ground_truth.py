from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.semantic_ground_truth import (
    corpus_semantic_records_from_pack,
    load_semantic_ground_truth_pack,
)


class SemanticGroundTruthTests(unittest.TestCase):
    def test_semantic_ground_truth_pack_requires_source_and_binary_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "semantic.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_semantic_ground_truth_pack_v1",
                        "pairs": [
                            {
                                "id": "resource-lifetime",
                                "reference": "semantic://resource-lifetime",
                                "source_path": "src/resource.c",
                                "binary_path": "build/resource.elf",
                                "function": "open_close",
                                "semantic_kind": "resource_lifetime",
                                "oracle": "open result reaches close on success paths",
                                "validation": "source map plus runtime harness",
                                "status": "validated",
                            },
                            {
                                "id": "symbol-only-blocked",
                                "reference": "semantic://blocked",
                                "source_path": "src/symbol.c",
                                "binary_path": "build/symbol.elf",
                                "function": "symbol",
                                "semantic_kind": "symbol_identity",
                                "oracle": "symbol name only",
                                "validation": "not behavior-equivalent",
                                "status": "blocked",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            pack = load_semantic_ground_truth_pack(path)
            records = corpus_semantic_records_from_pack(pack)

        self.assertEqual(2, pack["summary"]["pair_count"])
        self.assertEqual(1, pack["summary"]["qualified_pair_count"])
        self.assertEqual("resource_lifetime", records[0]["semantic_kind"])
        self.assertEqual("validated", records[0]["status"])


if __name__ == "__main__":
    unittest.main()
