from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.multi_ir_evidence import (
    corpus_records_from_multi_ir_evidence,
    load_multi_ir_evidence,
)


class MultiIrEvidenceTests(unittest.TestCase):
    def test_multi_ir_evidence_normalizes_views_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "multi-ir.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_multi_ir_evidence_v1",
                        "records": [
                            {
                                "function": "OpenClose",
                                "views": ["ida_hexrays", "ghidra_pcode", "angr_ail"],
                                "reference": "multi-ir://open-close",
                                "status": "validated",
                            },
                            {
                                "function": "Blocked",
                                "views": "ida_hexrays,binaryninja_hlil",
                                "reference": "multi-ir://blocked",
                                "status": "blocked",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = load_multi_ir_evidence(path)
            records = corpus_records_from_multi_ir_evidence(evidence)

        self.assertEqual(2, evidence["summary"]["record_count"])
        self.assertEqual(1, evidence["summary"]["qualified_record_count"])
        self.assertEqual(3, evidence["summary"]["qualified_view_count"])
        self.assertEqual("OpenClose", records[0]["function"])
        self.assertEqual(["angr_ail", "ghidra_pcode", "ida_hexrays"], records[0]["views"])


if __name__ == "__main__":
    unittest.main()
