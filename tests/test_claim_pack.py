from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ClaimPackTests(unittest.TestCase):
    def test_claim_pack_tool_writes_benchmark_gap_and_summary(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        corpus_root = repo_root / "tests" / "fixtures" / "general_corpus"
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "claim-pack"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_claim_pack.py"),
                    str(fixture_root),
                    "--corpus-manifest",
                    str(corpus_root / "claim_useful_manifest.json"),
                    "--external-baseline-ledger",
                    str(corpus_root / "external_baseline_ledger.json"),
                    "--analyst-audit-ledger",
                    str(corpus_root / "analyst_audit_ledger.json"),
                    "--cross-function-contract-ledger",
                    str(corpus_root / "cross_function_contract_ledger.json"),
                    "--no-runtime",
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            benchmark = json.loads((out_dir / "benchmark.json").read_text(encoding="utf-8"))
            gap = json.loads((out_dir / "claim-gap.json").read_text(encoding="utf-8"))
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            markdown = (out_dir / "claim-gap.md").read_text(encoding="utf-8")

        self.assertEqual("useful general assistant", summary["claim_level"])
        self.assertEqual("useful general assistant", benchmark["claim_level"])
        self.assertGreater(gap["gap_count"], 0)
        self.assertFalse(summary["world_class_claim_allowed"])
        self.assertIn("PseudoForge World-Class Claim Gap", markdown)


if __name__ == "__main__":
    unittest.main()
