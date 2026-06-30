from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.analyst_audit_worklist import analyst_audit_ledger_from_corpus_manifest
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence
from ida_pseudoforge.core.evidence_pack import (
    apply_evidence_ledgers,
    load_analyst_audit_ledger,
)


class AnalystAuditWorklistTests(unittest.TestCase):
    def test_worklist_entries_are_non_qualifying_until_analyst_accepts_them(self) -> None:
        manifest = _manifest()

        ledger = analyst_audit_ledger_from_corpus_manifest(
            manifest,
            reviewer="analyst-a",
            reference_prefix="review://unit/",
        )
        merged = apply_evidence_ledgers(manifest, analyst_audit_ledgers=[ledger])

        self.assertEqual("pseudoforge_analyst_audit_ledger_v1", ledger["schema"])
        self.assertEqual(1, len(ledger["audits"]))
        self.assertEqual("blocked", ledger["audits"][0]["status"])
        self.assertEqual(0, merged["corpora"][0]["analyst_audit_count"])

    def test_worklist_tool_writes_loadable_non_qualifying_ledger(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            ledger_path = Path(temp_dir) / "audit-ledger.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_analyst_audit_worklist.py"),
                    str(manifest_path),
                    "--reviewer",
                    "analyst-a",
                    "--reference-prefix",
                    "review://unit/",
                    "--json-out",
                    str(ledger_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            ledger = load_analyst_audit_ledger(ledger_path)
            merged_path = Path(temp_dir) / "merged.json"
            merged = apply_evidence_ledgers(_manifest(), analyst_audit_ledgers=[ledger])
            merged_path.write_text(json.dumps(merged), encoding="utf-8")
            evidence = load_corpus_evidence([merged_path])

        self.assertEqual(1, len(ledger["audits"]))
        self.assertEqual(0, evidence["qualified_analyst_audit_count"])


def _manifest() -> dict[str, object]:
    return {
        "schema": "pseudoforge_general_corpus_manifest_v1",
        "corpora": [
            {
                "name": "ida_batch_replay_windows_user_pe_0",
                "target_family": "windows_user_pe",
                "origin": "ida_batch_replay_summary",
                "claim_eligible": True,
                "source_reference": "ida-batch://unit",
                "function_count": 10,
                "ground_truth_pair_count": 0,
                "ground_truth_pairs": [],
                "ir_evidence_function_count": 10,
                "ir_total_function_count": 10,
                "cross_function_contract_count": 0,
                "external_baselines": [],
                "analyst_audit_count": 0,
            },
            {
                "name": "synthetic_preview",
                "target_family": "windows_user_pe",
                "origin": "unit",
                "claim_eligible": False,
                "source_reference": "synthetic://unit",
                "function_count": 1,
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
