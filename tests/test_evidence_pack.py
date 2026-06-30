from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, load_corpus_manifest, summarize_corpus_manifests
from ida_pseudoforge.core.evidence_pack import (
    apply_evidence_ledgers,
    load_analyst_audit_ledger,
    load_cross_function_contract_ledger,
    load_external_baseline_ledger,
)


class EvidencePackTests(unittest.TestCase):
    def test_evidence_ledgers_attach_only_qualified_records(self) -> None:
        root = Path(__file__).resolve().parent / "fixtures" / "general_corpus"
        manifest = load_corpus_manifest(root / "claim_useful_manifest.json")
        baseline_ledger = load_external_baseline_ledger(root / "external_baseline_ledger.json")
        audit_ledger = load_analyst_audit_ledger(root / "analyst_audit_ledger.json")
        contract_ledger = load_cross_function_contract_ledger(root / "cross_function_contract_ledger.json")

        merged = apply_evidence_ledgers(manifest, [baseline_ledger], [audit_ledger], [contract_ledger])
        evidence = summarize_corpus_manifests([merged])

        self.assertEqual(2, evidence["qualified_external_baseline_count"])
        self.assertEqual(["binary-ninja", "ghidra"], evidence["qualified_external_baselines"])
        self.assertEqual(1, evidence["qualified_analyst_audit_count"])
        self.assertEqual(["audit-win-user-file-lifetime"], evidence["qualified_analyst_audits"])
        self.assertEqual(2, evidence["qualified_cross_function_contract_count"])

    def test_external_baseline_ledger_requires_metric(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "baseline.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_external_baseline_ledger_v1",
                        "baselines": [
                            {
                                "name": "ghidra",
                                "corpus_name": "sample",
                                "target_family": "windows_user_pe",
                                "reference": "local-baseline://sample",
                                "status": "passed",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "metric is required"):
                load_external_baseline_ledger(path)

    def test_analyst_audit_ledger_rejects_unknown_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "audit.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_analyst_audit_ledger_v1",
                        "audits": [
                            {
                                "id": "audit",
                                "corpus_name": "sample",
                                "target_family": "windows_user_pe",
                                "reviewer": "local-review",
                                "reference": "local-audit://sample",
                                "status": "maybe",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "status is unsupported"):
                load_analyst_audit_ledger(path)

    def test_evidence_pack_tool_writes_merged_manifest(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_corpus"

        with tempfile.TemporaryDirectory() as temp_dir:
            merged_manifest = Path(temp_dir) / "merged_manifest.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_evidence_pack.py"),
                    "--corpus-manifest",
                    str(fixture_root / "claim_useful_manifest.json"),
                    "--external-baseline-ledger",
                    str(fixture_root / "external_baseline_ledger.json"),
                    "--analyst-audit-ledger",
                    str(fixture_root / "analyst_audit_ledger.json"),
                    "--cross-function-contract-ledger",
                    str(fixture_root / "cross_function_contract_ledger.json"),
                    "--json-out",
                    str(merged_manifest),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            evidence = load_corpus_evidence([merged_manifest])

        self.assertEqual(2, evidence["qualified_external_baseline_count"])
        self.assertEqual(1, evidence["qualified_analyst_audit_count"])
        self.assertEqual(2, evidence["qualified_cross_function_contract_count"])


if __name__ == "__main__":
    unittest.main()
