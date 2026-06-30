from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, summarize_corpus_manifests
from ida_pseudoforge.core.ida_batch_replay import (
    corpus_manifest_from_ida_batch_summaries,
    load_ida_batch_summaries,
)


class IdaBatchReplayTests(unittest.TestCase):
    def test_replay_manifest_records_ida_ir_coverage_without_ground_truth_inflation(self) -> None:
        summaries = [
            _summary("OpenFile", "windows_user_pe", ir_available=True),
            _summary("CloseFile", "windows_user_pe", ir_available=False),
            _summary("SendThing", "linux_elf_user", ir_available=True),
        ]

        manifest = corpus_manifest_from_ida_batch_summaries(
            summaries,
            name_prefix="ida_unit",
            source_reference="ida-batch://unit-run",
            claim_eligible=True,
        )
        evidence = summarize_corpus_manifests([manifest])

        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertEqual(3, evidence["real_corpus_function_count"])
        self.assertEqual(0, evidence["qualified_ground_truth_pair_count"])
        self.assertEqual(2, evidence["ir_evidence_function_count"])
        self.assertEqual(3, evidence["ir_total_function_count"])
        self.assertAlmostEqual(2 / 3, evidence["ir_evidence_coverage"])
        self.assertEqual(["linux_elf_user", "windows_user_pe"], evidence["target_families"])

    def test_replay_manifest_promotes_ida_evidence_only_when_requested(self) -> None:
        summaries = [
            _summary(
                "OpenFile",
                "windows_user_pe",
                ir_available=True,
                matched_symbols=["CreateFileW", "CloseHandle"],
            ),
            _summary(
                "sub_140002000",
                "windows_user_pe",
                ir_available=True,
                matched_symbols=["VirtualAlloc"],
            ),
            _summary(
                "NoIrSymbol",
                "windows_user_pe",
                ir_available=False,
                matched_symbols=["CloseHandle"],
            ),
        ]

        manifest = corpus_manifest_from_ida_batch_summaries(
            summaries,
            name_prefix="ida_unit",
            source_reference="ida-batch://unit-run",
            claim_eligible=True,
            include_symbol_ground_truth=True,
            include_contract_call_evidence=True,
        )
        evidence = summarize_corpus_manifests([manifest])
        corpus = manifest["corpora"][0]

        self.assertEqual(1, evidence["qualified_ground_truth_pair_count"])
        self.assertEqual(2, evidence["qualified_cross_function_contract_count"])
        self.assertEqual("OpenFile", corpus["cross_function_contracts"][0]["source_function"])
        self.assertIn("ida-batch://unit-run#sha256=", corpus["ground_truth_pairs"][0]["reference"])

    def test_claim_eligible_ida_replay_requires_source_reference(self) -> None:
        with self.assertRaisesRegex(ValueError, "source-reference"):
            corpus_manifest_from_ida_batch_summaries(
                [_summary("OpenFile", "windows_user_pe", ir_available=True)],
                claim_eligible=True,
            )

    def test_claim_eligible_ida_replay_rejects_zero_ir_coverage(self) -> None:
        with self.assertRaisesRegex(ValueError, "nonzero IR evidence coverage"):
            corpus_manifest_from_ida_batch_summaries(
                [_summary("OpenFile", "windows_user_pe", ir_available=False)],
                source_reference="ida-batch://zero-ir",
                claim_eligible=True,
            )

    def test_claim_eligible_ida_replay_rejects_unknown_target_family(self) -> None:
        with self.assertRaisesRegex(ValueError, "known target families"):
            corpus_manifest_from_ida_batch_summaries(
                [_summary("OpenFile", "unknown", ir_available=True)],
                source_reference="ida-batch://unknown-target",
                claim_eligible=True,
            )

    def test_ida_batch_replay_tool_writes_manifest_from_directory(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "0000000140001000_OpenFile"
            function_dir.mkdir(parents=True)
            (function_dir / "function.ida-batch-summary.json").write_text(
                json.dumps(_summary("OpenFile", "windows_user_pe", ir_available=True)),
                encoding="utf-8",
            )
            manifest_path = root / "manifest.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_ida_batch_replay.py"),
                    str(root),
                    "--claim-eligible",
                    "--source-reference",
                    "ida-batch://unit-directory",
                    "--include-symbol-ground-truth",
                    "--json-out",
                    str(manifest_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            evidence = load_corpus_evidence([manifest_path])

        self.assertEqual(1, evidence["real_corpus_count"])
        self.assertEqual(1, evidence["real_corpus_function_count"])
        self.assertEqual(1, evidence["qualified_ground_truth_pair_count"])
        self.assertEqual(1, evidence["ir_evidence_function_count"])
        self.assertEqual(1.0, evidence["ir_evidence_coverage"])

    def test_load_ida_batch_summaries_rejects_malformed_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "function.ida-batch-summary.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "root must be an object"):
                load_ida_batch_summaries([path])


def _summary(
    function: str,
    target_family: str,
    ir_available: bool,
    matched_symbols: list[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "mode": "ida_batch_export",
        "function": function,
        "function_ea": "0x140001000",
        "input_fingerprint": "unit-sha256",
        "target_context": {
            "target_family": target_family,
            "format": "pe" if target_family.startswith("windows") else "elf",
        },
        "ir_evidence_summary": {
            "schema": "pseudoforge_ir_evidence_v1",
            "adapter": "hexrays_cfunc_v1" if ir_available else "text_only",
            "source": "hexrays_cfunc" if ir_available else "pseudocode",
            "available": ir_available,
            "use_def_chains": 1 if ir_available else 0,
            "value_ranges": 0,
            "local_type_snapshots": 1 if ir_available else 0,
            "constant_origins": 0,
            "call_site_signatures": 1 if ir_available else 0,
            "diagnostics": 0,
        },
    }
    if matched_symbols is not None:
        payload["contract_pack_summary"] = {
            "schema": "pseudoforge_contract_pack_summary_v1",
            "matched_symbols": matched_symbols,
        }
    return payload


if __name__ == "__main__":
    unittest.main()
