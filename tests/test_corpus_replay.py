from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.benchmark import run_benchmark
from ida_pseudoforge.core.benchmark_schema import benchmark_fixture_from_dict, load_benchmark_fixtures
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, summarize_corpus_manifests
from ida_pseudoforge.core.corpus_replay import corpus_manifest_from_benchmark_reports
from tests.test_benchmark import LINUX_ELF_SAMPLE, WIN_USER_PE_SAMPLE


class CorpusReplayTests(unittest.TestCase):
    def test_replay_manifest_records_ground_truth_and_ir_coverage(self) -> None:
        fixtures = [
            benchmark_fixture_from_dict(
                {
                    "schema": "pseudoforge_general_benchmark_fixture_v1",
                    "name": "win_user_pe",
                    "source_path": r"C:\bin\client.exe",
                    "pseudocode": WIN_USER_PE_SAMPLE,
                    "profile_context": {
                        "format": "pe",
                        "platform": "windows",
                        "privilege_domain": "user",
                        "imports": ["CreateFileW", "VirtualAlloc", "CloseHandle"],
                        "enable_textual_ir_evidence": True,
                    },
                    "expected_observations": [
                        {"kind": "target_family", "value": "windows_user_pe"},
                        {"kind": "contract_symbol", "value": "CreateFileW"},
                    ],
                    "negative_controls": [
                        {"kind": "eligible_domain_pack", "value": "windows_kernel"},
                    ],
                }
            ),
            benchmark_fixture_from_dict(
                {
                    "schema": "pseudoforge_general_benchmark_fixture_v1",
                    "name": "linux_elf",
                    "source_path": "/tmp/server.elf",
                    "pseudocode": LINUX_ELF_SAMPLE,
                    "profile_context": {
                        "format": "elf",
                        "platform": "linux",
                        "imports": ["malloc", "pthread_mutex_lock", "socket"],
                    },
                    "expected_observations": [
                        {"kind": "target_family", "value": "linux_elf_user"},
                        {"kind": "contract_symbol", "value": "malloc"},
                    ],
                    "negative_controls": [
                        {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                    ],
                }
            ),
        ]
        report = run_benchmark(fixtures, measure_runtime=False)

        manifest = corpus_manifest_from_benchmark_reports(
            [report],
            name_prefix="unit_replay",
            source_reference="local-replay://unit",
            claim_eligible=True,
        )
        evidence = summarize_corpus_manifests([manifest])

        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertEqual(2, evidence["real_corpus_function_count"])
        self.assertEqual(4, evidence["qualified_ground_truth_pair_count"])
        self.assertEqual(1, evidence["ir_evidence_function_count"])
        self.assertEqual(2, evidence["ir_total_function_count"])
        self.assertEqual(0.5, evidence["ir_evidence_coverage"])
        self.assertEqual(["linux_elf_user", "windows_user_pe"], evidence["target_families"])

    def test_replay_manifest_is_not_claim_eligible_by_default(self) -> None:
        report = run_benchmark([], measure_runtime=False)

        manifest = corpus_manifest_from_benchmark_reports([report])
        evidence = summarize_corpus_manifests([manifest])

        self.assertEqual(0, evidence["real_corpus_count"])

    def test_corpus_replay_tool_writes_claim_eligible_manifest(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "benchmark.json"
            manifest_path = Path(temp_dir) / "manifest.json"
            report = run_benchmark(load_benchmark_fixtures([fixture_root]), measure_runtime=False)
            report_path.write_text(json.dumps(report), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_corpus_replay.py"),
                    str(report_path),
                    "--claim-eligible",
                    "--source-reference",
                    "local-replay://general-binaries",
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

        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertGreaterEqual(evidence["qualified_ground_truth_pair_count"], 20)
        self.assertEqual(2, evidence["ir_evidence_function_count"])
        self.assertEqual(2, evidence["ir_total_function_count"])
        self.assertEqual(1.0, evidence["ir_evidence_coverage"])


if __name__ == "__main__":
    unittest.main()
