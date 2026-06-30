from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.benchmark import run_benchmark
from ida_pseudoforge.core.benchmark_report import benchmark_report_to_markdown, write_benchmark_report
from ida_pseudoforge.core.benchmark_schema import (
    benchmark_fixture_from_dict,
    load_benchmark_fixture,
    load_benchmark_fixtures,
)
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence


WIN_USER_PE_SAMPLE = r"""
__int64 __fastcall WinUserPeBenchmark(void *iface)
{
  HANDLE hFile;
  void *region;

  hFile = CreateFileW(L"C:\\temp\\input.bin", 0x80000000, 1u, 0i64, 3u, 0x80u, 0i64);
  region = VirtualAlloc(0i64, 0x1000ui64, 0x3000u, 4u);
  CloseHandle(hFile);
  return region != 0;
}
"""


LINUX_ELF_SAMPLE = r"""
int __fastcall LinuxElfBenchmark(void *ctx)
{
  void *buffer;

  buffer = malloc(64);
  pthread_mutex_lock(ctx);
  socket(2, 1, 0);
  free(buffer);
  pthread_mutex_unlock(ctx);
  return 0;
}
"""


CXX_SAMPLE = r"""
__int64 __fastcall CxxBenchmark(struct Widget *thisPtr)
{
  void *storage;

  storage = operator new(32ui64);
  thisPtr->__vftable->Run(thisPtr);
  __CxxFrameHandler3();
  operator delete(storage);
  return 0;
}
"""


class BenchmarkTests(unittest.TestCase):
    def test_general_benchmark_runs_windows_linux_and_cxx_fixtures(self) -> None:
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
                        {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                        {"kind": "rejected_domain_pack", "value": "windows_kernel"},
                        {"kind": "comment_kind", "value": "win_user_handle_lifetime"},
                        {"kind": "comment_kind", "value": "contract_pack_api"},
                        {"kind": "contract_profile", "value": "contracts/win_user_api_contracts.json"},
                        {"kind": "contract_domain", "value": "windows_user_mode"},
                        {"kind": "contract_symbol", "value": "CreateFileW"},
                        {"kind": "contract_symbol", "value": "CloseHandle"},
                        {"kind": "ir_available", "value": "true"},
                        {"kind": "ir_call_site_min", "value": "3"},
                        {"kind": "ir_call_argument", "value": r'CreateFileW:L"C:\\temp\\input.bin"'},
                        {"kind": "ir_call_argument", "value": "VirtualAlloc:0x1000ui64"},
                        {"kind": "ir_use_def_min", "value": "2"},
                        {"kind": "ir_diagnostic", "value": "return_check:VirtualAlloc:region:nonzero_success"},
                    ],
                    "negative_controls": [
                        {"kind": "eligible_domain_pack", "value": "windows_kernel"},
                        {"kind": "contract_profile", "value": "contracts/linux_user_api_contracts.json"},
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
                        "sections": [".text", ".rodata", ".eh_frame"],
                    },
                    "expected_observations": [
                        {"kind": "target_family", "value": "linux_elf_user"},
                        {"kind": "import_family", "value": "libc"},
                        {"kind": "import_family", "value": "pthread"},
                        {"kind": "section_clue", "value": "elf_exception_metadata"},
                        {"kind": "eligible_domain_pack", "value": "linux_elf_user"},
                        {"kind": "rejected_domain_pack", "value": "win_user_pe"},
                        {"kind": "comment_kind", "value": "contract_pack_api"},
                        {"kind": "contract_profile", "value": "contracts/linux_user_api_contracts.json"},
                        {"kind": "contract_domain", "value": "linux_userland"},
                        {"kind": "contract_symbol", "value": "malloc"},
                        {"kind": "contract_symbol", "value": "pthread_mutex_lock"},
                        {"kind": "contract_symbol", "value": "socket"},
                    ],
                    "negative_controls": [
                        {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                        {"kind": "eligible_domain_pack", "value": "windows_kernel"},
                        {"kind": "contract_profile", "value": "contracts/win_user_api_contracts.json"},
                    ],
                }
            ),
            benchmark_fixture_from_dict(
                {
                    "schema": "pseudoforge_general_benchmark_fixture_v1",
                    "name": "cxx_msvc",
                    "source_path": r"C:\bin\widget.exe",
                    "pseudocode": CXX_SAMPLE,
                    "profile_context": {
                        "format": "pe",
                        "platform": "windows",
                        "privilege_domain": "user",
                    },
                    "expected_observations": [
                        {"kind": "runtime_clue", "value": "runtime:cxx"},
                        {"kind": "eligible_domain_pack", "value": "cxx_runtime"},
                        {"kind": "comment_kind", "value": "cxx_vtable_call"},
                    ],
                    "negative_controls": [
                        {"kind": "eligible_domain_pack", "value": "windows_kernel"},
                    ],
                }
            ),
        ]

        report = run_benchmark(fixtures, measure_runtime=False)
        markdown = benchmark_report_to_markdown(report)

        self.assertEqual("pseudoforge_general_benchmark_v1", report["schema"])
        self.assertEqual("foundation prototype", report["claim_level"])
        self.assertEqual("pseudoforge_general_claim_gate_v1", report["claim_gate"]["schema"])
        self.assertEqual("passed", report["claim_gate"]["status"])
        self.assertEqual(3, report["fixture_count"])
        self.assertEqual(3, report["passed"])
        self.assertEqual(0, report["failed"])
        self.assertGreaterEqual(report["accepted_observations"], 20)
        self.assertEqual(0, report["false_positives"])
        self.assertGreaterEqual(report["claim_gate"]["metrics"]["negative_controls"], 1)
        self.assertIn("real_corpus_gate_missing", report["claim_gate"]["blockers"])
        self.assertEqual(0, report["runtime_ms"])
        self.assertIn("win_user_pe", markdown)
        self.assertIn("linux_elf_user", markdown)
        self.assertIn("contracts/win_user_api_contracts.json", report["fixtures"][0]["contract_profiles"])
        self.assertIn("contracts/linux_user_api_contracts.json", report["fixtures"][1]["contract_profiles"])
        self.assertIn("foundation prototype", markdown)

    def test_general_benchmark_loads_contract_corpus_fixture_directory(self) -> None:
        fixture_root = Path(__file__).resolve().parent / "fixtures" / "general_binaries"

        fixtures = load_benchmark_fixtures([fixture_root])
        report = run_benchmark(fixtures, measure_runtime=False)

        self.assertGreaterEqual(len(fixtures), 2)
        self.assertEqual(len(fixtures), report["fixture_count"])
        self.assertEqual(len(fixtures), report["passed"])
        self.assertEqual(0, report["failed"])
        self.assertEqual(0, report["false_positives"])
        self.assertTrue(
            any(
                "contracts/win_user_api_contracts.json" in fixture["contract_profiles"]
                for fixture in report["fixtures"]
            )
        )
        self.assertTrue(
            any(
                "contracts/linux_user_api_contracts.json" in fixture["contract_profiles"]
                for fixture in report["fixtures"]
            )
        )

    def test_general_benchmark_uses_corpus_manifest_for_claim_gate(self) -> None:
        fixture_root = Path(__file__).resolve().parent / "fixtures" / "general_binaries"
        manifest_path = Path(__file__).resolve().parent / "fixtures" / "general_corpus" / "claim_useful_manifest.json"

        fixtures = load_benchmark_fixtures([fixture_root])
        corpus_evidence = load_corpus_evidence([manifest_path])
        report = run_benchmark(fixtures, measure_runtime=False, corpus_evidence=corpus_evidence)

        self.assertEqual("useful general assistant", report["claim_level"])
        self.assertEqual("passed", report["claim_gate"]["status"])
        self.assertEqual(2, report["claim_gate"]["corpus_evidence"]["real_corpus_count"])
        self.assertNotIn("real_corpus_gate_missing", report["claim_gate"]["blockers"])

    def test_benchmark_report_marks_incompatible_expectation_failed(self) -> None:
        fixture = benchmark_fixture_from_dict(
            {
                "schema": "pseudoforge_general_benchmark_fixture_v1",
                "name": "bad_expectation",
                "source_path": "/tmp/server.elf",
                "pseudocode": LINUX_ELF_SAMPLE,
                "profile_context": {"format": "elf", "platform": "linux"},
                "expected_observations": [
                    {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                ],
            }
        )

        report = run_benchmark([fixture], measure_runtime=False)

        self.assertEqual(1, report["failed"])
        self.assertFalse(report["fixtures"][0]["expectation_results"][0]["passed"])

    def test_benchmark_fixture_loader_reports_missing_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "name is required"):
            benchmark_fixture_from_dict(
                {
                    "schema": "pseudoforge_general_benchmark_fixture_v1",
                    "pseudocode": "int f(){return 0;}",
                }
            )

    def test_benchmark_cli_artifacts_can_be_written_from_fixture_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture_path = root / "fixture.json"
            fixture_path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_general_benchmark_fixture_v1",
                        "name": "win_user_file",
                        "source_path": r"C:\bin\client.exe",
                        "pseudocode": WIN_USER_PE_SAMPLE,
                        "profile_context": {
                            "format": "pe",
                            "platform": "windows",
                            "privilege_domain": "user",
                        },
                        "expected_observations": [
                            {"kind": "target_family", "value": "windows_user_pe"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_benchmark([load_benchmark_fixture(fixture_path)], measure_runtime=False)
            json_out = root / "benchmark.json"
            markdown_out = root / "benchmark.md"

            write_benchmark_report(report, json_out, markdown_out)

            self.assertTrue(json_out.exists())
            self.assertTrue(markdown_out.exists())
            self.assertEqual(
                "pseudoforge_general_benchmark_v1",
                json.loads(json_out.read_text(encoding="utf-8"))["schema"],
            )

    def test_benchmark_tool_script_runs_from_repo_root(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(repo_root / "tools" / "pseudoforge_benchmark.py"),
                str(fixture_root),
                "--no-runtime",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual("", completed.stderr)
        self.assertEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("foundation prototype", payload["claim_level"])
        self.assertEqual("passed", payload["claim_gate"]["status"])

    def test_benchmark_tool_script_accepts_corpus_manifest(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        manifest_path = repo_root / "tests" / "fixtures" / "general_corpus" / "claim_useful_manifest.json"

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(repo_root / "tools" / "pseudoforge_benchmark.py"),
                str(fixture_root),
                "--corpus-manifest",
                str(manifest_path),
                "--no-runtime",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual("", completed.stderr)
        self.assertEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("useful general assistant", payload["claim_level"])
        self.assertEqual("passed", payload["claim_gate"]["status"])

    def test_benchmark_tool_script_accepts_evidence_ledgers(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        corpus_root = repo_root / "tests" / "fixtures" / "general_corpus"

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(repo_root / "tools" / "pseudoforge_benchmark.py"),
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
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual("", completed.stderr)
        self.assertEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("useful general assistant", payload["claim_level"])
        self.assertEqual(2, payload["claim_gate"]["corpus_evidence"]["qualified_external_baseline_count"])
        self.assertEqual(1, payload["claim_gate"]["corpus_evidence"]["qualified_analyst_audit_count"])
        self.assertEqual(2, payload["claim_gate"]["corpus_evidence"]["qualified_cross_function_contract_count"])

    def test_benchmark_tool_script_fails_on_baseline_claim_regression(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "general_binaries"
        manifest_path = repo_root / "tests" / "fixtures" / "general_corpus" / "claim_useful_manifest.json"

        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_path = Path(temp_dir) / "baseline.json"
            fixtures = load_benchmark_fixtures([fixture_root])
            baseline_report = run_benchmark(
                fixtures,
                measure_runtime=False,
                corpus_evidence=load_corpus_evidence([manifest_path]),
            )
            baseline_path.write_text(json.dumps(baseline_report), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_benchmark.py"),
                    str(fixture_root),
                    "--baseline-json",
                    str(baseline_path),
                    "--no-runtime",
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual("", completed.stderr)
        self.assertEqual(1, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("failed", payload["claim_gate"]["status"])
        self.assertIn(
            "claim_rank",
            {item["metric"] for item in payload["claim_gate"]["regressions"]},
        )


if __name__ == "__main__":
    unittest.main()
