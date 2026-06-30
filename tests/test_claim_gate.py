from __future__ import annotations

import copy
import unittest

from ida_pseudoforge.core.benchmark import run_benchmark
from ida_pseudoforge.core.benchmark_schema import benchmark_fixture_from_dict
from ida_pseudoforge.core.claim_gate import evaluate_claim_gate


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


def _strong_report() -> dict[str, object]:
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
                },
                "expected_observations": [
                    {"kind": "target_family", "value": "windows_user_pe"},
                    {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                    {"kind": "contract_profile", "value": "contracts/win_user_api_contracts.json"},
                    {"kind": "contract_symbol", "value": "CreateFileW"},
                    {"kind": "contract_symbol", "value": "VirtualAlloc"},
                    {"kind": "contract_symbol", "value": "CloseHandle"},
                ],
                "negative_controls": [
                    {"kind": "eligible_domain_pack", "value": "windows_kernel"},
                    {"kind": "contract_profile", "value": "contracts/linux_user_api_contracts.json"},
                    {"kind": "contract_symbol", "value": "malloc"},
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
                    {"kind": "eligible_domain_pack", "value": "linux_elf_user"},
                    {"kind": "import_family", "value": "libc"},
                    {"kind": "import_family", "value": "pthread"},
                    {"kind": "contract_profile", "value": "contracts/linux_user_api_contracts.json"},
                    {"kind": "contract_symbol", "value": "malloc"},
                    {"kind": "contract_symbol", "value": "pthread_mutex_lock"},
                    {"kind": "contract_symbol", "value": "socket"},
                ],
                "negative_controls": [
                    {"kind": "eligible_domain_pack", "value": "win_user_pe"},
                    {"kind": "contract_profile", "value": "contracts/win_user_api_contracts.json"},
                    {"kind": "contract_symbol", "value": "CreateFileW"},
                ],
            }
        ),
    ]
    return run_benchmark(fixtures, measure_runtime=False)


class ClaimGateTests(unittest.TestCase):
    def test_synthetic_only_report_stays_foundation(self) -> None:
        report = _strong_report()
        gate = evaluate_claim_gate(report)

        self.assertEqual("passed", gate["status"])
        self.assertEqual("foundation prototype", gate["claim_level"])
        self.assertIn("real_corpus_gate_missing", gate["blockers"])
        self.assertIn("windows_user_pe", gate["target_families"])
        self.assertIn("linux_elf_user", gate["target_families"])

    def test_real_corpus_metrics_raise_to_useful_general_assistant(self) -> None:
        report = _strong_report()
        report["corpus_evidence"] = {
            "real_corpus_count": 2,
            "real_corpus_function_count": 80,
            "ground_truth_pair_count": 2,
            "qualified_ground_truth_pair_count": 2,
            "target_families": ["windows_user_pe", "linux_elf_user"],
        }

        gate = evaluate_claim_gate(report)

        self.assertEqual("passed", gate["status"])
        self.assertEqual("useful general assistant", gate["claim_level"])
        self.assertIn("useful_general_assistant_threshold", gate["passed_gates"])
        self.assertFalse(gate["world_class_claim_allowed"])

    def test_full_evidence_can_raise_to_world_class_candidate(self) -> None:
        report = _strong_report()
        report["accepted_observations"] = 45
        report["corpus_evidence"] = {
            "real_corpus_count": 5,
            "real_corpus_function_count": 1200,
            "ground_truth_pair_count": 300,
            "qualified_ground_truth_pair_count": 300,
            "ir_evidence_coverage": 0.75,
            "cross_function_contract_count": 50,
            "qualified_cross_function_contract_count": 50,
            "external_baseline_count": 2,
            "qualified_external_baseline_count": 2,
            "analyst_audit_count": 1,
            "qualified_analyst_audit_count": 1,
            "target_families": [
                "windows_user_pe",
                "linux_elf_user",
                "cxx_runtime",
                "uefi",
                "ue_cpp",
            ],
        }

        gate = evaluate_claim_gate(report)

        self.assertEqual("passed", gate["status"])
        self.assertEqual("world-class candidate", gate["claim_level"])
        self.assertTrue(gate["world_class_claim_allowed"])

    def test_unqualified_world_class_counts_do_not_raise_claim(self) -> None:
        report = _strong_report()
        report["accepted_observations"] = 45
        report["corpus_evidence"] = {
            "real_corpus_count": 5,
            "real_corpus_function_count": 1200,
            "ground_truth_pair_count": 300,
            "qualified_ground_truth_pair_count": 300,
            "ir_evidence_coverage": 0.75,
            "cross_function_contract_count": 50,
            "qualified_cross_function_contract_count": 50,
            "external_baseline_count": 2,
            "analyst_audit_count": 1,
            "target_families": [
                "windows_user_pe",
                "linux_elf_user",
                "cxx_runtime",
                "uefi",
                "ue_cpp",
            ],
        }

        gate = evaluate_claim_gate(report)

        self.assertEqual("advanced general cleanup", gate["claim_level"])
        self.assertFalse(gate["world_class_claim_allowed"])

    def test_unqualified_cross_function_contract_count_does_not_raise_advanced_claim(self) -> None:
        report = _strong_report()
        report["accepted_observations"] = 45
        report["corpus_evidence"] = {
            "real_corpus_count": 4,
            "real_corpus_function_count": 300,
            "ground_truth_pair_count": 60,
            "qualified_ground_truth_pair_count": 60,
            "ir_evidence_coverage": 0.75,
            "cross_function_contract_count": 50,
            "target_families": [
                "windows_user_pe",
                "linux_elf_user",
                "cxx_runtime",
            ],
        }

        gate = evaluate_claim_gate(report)

        self.assertEqual("useful general assistant", gate["claim_level"])
        self.assertFalse(gate["world_class_claim_allowed"])

    def test_high_candidate_count_alone_does_not_raise_claim(self) -> None:
        report = _strong_report()
        report["candidate_count"] = 10000
        report["fixtures"] = []
        report["fixture_count"] = 0
        report["accepted_observations"] = 0

        gate = evaluate_claim_gate(report)

        self.assertEqual("foundation prototype", gate["claim_level"])
        self.assertIn("missing_false_positive_data", gate["blockers"])
        self.assertIn("single_family_or_unknown_coverage", gate["blockers"])

    def test_regression_against_baseline_fails_gate(self) -> None:
        baseline = _strong_report()
        current = copy.deepcopy(baseline)
        current["accepted_observations"] = int(current["accepted_observations"]) - 2
        current["false_positives"] = 1

        gate = evaluate_claim_gate(current, baseline_report=baseline)

        self.assertEqual("failed", gate["status"])
        self.assertTrue(any(item["metric"] == "false_positives" for item in gate["regressions"]))
        self.assertTrue(any(item["metric"] == "accepted_observations" for item in gate["regressions"]))

    def test_regression_uses_freshly_computed_current_claim_level(self) -> None:
        baseline = _strong_report()
        baseline["corpus_evidence"] = {
            "real_corpus_count": 2,
            "real_corpus_function_count": 80,
            "ground_truth_pair_count": 2,
            "qualified_ground_truth_pair_count": 2,
        }
        baseline["claim_gate"] = evaluate_claim_gate(baseline)
        baseline["claim_level"] = baseline["claim_gate"]["claim_level"]
        current = copy.deepcopy(baseline)
        current["claim_level"] = "foundation prototype"

        gate = evaluate_claim_gate(current, baseline_report=baseline)

        self.assertEqual("passed", gate["status"])
        self.assertEqual("useful general assistant", gate["claim_level"])
        self.assertFalse(any(item["metric"] == "claim_rank" for item in gate["regressions"]))

    def test_regression_detects_corpus_evidence_drop_at_same_claim_level(self) -> None:
        baseline = _strong_report()
        baseline["corpus_evidence"] = {
            "real_corpus_count": 2,
            "real_corpus_function_count": 80,
            "ground_truth_pair_count": 2,
            "qualified_ground_truth_pair_count": 2,
            "target_families": ["windows_user_pe", "linux_elf_user"],
        }
        baseline["claim_gate"] = evaluate_claim_gate(baseline)
        baseline["claim_level"] = baseline["claim_gate"]["claim_level"]
        current = copy.deepcopy(baseline)
        current["corpus_evidence"] = {
            "real_corpus_count": 2,
            "real_corpus_function_count": 70,
            "ground_truth_pair_count": 2,
            "qualified_ground_truth_pair_count": 2,
            "target_families": ["windows_user_pe", "linux_elf_user"],
        }

        gate = evaluate_claim_gate(current, baseline_report=baseline)

        self.assertEqual("failed", gate["status"])
        self.assertEqual("useful general assistant", gate["claim_level"])
        self.assertTrue(
            any(item["metric"] == "real_corpus_function_count" for item in gate["regressions"])
        )


if __name__ == "__main__":
    unittest.main()
