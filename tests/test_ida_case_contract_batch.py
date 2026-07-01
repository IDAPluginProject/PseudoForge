from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture
from tools import pseudoforge_ida_case_contract_batch as batch


class IdaCaseContractBatchTests(unittest.TestCase):
    def test_parse_args_accepts_all_case_target_without_explicit_case(self) -> None:
        args = batch._parse_args(
            [
                "--target-all-cases",
                "NtSetSystemInformation",
                "--out-dir",
                "out",
            ]
        )

        self.assertEqual(["NtSetSystemInformation"], args.target_all_cases)
        self.assertEqual([], args.target)
        self.assertEqual(2, args.helper_depth)

    def test_parse_args_accepts_helper_depth_four(self) -> None:
        args = batch._parse_args(
            [
                "--target",
                "NtSetSystemInformation:75",
                "--out-dir",
                "out",
                "--helper-depth",
                "4",
            ]
        )

        self.assertEqual(4, args.helper_depth)

    def test_parse_args_rejects_helper_depth_below_minimum(self) -> None:
        with self.assertRaises(SystemExit):
            batch._parse_args(
                [
                    "--target",
                    "NtSetSystemInformation:75",
                    "--out-dir",
                    "out",
                    "--helper-depth",
                    "1",
                ]
            )

    def test_expand_all_case_targets_uses_recovered_flow_cases(self) -> None:
        old_capture = batch.capture_function_by_name
        old_build = batch.build_clean_plan
        capture = FunctionCapture(
            name="NtSetSystemInformation",
            prototype="NTSTATUS NTAPI NtSetSystemInformation(SYSTEM_INFORMATION_CLASS c, PVOID p, ULONG l)",
            pseudocode="",
        )

        def fake_build_clean_plan(item):
            self.assertIs(item, capture)
            return CleanPlan(
                function_ea=0,
                function_name="NtSetSystemInformation",
                input_fingerprint="fixture",
                flow_rewrites=[
                    FlowRewrite(
                        kind="switch_recovery",
                        dispatcher="systemInformationClass",
                        recovered_cases=[75, 24, 75],
                    )
                ],
            )

        batch.capture_function_by_name = lambda name: capture if name == "NtSetSystemInformation" else None
        batch.build_clean_plan = fake_build_clean_plan
        try:
            targets = batch._expand_all_case_targets(["NtSetSystemInformation"])
        finally:
            batch.capture_function_by_name = old_capture
            batch.build_clean_plan = old_build

        self.assertEqual(
            [
                ("NtSetSystemInformation", 24),
                ("NtSetSystemInformation", 75),
            ],
            targets,
        )

    def test_dedupe_targets_preserves_first_seen_order(self) -> None:
        targets = batch._dedupe_targets(
            [
                ("NtSetSystemInformation", 75),
                ("NtSetSystemInformation", 24),
                ("NtSetSystemInformation", 75),
            ]
        )

        self.assertEqual(
            [
                ("NtSetSystemInformation", 75),
                ("NtSetSystemInformation", 24),
            ],
            targets,
        )


if __name__ == "__main__":
    unittest.main()
