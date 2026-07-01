from __future__ import annotations

from pathlib import Path
import unittest

from ida_pseudoforge.core.plan_schema import (
    BufferContract,
    BufferSizeConstraint,
    CleanPlan,
    CommandBufferContract,
    FieldAccess,
    FieldConstraint,
    FlowRewrite,
    FunctionCapture,
    HelperContractEdge,
)
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

    def test_contract_metrics_separate_local_and_helper_evidence(self) -> None:
        contract = CommandBufferContract(
            dispatcher_kind="ntset_system",
            dispatcher="systemInformationClass",
            command_value=0x4F,
            command_name="SystemSuperfetchInformation",
            buffers=[
                BufferContract(
                    role="input",
                    source="arg",
                    variable="systemInformation",
                    length_variable="systemInformationLength",
                    structure_name="PF_SYSTEM_SystemSuperfetchInformation_INPUT",
                    size_constraints=[
                        BufferSizeConstraint(
                            buffer="systemInformation",
                            length="systemInformationLength",
                            relation="!=",
                            value="32",
                        )
                    ],
                    field_accesses=[
                        FieldAccess(
                            buffer="systemInformation",
                            structure="",
                            offset=0,
                            type="_QWORD",
                            field="field_0x00",
                            access="read",
                        )
                    ],
                    field_constraints=[
                        FieldConstraint(
                            buffer="systemInformation",
                            structure="",
                            offset=0,
                            field="field_0x00",
                            relation="!=",
                            value="0",
                        )
                    ],
                )
            ],
            helper_edges=[
                HelperContractEdge(
                    callee="PfSetSuperfetchInformation",
                    resolved=False,
                    propagated_size_constraints=[
                        BufferSizeConstraint(
                            buffer="systemInformation",
                            length="systemInformationLength",
                            relation="!=",
                            value="32",
                        )
                    ],
                    propagated_field_accesses=[
                        FieldAccess(
                            buffer="systemInformation",
                            structure="",
                            offset=0x18,
                            type="ULONG",
                            field="field_0x18",
                            access="read",
                        )
                    ],
                    propagated_field_constraints=[
                        FieldConstraint(
                            buffer="systemInformation",
                            structure="",
                            offset=0x18,
                            field="field_0x18",
                            relation="!=",
                            value="8",
                        )
                    ],
                    warnings=["unresolved helper edge"],
                )
            ],
            warnings=["case warning"],
        )

        metrics = batch._contract_metrics([contract])

        self.assertEqual(1, metrics["local_size_constraints"])
        self.assertEqual(1, metrics["local_field_accesses"])
        self.assertEqual(1, metrics["local_field_constraints"])
        self.assertEqual(1, metrics["helper_size_constraints"])
        self.assertEqual(1, metrics["helper_field_accesses"])
        self.assertEqual(1, metrics["helper_field_constraints"])
        self.assertEqual(1, metrics["helper_edges_unresolved"])
        self.assertEqual(2, metrics["warnings"])
        self.assertEqual(["systemInformation"], metrics["buffer_names"])

    def test_coverage_summary_tracks_zero_warning_and_unresolved_cases(self) -> None:
        summary = batch._build_coverage_summary(
            [
                {
                    "status": "ok",
                    "function": "NtSetSystemInformation",
                    "case": "0x4A",
                    "case_value": 0x4A,
                    "contracts": 0,
                },
                {
                    "status": "ok",
                    "function": "NtSetSystemInformation",
                    "case": "0x4F",
                    "case_value": 0x4F,
                    "command_name": "SystemSuperfetchInformation",
                    "contracts": 1,
                    "buffers": 1,
                    "helpers": 2,
                    "helper_field_accesses": 5,
                    "helper_field_constraints": 2,
                    "helper_edges_unresolved": 1,
                    "warnings": 1,
                    "warning_messages": ["unresolved helper edge"],
                },
                {
                    "status": "error",
                    "function": "NtSetSystemInformation",
                    "case": "0x5D",
                    "case_value": 0x5D,
                    "error": "fixture failure",
                },
            ],
            out_dir=Path("out"),
            source_path="ntoskrnl.exe.i64",
            helper_depth=4,
            elapsed_seconds=12.5,
            exit_code=1,
        )

        self.assertEqual({"ok": 2, "error": 1}, summary["status_counts"])
        self.assertEqual(3, summary["totals"]["targets"])
        self.assertEqual(1, summary["totals"]["contracts"])
        self.assertEqual(["0x4A"], summary["zero_contract_cases"])
        self.assertEqual(["0x4F"], summary["warning_cases"])
        self.assertEqual(["0x4F"], summary["unresolved_helper_cases"])

        markdown = batch._render_coverage_markdown(summary)
        self.assertIn("`0x4A`", markdown)
        self.assertIn("SystemSuperfetchInformation", markdown)
        self.assertIn("| `0x4F` |", markdown)


if __name__ == "__main__":
    unittest.main()
