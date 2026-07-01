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

    def test_zero_contract_context_classifies_no_buffer_status_case(self) -> None:
        plan = CleanPlan(
            function_ea=0,
            function_name="Dispatch",
            input_fingerprint="fixture",
            flow_rewrites=[
                FlowRewrite(
                    kind="switch_recovery",
                    dispatcher="selector",
                    recovered_cases=[0x10],
                    case_bodies={
                        0x10: [
                            "return STATUS_NOT_SUPPORTED;",
                        ]
                    },
                )
            ],
        )

        context = batch._zero_contract_context(plan, 0x10, [])

        self.assertEqual("no_buffer_immediate_status", context["zero_contract"]["classification"])

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
                    callee="MissingSuperfetchHelper",
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
                    warnings=[
                        "helper not available for buffer contract analysis",
                        "buffer pointer escapes to unknown function",
                    ],
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
        self.assertEqual(3, metrics["warnings"])
        self.assertEqual(3, metrics["blocking_warnings"])
        self.assertEqual(
            [
                "buffer pointer escapes to unknown function",
                "case warning",
                "helper not available for buffer contract analysis",
            ],
            metrics["blocking_warning_messages"],
        )
        self.assertEqual(["systemInformation"], metrics["buffer_names"])
        self.assertEqual(1, len(metrics["helper_edge_audit"]))
        self.assertEqual(
            {"helper_capture_missing": 1},
            metrics["helper_edge_class_counts"],
        )
        self.assertEqual(1, len(metrics["unresolved_helper_edge_audit"]))
        self.assertEqual(
            "helper_capture_missing",
            metrics["unresolved_helper_edge_audit"][0]["classification"],
        )
        self.assertEqual(1, len(metrics["blocking_unresolved_helper_edge_audit"]))
        self.assertEqual(1, len(metrics["helper_path_families"]))
        self.assertEqual(
            "MissingSuperfetchHelper",
            metrics["helper_path_families"][0]["root_callee"],
        )

    def test_helper_capture_metrics_focuses_ledger_on_roots_and_unresolved_helpers(self) -> None:
        plan = CleanPlan(
            function_ea=0,
            function_name="Dispatch",
            input_fingerprint="fixture",
            rule_report={
                "buffer_contract_helper_capture_ledger": [
                    {
                        "name": "RootHelper",
                        "depth": 1,
                        "status": "captured",
                        "reason": "captured by IDA Hex-Rays",
                    },
                    {
                        "name": "UnresolvedNestedHelper",
                        "depth": 3,
                        "status": "capture_limit_skipped",
                        "reason": "helper capture limit reached before this candidate was attempted",
                    },
                    {
                        "name": "NoisyNestedHelper",
                        "depth": 3,
                        "status": "capture_limit_skipped",
                        "reason": "helper capture limit reached before this candidate was attempted",
                    },
                ],
            },
        )

        metrics = batch._helper_capture_metrics(
            plan,
            [
                {
                    "callee": "UnresolvedNestedHelper",
                    "classification": "helper_capture_missing",
                }
            ],
        )

        self.assertEqual(3, metrics["helper_capture_candidate_count"])
        self.assertEqual(
            {"capture_limit_skipped": 2, "captured": 1},
            metrics["helper_capture_status_counts"],
        )
        self.assertEqual(
            ["RootHelper", "UnresolvedNestedHelper"],
            [item["name"] for item in metrics["helper_capture_ledger"]],
        )
        self.assertEqual(["UnresolvedNestedHelper"], [item["name"] for item in metrics["helper_capture_unavailable"]])

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
                    "helper_edge_class_counts": {
                        "helper_capture_missing": 1,
                    },
                    "helper_path_families": [
                        {
                            "family_id": "0x4F:0:MissingSuperfetchHelper",
                            "root_callee": "MissingSuperfetchHelper",
                            "root_classification": "helper_capture_missing",
                            "edge_count": 1,
                            "unresolved_edges": 1,
                            "field_accesses": 5,
                            "field_constraints": 2,
                            "warnings": 1,
                        }
                    ],
                    "unresolved_helper_edge_audit": [
                        {
                            "command": "0x4F",
                            "callee": "MissingSuperfetchHelper",
                            "classification": "helper_capture_missing",
                            "severity": "high",
                            "blocks_recovery": True,
                            "depth": 1,
                            "passed_buffers": ["systemInformation"],
                            "next_action": "decompile the callee",
                        }
                    ],
                    "helper_capture_ledger": [
                        {
                            "name": "MissingSuperfetchHelper",
                            "depth": 1,
                            "status": "capture_unavailable",
                            "reason": "capture_function_by_name returned no decompilable function",
                        }
                    ],
                    "helper_capture_status_counts": {
                        "capture_unavailable": 1,
                    },
                    "helper_capture_unavailable": [
                        {
                            "name": "MissingSuperfetchHelper",
                            "depth": 1,
                            "status": "capture_unavailable",
                            "reason": "capture_function_by_name returned no decompilable function",
                        }
                    ],
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
        self.assertEqual(1, len(summary["zero_contract_audit"]))
        self.assertEqual("unknown_unclassified", summary["zero_contract_audit"][0]["classification"])
        self.assertEqual(["0x4F"], summary["warning_cases"])
        self.assertEqual(["0x4F"], summary["blocking_warning_cases"])
        self.assertEqual(["0x4F"], summary["unresolved_helper_cases"])
        self.assertEqual({"helper_capture_missing": 1}, summary["helper_edge_class_counts"])
        self.assertEqual(1, len(summary["unresolved_helper_edge_audit"]))
        self.assertEqual(1, summary["path_family_count"])
        self.assertEqual(["0x4F:0:MissingSuperfetchHelper"], summary["path_families_with_unresolved"])
        self.assertEqual(1, summary["totals"]["blocking_unresolved_helper_edges"])
        self.assertEqual(1, summary["totals"]["blocking_warnings"])
        self.assertEqual(1, summary["totals"]["helper_capture_candidates"])
        self.assertEqual(1, summary["totals"]["helper_capture_unavailable"])
        self.assertEqual({"capture_unavailable": 1}, summary["helper_capture_status_counts"])
        self.assertEqual("0x4F", summary["helper_capture_unavailable"][0]["case"])
        self.assertEqual("failed", summary["recovery_gate"]["status"])
        self.assertEqual("insufficient_evidence", summary["recovery_gate"]["level"])
        self.assertIn("no_unresolved_helper_edges", summary["recovery_gate"]["blockers"])

        markdown = batch._render_coverage_markdown(summary)
        self.assertIn("`0x4A`", markdown)
        self.assertIn("SystemSuperfetchInformation", markdown)
        self.assertIn("| `0x4F` |", markdown)
        self.assertIn("MissingSuperfetchHelper", markdown)
        self.assertIn("helper_capture_missing", markdown)
        self.assertIn("blocking_unresolved_helper_edges", markdown)
        self.assertIn("Helper Path Families", markdown)
        self.assertIn("Recovery Gate", markdown)
        self.assertIn("insufficient_evidence", markdown)
        self.assertIn("Zero-Contract Audit", markdown)
        self.assertIn("Helper Capture Ledger", markdown)
        self.assertIn("capture_unavailable", markdown)

    def test_coverage_gate_ignores_nonblocking_warning_cases(self) -> None:
        summary = batch._build_coverage_summary(
            [
                {
                    "status": "ok",
                    "function": "NtSetSystemInformation",
                    "case": "0xA1",
                    "case_value": 0xA1,
                    "command_name": "SystemVmGenerationCountInformation",
                    "contracts": 1,
                    "buffers": 1,
                    "helpers": 1,
                    "helper_edges_total": 1,
                    "helper_edges_unresolved": 1,
                    "warnings": 4,
                    "blocking_warnings": 0,
                    "warning_messages": [
                        "KdInitialize: helper not available for buffer contract analysis",
                    ],
                    "helper_edge_class_counts": {
                        "terminal_helper_boundary_summary": 1,
                    },
                    "helper_path_families": [
                        {
                            "family_id": "0xA1:0:KdInitialize",
                            "root_callee": "KdInitialize",
                            "root_classification": "terminal_helper_boundary_summary",
                            "edge_count": 1,
                            "unresolved_edges": 1,
                            "blocking_unresolved_edges": 0,
                            "warnings": 4,
                        }
                    ],
                    "unresolved_helper_edge_audit": [
                        {
                            "command": "0xA1",
                            "callee": "KdInitialize",
                            "classification": "terminal_helper_boundary_summary",
                            "severity": "info",
                            "blocks_recovery": False,
                            "depth": 1,
                            "passed_buffers": ["systemInformation"],
                            "next_action": "none",
                        }
                    ],
                },
            ],
            out_dir=Path("out"),
            source_path="ntoskrnl.exe.i64",
            helper_depth=4,
            elapsed_seconds=1.0,
            exit_code=0,
        )

        self.assertEqual(["0xA1"], summary["warning_cases"])
        self.assertEqual([], summary["blocking_warning_cases"])
        self.assertEqual(0, summary["totals"]["blocking_warnings"])
        self.assertEqual("passed", summary["recovery_gate"]["status"])
        self.assertNotIn("no_blocking_warning_cases", summary["recovery_gate"]["blockers"])


if __name__ == "__main__":
    unittest.main()
