from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, RenameSuggestion, WarningDiagnostic
from ida_pseudoforge.core.render_warnings import (
    display_warning_count,
    display_warnings,
    export_warning_diagnostics,
    format_warning,
)
from ida_pseudoforge.profiles.loader import clear_profile_caches


def _plan(
    warnings: list[str],
    *,
    comments: list[dict[str, object]] | None = None,
    flow_rewrites: list[FlowRewrite] | None = None,
    renames: list[RenameSuggestion] | None = None,
) -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="Sample",
        input_fingerprint="fp",
        warnings=warnings,
        comments=comments or [],
        flow_rewrites=flow_rewrites or [],
        renames=renames or [],
    )


class RenderWarningsTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_profile_caches()

    def tearDown(self) -> None:
        clear_profile_caches()

    def test_display_warnings_hides_routine_large_dispatcher_rename_noise(self) -> None:
        plan = _plan(
            [
                "Skipped LLM rename v1->scratchValue: low confidence 0.62",
                "Potential bad call target sub_140001000: unresolved indirect call",
            ],
            flow_rewrites=[
                FlowRewrite(kind="switch", dispatcher="SystemInformationClass", recovered_cases=list(range(16))),
            ],
        )

        warnings = display_warnings(plan)

        self.assertEqual(warnings, ["Potential bad call target sub_140001000: unresolved indirect call"])
        self.assertEqual(display_warning_count(plan), 1)

    def test_display_warnings_hides_driver_entry_subroutine_noise(self) -> None:
        plan = _plan(
            [
                "Skipped PascalCase LLM rename sub_140001000->InitializeDevice",
                "Manual review required",
            ],
            comments=[{"kind": "driver_entry"}],
        )

        self.assertEqual(display_warnings(plan), ["Manual review required"])

    def test_display_warnings_hides_memory_manager_probe_llm_noise(self) -> None:
        plan = _plan(
            [
                "Skipped PascalCase LLM rename sub_1400030F4->ProbeMemoryManagementApis",
                "DestinationString and Mdl are already covered by stronger deterministic names.",
                "v2/v3/v4 are __int128 SSE temporaries used only to shuffle the decompiler copy sequence.",
                "qword_1400060A0 receives several unrelated probe outputs during this diagnostic routine.",
                "MappedSystemVa, NonCachedMemory, and ContiguousMemorySpecifyCache are covered by "
                "non-LLM naming rules.",
                "Skipped LLM rename v2->owordTmp1: low confidence 0.60",
                "Function looks like a kernel memory-API self-test exercising pool and MDL allocation paths.",
                "qword_1400060A0 is a global repeatedly overwritten as a scratch/result sink across many Mm calls.",
                "Pool2 may leak on failure path",
            ],
            comments=[{"kind": "memory_manager_probe"}],
            renames=[
                RenameSuggestion("lvar", "DestinationString", "systemRoutineName", 0.94, "kernel-mm-probe", "test"),
                RenameSuggestion("lvar", "Mdl", "mdl", 0.94, "kernel-mm-probe", "test"),
                RenameSuggestion("lvar", "qword_1400060A0", "probeSinkValue", 0.94, "kernel-mm-probe", "test"),
                RenameSuggestion("lvar", "MappedSystemVa", "mappedSystemVa", 0.84, "pattern", "test"),
                RenameSuggestion("lvar", "NonCachedMemory", "nonCachedMemory", 0.94, "kernel-mm-probe", "test"),
                RenameSuggestion(
                    "lvar",
                    "ContiguousMemorySpecifyCache",
                    "contiguousMemory",
                    0.94,
                    "kernel-mm-probe",
                    "test",
                ),
                RenameSuggestion("lvar", "Pool2", "poolBuffer", 0.94, "kernel-mm-probe", "test"),
            ],
        )

        self.assertEqual(display_warnings(plan), ["Pool2 may leak on failure path"])

    def test_display_warnings_hides_resolved_status_carrier_downgrades(self) -> None:
        plan = _plan(
            [
                "Downgraded status/object semantic conflict rename Object->referencedObject "
                "to Object->objectStatus: Object has NTSTATUS carrier evidence (assigned_from_call)",
                "Downgraded object-style status carrier name ObjectProperty->objectPropertyStatus: "
                "ObjectProperty has NTSTATUS carrier evidence (assigned_from_call)",
            ],
            renames=[
                RenameSuggestion("lvar", "Object", "objectStatus", 0.86, "semantic-rule", "test"),
                RenameSuggestion("lvar", "ObjectProperty", "objectPropertyStatus", 0.84, "kernel-status", "test"),
            ],
        )

        self.assertEqual(display_warnings(plan), [])
        self.assertEqual(display_warning_count(plan), 0)

    def test_display_warnings_keeps_unresolved_status_carrier_downgrade(self) -> None:
        warning = (
            "Downgraded object-style status carrier name ObjectProperty->objectPropertyStatus: "
            "ObjectProperty has NTSTATUS carrier evidence (assigned_from_call)"
        )

        self.assertEqual(display_warnings(_plan([warning])), [warning])

    def test_format_warning_handles_structured_and_json_warnings(self) -> None:
        self.assertEqual(
            format_warning({"old": "sub_140001000", "reason": "unresolved indirect call"}),
            "Potential bad call target sub_140001000: unresolved indirect call",
        )
        self.assertEqual(format_warning('{"message":"review manually"}'), "review manually")

    def test_format_warning_sanitizes_generated_comment_text(self) -> None:
        self.assertEqual(
            format_warning({"message": "mixed(_DWORD */_QWORD)\r\nraw /* marker"}),
            "mixed(_DWORD * /_QWORD)\\nraw / * marker",
        )

    def test_export_warning_diagnostics_serializes_machine_fields(self) -> None:
        plan = _plan(
            [],
        )
        plan.warning_diagnostics.append(
            WarningDiagnostic(
                kind="unassigned_local_live_in_register",
                message="Uninitialized local risk: v1 appears to be a live-in register value (r8d)",
                symbol="v1",
                usage="call argument to EtwpEventWriteFull",
                usage_class="call_argument",
                register="r8d",
                register_class="abi_argument",
                candidate_action="parameter_gap_candidate",
                confidence=0.78,
                source="validation.unassigned_local_usage",
            )
        )

        diagnostics = export_warning_diagnostics(plan)

        self.assertEqual(1, len(diagnostics))
        self.assertEqual("unassigned_local_live_in_register", diagnostics[0]["kind"])
        self.assertEqual("v1", diagnostics[0]["symbol"])
        self.assertEqual("r8d", diagnostics[0]["register"])
        self.assertEqual("abi_argument", diagnostics[0]["register_class"])
        self.assertEqual("parameter_gap_candidate", diagnostics[0]["candidate_action"])


if __name__ == "__main__":
    unittest.main()
