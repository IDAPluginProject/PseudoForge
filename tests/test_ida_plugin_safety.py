import tempfile
import threading
import time
import unittest
from pathlib import Path

from ida_pseudoforge.config import (
    LlmConfig,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    ProviderCredential,
    PreviewConfig,
    PseudoForgeConfig,
)
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ir_evidence import ir_evidence_summary
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import (
    CleanPlan,
    CommandBufferContract,
    FunctionIdentityCandidate,
    FunctionCapture,
    HelperContractEdge,
    LocalVariable,
    ParameterTypeCorrection,
    RenameSuggestion,
    make_lvar_identity,
)
from ida_pseudoforge.core.llm_failures import summarize_llm_failure
from ida_pseudoforge.ida import actions as actions_module
from ida_pseudoforge.ida import apply_changes as apply_module
from ida_pseudoforge.ida import async_runner
from ida_pseudoforge.ida import decompiler as decompiler_module
from ida_pseudoforge.ida import llm_config_dialog
from ida_pseudoforge.ida import plugin as plugin_module
from ida_pseudoforge.ida import ui_preview as ui_preview_module
from ida_pseudoforge.ida.action_registry import ActionRegistry
from ida_pseudoforge.ida.analysis_state import PluginAnalysisSession, PluginAnalysisState, normalize_source_identity
from ida_pseudoforge.ida.source_context import format_source_context_summary
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CODEX_CLI,
    PROVIDER_LLAMA_CPP,
    PROVIDER_LM_STUDIO,
    PROVIDER_OLLAMA,
    PROVIDER_VLLM,
)
from ida_pseudoforge.version import VERSION


def _capture() -> FunctionCapture:
    return FunctionCapture(
        ea=0x140001000,
        name="sub_140001000",
        prototype="__int64 __fastcall sub_140001000(int a1)",
        pseudocode="__int64 __fastcall sub_140001000(int a1)\n{\n  int v1;\n  return v1;\n}",
        lvars=[
            LocalVariable("a1", "int", True, 0),
            LocalVariable("v1", "int", False, 1),
            LocalVariable("v2", "int", False, 2),
            LocalVariable("v3", "int", False, 3),
            LocalVariable("v4", "int", False, 4),
            LocalVariable("v5", "int", False, 5),
            LocalVariable("v6", "int", False, 6),
        ],
        source_path=r"F:\target\driver.sys",
    )


def _closure_values(function):
    cells = getattr(function, "__closure__", None) or []
    return [cell.cell_contents for cell in cells]


def _plan(capture: FunctionCapture) -> CleanPlan:
    return CleanPlan(
        function_ea=capture.ea,
        function_name=capture.name,
        input_fingerprint=capture.input_fingerprint(),
        renames=[
            RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe"),
            RenameSuggestion("lvar", "v2", "disabledLocal", 0.95, "rule", "disabled", apply=False),
            RenameSuggestion("comment", "v3", "commentText", 0.95, "rule", "not an IDB rename"),
            RenameSuggestion("lvar", "v4", "bad-name", 0.95, "rule", "invalid"),
            RenameSuggestion("lvar", "v5", "duplicateTarget", 0.95, "rule", "first duplicate"),
            RenameSuggestion("lvar", "v6", "duplicateTarget", 0.95, "rule", "second duplicate"),
        ],
    )


def _type_assisted_capture_plan() -> tuple[FunctionCapture, CleanPlan]:
    capture = FunctionCapture(
        ea=0x140002000,
        name="IoDeleteDevice",
        prototype="__int64 __fastcall IoDeleteDevice(__int64 a1)",
        pseudocode="__int64 __fastcall IoDeleteDevice(__int64 a1)\n{\n  return a1;\n}",
        lvars=[LocalVariable("a1", "__int64", True, 0)],
        source_path=r"F:\target\ntoskrnl.exe",
    )
    plan = CleanPlan(
        function_ea=capture.ea,
        function_name=capture.name,
        input_fingerprint=capture.input_fingerprint(),
    )
    plan.function_identity_candidates.append(
        FunctionIdentityCandidate(
            profile_id="windows.io_manager.delete_device",
            subsystem="I/O Manager",
            function_name="IoDeleteDevice",
            match_kind="function_name",
            confidence=0.95,
            evidence=["exact_function_name", "source_context_ntoskrnl"],
            blockers=[],
            effective_mode="canonical-rewrite-eligible",
        )
    )
    plan.type_corrections.append(
        ParameterTypeCorrection(
            parameter_index=0,
            old_name="a1",
            new_name="deviceObject",
            old_type="__int64",
            canonical_type="PDEVICE_OBJECT",
            profile_id="windows.io_manager.delete_device",
            confidence=0.92,
            effective_mode="canonical-rewrite-eligible",
        )
    )
    return capture, plan


class FakeHexrays:
    def __init__(self) -> None:
        self.calls = []

    def rename_lvar(self, ea, old, new):
        self.calls.append((ea, old, new))
        return True


class FakeIdaApi:
    PLUGIN_KEEP = 1
    PLUGIN_SKIP = 0
    SETMENU_APP = 1

    def __init__(self) -> None:
        self.registered = []
        self.attached = []
        self.unregistered = []

    def action_desc_t(self, action_name, label, handler, hotkey, tooltip, icon):
        return {
            "name": action_name,
            "label": label,
            "handler": handler,
            "hotkey": hotkey,
            "tooltip": tooltip,
            "icon": icon,
        }

    def register_action(self, desc):
        self.registered.append(desc["name"])
        return True

    def attach_action_to_menu(self, menu_path, action_name, flags):
        self.attached.append((menu_path, action_name, flags))
        return True

    def unregister_action(self, action_name):
        self.unregistered.append(action_name)
        return True


class FakeHexraysPlugin:
    def init_hexrays_plugin(self):
        return True


class FakeKernwinPlugin:
    def __init__(self):
        self.created_menus = []

    def is_idaq(self):
        return True

    def create_menu(self, name, label, menupath=None):
        self.created_menus.append((name, label, menupath))
        return True


class FakeContextMenuHooks:
    def hook(self):
        return True

    def unhook(self):
        return True


class FakeIdcTypeApi:
    def __init__(
        self,
        original_type: str,
        fail_on_restore: bool = False,
        function_name: str = "IoDeleteDevice",
        ignore_first_apply: bool = False,
    ) -> None:
        self.current_type = original_type
        self.fail_on_restore = fail_on_restore
        self.function_name = function_name
        self.ignore_first_apply = ignore_first_apply
        self.calls = []

    def get_type(self, ea):
        return self.current_type

    def get_func_name(self, ea):
        return self.function_name

    def get_name(self, ea):
        return self.function_name

    def SetType(self, ea, type_text):
        self.calls.append((ea, type_text))
        if self.fail_on_restore and len(self.calls) > 1:
            raise RuntimeError("restore failed")
        if self.ignore_first_apply and len(self.calls) == 1:
            return True
        self.current_type = type_text
        return True

    def del_type(self, ea):
        self.calls.append((ea, "<delete>"))
        self.current_type = ""
        return True


class FakePseudocodeLine:
    def __init__(self, line: str) -> None:
        self.line = line


class FakeCpos:
    def __init__(self, lnnum: int) -> None:
        self.lnnum = lnnum


class FakeCfunc:
    def __init__(self, lines: list[str]) -> None:
        self._lines = [FakePseudocodeLine(line) for line in lines]

    def get_pseudocode(self):
        return self._lines


class FakeVdui:
    def __init__(self, lines: list[str], line_index: int) -> None:
        self.cpos = FakeCpos(line_index)
        self.cfunc = FakeCfunc(lines)


class FakeHexraysCursor:
    def __init__(self, widget, vdui) -> None:
        self.widget = widget
        self.vdui = vdui

    def get_widget_vdui(self, widget):
        return self.vdui if widget is self.widget else None


class FakeKernwinCursor:
    def __init__(self, widget) -> None:
        self.widget = widget

    def get_current_widget(self):
        return self.widget


class IdaPluginSafetyTests(unittest.TestCase):
    def tearDown(self):
        async_runner._ACTIVE_TASKS.clear()
        async_runner._ACTIVE_GROUPS.clear()
        actions_module._ANALYSIS_STATE.clear()

    def test_plugin_analysis_session_records_identity_and_fingerprint(self):
        capture = _capture()
        plan = _plan(capture)
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            plan,
            target_path=capture.source_path,
            forge_path=r"F:\target\driver.forge",
            forge_text="forge text",
        )

        self.assertEqual(session.target_path, normalize_source_identity(capture.source_path))
        self.assertEqual(session.function_ea, capture.ea)
        self.assertEqual(session.function_name, capture.name)
        self.assertEqual(session.fingerprint, plan.input_fingerprint)
        self.assertTrue(session.matches_current(capture.source_path, capture.ea))
        self.assertFalse(session.matches_current(capture.source_path, capture.ea + 0x10))

        state = PluginAnalysisState()
        self.assertIs(state.set(session), session)
        self.assertIs(state.get(), session)
        state.clear()
        self.assertIsNone(state.get())

    def test_ida_render_path_requests_validated_layout_rewrites(self):
        capture = _capture()
        plan = _plan(capture)
        calls = []
        old_aliases = actions_module._direct_runtime_helper_aliases
        old_render = actions_module.render_cleaned_pseudocode
        actions_module._direct_runtime_helper_aliases = lambda text, capture_arg: {}

        def fake_render(capture_arg, plan_arg, apply_validated_layout_rewrites=False):
            calls.append(apply_validated_layout_rewrites)
            return "cleaned"

        actions_module.render_cleaned_pseudocode = fake_render
        try:
            rendered = actions_module._render_cleaned_with_direct_helper_aliases(capture, plan)
        finally:
            actions_module._direct_runtime_helper_aliases = old_aliases
            actions_module.render_cleaned_pseudocode = old_render

        self.assertEqual("cleaned", rendered)
        self.assertEqual([True], calls)

    def test_ida_export_requests_validated_layout_rewrites(self):
        capture = _capture()
        plan = _plan(capture)
        calls = []
        old_analyze = actions_module.analyze_current_function
        old_run_on_main_thread = actions_module.run_on_main_thread
        old_default_output_dir = actions_module._default_output_dir
        old_write_export_bundle = actions_module.write_export_bundle
        with tempfile.TemporaryDirectory() as temp_dir:
            actions_module.analyze_current_function = lambda purpose="analyze": (capture, plan)
            actions_module.run_on_main_thread = lambda callback, write=False: callback()
            actions_module._default_output_dir = lambda: Path(temp_dir)

            def fake_write_export_bundle(output_dir, capture_arg, plan_arg, **kwargs):
                calls.append((Path(output_dir), capture_arg, plan_arg, kwargs))
                return {"cleaned_pseudocode": str(Path(output_dir) / "sample.cleaned.cpp")}

            actions_module.write_export_bundle = fake_write_export_bundle
            try:
                result = actions_module.export_current_function()
            finally:
                actions_module.analyze_current_function = old_analyze
                actions_module.run_on_main_thread = old_run_on_main_thread
                actions_module._default_output_dir = old_default_output_dir
                actions_module.write_export_bundle = old_write_export_bundle

        self.assertIn("cleaned_pseudocode", result)
        self.assertEqual(1, len(calls))
        self.assertIs(capture, calls[0][1])
        self.assertIs(plan, calls[0][2])
        self.assertEqual("ida_interactive", calls[0][3]["entrypoint"])
        self.assertTrue(calls[0][3]["apply_validated_layout_rewrites"])

    def test_render_cleaned_aliases_direct_runtime_helper_without_full_batch(self):
        capture = FunctionCapture(
            ea=0x140001100,
            name="Caller",
            prototype="void __fastcall Caller(char *buffer)",
            pseudocode=(
                "void __fastcall Caller(char *buffer)\n"
                "{\n"
                "  sub_140001000(buffer, 0, 64LL);\n"
                "}\n"
            ),
            lvars=[LocalVariable("buffer", "char *", True, 0)],
            source_path=r"F:\target\driver.sys",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
        )
        helper_capture = FunctionCapture(
            ea=0x140001000,
            name="sub_140001000",
            prototype="__int64 __fastcall sub_140001000(char *a1, unsigned __int8 a2, unsigned __int64 a3)",
            pseudocode=(
                "__int64 __fastcall sub_140001000(char *a1, unsigned __int8 a2, unsigned __int64 a3)\n"
                "{\n"
                "  __int64 result;\n"
                "  __int64 v4;\n"
                "\n"
                "  result = (__int64)a1;\n"
                "  v4 = 0x101010101010101LL * a2;\n"
                "  if ( a3 >= 4 )\n"
                "  {\n"
                "    *(_DWORD *)a1 = v4;\n"
                "    *(_DWORD *)&a1[a3 - 4] = v4;\n"
                "  }\n"
                "  return result;\n"
                "}\n"
            ),
            lvars=[
                LocalVariable("a1", "char *", True, 0),
                LocalVariable("a2", "unsigned __int8", True, 1),
                LocalVariable("a3", "unsigned __int64", True, 2),
            ],
            source_path=r"F:\target\driver.sys",
        )
        old_capture = actions_module.capture_function_by_name
        actions_module.capture_function_by_name = lambda name: helper_capture if name == "sub_140001000" else None
        try:
            rendered = actions_module._render_cleaned_with_direct_helper_aliases(capture, plan)
        finally:
            actions_module.capture_function_by_name = old_capture

        self.assertIn("memset(buffer, 0, 64LL);", rendered)
        self.assertNotIn("sub_140001000(buffer", rendered)

    def test_direct_runtime_helper_alias_hides_resolved_helper_warning(self):
        capture = FunctionCapture(
            ea=0x140001100,
            name="Caller",
            prototype="void __fastcall Caller()",
            pseudocode=(
                "void __fastcall Caller()\n"
                "{\n"
                "  _BYTE localBuffer[64];\n"
                "\n"
                "  sub_140001000(localBuffer, 0LL, 64LL);\n"
                "}\n"
            ),
            lvars=[LocalVariable("localBuffer", "_BYTE[64]", False, 0)],
            source_path=r"F:\target\driver.sys",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            warnings=["sub_140001000 behaves like memset (dst,0,len)"],
        )
        helper_capture = FunctionCapture(
            ea=0x140001000,
            name="sub_140001000",
            prototype="__int64 __fastcall sub_140001000(char *a1, unsigned __int8 a2, unsigned __int64 a3)",
            pseudocode=(
                "__int64 __fastcall sub_140001000(char *a1, unsigned __int8 a2, unsigned __int64 a3)\n"
                "{\n"
                "  __int64 result;\n"
                "  __int64 v4;\n"
                "\n"
                "  result = (__int64)a1;\n"
                "  v4 = 0x101010101010101LL * a2;\n"
                "  if ( a3 >= 4 )\n"
                "  {\n"
                "    *(_DWORD *)a1 = v4;\n"
                "    *(_DWORD *)&a1[a3 - 4] = v4;\n"
                "  }\n"
                "  return result;\n"
                "}\n"
            ),
            lvars=[
                LocalVariable("a1", "char *", True, 0),
                LocalVariable("a2", "unsigned __int8", True, 1),
                LocalVariable("a3", "unsigned __int64", True, 2),
            ],
            source_path=r"F:\target\driver.sys",
        )
        old_capture = actions_module.capture_function_by_name
        actions_module.capture_function_by_name = lambda name: helper_capture if name == "sub_140001000" else None
        try:
            rendered = actions_module._render_cleaned_with_direct_helper_aliases(capture, plan)
        finally:
            actions_module.capture_function_by_name = old_capture

        self.assertIn("Warnings: 0", rendered)
        self.assertNotIn("Warning detail:", rendered)
        self.assertNotIn("behaves like memset", rendered)
        self.assertIn("memset(localBuffer, 0, sizeof(localBuffer));", rendered)

    def test_llm_failure_summary_is_short_and_ascii_safe(self):
        summary = summarize_llm_failure(
            RuntimeError("You've hit your session limit \u00b7 resets 2:20am (Asia/Seoul)" + " x" * 200)
        )

        self.assertLessEqual(len(summary), 220)
        self.assertIn("session limit", summary)
        self.assertNotIn("\u00b7", summary)

    def test_plugin_analysis_session_normalizes_windows_path_identity(self):
        capture = _capture()
        plan = _plan(capture)
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            plan,
            target_path=r"F:/target/driver.sys",
        )

        self.assertTrue(session.matches_current(r"F:\target\driver.sys", capture.ea))
        self.assertFalse(session.matches_current(r"F:\target\other.sys", capture.ea))

    def test_set_capture_source_path_populates_profile_context_when_source_already_set(self):
        capture = FunctionCapture(
            ea=0x140001000,
            name="ExpReleaseResourceForThreadLite",
            prototype="char __fastcall ExpReleaseResourceForThreadLite(ULONG_PTR a1)",
            pseudocode="char __fastcall ExpReleaseResourceForThreadLite(ULONG_PTR a1)\n{\n  return a1 != 0;\n}",
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe.i64",
        )
        capture.profile_context = {}

        actions_module._set_capture_source_path(capture)

        self.assertEqual("ntoskrnl.exe", capture.profile_context["image"])
        self.assertEqual("26200.8457", capture.profile_context["build"])
        self.assertEqual("x64", capture.profile_context["arch"])

    def test_format_source_context_summary_reports_build_bound_ntoskrnl(self):
        summary = format_source_context_summary(
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe.i64",
            idb_path=r"D:\bin\os\26200.8457\ntoskrnl.exe.i64",
            configured_profile_dir="",
            active_profile_root=r"F:\kernullist\PseudoForge\ida_pseudoforge\profiles",
        )

        self.assertIn("Target path: D:\\bin\\os\\26200.8457\\ntoskrnl.exe.i64", summary)
        self.assertIn("IDB path: D:\\bin\\os\\26200.8457\\ntoskrnl.exe.i64", summary)
        self.assertIn("Context basis: target path", summary)
        self.assertIn("Inferred image: ntoskrnl.exe", summary)
        self.assertIn("Inferred arch: x64", summary)
        self.assertIn("Inferred build: 26200.8457", summary)
        self.assertIn("Context status: complete", summary)
        self.assertIn("Configured profile dir: (default/env)", summary)
        self.assertIn("Active profile root: F:\\kernullist\\PseudoForge\\ida_pseudoforge\\profiles", summary)

    def test_format_source_context_summary_reports_missing_build_for_plain_idb_path(self):
        summary = format_source_context_summary(
            source_path="",
            idb_path=r"D:\scratch\ntoskrnl.exe.i64",
            configured_profile_dir=r"F:\profiles\wdk26100",
            active_profile_root=r"F:\profiles\wdk26100",
        )

        self.assertIn("Target path: (unavailable)", summary)
        self.assertIn("IDB path: D:\\scratch\\ntoskrnl.exe.i64", summary)
        self.assertIn("Context basis: IDB path fallback", summary)
        self.assertIn("Inferred image: ntoskrnl.exe", summary)
        self.assertIn("Inferred arch: x64", summary)
        self.assertIn("Inferred build: (missing)", summary)
        self.assertIn("Context status: missing build", summary)

    def test_format_source_context_summary_reports_unavailable_source(self):
        summary = format_source_context_summary(
            source_path="",
            idb_path="",
            configured_profile_dir="",
            active_profile_root="",
        )

        self.assertIn("Target path: (unavailable)", summary)
        self.assertIn("IDB path: (unavailable)", summary)
        self.assertIn("Context basis: (none)", summary)
        self.assertIn("Inferred image: (missing)", summary)
        self.assertIn("Inferred arch: (missing)", summary)
        self.assertIn("Inferred build: (missing)", summary)
        self.assertIn("Context status: missing source_path, image, arch, build", summary)

    def test_text_only_ir_evidence_is_inert_without_external_facts(self):
        capture = capture_from_pseudocode(
            """
__int64 __fastcall TextOnlyIrSample(int a1)
{
  return a1 + 1;
}
""",
            source_path="text_only.cpp",
        )
        plan = build_clean_plan(capture)
        summary = ir_evidence_summary(plan.ir_evidence)

        self.assertEqual("text_only", capture.ir_evidence.adapter)
        self.assertEqual("text_only", summary["adapter"])
        self.assertFalse(summary["available"])
        self.assertEqual(0, summary["use_def_chains"])
        self.assertEqual(0, summary["value_ranges"])
        self.assertEqual(0, summary["local_type_snapshots"])
        self.assertEqual(0, summary["constant_origins"])
        self.assertEqual(0, summary["call_site_signatures"])

    def test_preflight_rejects_invalid_colliding_and_unselected_renames(self):
        capture = _capture()
        plan = _plan(capture)
        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1", "v2", "v3", "v4", "v5", "v6", "missing"],
            known_lvar_names=[var.name for var in capture.lvars],
        )

        self.assertEqual([rename.old for rename in accepted], ["v1", "v5"])
        joined = "\n".join(rejected)
        self.assertIn("not marked apply-safe", joined)
        self.assertIn("cannot modify IDB", joined)
        self.assertIn("not a valid C identifier", joined)
        self.assertIn("duplicated", joined)
        self.assertIn("not in the plan", joined)

    def test_preflight_rejects_same_name_different_lvar_identity(self):
        capture = _capture()
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion(
                    "lvar",
                    "v1",
                    "renamedLocal",
                    0.95,
                    "rule",
                    "safe",
                    identity=make_lvar_identity("v1", "int", False, 1, "stack:-4"),
                )
            ],
        )
        captured_lvars = [
            LocalVariable("v1", "int", False, 1, "stack:-4", make_lvar_identity("v1", "int", False, 1, "stack:-4"))
        ]
        current_lvars = [
            LocalVariable("v1", "int", False, 2, "stack:-8", make_lvar_identity("v1", "int", False, 2, "stack:-8"))
        ]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=captured_lvars,
            current_lvars=current_lvars,
        )

        self.assertEqual(accepted, [])
        self.assertEqual(rejected, ["Current local variable identity changed: v1"])

    def test_preflight_allows_matching_lvar_identity(self):
        capture = _capture()
        identity = make_lvar_identity("v1", "int", False, 1, "stack:-4")
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion(
                    "lvar",
                    "v1",
                    "renamedLocal",
                    0.95,
                    "rule",
                    "safe",
                    identity=identity,
                )
            ],
        )
        lvars = [LocalVariable("v1", "int", False, 1, "stack:-4", identity)]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=lvars,
            current_lvars=lvars,
        )

        self.assertEqual([rename.old for rename in accepted], ["v1"])
        self.assertEqual(rejected, [])

    def test_preflight_uses_legacy_name_fallback_without_lvar_identity(self):
        capture = _capture()
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe")],
        )
        legacy_lvars = [LocalVariable("v1", "int", False, 1)]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=legacy_lvars,
            current_lvars=legacy_lvars,
        )

        self.assertEqual([rename.old for rename in accepted], ["v1"])
        self.assertEqual(rejected, [])

    def test_decompiler_lvar_identity_uses_stable_stack_location_anchor(self):
        class FakeLocation:
            def get_stkoff(self):
                return -16

            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        expected_identity = make_lvar_identity("v1", "int", False, 0, "stkoff:-16")
        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "stkoff:-16")
        self.assertEqual(lvars[0].identity, expected_identity)

    def test_decompiler_lvar_location_falls_back_to_lvar_scalar_anchor(self):
        class FakeLocation:
            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

            def get_reg(self):
                return 3

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "reg:3")

    def test_decompiler_lvar_location_ignores_unstable_object_address_text(self):
        class FakeLocation:
            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "")

    def test_decompiler_lvar_location_formats_definition_ea_anchor(self):
        class FakeLvar:
            name = "v1"
            type = "int"

            def is_arg_var(self):
                return False

            def get_defea(self):
                return 0x140001020

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "defea:0x140001020")

    def test_analysis_summary_includes_rule_report_diagnostics(self):
        capture = _capture()
        plan = _plan(capture)
        plan.rule_report = {
            "matched_rules": [{"rule_id": "one"}, {"rule_id": "two"}],
            "rewrite_emissions": [
                {"status": "applied"},
                {"status": "shadowed"},
                {"status": "rejected"},
            ],
            "load_errors": [{"path": "bad.json"}],
            "validation_errors": [{"path": "invalid.json"}],
        }

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn(
            "Rules: 2 matched, 1 rewrite(s) applied, 1 shadowed, 1 rejected, 1 load error(s), 1 validation error(s)",
            summary,
        )
        self.assertIn("Rule load errors:", summary)
        self.assertIn("- bad.json", summary)
        self.assertIn("Rule validation errors:", summary)
        self.assertIn("- invalid.json", summary)

    def test_analysis_summary_ignores_malformed_rule_report_rewrites(self):
        capture = _capture()
        plan = _plan(capture)
        plan.rule_report = {
            "matched_rules": [{"rule_id": "one"}],
            "rewrite_emissions": None,
        }

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn(
            "Rules: 1 matched, 0 rewrite(s) applied, 0 shadowed, 0 rejected, 0 load error(s), 0 validation error(s)",
            summary,
        )

    def test_apply_calls_rename_lvar_only_after_preflight_passes(self):
        capture = _capture()
        plan = _plan(capture)
        fake_hexrays = FakeHexrays()
        old_hexrays = apply_module.ida_hexrays
        old_run_on_main_thread = apply_module.run_on_main_thread
        apply_module.ida_hexrays = fake_hexrays
        apply_module.run_on_main_thread = lambda func, write=False: func()
        try:
            result = apply_module.apply_selected_renames(
                capture.ea,
                plan,
                ["v1", "v4", "v5", "v6"],
                known_lvar_names=[var.name for var in capture.lvars],
            )
        finally:
            apply_module.ida_hexrays = old_hexrays
            apply_module.run_on_main_thread = old_run_on_main_thread

        self.assertEqual(
            fake_hexrays.calls,
            [
                (capture.ea, "v1", "renamedLocal"),
                (capture.ea, "v5", "duplicateTarget"),
            ],
        )
        self.assertEqual(
            result.applied,
            [
                {"old": "v1", "new": "renamedLocal"},
                {"old": "v5", "new": "duplicateTarget"},
            ],
        )
        self.assertEqual(len(result.rejected), 2)

    def test_apply_refuses_stale_current_function_session(self):
        capture = _capture()
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            _plan(capture),
            target_path=capture.source_path,
        )
        actions_module._ANALYSIS_STATE.set(session)
        warnings = []
        choose_calls = []
        old_current = actions_module._current_function_identity
        old_warning = actions_module.warning
        old_choose = actions_module.choose_renames
        old_apply = actions_module.apply_selected_renames
        actions_module._current_function_identity = lambda: (capture.ea + 0x20, "other_function")
        actions_module.warning = warnings.append
        actions_module.choose_renames = lambda plan: choose_calls.append(plan) or ["v1"]
        actions_module.apply_selected_renames = lambda *args, **kwargs: self.fail("stale apply reached IDB path")
        try:
            actions_module._apply_selected_renames_from_session()
        finally:
            actions_module._current_function_identity = old_current
            actions_module.warning = old_warning
            actions_module.choose_renames = old_choose
            actions_module.apply_selected_renames = old_apply

        self.assertFalse(choose_calls)
        self.assertEqual(len(warnings), 1)
        self.assertIn("current function no longer matches", warnings[0])

    def test_apply_refuses_identity_backed_rename_when_current_identity_unavailable(self):
        capture = _capture()
        identity = make_lvar_identity("v1", "int", False, 1, "stack:-4")
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe", identity=identity)],
        )
        session = PluginAnalysisSession.from_capture_plan(capture, plan, target_path=capture.source_path)
        actions_module._ANALYSIS_STATE.set(session)
        warnings = []
        old_current = actions_module._current_function_identity
        old_target = actions_module._target_file_path
        old_warning = actions_module.warning
        old_info = actions_module.info
        old_choose = actions_module.choose_renames
        old_capture_lvars = actions_module.capture_current_lvars
        old_apply = actions_module.apply_selected_renames
        actions_module._current_function_identity = lambda: (capture.ea, capture.name)
        actions_module._target_file_path = lambda: Path(capture.source_path)
        actions_module.warning = warnings.append
        actions_module.info = lambda message: None
        actions_module.choose_renames = lambda plan: ["v1"]
        actions_module.capture_current_lvars = lambda: (_ for _ in ()).throw(RuntimeError("no lvars"))
        actions_module.apply_selected_renames = lambda *args, **kwargs: self.fail("identity-backed fallback reached IDB path")
        try:
            actions_module._apply_selected_renames_from_session()
        finally:
            actions_module._current_function_identity = old_current
            actions_module._target_file_path = old_target
            actions_module.warning = old_warning
            actions_module.info = old_info
            actions_module.choose_renames = old_choose
            actions_module.capture_current_lvars = old_capture_lvars
            actions_module.apply_selected_renames = old_apply

        self.assertEqual(len(warnings), 1)
        self.assertIn("identity could not be verified", warnings[0])

    def test_analyzed_functions_action_reads_cached_forge_without_opening_full_preview(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            forge_path.write_text("cached forge text", encoding="utf-8")
            old_paths = actions_module._target_and_forge_paths
            old_show = actions_module.show_analyzed_functions_from_text
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module.show_analyzed_functions_from_text = (
                lambda text, source_path=None, target_stem=None, source_title="": calls.append(
                    (text, source_path, target_stem, source_title)
                )
                or True
            )
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_analyzed_functions_for_current_target())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module.show_analyzed_functions_from_text = old_show
                actions_module.warning = old_warning

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "cached forge text")
        self.assertEqual(calls[0][1], forge_path)
        self.assertEqual(calls[0][2], "driver")
        self.assertFalse(warnings)

    def test_current_function_preview_reports_not_opened_without_cached_forge(self):
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (0x140001000, "sub_140001000")
            actions_module.warning = warnings.append
            try:
                self.assertFalse(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("Run Analyze current function first", warnings[0])

    def test_current_function_preview_uses_active_session_for_side_by_side(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            capture = _capture()
            capture.source_path = str(target_path)
            plan = _plan(capture)
            cleaned_text = "__int64 __fastcall sub_140001000(int argument)\n{\n    return renamedLocal;\n}\n"
            forge_text = actions_module.write_forge_function(forge_path, target_path, capture, plan, cleaned_text)
            session = PluginAnalysisSession.from_capture_plan(
                capture,
                plan,
                target_path=target_path,
                forge_path=forge_path,
                forge_text=forge_text,
            )
            actions_module._ANALYSIS_STATE.set(session)
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (capture.ea, capture.name)
            actions_module.side_by_side_preview_enabled = lambda: True

            def fake_show(title, text, **kwargs):
                calls.append((title, text, kwargs))
                return "dockable_side_by_side"

            actions_module.show_text_view = fake_show
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(calls), 1)
        self.assertIn("PseudoForge: driver!sub_140001000 0x140001000", calls[0][0])
        self.assertEqual(calls[0][2]["reference_text"], capture.pseudocode)
        self.assertEqual(calls[0][2]["reference_title"], "Raw Hex-Rays pseudocode")
        self.assertEqual(calls[0][2]["content_title"], "PseudoForge cleaned pseudocode")
        self.assertIn("PseudoForge analyzed 0x140001000", calls[0][2]["summary_text"])

    def test_current_function_preview_uses_persisted_raw_for_side_by_side_without_active_session(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            capture = _capture()
            capture.source_path = str(target_path)
            plan = _plan(capture)
            actions_module.write_forge_function(
                forge_path,
                target_path,
                capture,
                plan,
                "__int64 __fastcall sub_140001000(int argument)\n{\n    return renamedLocal;\n}\n",
            )
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (capture.ea, capture.name)
            actions_module.side_by_side_preview_enabled = lambda: True
            actions_module.show_text_view = lambda title, text, **kwargs: calls.append((title, text, kwargs)) or "simple"
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2]["reference_text"], capture.pseudocode.rstrip() + "\n")
        self.assertIn("raw pseudocode loaded from .forge", calls[0][2]["summary_text"])

    def test_current_function_preview_warns_when_side_by_side_has_no_stored_raw(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            forge_path.write_text(
                """// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: driver.sys

// PSEUDOFORGE FUNCTION BEGIN ea=0x140001000 name=sub_140001000 fingerprint=legacy
__int64 __fastcall sub_140001000(int argument)
{
    return renamedLocal;
}
// PSEUDOFORGE FUNCTION END ea=0x140001000
""",
                encoding="utf-8",
            )
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (0x140001000, "sub_140001000")
            actions_module.side_by_side_preview_enabled = lambda: True
            actions_module.show_text_view = lambda title, text, **kwargs: calls.append((title, text, kwargs)) or "simple"
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("stored raw Hex-Rays pseudocode", warnings[0])
        self.assertEqual(len(calls), 1)
        self.assertNotIn("reference_text", calls[0][2])

    def test_background_group_prevents_shared_state_overlap_and_cleans_up(self):
        started = threading.Event()
        release = threading.Event()

        def work():
            started.set()
            release.wait(5)

        self.assertTrue(async_runner.run_background("analyze", work, group_name="plugin_state"))
        self.assertTrue(started.wait(2))
        self.assertFalse(async_runner.run_background("export", lambda: None, group_name="plugin_state"))
        release.set()

        deadline = time.time() + 2
        while async_runner.active_group_task("plugin_state") and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(async_runner.active_group_task("plugin_state"), "")

    def test_background_cancel_request_stops_task_at_cooperative_checkpoint(self):
        task_name = "cancel_test"
        started = threading.Event()
        cancelled = threading.Event()

        def work():
            started.set()
            deadline = time.time() + 2
            while time.time() < deadline and not async_runner.cancel_requested(task_name):
                time.sleep(0.01)
            try:
                async_runner.raise_if_cancelled(task_name)
            except async_runner.CancellationRequested:
                cancelled.set()
                raise
            self.fail("cancelled background task should not continue past the checkpoint")

        self.assertTrue(async_runner.run_background(task_name, work, group_name="cancel_group"))
        self.assertTrue(started.wait(2))
        self.assertTrue(async_runner.request_group_cancel("cancel_group"))

        deadline = time.time() + 2
        while async_runner.active_group_task("cancel_group") and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(async_runner.active_group_task("cancel_group"), "")
        self.assertTrue(cancelled.is_set())
        self.assertFalse(async_runner.cancel_requested(task_name))

    def test_background_cancel_after_work_skips_success_callback(self):
        task_name = "cancel_after_work_test"
        started = threading.Event()
        requested = threading.Event()
        successes = []

        def work():
            started.set()
            self.assertTrue(async_runner.request_cancel(task_name))
            requested.set()
            return "done"

        self.assertTrue(async_runner.run_background(task_name, work, successes.append))
        self.assertTrue(started.wait(2))
        self.assertTrue(requested.wait(2))

        deadline = time.time() + 2
        while async_runner.cancel_requested(task_name) and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(successes, [])
        self.assertFalse(async_runner.cancel_requested(task_name))

    def test_analysis_cancellation_is_not_swallowed_by_forge_write_warning_path(self):
        old_capture = actions_module.capture_current_function
        old_set_source = actions_module._set_capture_source_path
        old_build = actions_module._build_plan_with_config
        old_write = actions_module._write_forge_snapshot
        capture = _capture()
        plan = _plan(capture)
        actions_module.capture_current_function = lambda: (capture, object())
        actions_module._set_capture_source_path = lambda captured: None
        actions_module._build_plan_with_config = lambda captured, task_name="": plan
        actions_module._write_forge_snapshot = lambda captured, built_plan: (_ for _ in ()).throw(
            async_runner.CancellationRequested("stop before forge write")
        )
        try:
            with self.assertRaises(async_runner.CancellationRequested):
                actions_module.analyze_current_function("direct_cancel_test")
        finally:
            actions_module.capture_current_function = old_capture
            actions_module._set_capture_source_path = old_set_source
            actions_module._build_plan_with_config = old_build
            actions_module._write_forge_snapshot = old_write

    def test_cancel_current_task_handler_requests_active_group_cancel(self):
        handler = actions_module.CancelCurrentTaskHandler()
        old_request = actions_module.request_group_cancel
        old_info = actions_module.info
        requested = []
        messages = []
        actions_module.request_group_cancel = lambda group: requested.append(group) or "analyze"
        actions_module.info = messages.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.request_group_cancel = old_request
            actions_module.info = old_info

        self.assertEqual(requested, [actions_module.PLUGIN_STATE_GROUP])
        self.assertEqual(len(messages), 1)
        self.assertIn("cancellation requested for analyze", messages[0])

    def test_buffer_contract_case_value_parser_accepts_c_literals(self):
        self.assertEqual(0x91234004, actions_module._parse_buffer_contract_case_value("0x91234004u"))
        self.assertEqual(29, actions_module._parse_buffer_contract_case_value("29"))
        self.assertEqual(75, actions_module._parse_buffer_contract_case_value("'K'"))
        self.assertEqual(75, actions_module._parse_buffer_contract_case_value(r"'\x4B'"))
        self.assertIsNone(actions_module._parse_buffer_contract_case_value("not_a_case"))

    def test_buffer_contract_cursor_location_prefers_hexrays_vdui(self):
        widget = object()
        lines = [
            "NTSTATUS __fastcall Dispatch(int code)",
            "{",
            "  switch ( code )",
            "  {",
            "    case 0x91234004:",
            "      if ( outputBufferLength < 24 )",
            "      {",
        ]
        old_hexrays = actions_module.ida_hexrays
        old_kernwin = actions_module.ida_kernwin
        actions_module.ida_hexrays = FakeHexraysCursor(widget, FakeVdui(lines, 5))
        actions_module.ida_kernwin = FakeKernwinCursor(widget)
        try:
            line_index, line_text = actions_module._current_pseudocode_cursor_location(None)
        finally:
            actions_module.ida_hexrays = old_hexrays
            actions_module.ida_kernwin = old_kernwin

        self.assertEqual(5, line_index)
        self.assertEqual("      if ( outputBufferLength < 24 )", line_text)

    def test_buffer_contract_cursor_resolution_uses_enclosing_case_without_prompt(self):
        pseudocode = "\n".join(
            [
                "NTSTATUS __fastcall Dispatch(int code)",
                "{",
                "  switch ( code )",
                "  {",
                "    case 0x91234004:",
                "      if ( outputBufferLength < 24 )",
                "      {",
                "        return STATUS_BUFFER_TOO_SMALL;",
                "      }",
                "      return 0;",
                "    default:",
                "      return STATUS_INVALID_DEVICE_REQUEST;",
                "  }",
                "}",
            ]
        )
        capture = FunctionCapture(
            ea=0x140001000,
            name="Dispatch",
            prototype="NTSTATUS __fastcall Dispatch(int code)",
            pseudocode=pseudocode,
        )
        old_location = actions_module._current_pseudocode_cursor_location
        old_capture = actions_module.capture_current_function
        actions_module._current_pseudocode_cursor_location = lambda ctx: (5, "      if ( outputBufferLength < 24 )")
        actions_module.capture_current_function = lambda: (capture, object())
        try:
            value, resolved_capture = actions_module._resolve_buffer_contract_case_from_cursor(object())
        finally:
            actions_module._current_pseudocode_cursor_location = old_location
            actions_module.capture_current_function = old_capture

        self.assertEqual(0x91234004, value)
        self.assertIs(resolved_capture, capture)

    def test_buffer_contract_cursor_action_does_not_prompt_when_cursor_unresolved(self):
        handler = actions_module.AnalyzeBufferContractCaseHandler(prompt_always=False)
        old_resolve = actions_module._resolve_buffer_contract_case_from_cursor
        old_ask = actions_module._ask_buffer_contract_case_value
        old_warning = actions_module.warning
        old_run = actions_module.run_background
        asks = []
        warnings = []
        runs = []
        actions_module._resolve_buffer_contract_case_from_cursor = lambda ctx: (None, None)
        actions_module._ask_buffer_contract_case_value = lambda: asks.append(True) or 0x91234004
        actions_module.warning = warnings.append
        actions_module.run_background = lambda *args, **kwargs: runs.append((args, kwargs)) or True
        try:
            self.assertEqual(handler.activate(object()), 1)
        finally:
            actions_module._resolve_buffer_contract_case_from_cursor = old_resolve
            actions_module._ask_buffer_contract_case_value = old_ask
            actions_module.warning = old_warning
            actions_module.run_background = old_run

        self.assertFalse(asks)
        self.assertFalse(runs)
        self.assertEqual(len(warnings), 1)
        self.assertIn("could not resolve the switch case under the cursor", warnings[0])

    def test_buffer_contract_value_action_prompts_for_case_value(self):
        handler = actions_module.AnalyzeBufferContractCaseHandler(prompt_always=True)
        old_ask = actions_module._ask_buffer_contract_case_value
        old_ask_depth = actions_module._ask_buffer_contract_helper_depth
        old_run = actions_module.run_background
        asks = []
        runs = []
        actions_module._ask_buffer_contract_case_value = lambda: asks.append(True) or 0x91234004
        actions_module._ask_buffer_contract_helper_depth = lambda: 4
        actions_module.run_background = lambda *args, **kwargs: runs.append((args, kwargs)) or True
        try:
            self.assertEqual(handler.activate(object()), 1)
        finally:
            actions_module._ask_buffer_contract_case_value = old_ask
            actions_module._ask_buffer_contract_helper_depth = old_ask_depth
            actions_module.run_background = old_run

        self.assertEqual(asks, [True])
        self.assertEqual(len(runs), 1)
        self.assertIn(4, _closure_values(runs[0][0][1]))

    def test_ioctl_action_prompts_when_cursor_case_is_unresolved(self):
        handler = actions_module.AnalyzeIoctlCaseHandler()
        old_resolve = actions_module._resolve_buffer_contract_case_from_cursor
        old_ask = actions_module._ask_buffer_contract_case_value
        old_ask_depth = actions_module._ask_buffer_contract_helper_depth
        old_run = actions_module.run_background
        asks = []
        runs = []
        actions_module._resolve_buffer_contract_case_from_cursor = lambda ctx: (None, None)
        actions_module._ask_buffer_contract_case_value = lambda: asks.append(True) or 0x91234000
        actions_module._ask_buffer_contract_helper_depth = lambda: 3
        actions_module.run_background = lambda *args, **kwargs: runs.append((args, kwargs)) or True
        try:
            self.assertEqual(handler.activate(object()), 1)
        finally:
            actions_module._resolve_buffer_contract_case_from_cursor = old_resolve
            actions_module._ask_buffer_contract_case_value = old_ask
            actions_module._ask_buffer_contract_helper_depth = old_ask_depth
            actions_module.run_background = old_run

        self.assertEqual(asks, [True])
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][0][0], "selector-case")
        self.assertIn(3, _closure_values(runs[0][0][1]))

    def test_ioctl_action_accepts_non_ioctl_selector_case_value(self):
        handler = actions_module.AnalyzeIoctlCaseHandler()
        old_resolve = actions_module._resolve_buffer_contract_case_from_cursor
        old_ask = actions_module._ask_buffer_contract_case_value
        old_ask_depth = actions_module._ask_buffer_contract_helper_depth
        old_run = actions_module.run_background
        runs = []
        actions_module._resolve_buffer_contract_case_from_cursor = lambda ctx: (None, None)
        actions_module._ask_buffer_contract_case_value = lambda: 75
        actions_module._ask_buffer_contract_helper_depth = lambda: 4
        actions_module.run_background = lambda *args, **kwargs: runs.append((args, kwargs)) or True
        try:
            self.assertEqual(handler.activate(object()), 1)
        finally:
            actions_module._resolve_buffer_contract_case_from_cursor = old_resolve
            actions_module._ask_buffer_contract_case_value = old_ask
            actions_module._ask_buffer_contract_helper_depth = old_ask_depth
            actions_module.run_background = old_run

        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0][0][0], "selector-case")
        self.assertIn(4, _closure_values(runs[0][0][1]))

    def test_ioctl_action_cancels_when_helper_depth_prompt_is_cancelled(self):
        handler = actions_module.AnalyzeIoctlCaseHandler()
        old_resolve = actions_module._resolve_buffer_contract_case_from_cursor
        old_ask = actions_module._ask_buffer_contract_case_value
        old_ask_depth = actions_module._ask_buffer_contract_helper_depth
        old_run = actions_module.run_background
        runs = []
        actions_module._resolve_buffer_contract_case_from_cursor = lambda ctx: (None, None)
        actions_module._ask_buffer_contract_case_value = lambda: 75
        actions_module._ask_buffer_contract_helper_depth = lambda: None
        actions_module.run_background = lambda *args, **kwargs: runs.append((args, kwargs)) or True
        try:
            self.assertEqual(handler.activate(object()), 1)
        finally:
            actions_module._resolve_buffer_contract_case_from_cursor = old_resolve
            actions_module._ask_buffer_contract_case_value = old_ask
            actions_module._ask_buffer_contract_helper_depth = old_ask_depth
            actions_module.run_background = old_run

        self.assertFalse(runs)

    def test_buffer_contract_case_analysis_captures_helper_from_selected_case_body(self):
        pseudocode = r"""
NTSTATUS __fastcall DispatchHelperOnly(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  NTSTATUS status;
  PVOID payload;
  ULONG inputLength;
  ULONG outputLength;
  ULONG controlCode;
  ULONG_PTR information;
  _DWORD *stack;

  stack = (_DWORD *)IoGetCurrentIrpStackLocation(irp);
  payload = irp->AssociatedIrp.MasterIrp;
  inputLength = stack[2];
  outputLength = stack[4];
  controlCode = stack[6];
  information = 0;
  switch ( controlCode )
  {
    case 0x91236000:
      status = HandlePayload(payload, inputLength, outputLength, &information);
      break;
    case 0x91236004:
      status = 0;
      break;
    case 0x91236008:
      status = 0;
      break;
    case 0x9123600C:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  irp->IoStatus.Information = information;
  irp->IoStatus.Status = status;
  IofCompleteRequest(irp, 0);
  return status;
}
"""
        capture = capture_from_pseudocode(pseudocode)
        initial_plan = build_clean_plan(capture, buffer_contract_case_values=[0x91236000])
        initial_plan.buffer_contracts = []
        captured_helper_names = []
        old_build = actions_module._build_plan_with_config
        old_capture_helpers = actions_module._capture_buffer_contract_helpers_with_status
        old_set_source = actions_module._set_capture_source_path

        def fake_build(*args, **kwargs):
            return initial_plan

        def fake_capture_helpers(helper_names, **kwargs):
            captured_helper_names.extend(helper_names)
            return {}, []

        actions_module._build_plan_with_config = fake_build
        actions_module._capture_buffer_contract_helpers_with_status = fake_capture_helpers
        actions_module._set_capture_source_path = lambda captured: None
        try:
            actions_module.analyze_current_buffer_contract_case(0x91236000, capture=capture)
        finally:
            actions_module._build_plan_with_config = old_build
            actions_module._capture_buffer_contract_helpers_with_status = old_capture_helpers
            actions_module._set_capture_source_path = old_set_source

        self.assertEqual(["HandlePayload"], captured_helper_names)

    def test_buffer_contract_preview_reports_unlinked_helper_captures(self):
        capture = FunctionCapture(
            ea=0x140001000,
            name="Dispatch",
            pseudocode="NTSTATUS Dispatch(void)\n{\n  return 0;\n}\n",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            buffer_contracts=[
                CommandBufferContract(
                    dispatcher_kind="ioctl",
                    dispatcher="ioControlCode",
                    command_value=0x91236000,
                    helper_edges=[
                        HelperContractEdge(callee="LinkedHelper", resolved=True),
                    ],
                )
            ],
        )
        text = actions_module._format_buffer_contract_case_preview(
            capture,
            plan,
            0x91236000,
            {
                "LinkedHelper": FunctionCapture(name="LinkedHelper"),
                "UnlinkedHelper": FunctionCapture(name="UnlinkedHelper"),
            },
            ["LinkedHelper"],
        )

        self.assertIn("Captured helpers not linked to selected buffer path", text)
        unlinked_section = text.split("Captured helpers not linked to selected buffer path:", 1)[1].split("# Buffer Contract Report", 1)[0]
        self.assertIn("`UnlinkedHelper`", unlinked_section)
        self.assertNotIn("`LinkedHelper`", unlinked_section)

    def test_buffer_contract_value_disasm_capture_attempts_entry_search(self):
        capture = FunctionCapture(ea=0x140001000, name="Dispatch")
        calls = []
        old_capture = actions_module.capture_disasm_case_slice

        def fake_capture(function_ea, command_value, entry_ea=None, **kwargs):
            calls.append((function_ea, command_value, entry_ea, kwargs))
            return None

        actions_module.capture_disasm_case_slice = fake_capture
        try:
            result = actions_module._capture_buffer_contract_case_disasm(capture, 0x91236000, None)
        finally:
            actions_module.capture_disasm_case_slice = old_capture

        self.assertEqual({}, result)
        self.assertEqual(1, len(calls))
        self.assertEqual(0x140001000, calls[0][0])
        self.assertEqual(0x91236000, calls[0][1])
        self.assertIsNone(calls[0][2])

    def test_buffer_contract_helper_capture_preserves_call_site_name(self):
        helper_capture = FunctionCapture(
            ea=0x140002000,
            name="RenamedHelper",
            prototype="NTSTATUS __fastcall RenamedHelper(PVOID buffer)",
            pseudocode="NTSTATUS __fastcall RenamedHelper(PVOID buffer)\n{\n  return 0;\n}\n",
        )
        old_capture = actions_module.capture_function_by_name
        actions_module.capture_function_by_name = lambda name: helper_capture if name == "sub_140002000" else None
        try:
            captures = actions_module._capture_buffer_contract_helpers(
                ["sub_140002000"],
                caller_ea=0x140001000,
                max_depth=1,
                max_helpers=4,
            )
        finally:
            actions_module.capture_function_by_name = old_capture

        self.assertIn("sub_140002000", captures)
        self.assertIs(helper_capture, captures["sub_140002000"])
        self.assertNotIn("RenamedHelper", captures)

    def test_buffer_contract_helper_capture_ledger_records_attempt_statuses(self):
        caller_ea = 0x140001000
        helper_capture = FunctionCapture(
            ea=0x140002000,
            name="ResolvedHelper",
            prototype="NTSTATUS __fastcall ResolvedHelper(PVOID buffer)",
            pseudocode="NTSTATUS __fastcall ResolvedHelper(PVOID buffer)\n{\n  return 0;\n}\n",
        )
        self_capture = FunctionCapture(ea=caller_ea, name="Dispatch")
        old_capture = actions_module.capture_function_by_name

        def fake_capture(name):
            if name == "ResolvedHelper":
                return helper_capture
            if name == "SelfHelper":
                return self_capture
            if name == "BoomHelper":
                raise RuntimeError("decompile failed")
            return None

        actions_module.capture_function_by_name = fake_capture
        try:
            captures, ledger = actions_module._capture_buffer_contract_helpers_with_status(
                ["ResolvedHelper", "MissingHelper", "SelfHelper", "BoomHelper"],
                caller_ea=caller_ea,
                max_depth=1,
                max_helpers=8,
            )
        finally:
            actions_module.capture_function_by_name = old_capture

        self.assertEqual(["ResolvedHelper"], list(captures))
        statuses = {item["name"]: item["status"] for item in ledger}
        self.assertEqual("captured", statuses["ResolvedHelper"])
        self.assertEqual("capture_unavailable", statuses["MissingHelper"])
        self.assertEqual("caller_self", statuses["SelfHelper"])
        self.assertEqual("capture_failed", statuses["BoomHelper"])

    def test_buffer_contract_helper_capture_ledger_records_limit_skips(self):
        root_capture = FunctionCapture(
            ea=0x140002000,
            name="RootHelper",
            calls=["NestedHelper"],
        )
        old_capture = actions_module.capture_function_by_name
        actions_module.capture_function_by_name = lambda name: root_capture if name == "RootHelper" else None
        try:
            _captures, ledger = actions_module._capture_buffer_contract_helpers_with_status(
                ["RootHelper"],
                caller_ea=0x140001000,
                max_depth=2,
                max_helpers=1,
            )
        finally:
            actions_module.capture_function_by_name = old_capture

        statuses = {item["name"]: item["status"] for item in ledger}
        self.assertEqual("captured", statuses["RootHelper"])
        self.assertEqual("capture_limit_skipped", statuses["NestedHelper"])

    def test_buffer_contract_helper_capture_prioritizes_buffer_forwarding_calls(self):
        root_capture = FunctionCapture(
            ea=0x140002000,
            name="RootHelper",
            prototype="NTSTATUS __fastcall RootHelper(PVOID payload)",
            pseudocode="\n".join(
                [
                    "NTSTATUS __fastcall RootHelper(PVOID payload)",
                    "{",
                    "  NoiseHelper(context);",
                    "  FocusedNestedHelper(payload);",
                    "  return 0;",
                    "}",
                ]
            ),
            calls=["NoiseHelper", "FocusedNestedHelper"],
        )
        noise_capture = FunctionCapture(ea=0x140003000, name="NoiseHelper")
        focused_capture = FunctionCapture(ea=0x140004000, name="FocusedNestedHelper")
        old_capture = actions_module.capture_function_by_name

        def fake_capture(name):
            if name == "RootHelper":
                return root_capture
            if name == "NoiseHelper":
                return noise_capture
            if name == "FocusedNestedHelper":
                return focused_capture
            return None

        actions_module.capture_function_by_name = fake_capture
        try:
            captures, ledger = actions_module._capture_buffer_contract_helpers_with_status(
                ["RootHelper"],
                caller_ea=0x140001000,
                max_depth=2,
                max_helpers=2,
                focus_names={"systemInformation"},
                helper_focus_indices={"RootHelper": {0}},
            )
        finally:
            actions_module.capture_function_by_name = old_capture

        self.assertEqual(["RootHelper", "FocusedNestedHelper"], list(captures))
        statuses = {item["name"]: item["status"] for item in ledger}
        self.assertEqual("captured", statuses["FocusedNestedHelper"])
        self.assertEqual("capture_limit_skipped", statuses["NoiseHelper"])

    def test_buffer_contract_helper_focus_context_preserves_zero_command(self):
        capture = FunctionCapture(ea=0x140001000, name="NtLikeDispatcher")
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            buffer_contracts=[
                CommandBufferContract(
                    dispatcher_kind="selector",
                    dispatcher="SystemInformationClass",
                    command_value=0,
                    helper_edges=[
                        HelperContractEdge(
                            callee="ZeroClassHelper",
                            arguments=["systemInformation", "systemInformationLength"],
                            passed_buffers=["systemInformation"],
                        ),
                    ],
                )
            ],
        )

        focus_names, helper_focus_indices = actions_module._helper_capture_focus_context(plan, 0)

        self.assertIn("systemInformation", focus_names)
        self.assertEqual({0}, helper_focus_indices["ZeroClassHelper"])

    def test_action_registry_tracks_and_unregisters_actions(self):
        fake_idaapi = FakeIdaApi()
        registry = ActionRegistry(fake_idaapi)

        self.assertTrue(registry.register("pseudoforge:test", "Test", object(), "", "Test action"))
        self.assertTrue(registry.attach_menu("Edit/PseudoForge/Test", "pseudoforge:test"))
        registry.unregister_all()

        self.assertEqual(fake_idaapi.registered, ["pseudoforge:test"])
        self.assertEqual(fake_idaapi.attached, [("Edit/PseudoForge/Test", "pseudoforge:test", fake_idaapi.SETMENU_APP)])
        self.assertEqual(fake_idaapi.unregistered, ["pseudoforge:test", "pseudoforge:test"])
        self.assertEqual(registry.registered_actions, ())

    def test_plugin_menu_replaces_full_forge_preview_with_function_actions(self):
        fake_idaapi = FakeIdaApi()
        old_idaapi = plugin_module.idaapi
        old_kernwin = plugin_module.ida_kernwin
        old_hexrays = plugin_module.ida_hexrays
        old_start = plugin_module.start_output_logger
        old_stop = plugin_module.stop_output_logger
        old_hooks = plugin_module.ContextMenuHooks
        plugin_module.idaapi = fake_idaapi
        fake_kernwin = FakeKernwinPlugin()
        plugin_module.ida_kernwin = fake_kernwin
        plugin_module.ida_hexrays = FakeHexraysPlugin()
        plugin_module.start_output_logger = lambda: None
        plugin_module.stop_output_logger = lambda: None
        plugin_module.ContextMenuHooks = FakeContextMenuHooks
        plugin = plugin_module.PseudoForgePlugin()
        try:
            self.assertEqual(plugin.init(), fake_idaapi.PLUGIN_KEEP)
            attached_paths = [item[0] for item in fake_idaapi.attached]
            self.assertIn(plugin_module.PseudoForgePlugin.preview_current_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.analyzed_functions_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.buffer_contract_cursor_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.buffer_contract_value_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.ioctl_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.cancel_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.type_assisted_recompile_preview_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.configure_preview_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.configure_profile_action_name, fake_idaapi.registered)
            self.assertNotIn(plugin_module.PseudoForgePlugin.legacy_preview_action_name, fake_idaapi.registered)
            attached_menu_actions = [(path, action_name) for path, action_name, _flags in fake_idaapi.attached]
            self.assertIn(("pseudoforge_menu", "PseudoForge", "Edit/"), fake_kernwin.created_menus)
            self.assertIn(("pseudoforge_ioctl_menu", "Selector Analysis", "Edit/PseudoForge/"), fake_kernwin.created_menus)
            self.assertIn(("pseudoforge_advanced_menu", "Advanced", "Edit/PseudoForge/"), fake_kernwin.created_menus)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.analyze_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.preview_current_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.analyzed_functions_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.buffer_contract_cursor_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.buffer_contract_value_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/Selector Analysis/", plugin_module.PseudoForgePlugin.ioctl_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.cancel_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.configure_preview_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.configure_profile_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/Advanced/", plugin_module.PseudoForgePlugin.apply_renames_action_name), attached_menu_actions)
            self.assertIn(
                ("Edit/PseudoForge/Advanced/", plugin_module.PseudoForgePlugin.type_assisted_recompile_preview_action_name),
                attached_menu_actions,
            )
            self.assertNotIn("Edit/PseudoForge/Preview cleaned pseudocode", attached_paths)
        finally:
            plugin.term()
            plugin_module.idaapi = old_idaapi
            plugin_module.ida_kernwin = old_kernwin
            plugin_module.ida_hexrays = old_hexrays
            plugin_module.start_output_logger = old_start
            plugin_module.stop_output_logger = old_stop
            plugin_module.ContextMenuHooks = old_hooks

    def test_plugin_run_opens_preview_configuration_fallback(self):
        old_handler = plugin_module.ConfigurePreviewModeHandler
        activated = []

        class FakeConfigurePreviewModeHandler:
            def activate(self, ctx):
                activated.append(ctx)
                return 1

        plugin_module.ConfigurePreviewModeHandler = FakeConfigurePreviewModeHandler
        try:
            self.assertEqual(plugin_module.PseudoForgePlugin().run(None), 1)
        finally:
            plugin_module.ConfigurePreviewModeHandler = old_handler

        self.assertEqual(activated, [None])

    def test_preview_cleanup_unregisters_preview_actions(self):
        fake_idaapi = FakeIdaApi()
        old_idaapi = ui_preview_module.idaapi
        ui_preview_module.idaapi = fake_idaapi
        ui_preview_module._ACTIONS_REGISTERED = True
        try:
            ui_preview_module.cleanup_preview_actions()
        finally:
            ui_preview_module.idaapi = old_idaapi

        self.assertIn("pseudoforge:preview_copy_all", fake_idaapi.unregistered)
        self.assertIn("pseudoforge:preview_save_as", fake_idaapi.unregistered)
        self.assertIn("pseudoforge:preview_functions", fake_idaapi.unregistered)
        self.assertFalse(ui_preview_module._ACTIONS_REGISTERED)

    def test_model_discovery_exception_uses_static_fallback(self):
        old_discover = llm_config_dialog.discover_provider_models
        llm_config_dialog.discover_provider_models = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            result = llm_config_dialog._safe_discover_models(PROVIDER_CODEX_CLI)
        finally:
            llm_config_dialog.discover_provider_models = old_discover

        self.assertIn("gpt-5", result.models)
        self.assertEqual(result.source, "static fallback")
        self.assertIn("model discovery failed", result.warning)

    def test_llm_summary_marks_local_http_provider_api_key_not_required(self):
        config = PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider=PROVIDER_OLLAMA,
                base_url="http://localhost:11434/v1",
                model="llama3.2",
            )
        )

        summary = llm_config_dialog.format_llm_summary(config.llm, config)

        self.assertIn("Provider: Ollama (ollama)", summary)
        self.assertIn("Base URL: http://localhost:11434/v1", summary)
        self.assertIn("API key: not required", summary)

    def test_model_discovery_dialog_uses_nonblocking_background_refresh(self):
        old_discover = llm_config_dialog.discover_provider_models
        started = threading.Event()
        release = threading.Event()
        calls = []

        def fake_discover(*args, **kwargs):
            calls.append((args, kwargs))
            started.set()
            release.wait(2.0)
            return llm_config_dialog.ModelDiscoveryResult(
                models=["fresh-codex-model"],
                source="test catalog",
            )

        llm_config_dialog._reset_model_discovery_cache_for_tests()
        llm_config_dialog.discover_provider_models = fake_discover
        try:
            first = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
            self.assertIn("gpt-5", first.models)
            self.assertEqual("static fallback (background refresh pending)", first.source)
            self.assertTrue(started.wait(1.0))

            second = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
            self.assertEqual("static fallback (background refresh pending)", second.source)
            self.assertEqual(1, len(calls))

            release.set()
            deadline = time.time() + 2.0
            refreshed = None
            while time.time() < deadline:
                candidate = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
                if candidate.models == ["fresh-codex-model"]:
                    refreshed = candidate
                    break
                time.sleep(0.01)

            self.assertIsNotNone(refreshed)
            self.assertEqual("test catalog", refreshed.source)
        finally:
            release.set()
            llm_config_dialog.discover_provider_models = old_discover
            llm_config_dialog._reset_model_discovery_cache_for_tests()

    def test_http_model_discovery_dialog_prefers_live_catalog_for_current_base_url(self):
        old_discover = llm_config_dialog.discover_provider_models
        calls = []

        def fake_discover(provider, base_url="", api_key="", timeout_seconds=15):
            calls.append((provider, base_url, api_key, timeout_seconds))
            return llm_config_dialog.ModelDiscoveryResult(
                models=["%s-live-model" % provider],
                source="%s/models" % base_url,
            )

        providers = (
            (PROVIDER_LM_STUDIO, "http://127.0.0.1:1234/v1"),
            (PROVIDER_OLLAMA, "http://127.0.0.1:11434/v1"),
            (PROVIDER_VLLM, "http://127.0.0.1:8000/v1"),
            (PROVIDER_LLAMA_CPP, "http://127.0.0.1:8080/v1"),
        )

        llm_config_dialog._reset_model_discovery_cache_for_tests()
        llm_config_dialog.discover_provider_models = fake_discover
        try:
            for provider, base_url in providers:
                with self.subTest(provider=provider):
                    result = llm_config_dialog._model_options_for_dialog(
                        provider,
                        base_url=base_url,
                        timeout_seconds=60,
                        prefer_live=True,
                    )

                    self.assertEqual(["%s-live-model" % provider], result.models)
                    self.assertEqual("%s/models" % base_url, result.source)

            self.assertEqual(len(providers), len(calls))
            for provider, base_url in providers:
                self.assertIn((provider, base_url, "", 60), calls)
        finally:
            llm_config_dialog.discover_provider_models = old_discover
            llm_config_dialog._reset_model_discovery_cache_for_tests()

    def test_configure_handler_does_not_save_when_dialog_fails(self):
        handler = actions_module.ConfigureLlmHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_llm_config
        old_warning = actions_module.warning
        warnings = []
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=True))
        actions_module.save_config = lambda config: self.fail("save_config should not be called")
        actions_module.ask_llm_config = lambda config, warn: (_ for _ in ()).throw(RuntimeError("discovery failed"))
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_llm_config = old_ask
            actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("configuration failed", warnings[0])

    def test_configure_profile_directory_handler_saves_and_applies_selection(self):
        handler = actions_module.ConfigureProfileDirectoryHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_profile_dir
        old_configure = actions_module.configure_profile_dir
        old_summary = actions_module.format_profile_summary
        old_info = actions_module.info
        old_warning = actions_module.warning
        saved_configs = []
        configured = []
        messages = []
        warnings = []
        selected = r"F:\profiles\wdk26100"
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.save_config = lambda config: saved_configs.append(config) or Path(r"F:\ida\pseudoforge_config.json")
        actions_module.ask_profile_dir = lambda current, warn: selected
        actions_module.configure_profile_dir = lambda profile_dir: configured.append(profile_dir) or Path(profile_dir)
        actions_module.format_profile_summary = lambda profile_dir: "Profile directory: %s" % profile_dir
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_profile_dir = old_ask
            actions_module.configure_profile_dir = old_configure
            actions_module.format_profile_summary = old_summary
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual([config.profile_dir for config in saved_configs], [selected])
        self.assertEqual(configured, [selected])
        self.assertEqual(len(messages), 1)
        self.assertIn("Profile directory: %s" % selected, messages[0])

    def test_configure_preview_mode_handler_saves_selection(self):
        handler = actions_module.ConfigurePreviewModeHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_preview_config
        old_summary = actions_module.format_preview_summary
        old_info = actions_module.info
        old_warning = actions_module.warning
        saved_configs = []
        messages = []
        warnings = []

        def fake_ask(config, warn):
            config.preview = PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE)
            return config

        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.save_config = lambda config: saved_configs.append(config) or Path(r"F:\ida\pseudoforge_config.json")
        actions_module.ask_preview_config = fake_ask
        actions_module.format_preview_summary = lambda preview: "Preview mode: %s" % preview.backend
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_preview_config = old_ask
            actions_module.format_preview_summary = old_summary
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual([config.preview.backend for config in saved_configs], [PREVIEW_BACKEND_SIDE_BY_SIDE])
        self.assertEqual(len(messages), 1)
        self.assertIn("Preview mode: %s" % PREVIEW_BACKEND_SIDE_BY_SIDE, messages[0])

    def test_build_plan_applies_configured_profile_dir_before_analysis(self):
        capture = _capture()
        old_load = actions_module.load_config
        old_configure = actions_module.configure_profile_dir
        old_build = actions_module.build_clean_plan
        configured = []
        selected = r"F:\profiles\wdk26100"
        actions_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(enabled=False),
            profile_dir=selected,
        )
        actions_module.configure_profile_dir = lambda profile_dir: configured.append(profile_dir) or Path(profile_dir)
        actions_module.build_clean_plan = lambda captured, **_kwargs: _plan(captured)
        try:
            plan = actions_module._build_plan_with_config(capture)
        finally:
            actions_module.load_config = old_load
            actions_module.configure_profile_dir = old_configure
            actions_module.build_clean_plan = old_build

        self.assertEqual(configured, [selected])
        self.assertEqual(plan.function_ea, capture.ea)

    def test_analysis_summary_includes_domain_identity_hits(self):
        capture = _capture()
        plan = _plan(capture)
        plan.comments.append(
            {
                "kind": "domain_structure_identity",
                "profile_id": "windows.io_manager.delete_device",
                "effective_mode": "report-only",
                "blockers": ["profile_report_only", "build_mismatch"],
                "forced_report_only_reasons": ["build_mismatch"],
            }
        )

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn("Domain identities: 1 hit(s)", summary)
        self.assertIn("Top profiles: windows.io_manager.delete_device.", summary)
        self.assertIn("profile_report_only=1", summary)
        self.assertIn("build_mismatch=1", summary)

    def test_analysis_summary_includes_function_identity_and_type_correction_evidence(self):
        capture = _capture()
        plan = _plan(capture)
        plan.function_identity_candidates.append(
            FunctionIdentityCandidate(
                profile_id="windows.io_manager.delete_device",
                subsystem="I/O Manager",
                function_name="IoDeleteDevice",
                match_kind="function_name",
                confidence=0.74,
                evidence=["function_name"],
                blockers=["report_only_profile"],
                effective_mode="report-only",
            )
        )
        plan.type_corrections.append(
            ParameterTypeCorrection(
                parameter_index=0,
                old_name="a1",
                new_name="deviceObject",
                old_type="__int64",
                canonical_type="PDEVICE_OBJECT",
                profile_id="windows.io_manager.delete_device",
                confidence=0.92,
                effective_mode="report-only",
            )
        )
        plan.type_corrections.append(
            ParameterTypeCorrection(
                parameter_index=1,
                old_name="a2",
                new_name="irp",
                old_type="int",
                canonical_type="PIRP",
                profile_id="windows.io_manager.call_driver",
                confidence=0.90,
                effective_mode="report-only",
                blockers=["type_conflict"],
                apply_to_preview=False,
            )
        )

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn("Function identities: 1 candidate(s), 1 report-only", summary)
        self.assertIn("Top function profiles: windows.io_manager.delete_device.", summary)
        self.assertIn("Function identity blockers: report_only_profile=1.", summary)
        self.assertIn("Parameter type corrections: 1 applied, 1 blocked.", summary)
        self.assertIn("Applied corrections: a1->deviceObject __int64->PDEVICE_OBJECT", summary)
        self.assertIn("Blocked corrections: a2->irp int->PIRP", summary)
        self.assertIn("Type correction blockers: type_conflict=1.", summary)

    def test_analysis_summary_flags_type_assisted_recompile_when_available(self):
        capture, plan = _type_assisted_capture_plan()

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn("Type-assisted re-decompile available: 1 profile-backed parameter correction(s).", summary)
        self.assertIn("PseudoForge-cleaned redecompile", summary)

    def test_type_assisted_prototype_proposal_uses_canonical_parameter_types(self):
        capture, plan = _type_assisted_capture_plan()

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertFalse(proposal.blockers)
        self.assertIn("windows.io_manager.delete_device", proposal.profile_ids)
        self.assertIn("PDEVICE_OBJECT deviceObject", proposal.prototype)
        self.assertTrue(any("exact_function_name" in item for item in proposal.evidence))
        self.assertEqual(proposal.corrections, ("param0 a1->deviceObject __int64->PDEVICE_OBJECT",))

    def test_type_assisted_prototype_ignores_generic_subsystem_prefix_blockers(self):
        capture, plan = _type_assisted_capture_plan()
        plan.function_identity_candidates.append(
            FunctionIdentityCandidate(
                profile_id="windows.subsystem_prefix.io_manager",
                subsystem="I/O Manager",
                function_name="IoDeleteDevice",
                match_kind="function_regex",
                confidence=0.74,
                evidence=["function_regex"],
                blockers=["generic_subsystem_prefix", "report_only_profile"],
                effective_mode="report-only",
            )
        )

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertFalse(proposal.blockers)
        self.assertIn("PDEVICE_OBJECT deviceObject", proposal.prototype)
        self.assertEqual(proposal.corrections, ("param0 a1->deviceObject __int64->PDEVICE_OBJECT",))

    def test_type_assisted_prototype_allows_exact_report_only_signature_preview(self):
        capture, plan = _type_assisted_capture_plan()
        plan.function_identity_candidates[0].effective_mode = "report-only"
        plan.function_identity_candidates[0].blockers = ["report_only_profile"]
        plan.type_corrections[0].effective_mode = "report-only"

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertFalse(proposal.blockers)
        self.assertIn("PDEVICE_OBJECT deviceObject", proposal.prototype)
        self.assertIn(
            "type_correction_report_only_preview:windows.io_manager.delete_device:param0",
            proposal.evidence,
        )
        self.assertEqual(proposal.corrections, ("param0 a1->deviceObject __int64->PDEVICE_OBJECT",))

    def test_type_assisted_prototype_uses_public_kernel_api_signature_metadata(self):
        capture = FunctionCapture(
            ea=0x140003000,
            name="RtlFindLastBackwardRunClear",
            prototype="__int64 __fastcall RtlFindLastBackwardRunClear(__int64 a1, int a2, __int64 a3)",
            pseudocode=(
                "__int64 __fastcall RtlFindLastBackwardRunClear(__int64 a1, int a2, __int64 a3)\n"
                "{\n"
                "  return a1 + a2 + a3;\n"
                "}"
            ),
            lvars=[
                LocalVariable("a1", "__int64", True, 0),
                LocalVariable("a2", "int", True, 1),
                LocalVariable("a3", "__int64", True, 2),
            ],
            source_path=r"F:\target\ntoskrnl.exe",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
        )

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertFalse(proposal.blockers)
        self.assertIn("windows.public_kernel_api.rtlfindlastbackwardrunclear", proposal.profile_ids)
        self.assertIn("PRTL_BITMAP bitMapHeader", proposal.prototype)
        self.assertIn("ULONG fromIndex", proposal.prototype)
        self.assertIn("PULONG startingRunIndex", proposal.prototype)
        self.assertIn(
            "param0 a1->bitMapHeader __int64->PRTL_BITMAP",
            proposal.corrections,
        )
        self.assertTrue(any("public_kernel_api_exact_name" in item for item in proposal.evidence))

    def test_type_assisted_prototype_recovers_public_kernel_api_arity_preview(self):
        capture = FunctionCapture(
            ea=0x140004000,
            name="ZwMapViewOfSectionEx",
            prototype="__int64 __fastcall ZwMapViewOfSectionEx(__int64 a1, __int64 a2)",
            pseudocode=(
                "__int64 __fastcall ZwMapViewOfSectionEx(__int64 a1, __int64 a2)\n"
                "{\n"
                "  return a1 + a2;\n"
                "}"
            ),
            lvars=[
                LocalVariable("a1", "__int64", True, 0),
                LocalVariable("a2", "__int64", True, 1),
            ],
            source_path=r"F:\target\ntoskrnl.exe",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
        )

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertFalse(proposal.blockers)
        self.assertIn("windows.public_kernel_api.zwmapviewofsectionex", proposal.profile_ids)
        self.assertIn("NTSTATUS __fastcall ZwMapViewOfSectionEx", proposal.prototype)
        self.assertIn("HANDLE sectionHandle", proposal.prototype)
        self.assertIn("HANDLE processHandle", proposal.prototype)
        self.assertIn("PVOID *baseAddress", proposal.prototype)
        self.assertIn("PMEM_EXTENDED_PARAMETER extendedParameters", proposal.prototype)
        self.assertIn("ULONG extendedParameterCount", proposal.prototype)
        self.assertIn("public_signature_arity 2->9", proposal.corrections)

    def test_type_assisted_prototype_refuses_public_kernel_api_prefix_alias(self):
        capture = FunctionCapture(
            ea=0x140005000,
            name="IopAllocateMdl",
            prototype=(
                "__int64 __fastcall IopAllocateMdl("
                "__int64 a1, unsigned int a2, char a3, __int64 a4, __int64 a5, int a6)"
            ),
            pseudocode=(
                "__int64 __fastcall IopAllocateMdl("
                "__int64 a1, unsigned int a2, char a3, __int64 a4, __int64 a5, int a6)\n"
                "{\n"
                "  return a1 + a2 + a3 + a4 + a5 + a6;\n"
                "}"
            ),
            lvars=[
                LocalVariable("a1", "__int64", True, 0),
                LocalVariable("a2", "unsigned int", True, 1),
                LocalVariable("a3", "char", True, 2),
                LocalVariable("a4", "__int64", True, 3),
                LocalVariable("a5", "__int64", True, 4),
                LocalVariable("a6", "int", True, 5),
            ],
            source_path=r"F:\target\ntoskrnl.exe",
        )
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
        )

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertIn("no_profile_parameter_type_corrections", proposal.blockers)
        self.assertFalse(proposal.corrections)

    def test_type_assisted_prototype_refuses_report_only_build_mismatch(self):
        capture, plan = _type_assisted_capture_plan()
        plan.function_identity_candidates[0].effective_mode = "report-only"
        plan.function_identity_candidates[0].blockers = ["report_only_profile", "build_mismatch"]
        plan.type_corrections[0].effective_mode = "report-only"
        plan.type_corrections[0].blockers = ["build_mismatch"]
        plan.type_corrections[0].apply_to_preview = False

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertIn(
            "function_identity_blocked:windows.io_manager.delete_device:build_mismatch",
            proposal.blockers,
        )
        self.assertIn(
            "type_correction_blocked:windows.io_manager.delete_device:param0:build_mismatch",
            proposal.blockers,
        )
        self.assertIn(
            "type_correction_preview_disabled:windows.io_manager.delete_device:param0",
            proposal.blockers,
        )

    def test_type_assisted_prototype_refuses_blocked_corrections_before_type_api(self):
        capture, plan = _type_assisted_capture_plan()
        plan.type_corrections[0].blockers.append("type_conflict")
        fake_idc = FakeIdcTypeApi("__int64 __fastcall IoDeleteDevice(__int64 a1)")
        old_idc = actions_module.idc
        actions_module.idc = fake_idc
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            self.assertIn("type_correction_blocked:windows.io_manager.delete_device:param0:type_conflict", proposal.blockers)
            with self.assertRaisesRegex(RuntimeError, "prototype blockers"):
                actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc

        self.assertEqual(fake_idc.calls, [])

    def test_type_assisted_prototype_refuses_report_only_and_weak_identity(self):
        capture, plan = _type_assisted_capture_plan()
        plan.function_identity_candidates[0].effective_mode = "report-only"
        plan.function_identity_candidates[0].match_kind = "body_only_weak"
        plan.type_corrections[0].effective_mode = "report-only"

        proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)

        self.assertIn("body_only_weak_match:windows.io_manager.delete_device", proposal.blockers)
        self.assertIn("type_correction_report_only:windows.io_manager.delete_device:param0", proposal.blockers)
        self.assertIn("function_identity_report_only:windows.io_manager.delete_device", proposal.blockers)

    def test_analyze_current_function_does_not_touch_ida_type_api(self):
        capture = _capture()
        plan = _plan(capture)
        old_capture = actions_module.capture_current_function
        old_build = actions_module._build_plan_with_config
        old_write = actions_module._write_forge_snapshot
        old_get_type = actions_module._get_ida_function_type
        old_apply_type = actions_module._apply_ida_function_type
        actions_module.capture_current_function = lambda: (capture, None)
        actions_module._build_plan_with_config = lambda captured, task_name="": plan
        actions_module._write_forge_snapshot = lambda captured, built_plan: (Path(r"F:\target\driver.forge"), "forge text")
        actions_module._get_ida_function_type = lambda ea: self.fail("default analyze read IDB type")
        actions_module._apply_ida_function_type = lambda ea, type_text: self.fail("default analyze wrote IDB type")
        try:
            analyzed_capture, analyzed_plan = actions_module.analyze_current_function()
        finally:
            actions_module.capture_current_function = old_capture
            actions_module._build_plan_with_config = old_build
            actions_module._write_forge_snapshot = old_write
            actions_module._get_ida_function_type = old_get_type
            actions_module._apply_ida_function_type = old_apply_type

        self.assertIs(analyzed_capture, capture)
        self.assertIs(analyzed_plan, plan)

    def test_type_assisted_recompile_restores_original_type_on_success(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "__int64 __fastcall IoDeleteDevice(__int64 a1)"
        fake_idc = FakeIdcTypeApi(original_type)
        old_idc = actions_module.idc
        old_decompile = actions_module._decompile_function_pseudocode
        old_refresh = actions_module._refresh_function_type_state
        old_clean = actions_module._render_type_assisted_cleaned_pseudocode
        clean_calls = []
        actions_module.idc = fake_idc
        actions_module._decompile_function_pseudocode = (
            lambda ea: "void __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)\n{\n  IopCompleteUnloadOrDelete((ULONG_PTR)deviceObject);\n}"
        )
        actions_module._refresh_function_type_state = lambda ea: None

        def fake_clean(captured, improved_pseudocode):
            clean_calls.append((captured, improved_pseudocode, fake_idc.current_type))
            return "PseudoForge cleaned type-assisted output"

        actions_module._render_type_assisted_cleaned_pseudocode = fake_clean
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            result = actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._refresh_function_type_state = old_refresh
            actions_module._render_type_assisted_cleaned_pseudocode = old_clean

        self.assertTrue(result.restore_succeeded)
        self.assertIn("PDEVICE_OBJECT deviceObject", result.improved_pseudocode)
        self.assertEqual("PseudoForge cleaned type-assisted output", result.cleaned_pseudocode)
        self.assertEqual("", result.cleanup_error)
        self.assertEqual(1, len(clean_calls))
        self.assertIs(capture, clean_calls[0][0])
        self.assertIn("IopCompleteUnloadOrDelete", clean_calls[0][1])
        self.assertEqual("__int64 __fastcall IoDeleteDevice(__int64 a1);", clean_calls[0][2])
        self.assertEqual(
            fake_idc.calls,
            [
                (capture.ea, "__int64 __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject);"),
                (capture.ea, "__int64 __fastcall IoDeleteDevice(__int64 a1);"),
            ],
        )

    def test_type_assisted_recompile_rejects_ignored_temporary_type_apply(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "__int64 __fastcall IoDeleteDevice(__int64 a1)"
        fake_idc = FakeIdcTypeApi(original_type, ignore_first_apply=True)
        old_idc = actions_module.idc
        old_decompile = actions_module._decompile_function_pseudocode
        old_refresh = actions_module._refresh_function_type_state
        actions_module.idc = fake_idc
        actions_module._decompile_function_pseudocode = (
            lambda ea: "__int64 __fastcall IoDeleteDevice(__int64 a1)\n{\n  return a1;\n}"
        )
        actions_module._refresh_function_type_state = lambda ea: None
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            with self.assertRaisesRegex(RuntimeError, "temporary prototype was not reflected"):
                actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._refresh_function_type_state = old_refresh

        self.assertEqual(
            fake_idc.calls,
            [
                (capture.ea, "__int64 __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject);"),
                (capture.ea, "__int64 __fastcall IoDeleteDevice(__int64 a1);"),
            ],
        )
        self.assertEqual(fake_idc.current_type, "__int64 __fastcall IoDeleteDevice(__int64 a1);")

    def test_type_assisted_recompile_restores_ida_nameless_original_type(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "__int64 __fastcall(__int64 a1)"
        fake_idc = FakeIdcTypeApi(original_type)
        old_idc = actions_module.idc
        old_decompile = actions_module._decompile_function_pseudocode
        old_refresh = actions_module._refresh_function_type_state
        old_clean = actions_module._render_type_assisted_cleaned_pseudocode
        actions_module.idc = fake_idc
        actions_module._decompile_function_pseudocode = (
            lambda ea: "void __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)\n{\n  IopCompleteUnloadOrDelete((ULONG_PTR)deviceObject);\n}"
        )
        actions_module._refresh_function_type_state = lambda ea: None
        actions_module._render_type_assisted_cleaned_pseudocode = lambda captured, improved: "cleaned"
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            result = actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._refresh_function_type_state = old_refresh
            actions_module._render_type_assisted_cleaned_pseudocode = old_clean

        self.assertTrue(result.restore_succeeded)
        self.assertEqual(
            fake_idc.calls,
            [
                (capture.ea, "__int64 __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject);"),
                (capture.ea, "__int64 __fastcall IoDeleteDevice(__int64 a1);"),
            ],
        )

    def test_type_assisted_recompile_refuses_unstable_unknown_original_type(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "_UNKNOWN **__fastcall(int, __int64, __int64)"
        fake_idc = FakeIdcTypeApi(original_type)
        old_idc = actions_module.idc
        actions_module.idc = fake_idc
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            with self.assertRaisesRegex(RuntimeError, "unstable_original_type_unknown"):
                actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc

        self.assertEqual([], fake_idc.calls)
        self.assertEqual(original_type, fake_idc.current_type)

    def test_type_assisted_recompile_restores_original_type_after_decompile_failure(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "__int64 __fastcall IoDeleteDevice(__int64 a1)"
        fake_idc = FakeIdcTypeApi(original_type)
        old_idc = actions_module.idc
        old_decompile = actions_module._decompile_function_pseudocode
        old_refresh = actions_module._refresh_function_type_state
        actions_module.idc = fake_idc
        actions_module._decompile_function_pseudocode = (
            lambda ea: (_ for _ in ()).throw(RuntimeError("decompile failed"))
        )
        actions_module._refresh_function_type_state = lambda ea: None
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            with self.assertRaisesRegex(RuntimeError, "original IDB type was restored"):
                actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._refresh_function_type_state = old_refresh

        self.assertEqual(
            fake_idc.calls,
            [
                (capture.ea, "__int64 __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject);"),
                (capture.ea, "__int64 __fastcall IoDeleteDevice(__int64 a1);"),
            ],
        )
        self.assertEqual(fake_idc.current_type, "__int64 __fastcall IoDeleteDevice(__int64 a1);")

    def test_type_assisted_recompile_reports_high_severity_restore_failure(self):
        capture, plan = _type_assisted_capture_plan()
        original_type = "__int64 __fastcall IoDeleteDevice(__int64 a1)"
        fake_idc = FakeIdcTypeApi(original_type, fail_on_restore=True)
        warnings = []
        old_idc = actions_module.idc
        old_decompile = actions_module._decompile_function_pseudocode
        old_refresh = actions_module._refresh_function_type_state
        old_warning = actions_module.warning
        actions_module.idc = fake_idc
        actions_module._decompile_function_pseudocode = (
            lambda ea: "void __fastcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)\n{\n}"
        )
        actions_module._refresh_function_type_state = lambda ea: None
        actions_module.warning = warnings.append
        try:
            proposal = actions_module._build_type_assisted_prototype_proposal(capture, plan)
            result = actions_module._run_type_assisted_recompile_preview(capture, plan, proposal)
        finally:
            actions_module.idc = old_idc
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._refresh_function_type_state = old_refresh
            actions_module.warning = old_warning

        self.assertFalse(result.restore_succeeded)
        self.assertEqual(len(warnings), 1)
        self.assertIn("HIGH SEVERITY", warnings[0])
        self.assertIn("restore failed", warnings[0])

    def test_build_plan_logs_provider_cyber_policy_block_to_output_and_plan(self):
        capture = _capture()
        old_load = actions_module.load_config
        old_configure = actions_module.configure_profile_dir
        old_active = actions_module.active_profile_root
        old_provider = actions_module.build_rename_provider
        old_api_key = actions_module.get_provider_api_key
        old_build = actions_module.build_clean_plan
        old_log_output = actions_module.log_output
        messages = []
        error = (
            "API Error: request violates Usage Policy and triggered cyber-related safeguards. "
            "Request ID: req_policy_456"
        )

        def fake_build(captured, rename_provider=None, **_kwargs):
            if rename_provider is not None:
                raise RuntimeError(error)
            return _plan(captured)

        actions_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="claude_login_via_claude_cli",
                model="claude-opus-4-8",
            ),
        )
        actions_module.configure_profile_dir = lambda profile_dir: Path(r"F:\profiles\default")
        actions_module.active_profile_root = lambda: Path(r"F:\profiles\default")
        actions_module.build_rename_provider = lambda config, api_key="": object()
        actions_module.get_provider_api_key = lambda config, provider: ""
        actions_module.build_clean_plan = fake_build
        actions_module.log_output = messages.append
        try:
            plan = actions_module._build_plan_with_config(capture)
        finally:
            actions_module.load_config = old_load
            actions_module.configure_profile_dir = old_configure
            actions_module.active_profile_root = old_active
            actions_module.build_rename_provider = old_provider
            actions_module.get_provider_api_key = old_api_key
            actions_module.build_clean_plan = old_build
            actions_module.log_output = old_log_output

        self.assertIn("blocked by provider cyber policy", "\n".join(messages))
        self.assertIn("req_policy_456", "\n".join(messages))
        self.assertIn("blocked by provider cyber policy", plan.warnings[0])
        self.assertIn("req_policy_456", plan.warnings[0])

    def test_build_plan_does_not_pass_stale_api_key_to_local_http_provider(self):
        capture = _capture()
        old_load = actions_module.load_config
        old_configure = actions_module.configure_profile_dir
        old_active = actions_module.active_profile_root
        old_provider = actions_module.build_rename_provider
        old_build = actions_module.build_clean_plan
        provider_calls = []

        actions_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="ollama",
                model="llama3.2",
                base_url="http://localhost:11434/v1",
            ),
            credentials={
                "ollama": ProviderCredential(api_key="stale-local-key"),
            },
        )
        actions_module.configure_profile_dir = lambda profile_dir: Path(r"F:\profiles\default")
        actions_module.active_profile_root = lambda: Path(r"F:\profiles\default")
        actions_module.build_rename_provider = lambda config, api_key="": provider_calls.append(api_key) or object()
        actions_module.build_clean_plan = lambda captured, **_kwargs: _plan(captured)
        try:
            plan = actions_module._build_plan_with_config(capture)
        finally:
            actions_module.load_config = old_load
            actions_module.configure_profile_dir = old_configure
            actions_module.active_profile_root = old_active
            actions_module.build_rename_provider = old_provider
            actions_module.build_clean_plan = old_build

        self.assertEqual(provider_calls, [""])
        self.assertEqual(plan.function_ea, capture.ea)

    def test_show_settings_includes_plugin_version(self):
        handler = actions_module.ShowSettingsHandler()
        old_load = actions_module.load_config
        old_info = actions_module.info
        old_warning = actions_module.warning
        messages = []
        warnings = []
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(messages), 1)
        self.assertIn("Version: %s" % VERSION, messages[0])
        self.assertIn("Profile directory:", messages[0])
        self.assertIn("Available domain packs:", messages[0])
        self.assertIn("Preview mode:", messages[0])

    def test_show_settings_includes_source_context(self):
        handler = actions_module.ShowSettingsHandler()
        old_load = actions_module.load_config
        old_info = actions_module.info
        old_warning = actions_module.warning
        old_target = actions_module._target_file_path
        old_idb = actions_module._idb_path
        old_active = actions_module.active_profile_root
        old_ida_nalt = actions_module.ida_nalt
        messages = []
        warnings = []
        actions_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(enabled=False),
            profile_dir=r"F:\profiles\wdk26100",
        )
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        actions_module._target_file_path = lambda: Path(r"D:\bin\os\26200.8457\ntoskrnl.exe.i64")
        actions_module._idb_path = lambda: Path(r"D:\bin\os\26200.8457\ntoskrnl.exe.i64")
        actions_module.active_profile_root = lambda: r"F:\profiles\wdk26100"
        actions_module.ida_nalt = object()
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.info = old_info
            actions_module.warning = old_warning
            actions_module._target_file_path = old_target
            actions_module._idb_path = old_idb
            actions_module.active_profile_root = old_active
            actions_module.ida_nalt = old_ida_nalt

        self.assertFalse(warnings)
        self.assertEqual(len(messages), 1)
        self.assertIn("Source context:", messages[0])
        self.assertIn("Target path: D:\\bin\\os\\26200.8457\\ntoskrnl.exe.i64", messages[0])
        self.assertIn("Inferred image: ntoskrnl.exe", messages[0])
        self.assertIn("Inferred build: 26200.8457", messages[0])
        self.assertIn("Context status: complete", messages[0])


if __name__ == "__main__":
    unittest.main()
