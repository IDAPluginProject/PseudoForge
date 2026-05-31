from __future__ import annotations

try:
    import ida_hexrays  # type: ignore
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
except Exception:
    ida_hexrays = None
    ida_kernwin = None
    idaapi = None

from ida_pseudoforge.ida.actions import (
    AnalyzeCurrentFunctionHandler,
    ApplySelectedRenamesHandler,
    CancelCurrentTaskHandler,
    ConfigureLlmHandler,
    ConfigureProfileDirectoryHandler,
    ExportCleanedPseudocodeHandler,
    PreviewCurrentAnalyzedFunctionHandler,
    ShowAnalyzedFunctionsHandler,
    ShowSettingsHandler,
)
from ida_pseudoforge.ida.action_registry import ActionRegistry
from ida_pseudoforge.ida.ui_preview import cleanup_preview_actions
from ida_pseudoforge.logging import start_output_logger, stop_output_logger
from ida_pseudoforge.version import plugin_title


class PseudoForgePlugin(idaapi.plugin_t if idaapi else object):
    flags = 0
    wanted_name = "PseudoForge"
    wanted_hotkey = ""
    comment = "Refactor Hex-Rays pseudocode into rename plans and readable exports"
    help = plugin_title()

    analyze_action_name = "pseudoforge:analyze_current_function"
    preview_current_action_name = "pseudoforge:preview_current_analyzed_function"
    analyzed_functions_action_name = "pseudoforge:analyzed_functions"
    export_action_name = "pseudoforge:export_cleaned_pseudocode"
    cancel_action_name = "pseudoforge:cancel_current_task"
    apply_renames_action_name = "pseudoforge:apply_selected_renames"
    configure_llm_action_name = "pseudoforge:configure_llm"
    configure_profile_action_name = "pseudoforge:configure_profile_dir"
    show_settings_action_name = "pseudoforge:show_settings"
    legacy_preview_action_name = "pseudoforge:preview_cleaned_pseudocode"

    def init(self):
        if idaapi is None or ida_kernwin is None or ida_hexrays is None:
            return 0
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        if not ida_kernwin.is_idaq():
            return idaapi.PLUGIN_SKIP

        start_output_logger()

        self._actions = ActionRegistry(idaapi)
        self._unregister_legacy_actions()

        self._actions.register(
            self.analyze_action_name,
            "Analyze current function",
            AnalyzeCurrentFunctionHandler(),
            "Ctrl+Alt+F",
            "Analyze current function with PseudoForge",
        )
        self._actions.register(
            self.export_action_name,
            "Export cleaned pseudocode",
            ExportCleanedPseudocodeHandler(),
            "Ctrl+Alt+Shift+F",
            "Export a readable pseudocode bundle",
        )
        self._actions.register(
            self.cancel_action_name,
            "Cancel current operation",
            CancelCurrentTaskHandler(),
            "",
            "Request cancellation for the running PseudoForge task",
        )
        self._actions.register(
            self.preview_current_action_name,
            "Show current analysis result",
            PreviewCurrentAnalyzedFunctionHandler(),
            "Ctrl+Alt+P",
            "Show the cached PseudoForge result for the current function",
        )
        self._actions.register(
            self.analyzed_functions_action_name,
            "Analyzed functions...",
            ShowAnalyzedFunctionsHandler(),
            "Ctrl+Alt+Shift+P",
            "Choose from cached PseudoForge analyzed function sections",
        )
        self._actions.register(
            self.apply_renames_action_name,
            "Advanced: apply selected renames to IDB",
            ApplySelectedRenamesHandler(),
            "",
            "Apply selected local variable renames to the IDB",
        )
        self._actions.register(
            self.configure_llm_action_name,
            "Configure LLM rename assist",
            ConfigureLlmHandler(),
            "",
            "Configure LLM rename assist provider for PseudoForge",
        )
        self._actions.register(
            self.configure_profile_action_name,
            "Configure profile directory",
            ConfigureProfileDirectoryHandler(),
            "",
            "Configure the PseudoForge profile directory",
        )
        self._actions.register(
            self.show_settings_action_name,
            "Show settings",
            ShowSettingsHandler(),
            "",
            "Show current PseudoForge settings",
        )

        self._actions.attach_menu(
            "Edit/PseudoForge/Analyze current function",
            self.analyze_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Show current analysis result",
            self.preview_current_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Analyzed functions...",
            self.analyzed_functions_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Export cleaned pseudocode",
            self.export_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Cancel current operation",
            self.cancel_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Advanced/Apply selected renames to IDB",
            self.apply_renames_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Configure LLM rename assist",
            self.configure_llm_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Configure profile directory",
            self.configure_profile_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Show settings",
            self.show_settings_action_name,
        )

        self._hooks = ContextMenuHooks()
        self._hooks.hook()
        return idaapi.PLUGIN_KEEP

    def _unregister_legacy_actions(self) -> None:
        for action_name in (self.legacy_preview_action_name,):
            try:
                idaapi.unregister_action(action_name)
            except Exception:
                pass

    def run(self, arg):
        return None

    def term(self):
        if idaapi is None:
            return None
        stop_output_logger()
        try:
            if getattr(self, "_hooks", None):
                self._hooks.unhook()
        except Exception:
            pass
        try:
            cleanup_preview_actions()
        except Exception:
            pass
        registry = getattr(self, "_actions", None)
        if registry is not None:
            try:
                registry.unregister_all()
            except Exception:
                pass
        return None


class ContextMenuHooks(idaapi.UI_Hooks if idaapi else object):
    def finish_populating_widget_popup(self, form, popup, ctx=None):
        if idaapi is None:
            return 0
        try:
            widget_type = idaapi.get_widget_type(form)
        except Exception:
            return 0
        if widget_type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.analyze_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.preview_current_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.analyzed_functions_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.export_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.cancel_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.apply_renames_action_name,
                "PseudoForge/Advanced/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.configure_llm_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.configure_profile_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.show_settings_action_name,
                "PseudoForge/",
            )
        return 0
