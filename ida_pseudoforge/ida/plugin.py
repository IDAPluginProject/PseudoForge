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
    AnalyzeBufferContractCaseHandler,
    AnalyzeIoctlCaseHandler,
    ApplySelectedRenamesHandler,
    CancelCurrentTaskHandler,
    ConfigureLlmHandler,
    ConfigurePreviewModeHandler,
    ConfigureProfileDirectoryHandler,
    ExportCleanedPseudocodeHandler,
    PreviewCurrentAnalyzedFunctionHandler,
    ShowAnalyzedFunctionsHandler,
    ShowSettingsHandler,
    TypeAssistedRedecompilePreviewHandler,
)
from ida_pseudoforge.ida.action_registry import ActionRegistry
from ida_pseudoforge.ida.ui_preview import cleanup_preview_actions
from ida_pseudoforge.logging import log_event, start_output_logger, stop_output_logger
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
    buffer_contract_cursor_action_name = "pseudoforge:analyze_buffer_contract_cursor_case"
    buffer_contract_value_action_name = "pseudoforge:analyze_buffer_contract_case_value"
    ioctl_action_name = "pseudoforge:analyze_ioctl_case"
    cancel_action_name = "pseudoforge:cancel_current_task"
    apply_renames_action_name = "pseudoforge:apply_selected_renames"
    type_assisted_recompile_preview_action_name = "pseudoforge:type_assisted_recompile_preview"
    configure_llm_action_name = "pseudoforge:configure_llm"
    configure_preview_action_name = "pseudoforge:configure_preview_mode"
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
        self._create_static_menus()

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
            self.buffer_contract_cursor_action_name,
            "Analyze buffer contract for cursor case",
            AnalyzeBufferContractCaseHandler(prompt_always=False),
            "Ctrl+Alt+B",
            "Deep-analyze command buffer contracts for the switch case under the cursor",
        )
        self._actions.register(
            self.buffer_contract_value_action_name,
            "Analyze buffer contract by case value...",
            AnalyzeBufferContractCaseHandler(prompt_always=True),
            "",
            "Deep-analyze command buffer contracts for a specific switch case value",
        )
        self._actions.register(
            self.ioctl_action_name,
            "Analyze IOCTL/selector path...",
            AnalyzeIoctlCaseHandler(),
            "Ctrl+Alt+I",
            "Deep-analyze input/output structures and meaningful path predicates for the selected IOCTL or selector case",
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
            self.type_assisted_recompile_preview_action_name,
            "Advanced: type-assisted re-decompile preview",
            TypeAssistedRedecompilePreviewHandler(),
            "",
            "Temporarily apply a profile-backed prototype, re-decompile for preview, then restore the IDB type",
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
            self.configure_preview_action_name,
            "Configure preview mode",
            ConfigurePreviewModeHandler(),
            "Ctrl+Alt+Shift+V",
            "Configure the PseudoForge preview mode",
        )
        self._actions.register(
            self.show_settings_action_name,
            "Show settings",
            ShowSettingsHandler(),
            "",
            "Show current PseudoForge settings",
        )

        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.analyze_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.preview_current_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.analyzed_functions_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.export_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.buffer_contract_cursor_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.buffer_contract_value_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Selector Analysis/",
            self.ioctl_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.cancel_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Advanced/",
            self.apply_renames_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/Advanced/",
            self.type_assisted_recompile_preview_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.configure_llm_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.configure_profile_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
            self.configure_preview_action_name,
        )
        self._actions.attach_menu(
            "Edit/PseudoForge/",
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

    def _create_static_menus(self) -> None:
        create_menu = getattr(ida_kernwin, "create_menu", None) or getattr(idaapi, "create_menu", None)
        if create_menu is None:
            log_event("menu.create.unavailable")
            return

        for name, label, menu_path in (
            ("pseudoforge_menu", "PseudoForge", "Edit/"),
            ("pseudoforge_ioctl_menu", "Selector Analysis", "Edit/PseudoForge/"),
            ("pseudoforge_advanced_menu", "Advanced", "Edit/PseudoForge/"),
        ):
            try:
                ok = bool(create_menu(name, label, menu_path))
            except Exception as exc:
                log_event(
                    "menu.create.failed name=%s path=\"%s\" error=\"%s\""
                    % (name, _ascii_for_log(menu_path), _ascii_for_log(str(exc)))
                )
                continue
            log_event(
                "menu.create name=%s path=\"%s\" ok=%d"
                % (name, _ascii_for_log(menu_path), int(ok))
            )

    def run(self, arg):
        try:
            return ConfigurePreviewModeHandler().activate(None)
        except Exception as exc:
            log_event("plugin.run.configure_preview.failed error=\"%s\"" % _ascii_for_log(str(exc)))
            if ida_kernwin is not None:
                try:
                    ida_kernwin.warning("PseudoForge preview mode configuration failed: %s" % exc)
                except Exception:
                    pass
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
                PseudoForgePlugin.buffer_contract_cursor_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.buffer_contract_value_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.ioctl_action_name,
                "PseudoForge/Selector Analysis/",
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
                PseudoForgePlugin.type_assisted_recompile_preview_action_name,
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
                PseudoForgePlugin.configure_preview_action_name,
                "PseudoForge/",
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                PseudoForgePlugin.show_settings_action_name,
                "PseudoForge/",
            )
        return 0


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")
