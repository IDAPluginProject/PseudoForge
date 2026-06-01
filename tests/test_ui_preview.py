from __future__ import annotations

import os
import tempfile
import unittest

from ida_pseudoforge.config import (
    LlmConfig,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    PreviewConfig,
    PseudoForgeConfig,
    save_config,
)
from ida_pseudoforge.ida import ui_preview as ui_preview_module
from ida_pseudoforge.ida.ui_preview import (
    _MAX_HIGHLIGHT_LINES,
    _SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT,
    _bounded_panel_text,
    _fixed_width_system_font,
    _highlight_preview_lines,
    _plain_text_no_wrap,
    _qt_horizontal_orientation,
    _search_line_matches,
    _side_by_side_summary_text,
    _side_by_side_highlight_rules,
    _scroll_editors_to_search_match,
    _syntax_highlight_lines,
    _text_cursor_move_operation,
    show_text_view,
    side_by_side_preview_enabled,
)


class UiPreviewTests(unittest.TestCase):
    def test_preview_syntax_highlighting_marks_cpp_tokens(self) -> None:
        lines = [
            "if ( status == STATUS_SUCCESS )",
            "  return ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'));",
            "  // comment",
            "name = \"http://example//not-comment\"; /* block */",
        ]

        def colorize(text: str, role: str) -> str:
            return "<%s>%s</%s>" % (role, text, role)

        rendered = "\n".join(_syntax_highlight_lines(lines, colorize))

        self.assertIn("<keyword>if</keyword>", rendered)
        self.assertIn("<constant>STATUS_SUCCESS</constant>", rendered)
        self.assertIn("<keyword>return</keyword>", rendered)
        self.assertIn("<function>ExAllocatePool2</function>", rendered)
        self.assertIn("<constant>POOL_FLAG_PAGED</constant>", rendered)
        self.assertIn("<number>0x28uLL</number>", rendered)
        self.assertIn("<char>'A'</char>", rendered)
        self.assertIn("<comment>// comment</comment>", rendered)
        self.assertIn("<string>\"http://example//not-comment\"</string>", rendered)
        self.assertIn("<comment>/* block */</comment>", rendered)

    def test_preview_syntax_highlighting_falls_back_for_large_views(self) -> None:
        lines = ["if ( status == STATUS_SUCCESS )"] * (_MAX_HIGHLIGHT_LINES + 1)

        self.assertEqual(_highlight_preview_lines(lines), lines)

    def test_preview_syntax_highlighting_can_be_disabled(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT")
        os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = "1"
        try:
            self.assertEqual(_highlight_preview_lines(["if ( STATUS_SUCCESS )"]), ["if ( STATUS_SUCCESS )"])
        finally:
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT", None)
            else:
                os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = old_value

    def test_preview_syntax_highlighting_accepts_ida_color_tags(self) -> None:
        class FakeIdaLines:
            SCOLOR_KEYWORD = "\x01"
            SCOLOR_REGCMT = "\x02"
            SCOLOR_STRING = "\x03"
            SCOLOR_CHAR = "\x04"
            SCOLOR_DNUM = "\x05"
            SCOLOR_MACRO = "\x06"
            SCOLOR_CNAME = "\x07"
            SCOLOR_TYPE = "\x08"

            @staticmethod
            def COLSTR(text, color):
                return "<%s>%s</>" % (repr(color), text)

        old_ida_lines = ui_preview_module.ida_lines
        ui_preview_module.ida_lines = FakeIdaLines
        try:
            highlighted = ui_preview_module._highlight_preview_lines(["if ( STATUS_SUCCESS ) // comment"])
        finally:
            ui_preview_module.ida_lines = old_ida_lines

        self.assertIn("<'\\x01'>if</>", highlighted[0])
        self.assertIn("<'\\x06'>STATUS_SUCCESS</>", highlighted[0])
        self.assertIn("<'\\x02'>// comment</>", highlighted[0])

    def test_side_by_side_preview_feature_flag_values(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        try:
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
            self.assertTrue(side_by_side_preview_enabled())
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "dockable"
            self.assertTrue(side_by_side_preview_enabled())
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "simple"
            self.assertFalse(side_by_side_preview_enabled())
        finally:
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

    def test_side_by_side_preview_uses_saved_preview_config_without_env(self) -> None:
        old_backend = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            save_config(
                PseudoForgeConfig(
                    llm=LlmConfig(enabled=False),
                    preview=PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE),
                )
            )
            try:
                self.assertTrue(side_by_side_preview_enabled())
            finally:
                if old_backend is None:
                    os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
                else:
                    os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_backend
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_side_by_side_preview_env_overrides_saved_preview_config(self) -> None:
        old_backend = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "simple"
            save_config(
                PseudoForgeConfig(
                    llm=LlmConfig(enabled=False),
                    preview=PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE),
                )
            )
            try:
                self.assertFalse(side_by_side_preview_enabled())
            finally:
                if old_backend is None:
                    os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
                else:
                    os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_backend
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_show_text_view_uses_feature_flagged_side_by_side_backend(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_try = ui_preview_module._try_show_side_by_side_view
        calls = []

        def fake_try(*args, **kwargs):
            calls.append((args, kwargs))
            return True

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = object()
        ui_preview_module._try_show_side_by_side_view = fake_try
        try:
            backend = show_text_view(
                "PseudoForge: sample",
                "cleaned text",
                reference_text="raw text",
                reference_title="Raw",
                content_title="Cleaned",
            )
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module._try_show_side_by_side_view = old_try
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertEqual("dockable_side_by_side", backend)
        self.assertEqual(1, len(calls))
        self.assertEqual("PseudoForge: sample", calls[0][0][0])
        self.assertEqual("raw text", calls[0][0][1])
        self.assertEqual("cleaned text", calls[0][0][2])
        self.assertEqual("Raw", calls[0][1]["reference_title"])
        self.assertEqual("Cleaned", calls[0][1]["content_title"])

    def test_side_by_side_panel_text_does_not_advertise_simple_viewer_actions(self) -> None:
        rendered = _bounded_panel_text("int status = 0;", None)

        self.assertIn("PseudoForge preview panel", rendered)
        self.assertNotIn("Right-click", rendered)
        self.assertNotIn("Copy all", rendered)
        self.assertNotIn("Save as", rendered)

    def test_side_by_side_summary_includes_counts_and_analysis_summary(self) -> None:
        summary = _side_by_side_summary_text(
            "int raw;\nreturn raw;",
            "// Warnings\n// Rule diagnostics\nint cleaned;",
            "PseudoForge analyzed 0x1400: 1 rename(s), 0 flow rewrite(s), 1 warning(s)",
        )

        self.assertIn("Raw lines: 2", summary)
        self.assertIn("Cleaned lines: 3", summary)
        self.assertIn("Warning markers: 1", summary)
        self.assertIn("Rule markers: 1", summary)
        self.assertIn("PseudoForge analyzed 0x1400", summary)

    def test_side_by_side_summary_pane_height_stays_compact(self) -> None:
        self.assertLessEqual(_SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT, 80)

    def test_side_by_side_search_line_matches_are_case_insensitive_by_panel(self) -> None:
        matches = _search_line_matches(
            [
                "alpha\nNeedle raw\nbeta",
                "clean\nneedle cleaned\nneedle again",
            ],
            "NEEDLE",
        )

        self.assertEqual(matches, [(0, 1), (1, 1), (1, 2)])

    def test_side_by_side_search_scroll_does_not_steal_focus(self) -> None:
        class FakeQtGui:
            class QTextCursor:
                Start = "start"
                Down = "down"

        class FakeCursor:
            def __init__(self) -> None:
                self.moves = []

            def movePosition(self, position):
                self.moves.append(position)
                return True

        class FakeEditor:
            def __init__(self) -> None:
                self.cursor = FakeCursor()
                self.centered = False

            def textCursor(self):
                return self.cursor

            def setTextCursor(self, cursor) -> None:
                self.cursor = cursor

            def centerCursor(self) -> None:
                self.centered = True

            def setFocus(self) -> None:
                raise AssertionError("search scrolling must not steal focus")

        editors = [FakeEditor(), FakeEditor()]

        _scroll_editors_to_search_match(editors, [(1, 2)], 0, FakeQtGui)

        for editor in editors:
            self.assertTrue(editor.centered)
            self.assertEqual(editor.cursor.moves, ["start", "down", "down"])

    def test_side_by_side_qt_compat_helpers_accept_modern_enums(self) -> None:
        class FakeQtCore:
            class Qt:
                class Orientation:
                    Horizontal = "horizontal"

        class FakeQtWidgets:
            class QPlainTextEdit:
                class LineWrapMode:
                    NoWrap = "no_wrap"

        class FakeQtGui:
            class QTextCursor:
                class MoveOperation:
                    Start = "start"
                    Down = "down"

            class QFontDatabase:
                class SystemFont:
                    FixedFont = "fixed_font"

                @staticmethod
                def systemFont(value):
                    return "font:%s" % value

        self.assertEqual(_qt_horizontal_orientation(FakeQtCore), "horizontal")
        self.assertEqual(_plain_text_no_wrap(FakeQtWidgets), "no_wrap")
        self.assertEqual(_text_cursor_move_operation(FakeQtGui, "Start"), "start")
        self.assertEqual(_text_cursor_move_operation(FakeQtGui, "Down"), "down")
        self.assertEqual(_fixed_width_system_font(FakeQtGui), "font:fixed_font")

    def test_side_by_side_highlight_rules_cover_cpp_roles(self) -> None:
        role_matches = {
            role
            for pattern, role in _side_by_side_highlight_rules()
            if pattern.search("#define STATUS_SUCCESS 0")
            or pattern.search("if ( NT_SUCCESS(status) )")
            or pattern.search("return 0xC0000001;")
            or pattern.search("DbgPrint(\"status\"); // comment")
        }

        self.assertIn("preprocessor", role_matches)
        self.assertIn("constant", role_matches)
        self.assertIn("keyword", role_matches)
        self.assertIn("number", role_matches)
        self.assertIn("string", role_matches)
        self.assertIn("function", role_matches)
        self.assertIn("comment", role_matches)

    def test_side_by_side_backend_treats_false_show_result_as_failure(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_load_qt_modules = ui_preview_module._load_qt_modules
        old_form_class = ui_preview_module._side_by_side_form_class
        old_warning = ui_preview_module.warning

        class FakePluginForm:
            WOPN_TAB = 1
            WOPN_RESTORE = 2

        class FakeKernwin:
            PluginForm = FakePluginForm

        class FakeForm:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def Show(self, title, options=0):
                return False

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = FakeKernwin
        ui_preview_module._load_qt_modules = lambda: object()
        ui_preview_module._side_by_side_form_class = lambda plugin_form_cls, qt_modules: FakeForm
        ui_preview_module.warning = lambda message: None
        try:
            shown = ui_preview_module._try_show_side_by_side_view("PseudoForge: fake", "raw", "clean")
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module._load_qt_modules = old_load_qt_modules
            ui_preview_module._side_by_side_form_class = old_form_class
            ui_preview_module.warning = old_warning
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertFalse(shown)
        self.assertNotIn("PseudoForge: fake", ui_preview_module._SIDE_BY_SIDE_FORMS)

    def test_side_by_side_backend_warns_when_dockable_prerequisite_is_missing(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_warning = ui_preview_module.warning
        warnings = []

        class FakeKernwin:
            pass

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = FakeKernwin
        ui_preview_module.warning = warnings.append
        ui_preview_module._SIDE_BY_SIDE_FALLBACK_WARNINGS.clear()
        try:
            shown = ui_preview_module._try_show_side_by_side_view("PseudoForge: missing form", "raw", "clean")
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module.warning = old_warning
            ui_preview_module._SIDE_BY_SIDE_FALLBACK_WARNINGS.clear()
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertFalse(shown)
        self.assertEqual(len(warnings), 1)
        self.assertIn("fell back to the simple viewer", warnings[0])
        self.assertIn("PluginForm", warnings[0])


if __name__ == "__main__":
    unittest.main()
