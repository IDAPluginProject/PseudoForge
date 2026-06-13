from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus.install_wiring import (
    MCP_SERVER_NAME,
    SKILL_NAME,
    build_mcp_config,
    install_skill,
    main,
    skill_plan,
    uninstall_skill,
)


class KernelCorpusInstallWiringTests(unittest.TestCase):
    def test_mcp_config_uses_explicit_pack_root_and_absolute_server_path(self) -> None:
        pack_root = r"F:\pseudoforge-corpora\ntoskrnl-26200.8457"

        config = build_mcp_config(pack_root, python_executable="python")

        server_config = config["mcpServers"][MCP_SERVER_NAME]
        args = server_config["args"]
        self.assertEqual("python", server_config["command"])
        self.assertEqual("-B", args[0])
        self.assertTrue(Path(args[1]).is_absolute())
        self.assertTrue(args[1].endswith(str(Path("tools") / "kernel_corpus" / "mcp_server.py")))
        self.assertEqual("--pack-root", args[2])
        self.assertEqual(pack_root, args[3])

        snippets = config["clientSnippets"]
        claude_command = snippets["claudeCode"]["addCommand"]
        codex_command = snippets["codex"]["addCommand"]
        codex_toml = snippets["codex"]["configToml"]
        self.assertIn("claude mcp add --transport stdio --scope local", claude_command)
        self.assertIn(MCP_SERVER_NAME, claude_command)
        self.assertIn(pack_root, claude_command)
        self.assertIn("codex mcp add", codex_command)
        self.assertIn("[mcp_servers.%s]" % MCP_SERVER_NAME, codex_toml)
        self.assertIn('command = "python"', codex_toml)
        self.assertIn(pack_root.replace("\\", "\\\\"), codex_toml)

    def test_skill_plan_reports_paths_without_creating_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_root = Path(temp_dir) / "skills"

            report = skill_plan(target_root)

            self.assertTrue(report["ok"], report["issues"])
            self.assertEqual("ready", report["status"])
            self.assertEqual(SKILL_NAME, report["skill_name"])
            self.assertFalse(target_root.exists())
            self.assertIn("install-skill", report["commands"]["install"])

    def test_install_update_and_uninstall_use_explicit_target_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_root = Path(temp_dir) / "skills"
            target = target_root / SKILL_NAME

            dry_run = install_skill(target_root)
            self.assertTrue(dry_run["ok"], dry_run["issues"])
            self.assertEqual("would_install", dry_run["status"])
            self.assertFalse(target.exists())

            install_report = install_skill(target_root, apply=True)
            self.assertTrue(install_report["ok"], install_report["issues"])
            self.assertEqual("installed", install_report["status"])
            self.assertTrue((target / "SKILL.md").is_file())

            blocked_report = install_skill(target_root, apply=True)
            self.assertFalse(blocked_report["ok"])
            self.assertEqual("target_exists", blocked_report["issues"][0]["code"])
            self.assertTrue((target / "SKILL.md").is_file())

            replace_report = install_skill(target_root, apply=True, replace=True)
            self.assertTrue(replace_report["ok"], replace_report["issues"])
            self.assertEqual("replaced", replace_report["status"])
            self.assertTrue((target / "SKILL.md").is_file())

            uninstall_report = uninstall_skill(target_root, apply=True)
            self.assertTrue(uninstall_report["ok"], uninstall_report["issues"])
            self.assertEqual("uninstalled", uninstall_report["status"])
            self.assertFalse(target.exists())

    def test_cli_mcp_config_outputs_copy_ready_json(self) -> None:
        pack_root = r"F:\pseudoforge-corpora\ntoskrnl-26200.8457"
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            code = main(["mcp-config", "--pack-root", pack_root])

        payload = json.loads(stdout.getvalue())
        server_config = payload["mcpServers"][MCP_SERVER_NAME]
        self.assertEqual(0, code)
        self.assertEqual(pack_root, server_config["args"][3])
        self.assertIn("claudeCode", payload["clientSnippets"])
        self.assertIn("configToml", payload["clientSnippets"]["codex"])


if __name__ == "__main__":
    unittest.main()
