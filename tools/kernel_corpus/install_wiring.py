from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SKILL_NAME = "kernel-corpus-analysis"
MCP_SERVER_NAME = "pseudoforge-kernel-corpus"
SOURCE_SKILL_DIR = Path(__file__).resolve().parent / "skills" / SKILL_NAME
MCP_SERVER_PATH = Path(__file__).resolve().parent / "mcp_server.py"
SCHEMA = "kernel_corpus_install_wiring_v1"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = _run_command(args)
    except (OSError, ValueError) as exc:
        print("Kernel corpus install wiring failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    if args.command == "mcp-config":
        return 0
    return 0 if payload.get("ok") else 2


def default_skill_target_root() -> Path:
    codex_home = os.environ.get("CODEX_HOME", "").strip()
    if codex_home:
        return Path(codex_home) / "skills"
    user_profile = os.environ.get("USERPROFILE", "").strip()
    if user_profile:
        return Path(user_profile) / ".codex" / "skills"
    return Path.home() / ".codex" / "skills"


def skill_paths(target_root: str | Path | None = None) -> dict[str, Path]:
    root = Path(target_root) if target_root is not None else default_skill_target_root()
    target = root / SKILL_NAME
    _assert_direct_skill_target(root, target)
    return {
        "source": SOURCE_SKILL_DIR.resolve(strict=False),
        "target_root": root.resolve(strict=False),
        "target": target.resolve(strict=False),
    }


def skill_plan(target_root: str | Path | None = None) -> dict[str, Any]:
    paths = skill_paths(target_root)
    source = paths["source"]
    target = paths["target"]
    issues: list[dict[str, str]] = []
    if not source.is_dir():
        issues.append({"code": "source_skill_missing", "path": str(source)})
    status = "ready"
    if target.exists():
        status = "target_exists"
    if issues:
        status = "error"
    return {
        "schema": SCHEMA,
        "operation": "skill-plan",
        "ok": not issues,
        "status": status,
        "apply": False,
        "skill_name": SKILL_NAME,
        "source": str(source),
        "target_root": str(paths["target_root"]),
        "target": str(target),
        "issues": issues,
        "commands": {
            "install": _command("install-skill", paths["target_root"], "--apply"),
            "update": _command("install-skill", paths["target_root"], "--replace --apply"),
            "uninstall": _command("uninstall-skill", paths["target_root"], "--apply"),
        },
    }


def install_skill(
    target_root: str | Path | None = None,
    *,
    apply: bool = False,
    replace: bool = False,
) -> dict[str, Any]:
    paths = skill_paths(target_root)
    source = paths["source"]
    target = paths["target"]
    issues: list[dict[str, str]] = []
    if not source.is_dir():
        issues.append({"code": "source_skill_missing", "path": str(source)})
    if target.exists() and not replace:
        issues.append({"code": "target_exists", "path": str(target)})
    if target.exists() and target.is_symlink():
        issues.append({"code": "target_is_symlink", "path": str(target)})
    if issues:
        return _skill_report(
            "install-skill",
            paths,
            ok=False,
            status="blocked",
            apply=apply,
            replace=replace,
            actions=[],
            issues=issues,
        )

    actions = ["copy_tree"]
    status = "would_install"
    if target.exists() and replace:
        actions.insert(0, "remove_existing_target")
        status = "would_replace"
    if apply:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            _assert_removable_skill_target(paths["target_root"], target)
            shutil.rmtree(target)
        shutil.copytree(source, target)
        status = "installed"
        if replace:
            status = "replaced"
    return _skill_report(
        "install-skill",
        paths,
        ok=True,
        status=status,
        apply=apply,
        replace=replace,
        actions=actions,
        issues=[],
    )


def uninstall_skill(
    target_root: str | Path | None = None,
    *,
    apply: bool = False,
) -> dict[str, Any]:
    paths = skill_paths(target_root)
    target = paths["target"]
    issues: list[dict[str, str]] = []
    if target.exists() and target.is_symlink():
        issues.append({"code": "target_is_symlink", "path": str(target)})
    if issues:
        return _skill_report(
            "uninstall-skill",
            paths,
            ok=False,
            status="blocked",
            apply=apply,
            replace=False,
            actions=[],
            issues=issues,
        )

    actions: list[str] = []
    status = "absent"
    if target.exists():
        actions.append("remove_target")
        status = "would_uninstall"
        if apply:
            _assert_removable_skill_target(paths["target_root"], target)
            shutil.rmtree(target)
            status = "uninstalled"
    return _skill_report(
        "uninstall-skill",
        paths,
        ok=True,
        status=status,
        apply=apply,
        replace=False,
        actions=actions,
        issues=[],
    )


def build_mcp_config(
    pack_root: str,
    *,
    python_executable: str = "python",
    server_path: str | Path | None = None,
) -> dict[str, Any]:
    server = Path(server_path) if server_path is not None else MCP_SERVER_PATH
    return {
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": python_executable,
                "args": [
                    "-B",
                    str(server.resolve(strict=False)),
                    "--pack-root",
                    str(pack_root),
                ],
            }
        }
    }


def _run_command(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "skill-plan":
        return skill_plan(args.target_root)
    if args.command == "install-skill":
        return install_skill(args.target_root, apply=args.apply, replace=args.replace)
    if args.command == "uninstall-skill":
        return uninstall_skill(args.target_root, apply=args.apply)
    if args.command == "mcp-config":
        return build_mcp_config(args.pack_root, python_executable=args.python_executable)
    raise ValueError("unsupported command: %s" % args.command)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan Kernel Corpus skill and MCP install wiring.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("skill-plan", help="Show source and target skill paths.")
    plan_parser.add_argument("--target-root", default=None, help="Skill root that will contain kernel-corpus-analysis.")

    install_parser = subparsers.add_parser("install-skill", help="Copy the skill into an explicit skill root.")
    install_parser.add_argument("--target-root", required=True, help="Skill root that will contain kernel-corpus-analysis.")
    install_parser.add_argument("--apply", action="store_true", help="Write files. Without this flag the command is dry-run only.")
    install_parser.add_argument("--replace", action="store_true", help="Replace an existing target skill directory.")

    uninstall_parser = subparsers.add_parser("uninstall-skill", help="Remove the copied skill from an explicit skill root.")
    uninstall_parser.add_argument("--target-root", required=True, help="Skill root that contains kernel-corpus-analysis.")
    uninstall_parser.add_argument("--apply", action="store_true", help="Delete files. Without this flag the command is dry-run only.")

    config_parser = subparsers.add_parser("mcp-config", help="Emit a copy-ready MCP config snippet.")
    config_parser.add_argument("--pack-root", default="<PACK_ROOT>", help="Kernel Corpus pack root for mcp_server.py.")
    config_parser.add_argument("--python", dest="python_executable", default="python", help="Python command for the MCP server.")
    return parser


def _skill_report(
    operation: str,
    paths: dict[str, Path],
    *,
    ok: bool,
    status: str,
    apply: bool,
    replace: bool,
    actions: list[str],
    issues: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "operation": operation,
        "ok": ok,
        "status": status,
        "apply": apply,
        "replace": replace,
        "skill_name": SKILL_NAME,
        "source": str(paths["source"]),
        "target_root": str(paths["target_root"]),
        "target": str(paths["target"]),
        "actions": actions,
        "issues": issues,
    }


def _assert_direct_skill_target(root: Path, target: Path) -> None:
    resolved_root = root.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    if resolved_target.name != SKILL_NAME:
        raise ValueError("unexpected skill target name: %s" % resolved_target)
    if resolved_target.parent != resolved_root:
        raise ValueError("skill target must be a direct child of target root: %s" % resolved_target)


def _assert_removable_skill_target(root: Path, target: Path) -> None:
    _assert_direct_skill_target(root, target)
    if not target.exists():
        return
    if not target.is_dir():
        raise ValueError("skill target is not a directory: %s" % target)
    if target.is_symlink():
        raise ValueError("refusing to modify symlinked skill target: %s" % target)


def _command(command: str, target_root: Path, flags: str) -> str:
    return (
        'python -B .\\tools\\kernel_corpus\\install_wiring.py %s --target-root "%s" %s'
        % (command, str(target_root), flags)
    )


if __name__ == "__main__":
    raise SystemExit(main())
