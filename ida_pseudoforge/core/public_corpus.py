from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ida_pseudoforge.core.corpus_evidence import CORPUS_MANIFEST_SCHEMA


PUBLIC_CORPUS_PLAN_SCHEMA = "pseudoforge_public_corpus_plan_v1"
PUBLIC_CORPUS_BOOTSTRAP_REPORT_SCHEMA = "pseudoforge_public_corpus_bootstrap_report_v1"
PUBLIC_CORPUS_ORIGIN = "public_corpus_bootstrap"
SUPPORTED_SOURCE_KINDS = {"git", "local"}
SUPPORTED_BUILD_SYSTEMS = {"cmake"}
MANIFEST_STATUS_BY_SEED_STATUS = {
    "accepted": "accepted",
    "accepted_with_notes": "accepted_with_notes",
    "blocked": "blocked",
    "failed": "failed",
    "passed": "passed",
    "planned": "blocked",
    "rejected": "rejected",
    "validated": "validated",
}
FUNCTION_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_\s\*\(\),]*\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{"
)


def load_public_corpus_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    try:
        payload = json.loads(plan_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("public corpus plan file not found: %s" % plan_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid public corpus plan JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("public corpus plan root must be an object")
    schema = str(payload.get("schema", PUBLIC_CORPUS_PLAN_SCHEMA) or PUBLIC_CORPUS_PLAN_SCHEMA)
    if schema != PUBLIC_CORPUS_PLAN_SCHEMA:
        raise ValueError("unsupported public corpus plan schema in %s: %s" % (plan_path, schema))
    projects = payload.get("projects", [])
    if not isinstance(projects, list):
        raise ValueError("public corpus plan projects must be a list in %s" % plan_path)
    return {
        "schema": PUBLIC_CORPUS_PLAN_SCHEMA,
        "source_path": str(plan_path),
        "name": str(payload.get("name", "") or "").strip(),
        "projects": [_project(item, plan_path, index) for index, item in enumerate(projects)],
    }


def bootstrap_public_corpus(
    plan: dict[str, Any],
    out_dir: str | Path,
    *,
    fetch: bool = True,
    build: bool = False,
    candidate_limit: int = 200,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    output_root = Path(out_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    source_root = output_root / "sources"
    build_root = output_root / "build"
    source_root.mkdir(parents=True, exist_ok=True)
    build_root.mkdir(parents=True, exist_ok=True)
    projects = [
        _bootstrap_project(
            project,
            source_root,
            build_root,
            fetch=fetch,
            build=build,
            candidate_limit=candidate_limit,
            timeout_seconds=timeout_seconds,
        )
        for project in plan.get("projects", []) or []
        if isinstance(project, dict)
    ]
    return {
        "schema": PUBLIC_CORPUS_BOOTSTRAP_REPORT_SCHEMA,
        "plan_source_path": str(plan.get("source_path", "") or ""),
        "workspace_root": str(output_root),
        "project_count": len(projects),
        "source_ready_count": sum(1 for item in projects if item.get("source_status") == "present"),
        "build_ready_count": sum(1 for item in projects if _project_has_built_artifact(item)),
        "candidate_function_count": sum(_int(item.get("candidate_function_count"), 0) for item in projects),
        "projects": projects,
    }


def write_public_corpus_outputs(report: dict[str, Any], out_dir: str | Path) -> dict[str, Path]:
    output_root = Path(out_dir)
    report_dir = output_root / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "public-corpus-bootstrap-report.json"
    manifest_path = report_dir / "pseudoforge-public-corpus-manifest.json"
    summary_path = report_dir / "public-corpus-summary.json"
    manifest = corpus_manifest_from_public_bootstrap_report(report)
    summary = summarize_public_corpus_report(report, manifest)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "report": report_path,
        "manifest": manifest_path,
        "summary": summary_path,
    }


def load_public_corpus_bootstrap_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("public corpus bootstrap report file not found: %s" % report_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid public corpus bootstrap report JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("public corpus bootstrap report root must be an object")
    schema = str(payload.get("schema", PUBLIC_CORPUS_BOOTSTRAP_REPORT_SCHEMA) or "")
    if schema != PUBLIC_CORPUS_BOOTSTRAP_REPORT_SCHEMA:
        raise ValueError("unsupported public corpus bootstrap report schema in %s: %s" % (report_path, schema))
    return payload


def corpus_manifest_from_public_bootstrap_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": CORPUS_MANIFEST_SCHEMA,
        "corpora": [
            _corpus_from_project(project)
            for project in report.get("projects", []) or []
            if isinstance(project, dict)
        ],
    }


def summarize_public_corpus_report(report: dict[str, Any], manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    projects = [item for item in report.get("projects", []) or [] if isinstance(item, dict)]
    if manifest is None:
        manifest = corpus_manifest_from_public_bootstrap_report(report)
    corpora = [item for item in manifest.get("corpora", []) or [] if isinstance(item, dict)]
    return {
        "schema": "pseudoforge_public_corpus_summary_v1",
        "project_count": len(projects),
        "source_ready_count": sum(1 for item in projects if item.get("source_status") == "present"),
        "build_ready_count": sum(1 for item in projects if _project_has_built_artifact(item)),
        "claim_eligible_corpus_count": sum(1 for item in corpora if bool(item.get("claim_eligible", False))),
        "candidate_function_count": sum(_int(item.get("candidate_function_count"), 0) for item in projects),
        "semantic_seed_count": sum(len(item.get("semantic_seeds", []) or []) for item in projects),
        "blocked_projects": [
            {
                "name": str(item.get("name", "") or ""),
                "source_status": str(item.get("source_status", "") or ""),
                "blockers": item.get("blockers", []) or [],
            }
            for item in projects
            if item.get("source_status") != "present" or item.get("blockers")
        ],
    }


def _project(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("public corpus plan projects[%d] must be an object in %s" % (index, path))
    source = _source(item.get("source"), path, index)
    return {
        "name": _required_string(item, "name", path, index),
        "plan_source_path": str(path),
        "target_family": _required_string(item, "target_family", path, index),
        "license": _required_string(item, "license", path, index),
        "source": source,
        "source_globs": _string_list(item.get("source_globs"), "source_globs", path, index)
        or ["**/*.c", "**/*.cc", "**/*.cpp", "**/*.h", "**/*.hpp"],
        "build_recipes": [
            _build_recipe(recipe, path, index, recipe_index)
            for recipe_index, recipe in enumerate(_list(item.get("build_recipes"), "build_recipes", path, index))
        ],
        "semantic_seeds": [
            _semantic_seed(seed, path, index, seed_index)
            for seed_index, seed in enumerate(_list(item.get("semantic_seeds"), "semantic_seeds", path, index))
        ],
    }


def _source(item: object, path: Path, index: int) -> dict[str, str]:
    if not isinstance(item, dict):
        raise ValueError("public corpus plan projects[%d].source must be an object in %s" % (index, path))
    kind = _required_string(item, "kind", path, index)
    if kind not in SUPPORTED_SOURCE_KINDS:
        raise ValueError("public corpus plan projects[%d].source.kind is unsupported in %s: %s" % (index, path, kind))
    if kind == "git":
        repo_url = _required_string(item, "repo_url", path, index)
        _validate_http_git_url(repo_url, path, index)
        return {
            "kind": kind,
            "repo_url": repo_url,
            "ref": _required_string(item, "ref", path, index),
            "commit": _required_string(item, "commit", path, index),
        }
    return {
        "kind": kind,
        "path": _required_string(item, "path", path, index),
    }


def _build_recipe(item: object, path: Path, project_index: int, recipe_index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(
            "public corpus plan projects[%d].build_recipes[%d] must be an object in %s"
            % (project_index, recipe_index, path)
        )
    system = _required_nested_string(item, "system", path, project_index, "build_recipes", recipe_index)
    if system not in SUPPORTED_BUILD_SYSTEMS:
        raise ValueError(
            "public corpus plan projects[%d].build_recipes[%d].system is unsupported in %s: %s"
            % (project_index, recipe_index, path, system)
        )
    return {
        "id": _required_nested_string(item, "id", path, project_index, "build_recipes", recipe_index),
        "system": system,
        "enabled": bool(item.get("enabled", True)),
        "configure_args": _string_list(
            item.get("configure_args"),
            "build_recipes[%d].configure_args" % recipe_index,
            path,
            project_index,
        ),
        "build_args": _string_list(
            item.get("build_args"),
            "build_recipes[%d].build_args" % recipe_index,
            path,
            project_index,
        ),
        "artifact_globs": _string_list(
            item.get("artifact_globs"),
            "build_recipes[%d].artifact_globs" % recipe_index,
            path,
            project_index,
        ),
    }


def _semantic_seed(item: object, path: Path, project_index: int, seed_index: int) -> dict[str, str]:
    if not isinstance(item, dict):
        raise ValueError(
            "public corpus plan projects[%d].semantic_seeds[%d] must be an object in %s"
            % (project_index, seed_index, path)
        )
    status = str(item.get("status", "planned") or "planned").strip()
    if status not in MANIFEST_STATUS_BY_SEED_STATUS:
        raise ValueError(
            "public corpus plan projects[%d].semantic_seeds[%d].status is unsupported in %s: %s"
            % (project_index, seed_index, path, status)
        )
    return {
        "id": _required_nested_string(item, "id", path, project_index, "semantic_seeds", seed_index),
        "function": _required_nested_string(item, "function", path, project_index, "semantic_seeds", seed_index),
        "semantic_kind": _required_nested_string(item, "semantic_kind", path, project_index, "semantic_seeds", seed_index),
        "oracle": _required_nested_string(item, "oracle", path, project_index, "semantic_seeds", seed_index),
        "validation": _required_nested_string(item, "validation", path, project_index, "semantic_seeds", seed_index),
        "status": status,
    }


def _bootstrap_project(
    project: dict[str, Any],
    source_workspace: Path,
    build_workspace: Path,
    *,
    fetch: bool,
    build: bool,
    candidate_limit: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    name = str(project.get("name", "") or "")
    source_info = project.get("source", {}) if isinstance(project.get("source"), dict) else {}
    blockers: list[dict[str, str]] = []
    source_path, source_status, source_blocker = _prepare_source(project, source_workspace, fetch, timeout_seconds)
    if source_blocker:
        blockers.append(source_blocker)
    source_hash = ""
    source_file_count = 0
    candidates: list[dict[str, Any]] = []
    if source_status == "present" and source_path is not None:
        source_files = _collect_source_files(source_path, project.get("source_globs", []) or [])
        source_file_count = len(source_files)
        source_hash = _hash_source_tree(source_path, source_files)
        candidates = _function_candidates(source_path, source_files, candidate_limit)
    build_results = [
        _run_build_recipe(name, source_path, recipe, build_workspace, build, timeout_seconds)
        for recipe in project.get("build_recipes", []) or []
        if isinstance(recipe, dict)
    ]
    for result in build_results:
        if isinstance(result, dict) and result.get("status") in {"blocked", "failed"}:
            blockers.append(
                {
                    "stage": "build",
                    "code": str(result.get("status", "") or ""),
                    "detail": str(result.get("message", "") or ""),
                }
            )
    actual_commit = _git_head(source_path) if source_path is not None and source_info.get("kind") == "git" else ""
    return {
        "name": name,
        "target_family": str(project.get("target_family", "") or ""),
        "license": str(project.get("license", "") or ""),
        "source": source_info,
        "source_path": str(source_path) if source_path is not None else "",
        "source_status": source_status,
        "source_hash": source_hash,
        "source_file_count": source_file_count,
        "actual_commit": actual_commit,
        "candidate_function_count": len(candidates),
        "function_candidates": candidates,
        "semantic_seeds": project.get("semantic_seeds", []) or [],
        "build_results": build_results,
        "blockers": blockers,
    }


def _prepare_source(
    project: dict[str, Any],
    source_workspace: Path,
    fetch: bool,
    timeout_seconds: int,
) -> tuple[Path | None, str, dict[str, str] | None]:
    source = project.get("source", {}) if isinstance(project.get("source"), dict) else {}
    kind = str(source.get("kind", "") or "")
    if kind == "local":
        path = Path(str(source.get("path", "") or "")).expanduser()
        if not path.is_absolute():
            plan_source = Path(str(project.get("plan_source_path", "") or ""))
            base = plan_source.parent if plan_source else Path.cwd()
            path = base / path
        if not path.is_dir():
            return None, "blocked", {"stage": "source", "code": "local_source_missing", "detail": str(path)}
        return path.resolve(), "present", None
    target = source_workspace / str(project.get("name", "") or "project")
    expected_commit = str(source.get("commit", "") or "")
    if not fetch:
        if not (target / ".git").is_dir():
            return target, "blocked", {"stage": "source", "code": "source_missing_no_fetch", "detail": str(target)}
        checkout_result = _git_checkout(target, expected_commit, timeout_seconds)
        if checkout_result:
            return target, "blocked", checkout_result
        return target, "present", None
    if not (target / ".git").is_dir():
        if target.exists() and any(target.iterdir()):
            return target, "blocked", {"stage": "source", "code": "source_path_not_git", "detail": str(target)}
        result = _run(["git", "clone", "--no-checkout", str(source.get("repo_url", "") or ""), str(target)], timeout_seconds)
        if result["returncode"] != 0:
            return target, "blocked", {"stage": "source", "code": "git_clone_failed", "detail": result["stderr_tail"]}
    fetch_result = _run(["git", "-C", str(target), "fetch", "--tags", "--prune", "origin"], timeout_seconds)
    if fetch_result["returncode"] != 0:
        return target, "blocked", {"stage": "source", "code": "git_fetch_failed", "detail": fetch_result["stderr_tail"]}
    checkout_result = _git_checkout(target, expected_commit, timeout_seconds)
    if checkout_result:
        return target, "blocked", checkout_result
    return target, "present", None


def _git_checkout(target: Path, expected_commit: str, timeout_seconds: int) -> dict[str, str] | None:
    checkout = _run(["git", "-C", str(target), "checkout", "--detach", expected_commit], timeout_seconds)
    if checkout["returncode"] != 0:
        return {"stage": "source", "code": "git_checkout_failed", "detail": checkout["stderr_tail"]}
    actual = _git_head(target)
    if expected_commit and actual.lower() != expected_commit.lower():
        return {
            "stage": "source",
            "code": "git_commit_mismatch",
            "detail": "expected %s got %s" % (expected_commit, actual),
        }
    return None


def _git_head(target: Path | None) -> str:
    if target is None:
        return ""
    result = _run(["git", "-C", str(target), "rev-parse", "HEAD"], 30)
    if result["returncode"] != 0:
        return ""
    return str(result["stdout_tail"]).strip().splitlines()[-1].strip()


def _run_build_recipe(
    project_name: str,
    source_path: Path | None,
    recipe: dict[str, Any],
    build_workspace: Path,
    build: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    recipe_id = str(recipe.get("id", "") or "default")
    build_path = build_workspace / project_name / recipe_id
    if not bool(recipe.get("enabled", True)):
        return {
            "id": recipe_id,
            "system": str(recipe.get("system", "") or ""),
            "status": "skipped",
            "message": "recipe disabled",
            "build_path": str(build_path),
            "artifacts": [],
        }
    if source_path is None:
        return {
            "id": recipe_id,
            "system": str(recipe.get("system", "") or ""),
            "status": "blocked",
            "message": "source not available",
            "build_path": str(build_path),
            "artifacts": [],
        }
    if not build:
        return {
            "id": recipe_id,
            "system": str(recipe.get("system", "") or ""),
            "status": "not_run",
            "message": "build disabled",
            "build_path": str(build_path),
            "artifacts": [],
        }
    build_path.mkdir(parents=True, exist_ok=True)
    if str(recipe.get("system", "") or "") != "cmake":
        return {
            "id": recipe_id,
            "system": str(recipe.get("system", "") or ""),
            "status": "blocked",
            "message": "unsupported build system",
            "build_path": str(build_path),
            "artifacts": [],
        }
    configure_cmd = ["cmake", "-S", str(source_path), "-B", str(build_path)]
    configure_cmd.extend(str(item) for item in recipe.get("configure_args", []) or [])
    configure = _run(configure_cmd, timeout_seconds)
    if configure["returncode"] != 0:
        return {
            "id": recipe_id,
            "system": "cmake",
            "status": "failed",
            "message": "cmake configure failed: %s" % configure["stderr_tail"],
            "build_path": str(build_path),
            "artifacts": [],
        }
    build_cmd = ["cmake", "--build", str(build_path)]
    build_cmd.extend(str(item) for item in recipe.get("build_args", []) or [])
    built = _run(build_cmd, timeout_seconds)
    if built["returncode"] != 0:
        return {
            "id": recipe_id,
            "system": "cmake",
            "status": "failed",
            "message": "cmake build failed: %s" % built["stderr_tail"],
            "build_path": str(build_path),
            "artifacts": [],
        }
    artifacts = _collect_artifacts(build_path, recipe.get("artifact_globs", []) or [])
    status = "passed" if artifacts else "blocked"
    message = "build passed" if artifacts else "build passed but no configured artifacts matched"
    return {
        "id": recipe_id,
        "system": "cmake",
        "status": status,
        "message": message,
        "build_path": str(build_path),
        "artifacts": artifacts,
    }


def _collect_artifacts(build_path: Path, artifact_globs: list[str]) -> list[dict[str, Any]]:
    results: list[Path] = []
    for pattern in artifact_globs:
        results.extend(path for path in build_path.glob(pattern) if path.is_file())
    deduped = sorted({path.resolve() for path in results})
    return [
        {
            "path": str(path),
            "sha256": _hash_file(path),
            "size": path.stat().st_size,
        }
        for path in deduped
    ]


def _collect_source_files(source_path: Path, source_globs: list[str]) -> list[Path]:
    files: set[Path] = set()
    for pattern in source_globs:
        files.update(path for path in source_path.glob(pattern) if path.is_file() and not _is_under_git(path))
    return sorted(files)


def _function_candidates(source_path: Path, files: list[Path], limit: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, 1):
            match = FUNCTION_RE.match(line)
            if not match:
                continue
            name = match.group("name")
            if name in {"if", "for", "while", "switch", "return"}:
                continue
            rel_path = _relative_posix(source_path, file_path)
            key = (rel_path, name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "name": name,
                    "source_path": rel_path,
                    "line": line_number,
                }
            )
            if len(candidates) >= limit:
                return candidates
    return candidates


def _hash_source_tree(source_path: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    for file_path in files:
        rel = _relative_posix(source_path, file_path)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _corpus_from_project(project: dict[str, Any]) -> dict[str, Any]:
    build_ready = _project_has_built_artifact(project)
    candidate_count = _int(project.get("candidate_function_count"), 0)
    source_reference = _source_reference(project)
    semantic_pairs = _semantic_pairs_from_project(project, build_ready)
    real_replay_targets = _real_replay_targets_from_project(project, build_ready)
    return {
        "name": "public_%s" % str(project.get("name", "") or "project"),
        "target_family": str(project.get("target_family", "") or ""),
        "origin": PUBLIC_CORPUS_ORIGIN,
        "claim_eligible": False,
        "source_reference": source_reference,
        "function_count": candidate_count if build_ready else 0,
        "ground_truth_pair_count": 0,
        "ground_truth_pairs": [],
        "ir_evidence_function_count": 0,
        "ir_total_function_count": candidate_count if build_ready else 0,
        "cross_function_contract_count": 0,
        "cross_function_contracts": [],
        "external_baselines": [],
        "analyst_audit_count": 0,
        "semantic_ground_truth_pair_count": len(semantic_pairs),
        "semantic_ground_truth_pairs": semantic_pairs,
        "real_replay_target_count": len(real_replay_targets),
        "real_replay_targets": real_replay_targets,
        "multi_ir_record_count": 0,
        "multi_ir_records": [],
        "dataflow_contract_count": 0,
        "dataflow_contracts": [],
        "baseline_comparison_count": 0,
        "baseline_comparisons": [],
        "agentic_task_count": 0,
        "agentic_tasks": [],
    }


def _semantic_pairs_from_project(project: dict[str, Any], build_ready: bool) -> list[dict[str, str]]:
    source_path = str(project.get("source_path", "") or "")
    binary_path = _first_artifact_path(project)
    result: list[dict[str, str]] = []
    for seed in project.get("semantic_seeds", []) or []:
        if not isinstance(seed, dict):
            continue
        seed_status = str(seed.get("status", "planned") or "planned")
        status = MANIFEST_STATUS_BY_SEED_STATUS.get(seed_status, "blocked")
        if not build_ready:
            status = "blocked"
        result.append(
            {
                "id": str(seed.get("id", "") or ""),
                "reference": "%s/semantic/%s" % (_source_reference(project), str(seed.get("id", "") or "")),
                "source_path": source_path,
                "binary_path": binary_path,
                "function": str(seed.get("function", "") or ""),
                "semantic_kind": str(seed.get("semantic_kind", "") or ""),
                "oracle": str(seed.get("oracle", "") or ""),
                "validation": str(seed.get("validation", "") or ""),
                "status": status,
            }
        )
    return result


def _real_replay_targets_from_project(project: dict[str, Any], build_ready: bool) -> list[dict[str, Any]]:
    if not build_ready:
        return []
    return [
        {
            "family": str(project.get("target_family", "") or ""),
            "tool": "ida",
            "reference": "%s/ida-replay" % _source_reference(project),
            "function_count": max(1, _int(project.get("candidate_function_count"), 0)),
            "status": "blocked",
        }
    ]


def _source_reference(project: dict[str, Any]) -> str:
    source = project.get("source", {}) if isinstance(project.get("source"), dict) else {}
    name = str(project.get("name", "") or "project")
    source_hash = str(project.get("source_hash", "") or "")
    if source.get("kind") == "git":
        commit = str(project.get("actual_commit", "") or source.get("commit", "") or "")
        return "public-corpus://git/%s@%s#%s" % (name, commit, source_hash)
    return "public-corpus://local/%s#%s" % (name, source_hash)


def _project_has_built_artifact(project: dict[str, Any]) -> bool:
    return bool(_first_artifact_path(project))


def _first_artifact_path(project: dict[str, Any]) -> str:
    for result in project.get("build_results", []) or []:
        if not isinstance(result, dict):
            continue
        if result.get("status") != "passed":
            continue
        for artifact in result.get("artifacts", []) or []:
            if isinstance(artifact, dict) and str(artifact.get("path", "") or ""):
                return str(artifact.get("path", "") or "")
    return ""


def _run(args: list[str], timeout_seconds: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        return {
            "returncode": 127,
            "stdout_tail": "",
            "stderr_tail": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout_tail": _tail(exc.stdout or ""),
            "stderr_tail": "timeout after %d seconds: %s" % (timeout_seconds, _tail(exc.stderr or "")),
        }
    return {
        "returncode": completed.returncode,
        "stdout_tail": _tail(completed.stdout),
        "stderr_tail": _tail(completed.stderr),
    }


def _tail(value: str, limit: int = 2000) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def _validate_http_git_url(value: str, path: Path, index: int) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("public corpus plan projects[%d].source.repo_url must be an http(s) URL in %s" % (index, path))


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("public corpus plan projects[%d].%s is required in %s" % (index, key, path))
    return value.strip()


def _required_nested_string(
    payload: dict[str, Any],
    key: str,
    path: Path,
    project_index: int,
    list_name: str,
    item_index: int,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "public corpus plan projects[%d].%s[%d].%s is required in %s"
            % (project_index, list_name, item_index, key, path)
        )
    return value.strip()


def _list(value: object, field_name: str, path: Path, index: int) -> list[object]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("public corpus plan projects[%d].%s must be a list in %s" % (index, field_name, path))
    return value


def _string_list(value: object, field_name: str, path: Path, index: int) -> list[str]:
    values = _list(value, field_name, path, index)
    result: list[str] = []
    for item_index, item in enumerate(values):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                "public corpus plan projects[%d].%s[%d] must be a non-empty string in %s"
                % (index, field_name, item_index, path)
            )
        result.append(item.strip())
    return result


def _is_under_git(path: Path) -> bool:
    return any(part == ".git" for part in path.parts)


def _relative_posix(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)
