from __future__ import annotations

import json
from pathlib import Path
from typing import Any


AGENTIC_TASK_SUITE_SCHEMA = "pseudoforge_agentic_task_suite_v1"
AGENTIC_BENCHMARK_REPORT_SCHEMA = "pseudoforge_agentic_benchmark_report_v1"


def load_agentic_task_suite(path: str | Path) -> dict[str, Any]:
    suite_path = Path(path)
    try:
        payload = json.loads(suite_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("agentic task suite file not found: %s" % suite_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid agentic task suite JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("agentic task suite root must be an object")
    schema = str(payload.get("schema", AGENTIC_TASK_SUITE_SCHEMA) or AGENTIC_TASK_SUITE_SCHEMA)
    if schema != AGENTIC_TASK_SUITE_SCHEMA:
        raise ValueError("unsupported agentic task suite schema in %s: %s" % (suite_path, schema))
    tasks = payload.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("agentic task suite tasks must be a list in %s" % suite_path)
    return {
        "schema": AGENTIC_TASK_SUITE_SCHEMA,
        "source_path": str(suite_path),
        "tasks": [_task(item, suite_path, index) for index, item in enumerate(tasks)],
    }


def run_agentic_benchmark(task_suite: dict[str, Any], benchmark_report: dict[str, Any]) -> dict[str, Any]:
    tasks = [item for item in task_suite.get("tasks", []) or [] if isinstance(item, dict)]
    results = [_run_task(task, benchmark_report) for task in tasks]
    passed = sum(1 for item in results if item["status"] == "passed")
    precision = 0.0
    if results:
        precision = passed / len(results)
    return {
        "schema": AGENTIC_BENCHMARK_REPORT_SCHEMA,
        "task_count": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "precision": precision,
        "tasks": results,
        "agentic_tasks": [
            {
                "id": str(item.get("id", "") or ""),
                "reference": str(item.get("reference", "") or ""),
                "objective": str(item.get("objective", "") or ""),
                "score": "%.4f" % float(item.get("score", 0.0) or 0.0),
                "status": str(item.get("status", "") or ""),
            }
            for item in results
        ],
    }


def apply_agentic_report_to_corpus_evidence(
    corpus_evidence: dict[str, Any] | None,
    agentic_report: dict[str, Any],
) -> dict[str, Any]:
    result = dict(corpus_evidence or {})
    existing_total = _int(result.get("agentic_task_count"), 0)
    existing_qualified = _int(result.get("qualified_agentic_task_count"), 0)
    task_count = _int(agentic_report.get("task_count"), 0)
    passed = _int(agentic_report.get("passed"), 0)
    total = existing_total + task_count
    qualified = existing_qualified + passed
    result["agentic_task_count"] = total
    result["qualified_agentic_task_count"] = qualified
    result["agentic_task_precision"] = qualified / total if total > 0 else 0.0
    return result


def _run_task(task: dict[str, Any], benchmark_report: dict[str, Any]) -> dict[str, Any]:
    assertions = [item for item in task.get("assertions", []) or [] if isinstance(item, dict)]
    assertion_results = [_run_assertion(item, benchmark_report) for item in assertions]
    passed = all(bool(item.get("passed", False)) for item in assertion_results)
    score = 0.0
    if assertion_results:
        score = sum(1 for item in assertion_results if item["passed"]) / len(assertion_results)
    return {
        "id": str(task.get("id", "") or ""),
        "reference": str(task.get("reference", "") or ""),
        "objective": str(task.get("objective", "") or ""),
        "status": "passed" if passed else "failed",
        "score": score,
        "assertions": assertion_results,
    }


def _run_assertion(assertion: dict[str, Any], benchmark_report: dict[str, Any]) -> dict[str, Any]:
    path = str(assertion.get("path", "") or "")
    operator = str(assertion.get("operator", "") or "")
    expected = assertion.get("value")
    actual = _path_value(benchmark_report, path)
    passed = _compare(actual, operator, expected)
    return {
        "path": path,
        "operator": operator,
        "expected": expected,
        "actual": actual,
        "passed": passed,
    }


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "equals":
        return str(actual) == str(expected)
    if operator == "min":
        return _float(actual, 0.0) >= _float(expected, 0.0)
    if operator == "max":
        return _float(actual, 0.0) <= _float(expected, 0.0)
    if operator == "contains":
        if isinstance(actual, list):
            return str(expected) in {str(item) for item in actual}
        return str(expected) in str(actual)
    if operator == "true":
        return bool(actual) is True
    if operator == "false":
        return bool(actual) is False
    return False


def _path_value(payload: Any, path: str) -> Any:
    current = payload
    for part in [item for item in path.split(".") if item]:
        if isinstance(current, dict):
            current = current.get(part)
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (TypeError, ValueError, IndexError):
                return None
            continue
        return None
    return current


def _task(item: object, path: Path, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("agentic task suite tasks[%d] must be an object in %s" % (index, path))
    assertions = item.get("assertions", [])
    if not isinstance(assertions, list) or not assertions:
        raise ValueError("agentic task suite tasks[%d].assertions must be a non-empty list in %s" % (index, path))
    return {
        "id": _required_string(item, "id", path, index),
        "reference": _required_string(item, "reference", path, index),
        "objective": _required_string(item, "objective", path, index),
        "assertions": [_assertion(assertion, path, index, assertion_index) for assertion_index, assertion in enumerate(assertions)],
    }


def _assertion(item: object, path: Path, task_index: int, assertion_index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(
            "agentic task suite tasks[%d].assertions[%d] must be an object in %s"
            % (task_index, assertion_index, path)
        )
    operator = _required_string(item, "operator", path, task_index)
    if operator not in {"contains", "equals", "false", "max", "min", "true"}:
        raise ValueError(
            "agentic task suite tasks[%d].assertions[%d].operator is unsupported in %s"
            % (task_index, assertion_index, path)
        )
    return {
        "path": _required_string(item, "path", path, task_index),
        "operator": operator,
        "value": item.get("value", ""),
    }


def _required_string(payload: dict[str, Any], key: str, path: Path, index: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("agentic task suite tasks[%d].%s is required in %s" % (index, key, path))
    return value.strip()


def _int(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _float(value: object, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)
