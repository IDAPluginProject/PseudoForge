from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SCHEMA = "pseudoforge_general_benchmark_fixture_v1"


@dataclass(frozen=True)
class BenchmarkObservation:
    kind: str
    value: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BenchmarkFixture:
    name: str
    pseudocode: str
    source_path: str = ""
    ea: int = 0
    profile_context: dict[str, Any] = field(default_factory=dict)
    expected_observations: tuple[BenchmarkObservation, ...] = ()
    negative_controls: tuple[BenchmarkObservation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["expected_observations"] = [item.to_dict() for item in self.expected_observations]
        payload["negative_controls"] = [item.to_dict() for item in self.negative_controls]
        return payload


def load_benchmark_fixture(path: str | Path) -> BenchmarkFixture:
    fixture_path = Path(path)
    try:
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("benchmark fixture file not found: %s" % fixture_path) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid benchmark fixture JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("benchmark fixture root must be an object")
    return benchmark_fixture_from_dict(payload, source=str(fixture_path))


def load_benchmark_fixtures(paths: list[str | Path]) -> list[BenchmarkFixture]:
    fixtures: list[BenchmarkFixture] = []
    for path in paths:
        target = Path(path)
        if target.is_dir():
            for item in sorted(target.glob("*.json")):
                fixtures.append(load_benchmark_fixture(item))
        else:
            fixtures.append(load_benchmark_fixture(target))
    return fixtures


def benchmark_fixture_from_dict(payload: dict[str, Any], source: str = "") -> BenchmarkFixture:
    schema = str(payload.get("schema", SCHEMA) or SCHEMA)
    if schema != SCHEMA:
        raise ValueError("unsupported benchmark fixture schema in %s: %s" % (source or "fixture", schema))
    name = _required_string(payload, "name", source)
    pseudocode = _required_string(payload, "pseudocode", source)
    profile_context = payload.get("profile_context", {})
    if profile_context is None:
        profile_context = {}
    if not isinstance(profile_context, dict):
        raise ValueError("benchmark fixture profile_context must be an object in %s" % (source or name))
    return BenchmarkFixture(
        name=name,
        pseudocode=pseudocode,
        source_path=str(payload.get("source_path", "") or ""),
        ea=_int_value(payload.get("ea"), 0),
        profile_context=dict(profile_context),
        expected_observations=tuple(_observations(payload.get("expected_observations"), "expected_observations", source)),
        negative_controls=tuple(_observations(payload.get("negative_controls"), "negative_controls", source)),
    )


def _observations(value: object, field_name: str, source: str) -> list[BenchmarkObservation]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("benchmark fixture %s must be a list in %s" % (field_name, source or "fixture"))
    result: list[BenchmarkObservation] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError("benchmark fixture %s[%d] must be an object" % (field_name, index))
        result.append(
            BenchmarkObservation(
                kind=_required_string(item, "kind", "%s[%d]" % (field_name, index)),
                value=_required_string(item, "value", "%s[%d]" % (field_name, index)),
                description=str(item.get("description", "") or ""),
            )
        )
    return result


def _required_string(payload: dict[str, Any], key: str, source: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("benchmark fixture %s is required in %s" % (key, source or "fixture"))
    return value


def _int_value(value: object, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)
