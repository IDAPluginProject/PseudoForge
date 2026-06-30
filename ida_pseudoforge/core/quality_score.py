from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


GENERIC_QUALITY_BUCKET = "generic_core"
WINDOWS_KERNEL_QUALITY_BUCKET = "windows_kernel"
RESERVED_DOMAIN_QUALITY_BUCKETS = (
    "win_user_pe",
    "linux_elf_user",
    "cxx_runtime",
    "firmware_uefi",
)
QUALITY_BUCKET_ORDER = (
    GENERIC_QUALITY_BUCKET,
    WINDOWS_KERNEL_QUALITY_BUCKET,
    *RESERVED_DOMAIN_QUALITY_BUCKETS,
)


@dataclass(frozen=True)
class QualityFinding:
    category: str
    severity: str
    count: int
    points: int
    message: str
    examples: tuple[str, ...] = ()
    bucket: str = GENERIC_QUALITY_BUCKET


@dataclass(frozen=True)
class QualityScore:
    score: int
    opportunity: int
    reward: int
    findings: tuple[QualityFinding, ...]
    rewards: tuple[QualityFinding, ...]
    quality_buckets: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class QualityFunctionRecord:
    file: str
    ea: str
    name: str
    score: QualityScore


@dataclass(frozen=True)
class _PenaltyRule:
    category: str
    severity: str
    pattern: re.Pattern[str]
    points_per_match: int
    point_cap: int
    message: str
    bucket: str = GENERIC_QUALITY_BUCKET


@dataclass(frozen=True)
class _RewardRule:
    category: str
    pattern: re.Pattern[str]
    points_per_match: int
    point_cap: int
    message: str
    bucket: str = GENERIC_QUALITY_BUCKET


_PENALTY_RULES: tuple[_PenaltyRule, ...] = (
    _PenaltyRule(
        "raw_argument_name",
        "high",
        re.compile(r"\ba\d+\b"),
        5,
        25,
        "Raw Hex-Rays argument names remain in the cleaned output.",
    ),
    _PenaltyRule(
        "generic_argument_name",
        "medium",
        re.compile(r"\bargument\d+\b"),
        4,
        20,
        "Generic fallback argument names remain instead of role-backed names.",
    ),
    _PenaltyRule(
        "compiler_local_name",
        "medium",
        re.compile(r"\bv\d+\b"),
        2,
        24,
        "Compiler-generated local names remain and need dataflow-backed recovery.",
    ),
    _PenaltyRule(
        "raw_pointer_offset",
        "high",
        re.compile(r"\*\s*\([^;\n]{1,160}\)\s*\([^;\n]{1,160}\+\s*(?:0x[0-9A-Fa-f]+|\d+)\s*\)"),
        5,
        30,
        "Raw pointer-offset field access remains instead of trusted structure fields.",
    ),
    _PenaltyRule(
        "typed_index_offset",
        "high",
        re.compile(r"\*\s*\(\s*\([^;\n)]*\*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*\d+\s*\)"),
        5,
        30,
        "Typed array-style offset access remains and may need profile/layout recovery.",
    ),
    _PenaltyRule(
        "decompiler_global_name",
        "medium",
        re.compile(r"\b(?:qword|dword|word|byte|xmmword|off|unk)_[0-9A-Fa-f]+\b"),
        3,
        24,
        "Decompiler-generated global names remain.",
    ),
    _PenaltyRule(
        "unresolved_width_type",
        "low",
        re.compile(r"\b(?:__int64|__int128|_QWORD|_DWORD|_WORD|_BYTE|_OWORD)\b"),
        1,
        18,
        "Width-only decompiler types remain where richer profile types may be possible.",
    ),
    _PenaltyRule(
        "byte_slice_macro",
        "medium",
        re.compile(r"\b(?:LOBYTE|HIBYTE|LOWORD|HIWORD|LODWORD|HIDWORD|BYTE\d+|WORD\d+|DWORD\d+|QWORD\d+)\b"),
        3,
        18,
        "Byte/word slice macros remain and may indicate scalar or flag recovery gaps.",
    ),
    _PenaltyRule(
        "unresolved_status_literal",
        "medium",
        re.compile(r"\b0xC[0-9A-Fa-f]{7}(?:u?i64|LL|u)?\b"),
        3,
        18,
        "NTSTATUS-like failure literals remain unresolved.",
        WINDOWS_KERNEL_QUALITY_BUCKET,
    ),
    _PenaltyRule(
        "unresolved_helper_call",
        "low",
        re.compile(r"\bsub_[0-9A-Fa-f]+\s*\("),
        2,
        20,
        "Unresolved helper calls remain; role propagation or wrapper profiling may help.",
    ),
    _PenaltyRule(
        "label_or_goto_artifact",
        "medium",
        re.compile(r"\b(?:goto\s+LABEL_|LABEL_\d+)\b"),
        3,
        24,
        "Raw label/goto artifacts remain in control-flow output.",
    ),
)

_REWARD_RULES: tuple[_RewardRule, ...] = (
    _RewardRule(
        "trusted_kernel_type",
        re.compile(
            r"\b(?:NTSTATUS|PIRP|PDEVICE_OBJECT|PDRIVER_OBJECT|DRIVER_OBJECT|"
            r"POB_PRE_OPERATION_INFORMATION|PUNICODE_STRING|UNICODE_STRING|"
            r"PIO_STACK_LOCATION|OBJECT_ATTRIBUTES|IO_STATUS_BLOCK|PEPROCESS|PMDL)\b"
        ),
        2,
        16,
        "Trusted kernel-oriented types are present.",
        WINDOWS_KERNEL_QUALITY_BUCKET,
    ),
    _RewardRule(
        "symbolic_status",
        re.compile(r"\bSTATUS_[A-Z0-9_]+\b"),
        2,
        16,
        "Symbolic NTSTATUS names are present.",
        WINDOWS_KERNEL_QUALITY_BUCKET,
    ),
    _RewardRule(
        "symbolic_status_check",
        re.compile(r"\bNT_(?:SUCCESS|ERROR|WARNING|INFORMATION)\s*\("),
        3,
        12,
        "Symbolic NTSTATUS predicates are present.",
        WINDOWS_KERNEL_QUALITY_BUCKET,
    ),
    _RewardRule(
        "profile_field_access",
        re.compile(r"->[A-Za-z_][A-Za-z0-9_]*\b"),
        1,
        20,
        "Structured field access is present.",
    ),
    _RewardRule(
        "symbolic_kernel_macro",
        re.compile(r"\b(?:CTL_CODE|POOL_TAG|CONTAINING_RECORD|NtCurrentProcess|NtCurrentThread)\b"),
        3,
        15,
        "Symbolic kernel macros or pseudo intrinsics are present.",
        WINDOWS_KERNEL_QUALITY_BUCKET,
    ),
    _RewardRule(
        "side_effect_preserved_void_call",
        re.compile(r"\(void\)\s*[A-Za-z_][A-Za-z0-9_]*\s*\("),
        2,
        10,
        "Side-effecting ignored-return calls are preserved explicitly.",
    ),
)


def score_pseudocode_quality(cleaned_text: str, raw_text: str = "") -> QualityScore:
    scoring_text = _strip_generated_context(cleaned_text)
    raw_scoring_text = _strip_generated_context(raw_text) if raw_text else ""
    findings = tuple(_score_penalties(scoring_text))
    rewards = tuple(_score_rewards(scoring_text, raw_scoring_text))
    opportunity = sum(item.points for item in findings)
    reward = min(sum(item.points for item in rewards), 25)
    score = max(0, min(100, 100 - opportunity + reward))
    return QualityScore(
        score=score,
        opportunity=opportunity,
        reward=reward,
        findings=findings,
        rewards=rewards,
        quality_buckets=_quality_bucket_totals(findings, rewards),
    )


def score_compare_directory(
    compare_dir: Path,
    report_path: Path | None = None,
    top: int = 15,
) -> dict[str, Any]:
    compare_dir = Path(compare_dir)
    cleaned_dir = compare_dir / "cleaned"
    raw_dir = compare_dir / "raw"
    metadata = _load_report_metadata(report_path) if report_path else {}
    records: list[QualityFunctionRecord] = []

    for cleaned_path in sorted(cleaned_dir.glob("*.cpp")):
        raw_path = raw_dir / cleaned_path.name
        cleaned_text = cleaned_path.read_text(encoding="utf-8", errors="replace")
        raw_text = raw_path.read_text(encoding="utf-8", errors="replace") if raw_path.exists() else ""
        item_metadata = metadata.get(str(cleaned_path)) or metadata.get(cleaned_path.name) or {}
        score = score_pseudocode_quality(cleaned_text, raw_text)
        records.append(
            QualityFunctionRecord(
                file=cleaned_path.name,
                ea=str(item_metadata.get("ea", "")),
                name=str(item_metadata.get("name", _name_from_file(cleaned_path))),
                score=score,
            )
        )

    return quality_records_to_summary(records, str(compare_dir), str(report_path or ""), top=top)


def quality_records_to_summary(
    records: Iterable[QualityFunctionRecord],
    compare_dir: str = "",
    report_path: str = "",
    top: int = 15,
) -> dict[str, Any]:
    record_list = list(records)
    finding_totals: Counter[str] = Counter()
    finding_points: Counter[str] = Counter()
    reward_totals: Counter[str] = Counter()
    reward_points: Counter[str] = Counter()

    functions: list[dict[str, Any]] = []
    for record in record_list:
        score = record.score
        function_entry = {
            "file": record.file,
            "ea": record.ea,
            "name": record.name,
            "score": score.score,
            "opportunity": score.opportunity,
            "reward": score.reward,
            "findings": [quality_finding_to_dict(item) for item in score.findings],
            "rewards": [quality_finding_to_dict(item) for item in score.rewards],
            "quality_buckets": score.quality_buckets,
            "domain_buckets": _domain_bucket_view(score.quality_buckets),
        }
        functions.append(function_entry)
        for finding in score.findings:
            finding_totals[finding.category] += finding.count
            finding_points[finding.category] += finding.points
        for reward in score.rewards:
            reward_totals[reward.category] += reward.count
            reward_points[reward.category] += reward.points

    functions.sort(key=lambda item: (-int(item["opportunity"]), int(item["score"]), item["file"]))
    count = len(functions)
    average_score = round(sum(int(item["score"]) for item in functions) / count, 2) if count else 0.0
    average_opportunity = round(sum(int(item["opportunity"]) for item in functions) / count, 2) if count else 0.0
    average_reward = round(sum(int(item["reward"]) for item in functions) / count, 2) if count else 0.0
    quality_buckets = _aggregate_quality_buckets(record.score.quality_buckets for record in record_list)

    return {
        "schema": "pseudoforge_quality_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "compare_dir": compare_dir,
        "report_path": report_path,
        "function_count": count,
        "average_score": average_score,
        "average_opportunity": average_opportunity,
        "average_reward": average_reward,
        "min_score": min((int(item["score"]) for item in functions), default=0),
        "max_score": max((int(item["score"]) for item in functions), default=0),
        "finding_totals": _counter_summary(finding_totals, finding_points),
        "reward_totals": _counter_summary(reward_totals, reward_points),
        "quality_buckets": quality_buckets,
        "generic_bucket": quality_buckets.get(GENERIC_QUALITY_BUCKET, {}),
        "domain_buckets": _domain_bucket_view(quality_buckets),
        "worst_functions": functions[:top],
        "functions": functions,
    }


def quality_finding_to_dict(finding: QualityFinding) -> dict[str, Any]:
    return {
        "category": finding.category,
        "severity": finding.severity,
        "count": finding.count,
        "points": finding.points,
        "message": finding.message,
        "examples": list(finding.examples),
        "bucket": finding.bucket,
    }


def _quality_bucket_totals(
    findings: Iterable[QualityFinding],
    rewards: Iterable[QualityFinding],
) -> dict[str, dict[str, Any]]:
    buckets = {bucket: _empty_quality_bucket(bucket) for bucket in QUALITY_BUCKET_ORDER}
    for finding in findings:
        item = _ensure_quality_bucket(buckets, finding.bucket)
        item["opportunity"] += int(finding.points)
        item["finding_count"] += int(finding.count)
    for reward in rewards:
        item = _ensure_quality_bucket(buckets, reward.bucket)
        item["reward"] += int(reward.points)
        item["reward_count"] += int(reward.count)
    return _ordered_quality_buckets(buckets)


def _aggregate_quality_buckets(
    bucket_maps: Iterable[dict[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    buckets = {bucket: _empty_quality_bucket(bucket) for bucket in QUALITY_BUCKET_ORDER}
    for bucket_map in bucket_maps:
        if not isinstance(bucket_map, dict):
            continue
        for bucket, source in bucket_map.items():
            if not isinstance(source, dict):
                continue
            item = _ensure_quality_bucket(buckets, str(bucket or GENERIC_QUALITY_BUCKET))
            for field in ("opportunity", "reward", "finding_count", "reward_count"):
                item[field] += _safe_int(source.get(field, 0))
    return _ordered_quality_buckets(buckets)


def _domain_bucket_view(bucket_map: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        bucket: dict(item)
        for bucket, item in _ordered_quality_buckets(bucket_map).items()
        if bucket != GENERIC_QUALITY_BUCKET
    }


def _empty_quality_bucket(bucket: str) -> dict[str, Any]:
    bucket_id = str(bucket or GENERIC_QUALITY_BUCKET)
    return {
        "bucket": bucket_id,
        "bucket_type": "generic" if bucket_id == GENERIC_QUALITY_BUCKET else "domain",
        "reserved": bucket_id in RESERVED_DOMAIN_QUALITY_BUCKETS,
        "opportunity": 0,
        "reward": 0,
        "finding_count": 0,
        "reward_count": 0,
    }


def _ensure_quality_bucket(
    buckets: dict[str, dict[str, Any]],
    bucket: str,
) -> dict[str, Any]:
    bucket_id = str(bucket or GENERIC_QUALITY_BUCKET)
    if bucket_id not in buckets:
        buckets[bucket_id] = _empty_quality_bucket(bucket_id)
    return buckets[bucket_id]


def _ordered_quality_buckets(bucket_map: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    buckets = {
        str(bucket): dict(item)
        for bucket, item in bucket_map.items()
        if isinstance(item, dict)
    }
    for bucket in QUALITY_BUCKET_ORDER:
        buckets.setdefault(bucket, _empty_quality_bucket(bucket))
    ordered: dict[str, dict[str, Any]] = {}
    for bucket in QUALITY_BUCKET_ORDER:
        ordered[bucket] = dict(buckets[bucket])
    for bucket in sorted(item for item in buckets if item not in ordered):
        ordered[bucket] = dict(buckets[bucket])
    return ordered


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def quality_summary_to_markdown(summary: dict[str, Any], top: int = 15) -> str:
    lines: list[str] = []
    lines.append("# PseudoForge Pseudocode Quality Score")
    lines.append("")
    lines.append(f"- Schema: `{summary.get('schema', '')}`")
    if summary.get("compare_dir"):
        lines.append(f"- Compare dir: `{summary.get('compare_dir')}`")
    if summary.get("report_path"):
        lines.append(f"- Batch report: `{summary.get('report_path')}`")
    lines.append(f"- Functions scored: {summary.get('function_count', 0)}")
    lines.append(f"- Average score: {summary.get('average_score', 0)}")
    lines.append(f"- Average opportunity: {summary.get('average_opportunity', 0)}")
    lines.append(f"- Average reward: {summary.get('average_reward', 0)}")
    lines.append(f"- Score range: {summary.get('min_score', 0)}..{summary.get('max_score', 0)}")
    lines.append("")
    lines.append("## Quality Buckets")
    lines.append("")
    lines.extend(_markdown_bucket_table(summary.get("quality_buckets") or {}))
    lines.append("")
    lines.append("## Common Remaining Findings")
    lines.append("")
    lines.extend(_markdown_counter_table(summary.get("finding_totals") or []))
    lines.append("")
    lines.append("## Common Positive Recovery Signals")
    lines.append("")
    lines.extend(_markdown_counter_table(summary.get("reward_totals") or []))
    lines.append("")
    lines.append("## Worst Remaining Functions")
    lines.append("")
    lines.append("| Rank | EA | Name | Score | Opportunity | Top findings |")
    lines.append("| --- | --- | --- | ---: | ---: | --- |")
    for index, function in enumerate((summary.get("worst_functions") or [])[:top], 1):
        findings = function.get("findings") or []
        top_findings = ", ".join(
            f"{item.get('category')}={item.get('count')}" for item in findings[:3]
        )
        lines.append(
            "| %d | `%s` | `%s` | %s | %s | %s |"
            % (
                index,
                function.get("ea", ""),
                function.get("name", ""),
                function.get("score", 0),
                function.get("opportunity", 0),
                top_findings or "none",
            )
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "The score is heuristic and bucketed. Generic artifacts are tracked in "
        "`generic_core`; Windows-kernel-specific signals are isolated under "
        "`windows_kernel`; other domain buckets are reserved until packs provide "
        "evidence."
    )
    return "\n".join(lines) + "\n"


def write_quality_summary(summary: dict[str, Any], json_path: Path, markdown_path: Path | None = None) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    if markdown_path is not None:
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(quality_summary_to_markdown(summary), encoding="utf-8")


def _score_penalties(text: str) -> Iterable[QualityFinding]:
    for rule in _PENALTY_RULES:
        examples = _find_examples(rule.pattern, text)
        if not examples:
            continue
        count = len(rule.pattern.findall(text))
        points = min(rule.point_cap, count * rule.points_per_match)
        yield QualityFinding(
            category=rule.category,
            severity=rule.severity,
            count=count,
            points=points,
            message=rule.message,
            examples=tuple(examples),
            bucket=rule.bucket,
        )


def _score_rewards(text: str, raw_text: str) -> Iterable[QualityFinding]:
    for rule in _REWARD_RULES:
        examples = _find_examples(rule.pattern, text)
        if not examples:
            continue
        count = len(rule.pattern.findall(text))
        points = min(rule.point_cap, count * rule.points_per_match)
        yield QualityFinding(
            category=rule.category,
            severity="reward",
            count=count,
            points=points,
            message=rule.message,
            examples=tuple(examples),
            bucket=rule.bucket,
        )

    if raw_text:
        raw_penalty = sum(item.points for item in _score_penalties(raw_text))
        cleaned_penalty = sum(item.points for item in _score_penalties(text))
        reduction = max(0, raw_penalty - cleaned_penalty)
        if reduction:
            yield QualityFinding(
                category="artifact_reduction",
                severity="reward",
                count=reduction,
                points=min(20, max(1, reduction // 4)),
                message="Cleaned output reduces generic decompiler artifact pressure versus raw input.",
                examples=(),
                bucket=GENERIC_QUALITY_BUCKET,
            )


def _strip_generated_context(text: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    cleaned_lines: list[str] = []
    for line in without_block_comments.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        line = re.sub(r"//.*", "", line)
        if line.strip():
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _find_examples(pattern: re.Pattern[str], text: str, limit: int = 4) -> list[str]:
    examples: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(text):
        value = match.group(0)
        value = re.sub(r"\s+", " ", value).strip()
        if len(value) > 96:
            value = value[:93] + "..."
        if value in seen:
            continue
        examples.append(value)
        seen.add(value)
        if len(examples) >= limit:
            break
    return examples


def _load_report_metadata(report_path: Path) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    if not report_path.exists():
        return metadata
    with report_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or record.get("event") != "function":
                continue
            comparison = record.get("comparison") or {}
            cleaned_path = str(comparison.get("cleaned_path") or "")
            if not cleaned_path:
                continue
            item = {
                "ea": record.get("ea", ""),
                "name": record.get("name", ""),
            }
            metadata[cleaned_path] = item
            metadata[Path(cleaned_path).name] = item
    return metadata


def _name_from_file(path: Path) -> str:
    stem = path.stem
    match = re.match(r"^[0-9A-Fa-f]{16}_(.+)$", stem)
    if match:
        return match.group(1)
    return stem


def _counter_summary(counter: Counter[str], points: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"category": category, "count": count, "points": points.get(category, 0)}
        for category, count in sorted(
            counter.items(),
            key=lambda item: (-points.get(item[0], 0), -item[1], item[0]),
        )
    ]


def _markdown_counter_table(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["none"]
    lines = ["| Category | Count | Points |", "| --- | ---: | ---: |"]
    for item in items:
        lines.append(
            "| `%s` | %s | %s |"
            % (item.get("category", ""), item.get("count", 0), item.get("points", 0))
        )
    return lines


def _markdown_bucket_table(bucket_map: dict[str, dict[str, Any]]) -> list[str]:
    buckets = _ordered_quality_buckets(bucket_map)
    lines = [
        "| Bucket | Type | Reserved | Opportunity | Reward | Findings | Rewards |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for bucket, item in buckets.items():
        lines.append(
            "| `%s` | `%s` | `%s` | %s | %s | %s | %s |"
            % (
                bucket,
                item.get("bucket_type", ""),
                str(bool(item.get("reserved", False))).lower(),
                item.get("opportunity", 0),
                item.get("reward", 0),
                item.get("finding_count", 0),
                item.get("reward_count", 0),
            )
        )
    return lines
