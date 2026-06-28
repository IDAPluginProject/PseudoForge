from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.projection_policy import projection_decision


_LOCAL_DECL_RE = re.compile(
    r"^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?)\s+"
    r"(?P<ptr>[\*\&][\*\&\s]*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[(?P<count>[^\]]+)\])?\s*;"
    r"(?P<tail>[^\n]*)$",
    re.MULTILINE,
)
_STACK_LOCATION_RE = re.compile(r"\[(?P<reg>r[bs]p)(?P<sign>[+-])(?P<value>[0-9A-Fa-f]+)h\]")
_ZERO_REGION_RE = re.compile(
    r"\b(?P<call>memset(?:_0)?|RtlZeroMemory)\s*\(\s*&(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
    r"(?:0|0LL|nullptr)\s*,\s*(?P<size>0x[0-9A-Fa-f]+|\d+)(?:uLL|ULL|LL|UL|U|L)?\s*\)"
)
_ACCUMULATOR_RE = re.compile(
    r"^\s*(?P<dst>v(?P<dst_num>\d+))\s*\+=\s*"
    r"(?:(?:\*(?P<src0>[A-Za-z_][A-Za-z0-9_]*))|"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>\d+)\s*\])\s*;",
    re.MULTILINE,
)
_STRIDED_EXPR_RE = re.compile(
    r"(?:(?P<stride_a>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|ULL|uLL|UL|U|L)?\s*\*\s*"
    r"(?P<index_a>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<base_a>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\+\s*(?P<offset_a>0x[0-9A-Fa-f]+|\d+))?|"
    r"(?P<base_b>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<stride_b>0x[0-9A-Fa-f]+|\d+)(?:LL|i64|ULL|uLL|UL|U|L)?\s*\*\s*"
    r"(?P<index_b>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\+\s*(?P<offset_b>0x[0-9A-Fa-f]+|\d+))?)"
)
_POOL_ALLOCATOR_NAMES = {
    "ExAllocateFromLookasideListEx",
    "ExAllocateFromNPagedLookasideList",
    "ExAllocatePool2",
    "ExAllocatePoolWithQuotaTag",
    "ExAllocatePoolWithTag",
    "MiAllocatePool",
}
_POOL_ALLOCATION_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:\([^;\n]*?\)\s*)?"
    r"(?P<allocator>ExAllocateFromLookasideListEx|ExAllocateFromNPagedLookasideList|"
    r"ExAllocatePool2|ExAllocatePoolWithQuotaTag|ExAllocatePoolWithTag|MiAllocatePool)"
    r"\s*\((?P<args>[^;\n]*)\)\s*;"
)
_OFFSET_STORE_RE = re.compile(
    r"(?P<lhs>\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)"
    r"(?:i64|LL|ULL|uLL|UL|U|L)?)?\s*\))\s*=\s*(?P<rhs>[^;\n]+);"
)
_DIRECT_STORE_RE = re.compile(
    r"(?P<lhs>\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b)\s*=\s*(?P<rhs>[^;\n]+);"
)
_INDEXED_CAST_STORE_RE = re.compile(
    r"(?P<lhs>\*\s*\(\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<index>\d+)\s*\))\s*=\s*(?P<rhs>[^;\n]+);"
)
_BASE_ASSIGNMENT_RE = re.compile(r"(?m)^\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>[+\-*/&|^]?=)\s*(?P<rhs>[^;\n]+);")
_POOL_FREE_RE = re.compile(r"\b(?:ExFreePool(?:WithTag)?|IoFreeMdl|MmFreeNonCachedMemory)\s*\(")
_INTERLOCKED_OR_VOLATILE_RE = re.compile(r"\b(?:Interlocked[A-Za-z0-9_]*|volatile|READ_REGISTER|WRITE_REGISTER)\b")

_TYPE_SIZES = {
    "__int8": 1,
    "char": 1,
    "_BYTE": 1,
    "BYTE": 1,
    "BOOLEAN": 1,
    "UCHAR": 1,
    "unsigned __int8": 1,
    "__int16": 2,
    "short": 2,
    "_WORD": 2,
    "WORD": 2,
    "USHORT": 2,
    "wchar_t": 2,
    "unsigned __int16": 2,
    "__int32": 4,
    "int": 4,
    "_DWORD": 4,
    "DWORD": 4,
    "LONG": 4,
    "NTSTATUS": 4,
    "ULONG": 4,
    "long": 4,
    "unsigned int": 4,
    "unsigned __int32": 4,
    "__int64": 8,
    "_QWORD": 8,
    "QWORD": 8,
    "LIST_ENTRY": 16,
    "_LIST_ENTRY": 16,
    "HANDLE": 8,
    "LONG_PTR": 8,
    "SIZE_T": 8,
    "ULONG_PTR": 8,
    "ULONGLONG": 8,
    "UINT_PTR": 8,
    "size_t": 8,
    "unsigned __int64": 8,
    "__int128": 16,
    "_OWORD": 16,
}


@dataclass(slots=True)
class _LocalDecl:
    name: str
    type_text: str
    count: int
    size: int
    offset: int | None
    line: str

    @property
    def total_size(self) -> int:
        return max(1, self.count) * max(1, self.size)

    @property
    def end_offset(self) -> int | None:
        if self.offset is None:
            return None
        return self.offset + self.total_size


@dataclass(slots=True)
class _AccumulatorAccess:
    dst: str
    dst_num: int
    source: str
    source_index: int


@dataclass(slots=True)
class _StridedRecordEvidence:
    base: str
    stride: int
    offsets: Counter[int]
    types_by_offset: dict[int, Counter[str]]
    indexes: set[str]
    access_count: int = 0


@dataclass(slots=True)
class _PoolAllocation:
    base: str
    allocator: str
    args: list[str]
    size_hint: int
    pool_tag: str
    pool_flags: str
    start: int
    end: int
    line: str


@dataclass(slots=True)
class _PoolFieldAccess:
    base: str
    offset: int
    type_text: str
    size: int
    rhs: str
    line: str
    start: int
    evidence: list[str]


def dense_structural_comments(
    capture: FunctionCapture,
    text: str,
    max_comments: int = 6,
) -> list[dict[str, Any]]:
    del capture
    source_text = text or ""
    locals_ = _parse_local_declarations(source_text)
    comments: list[dict[str, Any]] = []
    comments.extend(_synthetic_local_aggregate_comments(source_text, locals_))
    comments.extend(_synthetic_pool_aggregate_comments(source_text))
    comments.extend(_zeroed_stack_region_comments(source_text, locals_))
    comments.extend(_stack_array_region_comments(source_text, locals_))
    comments.extend(_accumulator_block_comments(source_text))
    comments.extend(_strided_record_comments(source_text))
    comments.sort(key=_comment_priority)
    return comments[: max(0, int(max_comments or 0))]


def _parse_local_declarations(text: str) -> list[_LocalDecl]:
    result = []
    for match in _LOCAL_DECL_RE.finditer(text or ""):
        line = match.group(0)
        type_text = _normalize_type_text((match.group("type") or "") + " " + (match.group("ptr") or ""))
        count = _parse_array_count(match.group("count"))
        size = _type_storage_size(type_text)
        offset = _stack_offset(match.group("tail") or "")
        result.append(
            _LocalDecl(
                name=match.group("name"),
                type_text=type_text,
                count=count,
                size=size,
                offset=offset,
                line=line,
            )
        )
    return result


def _zeroed_stack_region_comments(text: str, locals_: list[_LocalDecl]) -> list[dict[str, Any]]:
    by_name = {item.name: item for item in locals_}
    comments = []
    seen_bases = set()
    for match in _ZERO_REGION_RE.finditer(text or ""):
        base_name = match.group("base")
        if base_name in seen_bases:
            continue
        base = by_name.get(base_name)
        size = _parse_int(match.group("size"))
        if base is None or base.offset is None or size is None or size < 32:
            continue
        covered = _locals_covered_by_region(locals_, base.offset, size)
        v_locals = [item for item in covered if _v_number(item.name) is not None]
        if len(v_locals) < 8 and len(covered) < 10:
            continue
        seen_bases.add(base_name)
        names = [item.name for item in covered]
        comments.append(
            {
                "kind": "dense_stack_local_region",
                "text": (
                    "Stack local region %s spans %s(&%s, 0, 0x%X) and covers %d local(s) "
                    "%s; probable aggregate/array block. Review-only; body rewrite was not applied."
                    % (
                        _local_range_text(names),
                        match.group("call"),
                        base_name,
                        size,
                        len(covered),
                        _type_mix_text(covered),
                    )
                ),
                "confidence": 0.74 if len(v_locals) >= 16 else 0.68,
                "base": base_name,
                "locals": names,
                "region_size": size,
                "local_count": len(covered),
            }
        )
    return comments


def _stack_array_region_comments(text: str, locals_: list[_LocalDecl]) -> list[dict[str, Any]]:
    comments = []
    for item in locals_:
        if item.count < 3 or _v_number(item.name) is None:
            continue
        usage_count = len(re.findall(r"\b%s\s*\[" % re.escape(item.name), text or ""))
        address_use = bool(re.search(r"&\s*%s\b" % re.escape(item.name), text or ""))
        if usage_count < 2 and not address_use:
            continue
        neighbors = _nearby_stack_locals(locals_, item, window=64)
        if len(neighbors) < 3 and item.count < 8:
            continue
        comments.append(
            {
                "kind": "dense_stack_local_region",
                "text": (
                    "Stack array block %s[%d] sits with nearby locals %s; probable compact aggregate "
                    "or dimension/control block. Review-only; body rewrite was not applied."
                    % (item.name, item.count, _local_range_text([local.name for local in neighbors]))
                ),
                "confidence": 0.67,
                "base": item.name,
                "locals": [local.name for local in neighbors],
                "array_count": item.count,
                "usage_count": usage_count,
            }
        )
    return comments


def _accumulator_block_comments(text: str) -> list[dict[str, Any]]:
    accesses = [
        _AccumulatorAccess(
            dst=match.group("dst"),
            dst_num=int(match.group("dst_num")),
            source=match.group("src0") or match.group("src") or "",
            source_index=0 if match.group("src0") else int(match.group("index")),
        )
        for match in _ACCUMULATOR_RE.finditer(text or "")
    ]
    comments = []
    for run in _accumulator_runs(accesses):
        if len(run) < 8:
            continue
        first = run[0]
        last = run[-1]
        comments.append(
            {
                "kind": "dense_accumulator_block",
                "text": (
                    "Dense accumulator field block %s..%s adds %d scalar field(s) from %s indexes %d..%d; "
                    "probable counter vector or aggregate field run. Review-only summary; body rewrite was not applied."
                    % (
                        first.dst,
                        last.dst,
                        len(run),
                        first.source,
                        first.source_index,
                        last.source_index,
                    )
                ),
                "confidence": min(0.86, 0.62 + len(run) * 0.006),
                "base": first.dst,
                "source": first.source,
                "field_count": len(run),
                "source_index_start": first.source_index,
                "source_index_end": last.source_index,
            }
        )
    return comments


def _strided_record_comments(text: str) -> list[dict[str, Any]]:
    evidence_by_key: dict[tuple[str, int], _StridedRecordEvidence] = {}
    for line in (text or "").splitlines():
        if "*" not in line and "[" not in line:
            continue
        for match in _STRIDED_EXPR_RE.finditer(line):
            base = match.group("base_a") or match.group("base_b") or ""
            index = match.group("index_a") or match.group("index_b") or ""
            stride = _parse_int(match.group("stride_a") or match.group("stride_b") or "")
            offset = _parse_int(match.group("offset_a") or match.group("offset_b") or "0")
            if not base or not index or stride is None or offset is None:
                continue
            if stride < 8 or _looks_like_scalar(base):
                continue
            item = evidence_by_key.setdefault(
                (base, stride),
                _StridedRecordEvidence(
                    base=base,
                    stride=stride,
                    offsets=Counter(),
                    types_by_offset={},
                    indexes=set(),
                ),
            )
            item.offsets[offset] += 1
            item.types_by_offset.setdefault(offset, Counter())[_deref_type_near_match(line, match)] += 1
            item.indexes.add(index)
            item.access_count += 1
    comments = []
    for item in evidence_by_key.values():
        if not _has_strided_record_evidence(item):
            continue
        offsets = sorted(item.offsets)
        comments.append(
            {
                "kind": "review_only_struct_candidate",
                "text": (
                    "Review-only struct candidate for %s: stride 0x%X record access via index %s, "
                    "%d access(es) across %d field offset(s) %s. Link with field-layout review; "
                    "no structure type or body rewrite was inferred."
                    % (
                        item.base,
                        item.stride,
                        ", ".join(sorted(item.indexes)[:4]),
                        item.access_count,
                        len(offsets),
                        _offset_list_text(offsets),
                    )
                ),
                "confidence": min(0.78, 0.58 + len(offsets) * 0.025 + min(item.access_count, 12) * 0.006),
                "base": item.base,
                "stride": item.stride,
                "offsets": offsets,
                "access_count": item.access_count,
                "index_variables": sorted(item.indexes),
            }
        )
    return comments


def synthetic_aggregate_models(plan: CleanPlan) -> list[dict[str, Any]]:
    models = []
    for comment in plan.comments:
        if str(comment.get("kind", "") or "") not in {"synthetic_local_aggregate", "synthetic_pool_aggregate"}:
            continue
        models.append(_jsonable_aggregate_model(comment))
    return models


def synthetic_aggregate_json_payload(plan: CleanPlan) -> dict[str, Any]:
    models = synthetic_aggregate_models(plan)
    return {
        "schema": "pseudoforge_synthetic_aggregates_v2",
        "projection_policy": str(getattr(plan, "projection_policy", "review_only") or "review_only"),
        "aggregate_count": len(models),
        "canonical_rewrite_attempts": 0,
        "misleading_rewrites": 0,
        "projected_aggregates": sum(1 for item in models if bool(item.get("projection_applied"))),
        "aggregates": models,
    }


def render_synthetic_aggregate_report(plan: CleanPlan) -> str:
    payload = synthetic_aggregate_json_payload(plan)
    lines = [
        "# PseudoForge Inferred Aggregates",
        "",
        "Synthetic aggregate side view. Projection decisions are render-only and never modify IDB types.",
        "",
        "- Projection policy: `%s`" % str(payload.get("projection_policy", "review_only")),
        "- Aggregate count: `%d`" % int(payload["aggregate_count"]),
        "- Projected aggregates: `%d`" % int(payload["projected_aggregates"]),
        "- Canonical rewrite attempts: `0`",
        "- Misleading rewrites: `0`",
    ]
    for model in payload["aggregates"]:
        lines.extend(
            [
                "",
                "## %s" % model["synthetic_name"],
                "",
                "- Display name: `%s`" % model["display_name"],
                "- Kind: `%s`" % model["aggregate_kind"],
                "- Size hint: `%s`" % model["size_hint"],
                "- Confidence: `%.2f`" % float(model["confidence"]),
                "- Confidence tier: `%s`" % model["confidence_tier"],
                "- Policy decision: `%s`" % model["policy_decision"],
                "- Projection applied: `%s`" % str(bool(model["projection_applied"])).lower(),
                "- Evidence: `%s`" % ", ".join(model["evidence"]),
                "- Safety blockers: `%s`" % ", ".join(model["safety_blockers"]),
                "- Score reason: `%s`" % model["score_reason"],
                "",
                "| Offset | Field | Type | Size | Source | Accesses |",
                "| ---: | --- | --- | ---: | --- | ---: |",
            ]
        )
        for field in model["fields"]:
            lines.append(
                "| `+0x%X` | `%s` | `%s` | `%s` | `%s` | `%s` |"
                % (
                    int(field["offset"]),
                    field["name"],
                    field["type"],
                    field["size"],
                    field["source"],
                    field["access_count"],
                )
            )
    return "\n".join(lines).rstrip() + "\n"


def render_synthetic_struct_header(plan: CleanPlan) -> str:
    models = synthetic_aggregate_models(plan)
    lines = [
        "/*",
        "    PseudoForge review-only synthetic aggregate declarations.",
        "    These declarations are side views only. IDB and cleaned C semantics were not modified.",
        "*/",
        "",
    ]
    if not models:
        lines.append("// No inferred synthetic aggregates.")
        return "\n".join(lines).rstrip() + "\n"
    for model in models:
        lines.append("typedef struct _%s" % model["synthetic_name"])
        lines.append("{")
        cursor = 0
        for field in model["fields"]:
            offset = int(field["offset"])
            size = max(0, int(field["size"] or 0))
            if offset > cursor:
                lines.append("    unsigned char _padding_%X[0x%X];" % (cursor, offset - cursor))
            type_text = _hpp_field_type(str(field["type"] or ""), size)
            lines.append("    %s %s; // +0x%X source %s" % (type_text, field["name"], offset, field["source"]))
            cursor = max(cursor, offset + max(1, size))
        lines.append("} %s;" % model["synthetic_name"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _synthetic_local_aggregate_comments(text: str, locals_: list[_LocalDecl]) -> list[dict[str, Any]]:
    comments = []
    comments.extend(_synthetic_zero_region_comments(text, locals_, len(comments)))
    comments.extend(_synthetic_stack_array_comments(text, locals_, len(comments)))
    comments.extend(_synthetic_strided_record_comments(text, len(comments)))
    return comments


def _synthetic_pool_aggregate_comments(text: str) -> list[dict[str, Any]]:
    allocations = _pool_allocations(text)
    comments = []
    for allocation in allocations:
        accesses = _pool_field_accesses(text, allocation)
        if len(accesses) < 2:
            continue
        fields = _pool_fields_from_accesses(accesses)
        if len(fields) < 2:
            continue
        projection_blockers = _pool_projection_blockers(text, allocation, accesses, fields)
        evidence = [
            "kernel_pool_allocation",
            "fixed_offset_writes",
        ]
        if _pool_null_guard_after_allocation(text, allocation, accesses[0].start):
            evidence.append("null_guarded_initialization")
        if allocation.size_hint:
            evidence.append("constant_allocation_size")
        if allocation.pool_tag:
            evidence.append("pool_tag")
        if _pool_publication_after_initialization(text, allocation, accesses):
            evidence.append("post_init_escape_or_publication")
        confidence = _pool_aggregate_confidence(fields, evidence, projection_blockers, allocation)
        synthetic_name = _pool_synthetic_name(allocation, len(comments))
        display_name = _aggregate_display_name(allocation.base, len(comments))
        text_summary = (
            "Synthetic pool aggregate %s for %s: %d field candidate(s), allocator %s, "
            "size hint 0x%X, tag %s, evidence %s. Projection is policy-gated."
            % (
                synthetic_name,
                display_name,
                len(fields),
                allocation.allocator,
                max(0, int(allocation.size_hint)),
                allocation.pool_tag or "unknown",
                ", ".join(evidence),
            )
        )
        comment = {
            "kind": "synthetic_pool_aggregate",
            "text": text_summary,
            "confidence": round(float(confidence), 3),
            "synthetic_name": synthetic_name,
            "display_name": display_name,
            "aggregate_kind": "pool_allocation_object",
            "base": allocation.base,
            "size_hint": int(allocation.size_hint),
            "stride": 0,
            "index_variables": [],
            "fields": fields,
            "evidence": evidence,
            "safety_blockers": _pool_safety_blockers(projection_blockers),
            "projection_blockers": projection_blockers,
            "canonical_rewrite_attempted": False,
            "misleading_rewrite": False,
            "allocator": allocation.allocator,
            "pool_tag": allocation.pool_tag,
            "pool_flags": allocation.pool_flags,
            "allocation_size": int(allocation.size_hint),
            "allocation_line": allocation.line.strip(),
            "aliases": [allocation.base],
        }
        comment.update(projection_decision(comment, "review_only"))
        comments.append(comment)
    return comments


def _synthetic_zero_region_comments(text: str, locals_: list[_LocalDecl], start_index: int) -> list[dict[str, Any]]:
    by_name = {item.name: item for item in locals_}
    comments = []
    seen_bases = set()
    for match in _ZERO_REGION_RE.finditer(text or ""):
        base_name = match.group("base")
        if base_name in seen_bases:
            continue
        base = by_name.get(base_name)
        size = _parse_int(match.group("size"))
        if base is None or base.offset is None or size is None or size < 16:
            continue
        covered = _locals_covered_by_region(locals_, base.offset, size)
        if len(covered) < 3:
            continue
        fields = _aggregate_fields_from_locals(text, covered, base.offset, size)
        if len(fields) < 3:
            continue
        seen_bases.add(base_name)
        comments.append(
            _synthetic_aggregate_comment(
                synthetic_index=start_index + len(comments),
                aggregate_kind="stack_zero_region",
                display_name=_aggregate_display_name(base_name, start_index + len(comments)),
                base=base_name,
                size_hint=size,
                fields=fields,
                evidence=["zeroed_region", "stack_adjacency", "address_taken_size"],
                safety_blockers=_aggregate_safety_blockers(fields, size),
                confidence=0.84 if len(fields) >= 8 else 0.74,
            )
        )
    return comments


def _synthetic_stack_array_comments(text: str, locals_: list[_LocalDecl], start_index: int) -> list[dict[str, Any]]:
    comments = []
    for item in locals_:
        if item.count < 3 or item.offset is None:
            continue
        usage_count = len(re.findall(r"\b%s\s*\[" % re.escape(item.name), text or ""))
        address_use = bool(re.search(r"&\s*%s\b" % re.escape(item.name), text or ""))
        if usage_count < 2 and not address_use:
            continue
        fields = []
        for index in range(min(item.count, 32)):
            fields.append(
                {
                    "offset": index * max(1, item.size),
                    "name": "field_%02X" % (index * max(1, item.size)),
                    "type": item.type_text,
                    "size": item.size,
                    "source": "%s[%d]" % (item.name, index),
                    "source_local": item.name,
                    "access_count": usage_count,
                    "confidence": 0.68,
                    "evidence": ["stack_array", "indexed_local_access"],
                }
            )
        comments.append(
            _synthetic_aggregate_comment(
                synthetic_index=start_index + len(comments),
                aggregate_kind="stack_array",
                display_name=_aggregate_display_name(item.name, start_index + len(comments)),
                base=item.name,
                size_hint=item.total_size,
                fields=fields,
                evidence=["stack_array", "indexed_local_access"],
                safety_blockers=["stack array may represent a vector rather than a record"],
                confidence=0.68,
            )
        )
    return comments


def _synthetic_strided_record_comments(text: str, start_index: int) -> list[dict[str, Any]]:
    comments = []
    for item in _strided_record_evidence(text).values():
        if not _has_strided_record_evidence(item):
            continue
        fields = []
        for offset in sorted(item.offsets):
            field_type = _most_common_type(item.types_by_offset.get(offset, Counter()))
            fields.append(
                {
                    "offset": offset,
                    "name": "field_%02X" % offset,
                    "type": field_type,
                    "size": _type_storage_size(field_type),
                    "source": "%s + stride*%s" % (item.base, ",".join(sorted(item.indexes)[:3])),
                    "source_local": "",
                    "access_count": int(item.offsets[offset]),
                    "confidence": min(0.76, 0.58 + int(item.offsets[offset]) * 0.03),
                    "evidence": ["strided_record_access"],
                }
            )
        comments.append(
            _synthetic_aggregate_comment(
                synthetic_index=start_index + len(comments),
                aggregate_kind="strided_record",
                display_name=_aggregate_display_name(item.base, start_index + len(comments)),
                base=item.base,
                size_hint=item.stride,
                fields=fields,
                evidence=["strided_record_access", "repeated_offset_access"],
                safety_blockers=["ambiguous base/index", "stride is a size hint, not a validated type"],
                confidence=min(0.78, 0.60 + len(fields) * 0.03),
                stride=item.stride,
                index_variables=sorted(item.indexes),
            )
        )
    return comments


def _synthetic_aggregate_comment(
    synthetic_index: int,
    aggregate_kind: str,
    display_name: str,
    base: str,
    size_hint: int,
    fields: list[dict[str, Any]],
    evidence: list[str],
    safety_blockers: list[str],
    confidence: float,
    stride: int = 0,
    index_variables: list[str] | None = None,
) -> dict[str, Any]:
    synthetic_name = "PF_INFERRED_LOCAL_AGGREGATE_%d" % synthetic_index
    text = (
        "Synthetic local aggregate %s for %s: %d field candidate(s), size hint 0x%X, "
        "evidence %s. Projection is policy-gated; IDB type is not modified."
        % (synthetic_name, display_name, len(fields), max(0, int(size_hint)), ", ".join(evidence))
    )
    return {
        "kind": "synthetic_local_aggregate",
        "text": text,
        "confidence": round(float(confidence), 3),
        "synthetic_name": synthetic_name,
        "display_name": display_name,
        "aggregate_kind": aggregate_kind,
        "base": base,
        "size_hint": int(size_hint),
        "stride": int(stride or 0),
        "index_variables": list(index_variables or []),
        "fields": fields,
        "evidence": evidence,
        "safety_blockers": list(dict.fromkeys(safety_blockers + ["review-only synthetic aggregate"])),
        "projection_blockers": _aggregate_projection_blockers(safety_blockers),
        "canonical_rewrite_attempted": False,
        "misleading_rewrite": False,
    }


def _aggregate_fields_from_locals(
    text: str,
    locals_: list[_LocalDecl],
    base_offset: int,
    region_size: int,
) -> list[dict[str, Any]]:
    fields = []
    for item in locals_:
        if item.offset is None:
            continue
        offset = item.offset - base_offset
        if offset < 0 or offset >= region_size:
            continue
        fields.append(
            {
                "offset": offset,
                "name": "field_%02X" % offset,
                "type": item.type_text,
                "size": item.total_size,
                "source": item.name,
                "source_local": item.name,
                "access_count": _identifier_use_count(text, item.name),
                "confidence": 0.74,
                "evidence": ["stack_adjacency"],
            }
        )
    fields.sort(key=lambda item: int(item["offset"]))
    return fields


def _aggregate_safety_blockers(fields: list[dict[str, Any]], size_hint: int) -> list[str]:
    blockers = ["canonical aggregate rewrite disabled by default"]
    cursor = 0
    for field in sorted(fields, key=lambda item: int(item["offset"])):
        offset = int(field["offset"])
        size = max(1, int(field.get("size", 1) or 1))
        if offset < cursor:
            blockers.append("overlap/union possibility")
        if offset > cursor:
            blockers.append("non-contiguous local block")
        cursor = max(cursor, offset + size)
    if size_hint and cursor > size_hint:
        blockers.append("field range exceeds size hint")
    return list(dict.fromkeys(blockers))


def _aggregate_projection_blockers(safety_blockers: list[str]) -> list[str]:
    blockers = []
    for item in safety_blockers:
        normalized = str(item or "").lower()
        if "overlap" in normalized:
            blockers.append("offset/width conflict")
        elif "field range exceeds" in normalized:
            blockers.append("allocation size overrun")
        elif "stride" in normalized or "array may represent" in normalized:
            blockers.append("array/strided loop pattern")
    return list(dict.fromkeys(blockers))


def _pool_allocations(text: str) -> list[_PoolAllocation]:
    result = []
    for match in _POOL_ALLOCATION_ASSIGNMENT_RE.finditer(text or ""):
        args = _split_call_args(match.group("args") or "")
        allocator = match.group("allocator")
        size_hint = _pool_allocation_size(allocator, args)
        pool_tag = _pool_allocation_tag(allocator, args)
        pool_flags = args[0] if args else ""
        result.append(
            _PoolAllocation(
                base=match.group("base"),
                allocator=allocator,
                args=args,
                size_hint=size_hint,
                pool_tag=pool_tag,
                pool_flags=pool_flags,
                start=match.start(),
                end=match.end(),
                line=match.group(0),
            )
        )
    return result


def _pool_field_accesses(text: str, allocation: _PoolAllocation) -> list[_PoolFieldAccess]:
    result: list[_PoolFieldAccess] = []
    for match in _INDEXED_CAST_STORE_RE.finditer(text or ""):
        if match.group("base") != allocation.base or match.start() <= allocation.end:
            continue
        type_text = _normalize_type_text(match.group("type") or "")
        size = _type_storage_size(type_text)
        index = _parse_int(match.group("index") or "")
        if index is None:
            continue
        result.append(
            _PoolFieldAccess(
                base=allocation.base,
                offset=index * max(1, size),
                type_text=type_text,
                size=size,
                rhs=(match.group("rhs") or "").strip(),
                line=match.group(0).strip(),
                start=match.start(),
                evidence=["indexed_cast_store"],
            )
        )
    for match in _OFFSET_STORE_RE.finditer(text or ""):
        if match.group("base") != allocation.base or match.start() <= allocation.end:
            continue
        type_text = _normalize_type_text(match.group("type") or "")
        offset = _parse_int(match.group("offset") or "0")
        if offset is None:
            continue
        result.append(
            _PoolFieldAccess(
                base=allocation.base,
                offset=offset,
                type_text=type_text,
                size=_type_storage_size(type_text),
                rhs=(match.group("rhs") or "").strip(),
                line=match.group(0).strip(),
                start=match.start(),
                evidence=["offset_store"],
            )
        )
    for match in _DIRECT_STORE_RE.finditer(text or ""):
        if match.group("base") != allocation.base or match.start() <= allocation.end:
            continue
        type_text = _normalize_type_text(match.group("type") or "")
        result.append(
            _PoolFieldAccess(
                base=allocation.base,
                offset=0,
                type_text=type_text,
                size=_type_storage_size(type_text),
                rhs=(match.group("rhs") or "").strip(),
                line=match.group(0).strip(),
                start=match.start(),
                evidence=["direct_base_store"],
            )
        )
    result.sort(key=lambda item: (item.start, item.offset))
    return result


def _pool_fields_from_accesses(accesses: list[_PoolFieldAccess]) -> list[dict[str, Any]]:
    by_offset: dict[int, list[_PoolFieldAccess]] = {}
    for access in accesses:
        by_offset.setdefault(access.offset, []).append(access)
    fields = []
    for offset in sorted(by_offset):
        offset_accesses = by_offset[offset]
        selected = offset_accesses[0]
        type_counts = Counter(access.type_text for access in offset_accesses)
        type_text = _most_common_type(type_counts)
        size = _type_storage_size(type_text)
        rhs_names = [_field_name_from_rhs(access.rhs, type_text, offset) for access in offset_accesses]
        field_name = next((name for name in rhs_names if name and not name.startswith("field_")), "")
        if not field_name:
            field_name = "field_%02X" % offset
        evidence = []
        for access in offset_accesses:
            evidence.extend(access.evidence)
        fields.append(
            {
                "offset": offset,
                "name": field_name,
                "type": type_text,
                "size": size,
                "source": offset_accesses[0].line,
                "source_local": selected.base,
                "access_count": len(offset_accesses),
                "confidence": 0.82 if field_name.startswith("field_") else 0.86,
                "evidence": list(dict.fromkeys(evidence + ["pool_initializer_write"])),
            }
        )
    return fields


def _field_name_from_rhs(rhs: str, type_text: str, offset: int) -> str:
    value = str(rhs or "").strip()
    if "LIST_ENTRY" in str(type_text or "").upper():
        return "ListEntry" if offset else "ListHead"
    match = re.fullmatch(r"(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)", value)
    if not match:
        return "field_%02X" % offset
    name = match.group("name")
    if _looks_like_decompiler_temp(name) or _looks_like_scalar(name):
        return "field_%02X" % offset
    if name in {"NULL", "nullptr", "TRUE", "FALSE"}:
        return "field_%02X" % offset
    return _sanitize_field_name(name)


def _pool_projection_blockers(
    text: str,
    allocation: _PoolAllocation,
    accesses: list[_PoolFieldAccess],
    fields: list[dict[str, Any]],
) -> list[str]:
    blockers = []
    if _pool_has_offset_width_conflict(accesses):
        blockers.append("offset/width conflict")
    if _pool_has_multiple_allocation_sources(text, allocation):
        blockers.append("multiple allocation source merge")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", allocation.base):
        blockers.append("alias base unclear")
    first_access = accesses[0].start if accesses else allocation.end
    if not _pool_null_guard_after_allocation(text, allocation, first_access):
        blockers.append("dominance/null-guard unclear")
    if _pool_escape_before_init(text, allocation, first_access):
        blockers.append("escape-before-init")
    if _pool_free_before_first_access(text, allocation, first_access):
        blockers.append("free-before-use")
    if _pool_has_strided_or_loop_pattern(text, allocation):
        blockers.append("array/strided loop pattern")
    if allocation.size_hint and _field_extent(fields) > allocation.size_hint:
        blockers.append("allocation size overrun")
    if any(_INTERLOCKED_OR_VOLATILE_RE.search(access.line) for access in accesses):
        blockers.append("volatile/mmio/atomic/interlocked access")
    return list(dict.fromkeys(blockers))


def _pool_safety_blockers(projection_blockers: list[str]) -> list[str]:
    blockers = ["render-only projection; IDB type is not modified"]
    blockers.extend(projection_blockers)
    return list(dict.fromkeys(blockers))


def _pool_aggregate_confidence(
    fields: list[dict[str, Any]],
    evidence: list[str],
    blockers: list[str],
    allocation: _PoolAllocation,
) -> float:
    confidence = 0.70
    confidence += min(0.10, len(fields) * 0.025)
    confidence += min(0.08, len(evidence) * 0.02)
    if allocation.size_hint:
        confidence += 0.04
    if allocation.pool_tag:
        confidence += 0.03
    if blockers:
        confidence -= min(0.26, len(blockers) * 0.07)
    return max(0.30, min(0.91, confidence))


def _pool_null_guard_after_allocation(text: str, allocation: _PoolAllocation, before: int) -> bool:
    window = str(text or "")[allocation.end : max(allocation.end, before)]
    base = re.escape(allocation.base)
    return (
        re.search(r"\bif\s*\(\s*%s\s*\)" % base, window) is not None
        or re.search(r"\bif\s*\(\s*%s\s*!=\s*(?:0|NULL|nullptr)\s*\)" % base, window) is not None
        or re.search(r"\bif\s*\(\s*!\s*%s\s*\)" % base, window) is not None
        or re.search(r"\bif\s*\(\s*(?:0|NULL|nullptr)\s*==\s*%s\s*\)" % base, window) is not None
    )


def _pool_escape_before_init(text: str, allocation: _PoolAllocation, first_access: int) -> bool:
    window = str(text or "")[allocation.end : max(allocation.end, first_access)]
    base = re.escape(allocation.base)
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*\b%s\b[^;\n]*\)\s*;" % base, window):
        snippet = match.group(0)
        if allocation.allocator in snippet:
            continue
        if re.search(r"\b(?:memset|RtlZeroMemory|RtlFillMemory|RtlCopyMemory|memcpy)\b", snippet):
            continue
        return True
    return False


def _pool_free_before_first_access(text: str, allocation: _PoolAllocation, first_access: int) -> bool:
    window = str(text or "")[allocation.end : max(allocation.end, first_access)]
    base = re.escape(allocation.base)
    return _POOL_FREE_RE.search(window) is not None and re.search(r"\b%s\b" % base, window) is not None


def _pool_has_strided_or_loop_pattern(text: str, allocation: _PoolAllocation) -> bool:
    base = re.escape(allocation.base)
    if re.search(r"\b(?:for|while)\s*\(", text or "") and re.search(
        r"\b%s\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\b" % base,
        text or "",
    ):
        return True
    return re.search(r"\b%s\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]" % base, text or "") is not None


def _pool_has_offset_width_conflict(accesses: list[_PoolFieldAccess]) -> bool:
    widths_by_offset: dict[int, set[tuple[int, str]]] = {}
    for access in accesses:
        widths_by_offset.setdefault(access.offset, set()).add((access.size, access.type_text))
    return any(len(items) > 1 for items in widths_by_offset.values())


def _pool_has_multiple_allocation_sources(text: str, allocation: _PoolAllocation) -> bool:
    assignments = [
        item
        for item in _BASE_ASSIGNMENT_RE.finditer(text or "")
        if item.group("base") == allocation.base and item.group("op") == "="
    ]
    allocation_assignments = [
        item
        for item in assignments
        if any(name in (item.group("rhs") or "") for name in _POOL_ALLOCATOR_NAMES)
    ]
    return len(allocation_assignments) > 1


def _pool_publication_after_initialization(text: str, allocation: _PoolAllocation, accesses: list[_PoolFieldAccess]) -> bool:
    if not accesses:
        return False
    last_access = max(access.start for access in accesses)
    window = str(text or "")[last_access : last_access + 600]
    base = re.escape(allocation.base)
    return (
        re.search(r"\b(?:InsertTailList|InsertHeadList|ExInterlockedInsertTailList|ObInsertObject)\s*\(", window) is not None
        and re.search(r"\b%s\b" % base, window) is not None
    ) or re.search(r"\breturn\s+%s\s*;" % base, window) is not None


def _field_extent(fields: list[dict[str, Any]]) -> int:
    extent = 0
    for field in fields:
        offset = int(field.get("offset", 0) or 0)
        size = max(1, int(field.get("size", 1) or 1))
        extent = max(extent, offset + size)
    return extent


def _split_call_args(args: str) -> list[str]:
    result = []
    current = []
    depth = 0
    for char in str(args or ""):
        if char == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
    if current or args:
        result.append("".join(current).strip())
    return result


def _pool_allocation_size(allocator: str, args: list[str]) -> int:
    if allocator in {"ExAllocatePool2", "ExAllocatePoolWithTag", "ExAllocatePoolWithQuotaTag", "MiAllocatePool"}:
        if len(args) >= 2:
            return _parse_int(args[1]) or 0
    return 0


def _pool_allocation_tag(allocator: str, args: list[str]) -> str:
    if allocator in {"ExAllocatePool2", "ExAllocatePoolWithTag", "ExAllocatePoolWithQuotaTag"} and len(args) >= 3:
        return _pool_tag_text(args[2])
    return ""


def _pool_tag_text(value: str) -> str:
    text = str(value or "").strip()
    if re.fullmatch(r"'[^']{1,8}'", text):
        return text.strip("'")
    parsed = _parse_int(text)
    if parsed is None:
        return text if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) else ""
    chars = []
    for shift in (0, 8, 16, 24):
        byte = (parsed >> shift) & 0xFF
        if byte < 0x20 or byte > 0x7E:
            continue
        chars.append(chr(byte))
    return "".join(chars)


def _pool_synthetic_name(allocation: _PoolAllocation, index: int) -> str:
    tag = _sanitize_identifier(allocation.pool_tag or allocation.base or "POOL")
    size_text = "%X" % allocation.size_hint if allocation.size_hint else "%d" % index
    return "PF_INFERRED_POOL_%s_%s" % (tag or "POOL", size_text)


def _sanitize_field_name(value: str) -> str:
    cleaned = _sanitize_identifier(value)
    if not cleaned or cleaned[0].isdigit():
        return ""
    return cleaned


def _sanitize_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


def _looks_like_decompiler_temp(name: str) -> bool:
    return re.fullmatch(r"(?:v|a|argument)\d+", str(name or "")) is not None


def _aggregate_display_name(base: str, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", str(base or ""))
    if cleaned and not cleaned[0].isdigit():
        return "%sAggregate" % cleaned
    return "localAggregate%d" % index


def _strided_record_evidence(text: str) -> dict[tuple[str, int], _StridedRecordEvidence]:
    evidence_by_key: dict[tuple[str, int], _StridedRecordEvidence] = {}
    for line in (text or "").splitlines():
        if "*" not in line and "[" not in line:
            continue
        for match in _STRIDED_EXPR_RE.finditer(line):
            base = match.group("base_a") or match.group("base_b") or ""
            index = match.group("index_a") or match.group("index_b") or ""
            stride = _parse_int(match.group("stride_a") or match.group("stride_b") or "")
            offset = _parse_int(match.group("offset_a") or match.group("offset_b") or "0")
            if not base or not index or stride is None or offset is None:
                continue
            if stride < 8 or _looks_like_scalar(base):
                continue
            item = evidence_by_key.setdefault(
                (base, stride),
                _StridedRecordEvidence(
                    base=base,
                    stride=stride,
                    offsets=Counter(),
                    types_by_offset={},
                    indexes=set(),
                ),
            )
            item.offsets[offset] += 1
            item.types_by_offset.setdefault(offset, Counter())[_deref_type_near_match(line, match)] += 1
            item.indexes.add(index)
            item.access_count += 1
    return evidence_by_key


def _accumulator_runs(accesses: list[_AccumulatorAccess]) -> list[list[_AccumulatorAccess]]:
    runs: list[list[_AccumulatorAccess]] = []
    current: list[_AccumulatorAccess] = []
    for item in accesses:
        if (
            current
            and item.source == current[-1].source
            and item.dst_num == current[-1].dst_num + 1
            and item.source_index == current[-1].source_index + 1
        ):
            current.append(item)
            continue
        if current:
            runs.append(current)
        current = [item]
    if current:
        runs.append(current)
    return runs


def _locals_covered_by_region(locals_: list[_LocalDecl], start: int, size: int) -> list[_LocalDecl]:
    end = start + size
    result = []
    for item in locals_:
        if item.offset is None:
            continue
        item_end = item.end_offset if item.end_offset is not None else item.offset + 1
        if item.offset >= start and item.offset < end:
            result.append(item)
        elif item.offset < start and item_end > start:
            result.append(item)
    result.sort(key=lambda item: (item.offset if item.offset is not None else 0, _v_number(item.name) or 0))
    return result


def _nearby_stack_locals(locals_: list[_LocalDecl], target: _LocalDecl, window: int) -> list[_LocalDecl]:
    if target.offset is None:
        return [target]
    result = [
        item
        for item in locals_
        if item.offset is not None and abs(item.offset - target.offset) <= window
    ]
    result.sort(key=lambda item: item.offset if item.offset is not None else 0)
    return result


def _has_strided_record_evidence(evidence: _StridedRecordEvidence) -> bool:
    offset_count = len(evidence.offsets)
    if offset_count >= 3 and evidence.access_count >= 4:
        return True
    return offset_count >= 2 and evidence.access_count >= 6


def _comment_priority(comment: dict[str, Any]) -> tuple[int, int, str]:
    kind_order = {
        "synthetic_local_aggregate": 0,
        "synthetic_pool_aggregate": 0,
        "dense_accumulator_block": 0,
        "dense_stack_local_region": 1,
        "review_only_struct_candidate": 2,
    }
    magnitude = int(comment.get("field_count", comment.get("local_count", comment.get("access_count", 0))) or 0)
    if not magnitude:
        magnitude = len(comment.get("fields", []) or [])
    return (kind_order.get(str(comment.get("kind", "")), 9), -magnitude, str(comment.get("base", "")))


def _stack_offset(text: str) -> int | None:
    candidates = list(_STACK_LOCATION_RE.finditer(text or ""))
    if not candidates:
        return None
    selected = next((item for item in candidates if item.group("reg") == "rbp"), candidates[-1])
    value = int(selected.group("value"), 16)
    return value if selected.group("sign") == "+" else -value


def _type_storage_size(type_text: str) -> int:
    normalized = _normalize_type_text(type_text)
    if not normalized:
        return 1
    if normalized.endswith("LIST_ENTRY") or " LIST_ENTRY" in normalized:
        return 16
    if "*" in normalized or normalized.startswith("P") and normalized.upper() == normalized:
        return 8
    known = _TYPE_SIZES.get(normalized, _TYPE_SIZES.get(normalized.lower()))
    if known is not None:
        return known
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*", normalized):
        return 4
    return 1


def _normalize_type_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", str(text or "").strip())
    normalized = normalized.replace(" *", "*").replace("*", " *").strip()
    return re.sub(r"\s+", " ", normalized)


def _parse_array_count(value: str | None) -> int:
    if not value:
        return 1
    parsed = _parse_int(str(value).strip())
    return parsed if parsed is not None and parsed > 0 else 1


def _parse_int(value: str) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = re.sub(r"(?i)(?:ull|uLL|ll|i64|ul|u|l)$", "", text)
    try:
        return int(text, 0)
    except ValueError:
        return None


def _v_number(name: str) -> int | None:
    match = re.fullmatch(r"v(\d+)", str(name or ""))
    return int(match.group(1)) if match else None


def _looks_like_scalar(name: str) -> bool:
    lowered = str(name or "").lower()
    return lowered in {"i", "j", "k", "count", "size", "length", "index", "status", "result"}


def _local_range_text(names: list[str]) -> str:
    if not names:
        return "unknown"
    v_numbers = [(_v_number(name), name) for name in names]
    if all(number is not None for number, _name in v_numbers):
        return "%s..%s" % (names[0], names[-1])
    shown = names[:6]
    text = ", ".join(shown)
    if len(names) > len(shown):
        text += ", ..."
    return text


def _type_mix_text(locals_: list[_LocalDecl]) -> str:
    counts = Counter(item.type_text for item in locals_ if item.type_text)
    if not counts:
        return ""
    items = ["%s x%d" % (type_text, count) for type_text, count in counts.most_common(3)]
    return "(%s)" % ", ".join(items)


def _offset_list_text(offsets: list[int]) -> str:
    shown = offsets[:8]
    text = ", ".join("+0x%X" % offset for offset in shown)
    if len(offsets) > len(shown):
        text += ", ..."
    return text


def _identifier_use_count(text: str, name: str) -> int:
    if not name:
        return 0
    return len(re.findall(r"\b%s\b" % re.escape(name), text or ""))


def _deref_type_near_match(line: str, match: re.Match[str]) -> str:
    prefix = str(line or "")[: match.start()]
    candidates = list(re.finditer(r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*\(\s*$", prefix[-80:]))
    if not candidates:
        return "unknown"
    return _normalize_type_text(candidates[-1].group("type"))


def _most_common_type(values: Counter[str]) -> str:
    for value, _count in values.most_common():
        if value and value != "unknown":
            return value
    return "unknown"


def _jsonable_aggregate_model(comment: dict[str, Any]) -> dict[str, Any]:
    fields = []
    for field in comment.get("fields", []) or []:
        if not isinstance(field, dict):
            continue
        fields.append(
            {
                "offset": int(field.get("offset", 0) or 0),
                "name": str(field.get("name", "") or ""),
                "type": str(field.get("type", "") or "unknown"),
                "size": int(field.get("size", 0) or 0),
                "source": str(field.get("source", "") or ""),
                "source_local": str(field.get("source_local", "") or ""),
                "access_count": int(field.get("access_count", 0) or 0),
                "confidence": float(field.get("confidence", 0.0) or 0.0),
                "evidence": [str(item) for item in field.get("evidence", []) or []],
            }
        )
    return {
        "synthetic_name": str(comment.get("synthetic_name", "") or ""),
        "display_name": str(comment.get("display_name", "") or ""),
        "aggregate_kind": str(comment.get("aggregate_kind", "") or ""),
        "base": str(comment.get("base", "") or ""),
        "size_hint": int(comment.get("size_hint", 0) or 0),
        "stride": int(comment.get("stride", 0) or 0),
        "index_variables": [str(item) for item in comment.get("index_variables", []) or []],
        "confidence": float(comment.get("confidence", 0.0) or 0.0),
        "confidence_tier": str(comment.get("confidence_tier", "") or ""),
        "projection_policy": str(comment.get("policy", "") or comment.get("projection_policy", "") or ""),
        "policy_decision": str(comment.get("policy_decision", "") or ""),
        "projection_applied": bool(comment.get("projection_applied", False)),
        "projection_blockers": [str(item) for item in comment.get("projection_blockers", []) or []],
        "score_reason": str(comment.get("score_reason", "") or ""),
        "evidence": [str(item) for item in comment.get("evidence", []) or []],
        "safety_blockers": [str(item) for item in comment.get("safety_blockers", []) or []],
        "canonical_rewrite_attempted": bool(comment.get("canonical_rewrite_attempted", False)),
        "misleading_rewrite": bool(comment.get("misleading_rewrite", False)),
        "allocator": str(comment.get("allocator", "") or ""),
        "pool_tag": str(comment.get("pool_tag", "") or ""),
        "pool_flags": str(comment.get("pool_flags", "") or ""),
        "allocation_size": int(comment.get("allocation_size", 0) or 0),
        "allocation_line": str(comment.get("allocation_line", "") or ""),
        "aliases": [str(item) for item in comment.get("aliases", []) or []],
        "fields": fields,
    }


def _hpp_field_type(type_text: str, size: int) -> str:
    normalized = _normalize_type_text(type_text)
    if normalized and normalized != "unknown":
        if normalized in {"_BYTE", "BYTE"}:
            return "unsigned char"
        if normalized in {"_WORD", "WORD"}:
            return "unsigned short"
        if normalized in {"_DWORD", "DWORD"}:
            return "unsigned int"
        if normalized in {"_QWORD", "QWORD"}:
            return "unsigned __int64"
        return normalized
    if size == 1:
        return "unsigned char"
    if size == 2:
        return "unsigned short"
    if size == 4:
        return "unsigned int"
    if size == 8:
        return "unsigned __int64"
    return "unsigned char"
