from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class LocalVariable:
    name: str
    type: str = ""
    is_arg: bool = False
    index: int = -1
    location: str = ""
    identity: str = ""


@dataclass(slots=True)
class FunctionCapture:
    ea: int = 0
    name: str = ""
    prototype: str = ""
    pseudocode: str = ""
    lvars: list[LocalVariable] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    source_path: str = ""
    profile_context: dict[str, Any] = field(default_factory=dict)

    def input_fingerprint(self) -> str:
        import hashlib
        import json

        payload = "\n".join(
            [
                self.name,
                self.prototype,
                self.pseudocode,
                ",".join(var.name for var in self.lvars),
                json.dumps(self.profile_context, sort_keys=True, default=str),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class RenameSuggestion:
    kind: str
    old: str
    new: str
    confidence: float
    source: str
    evidence: str
    apply: bool = True
    identity: str = ""


@dataclass(slots=True)
class FlowRewrite:
    kind: str
    dispatcher: str
    recovered_cases: list[int] = field(default_factory=list)
    case_bodies: dict[int, list[str]] = field(default_factory=dict)
    case_names: dict[int, str] = field(default_factory=dict)
    case_body_states: dict[int, str] = field(default_factory=dict)
    case_anchors: dict[int, int] = field(default_factory=dict)
    case_labels: dict[int, str] = field(default_factory=dict)
    confidence: float = 0.0
    export_only: bool = True
    evidence: str = ""


@dataclass(slots=True)
class CleanupLabel:
    label: str
    classification: str
    start_line: int
    end_line: int
    confidence: float
    evidence: str


@dataclass(slots=True)
class ParameterTypeCorrection:
    parameter_index: int
    old_name: str
    new_name: str
    old_type: str
    canonical_type: str
    profile_id: str
    display_type: str = ""
    source: str = ""
    provenance: str = ""
    confidence: float = 0.0
    effective_mode: str = ""
    blockers: list[str] = field(default_factory=list)
    apply_to_preview: bool = True
    apply_to_idb: bool = False


@dataclass(slots=True)
class BufferSizeConstraint:
    buffer: str
    length: str
    relation: str
    value: str
    valid_relation: str = ""
    valid_value: str = ""
    role: str = ""
    evidence: str = ""
    source: str = "local"
    confidence: float = 0.0


@dataclass(slots=True)
class FieldAccess:
    buffer: str
    structure: str
    offset: int
    type: str
    field: str
    access: str
    evidence: str = ""
    source: str = "local"
    confidence: float = 0.0


@dataclass(slots=True)
class FieldConstraint:
    buffer: str
    structure: str
    offset: int
    field: str
    relation: str
    value: str = ""
    mask: str = ""
    valid_relation: str = ""
    valid_value: str = ""
    evidence: str = ""
    source: str = "local"
    confidence: float = 0.0


@dataclass(slots=True)
class HelperContractEdge:
    callee: str
    arguments: list[str] = field(default_factory=list)
    passed_buffers: list[str] = field(default_factory=list)
    resolved: bool = False
    depth: int = 0
    evidence: str = ""
    propagated_size_constraints: list[BufferSizeConstraint] = field(default_factory=list)
    propagated_field_accesses: list[FieldAccess] = field(default_factory=list)
    propagated_field_constraints: list[FieldConstraint] = field(default_factory=list)
    nested_edges: list["HelperContractEdge"] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(slots=True)
class BufferContract:
    role: str
    source: str
    variable: str
    length_variable: str
    structure_name: str
    size_constraints: list[BufferSizeConstraint] = field(default_factory=list)
    field_accesses: list[FieldAccess] = field(default_factory=list)
    field_constraints: list[FieldConstraint] = field(default_factory=list)
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class CommandBufferContract:
    dispatcher_kind: str
    dispatcher: str
    command_value: int
    command_name: str = ""
    buffers: list[BufferContract] = field(default_factory=list)
    helper_edges: list[HelperContractEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class CleanPlan:
    function_ea: int
    function_name: str
    input_fingerprint: str
    renames: list[RenameSuggestion] = field(default_factory=list)
    flow_rewrites: list[FlowRewrite] = field(default_factory=list)
    cleanup_labels: list[CleanupLabel] = field(default_factory=list)
    buffer_contracts: list[CommandBufferContract] = field(default_factory=list)
    comments: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rule_report: dict[str, Any] = field(default_factory=dict)
    type_corrections: list[ParameterTypeCorrection] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def active_renames(self) -> list[RenameSuggestion]:
        return [rename for rename in self.renames if rename.apply]


def make_lvar_identity(
    name: str,
    type_text: str = "",
    is_arg: bool = False,
    index: int = -1,
    location: str = "",
) -> str:
    if index < 0 and not location:
        return ""
    payload = "\x1f".join(
        [
            str(name or ""),
            str(type_text or ""),
            "arg" if is_arg else "local",
            str(index),
            str(location or ""),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
