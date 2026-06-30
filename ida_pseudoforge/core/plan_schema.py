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
class TargetContext:
    source_path: str = ""
    image_name: str = ""
    target_family: str = "unknown"
    confidence: float = 0.0
    format: str = "unknown"
    architecture: str = "unknown"
    bitness: int = 0
    endianness: str = "unknown"
    platform: str = "unknown"
    privilege_domain: str = "unknown"
    compiler_family: str = "unknown"
    abi: str = "unknown"
    language_runtime: str = "unknown"
    symbol_state: str = "unknown"
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    import_families: list[str] = field(default_factory=list)
    section_clues: list[str] = field(default_factory=list)
    runtime_clues: list[str] = field(default_factory=list)
    profile_root: str = ""
    active_domain_packs: list[str] = field(default_factory=list)
    eligible_domain_packs: list[str] = field(default_factory=list)
    rejected_domain_packs: list[str] = field(default_factory=list)
    domain_pack_activation_report: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IrUseDefChain:
    variable: str
    definitions: list[str] = field(default_factory=list)
    uses: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class IrValueRange:
    expression: str
    minimum: str = ""
    maximum: str = ""
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class IrLocalTypeSnapshot:
    name: str
    type_text: str = ""
    source: str = ""
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class IrConstantOrigin:
    value: str
    origin: str = ""
    expression: str = ""
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class IrCallSiteSignature:
    call_name: str
    return_type: str = ""
    argument_types: list[str] = field(default_factory=list)
    argument_names: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: str = ""


@dataclass(slots=True)
class IrEvidence:
    schema: str = "pseudoforge_ir_evidence_v1"
    adapter: str = "text_only"
    source: str = "pseudocode"
    available: bool = False
    use_def_chains: list[IrUseDefChain] = field(default_factory=list)
    value_ranges: list[IrValueRange] = field(default_factory=list)
    local_type_snapshots: list[IrLocalTypeSnapshot] = field(default_factory=list)
    constant_origins: list[IrConstantOrigin] = field(default_factory=list)
    call_site_signatures: list[IrCallSiteSignature] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    target_context: TargetContext = field(default_factory=TargetContext)
    ir_evidence: IrEvidence = field(default_factory=IrEvidence)

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
class FunctionIdentityCandidate:
    profile_id: str
    subsystem: str
    function_name: str
    match_kind: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    effective_mode: str = ""
    profile_source: str = ""
    profile_version: str = ""
    ambiguous_profile_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvidenceGraphNode:
    id: str
    kind: str
    label: str
    confidence: float = 0.0
    profile_id: str = ""
    effective_mode: str = ""
    role: str = ""
    structure: str = ""
    source: str = ""
    blockers: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceGraphEdge:
    source: str
    target: str
    kind: str
    confidence: float = 0.0
    promotion_lane: str = ""
    rewrite_eligible: bool = False
    blockers: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceGraph:
    nodes: list[EvidenceGraphNode] = field(default_factory=list)
    edges: list[EvidenceGraphEdge] = field(default_factory=list)


@dataclass(slots=True)
class WarningDiagnostic:
    kind: str
    message: str
    symbol: str
    usage: str
    usage_class: str
    register: str
    register_class: str
    candidate_action: str
    confidence: float
    source: str = ""
    legacy_candidate_action: str = ""
    callee_name: str = ""
    call_index: int = -1
    argument_index: int = -1
    callee_contract_action: str = ""
    callee_contract_confidence: float = 0.0
    callee_contract_evidence: str = ""
    stack_declaration: str = ""
    stack_slot: str = ""
    pseudo_local_evidence: str = ""
    existing_parameter_index: int = -1
    existing_parameter_raw_name: str = ""
    existing_parameter_rendered_name: str = ""
    existing_parameter_rename_source: str = ""


@dataclass(slots=True)
class CorrectedParameterField:
    offset: int
    name: str
    type_text: str
    size: int
    confidence: float
    source: str = ""
    provenance: str = ""
    note: str = ""


@dataclass(slots=True)
class CorrectedParameterMapEntry:
    parameter_index: int
    old_name: str
    new_name: str
    old_type: str
    canonical_type: str
    display_type: str
    profile_id: str
    role: str
    structure: str
    effective_mode: str
    confidence: float
    provenance: str = ""
    source: str = ""
    body_canonical_rewrite: bool = False
    apply_to_preview: bool = True
    apply_to_idb: bool = False
    base_names: list[str] = field(default_factory=list)
    fields: list[CorrectedParameterField] = field(default_factory=list)


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
class LlmCandidate:
    task: str
    kind: str
    confidence: float
    target: str = ""
    name: str = ""
    text: str = ""
    role: str = ""
    type_name: str = ""
    evidence: str = ""
    source: str = "llm_candidate"
    status: str = "blocked"
    blockers: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


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
    function_identity_candidates: list[FunctionIdentityCandidate] = field(default_factory=list)
    corrected_parameter_map: list[CorrectedParameterMapEntry] = field(default_factory=list)
    warning_diagnostics: list[WarningDiagnostic] = field(default_factory=list)
    llm_candidates: list[LlmCandidate] = field(default_factory=list)
    ir_evidence: IrEvidence = field(default_factory=IrEvidence)
    projection_policy: str = "review_only"

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
