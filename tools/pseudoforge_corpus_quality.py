from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.api_semantics import NTSTATUS_RETURN_MAP, STATUS_ARGUMENT_INDEXES
from ida_pseudoforge.core.normalize import (
    extract_function_signature,
    extract_parameters_from_signature,
)
from ida_pseudoforge.profiles.callee_contracts import callee_contract_for_call
from ida_pseudoforge.profiles import loader as profile_loader
from ida_pseudoforge.version import VERSION, plugin_title


DIRECT_CALL_RESULT_LAYOUT_HINTS_PROFILE_NAME = "direct_call_result_layout_hints.json"
_DEBUG_EXCEPTION_STATUS_NAMES = {
    "STATUS_BREAKPOINT",
    "STATUS_GUARD_PAGE_VIOLATION",
    "STATUS_SINGLE_STEP",
}
_KNOWN_CRYPTO_INITIAL_VALUES = {
    0xC1059ED8,  # SHA-224 H0
    0xC3D2E1F0,  # SHA-1 H4
}
_KNOWN_DEBUG_FILL_VALUES = {
    0xAABBAABB,
    0xBAADF00D,
    0xBAD0BEE0,
    0xCCCCCCCC,
    0xCCDDCCDD,
    0xCDCDCDCD,
    0xDDDDDDDD,
    0xDEADBEEF,
    0xFDFDFDFD,
    0xFEEEFEEE,
}
GENERIC_IDENTIFIER_RE = re.compile(r"\b[av]\d+\b")
GENERIC_PARAMETER_NAME_RE = re.compile(r"\b(?:[av]\d+|argument\d+)\b")
ABI_INTEGER_ARGUMENT_REGISTER_INDEX = {
    "rcx": 0,
    "ecx": 0,
    "cx": 0,
    "cl": 0,
    "rdx": 1,
    "edx": 1,
    "dx": 1,
    "dl": 1,
    "r8": 2,
    "r8d": 2,
    "r8w": 2,
    "r8b": 2,
    "r9": 3,
    "r9d": 3,
    "r9w": 3,
    "r9b": 3,
}
OFFSET_DEREF_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\([^;\n]*\+\s*(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)
OFFSET_DEREF_ITEM_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
NESTED_FIELD_POINTER_DEREF_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<parent>[A-Za-z_][A-Za-z0-9_]*)->(?P<field>field_[0-9A-Fa-f]+)"
    r"(?:\s*/\*[^*]*\*/)?\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
EMBEDDED_FIELD_REWRITE_RE = re.compile(
    r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)->"
    r"(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*/\*\s*(?P<type>[^+*]*?)\s+\+"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\*/"
)
DIRECT_BASE_DEREF_RE = re.compile(
    r"\*\s*\(\s*[^()]*?\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b"
)
DIRECT_BASE_DEREF_ITEM_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b(?P<call>\s*\()?"
)
DIRECT_CALL_RESULT_DEREF_ITEM_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"(?P<callee>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<args>[^;\n()]*)\)"
    r"(?P<member_path>(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*)"
)
PARAMETER_FIELD_POINTER_SOURCE_LOAD_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<source>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
POINTER_INDEXED_OFFSET_DEREF_RE = re.compile(
    r"(?P<outer_stars>\*+)\s*\(\s*\(\s*(?P<type>[A-Za-z_][A-Za-z0-9_:\s]*?)\s*"
    r"(?P<pointer_stars>\*+)\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<index>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
POINTER_INDEXED_TYPE_STORAGE_SIZES = {
    "__int8": 1,
    "signed __int8": 1,
    "unsigned __int8": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "_byte": 1,
    "byte": 1,
    "boolean": 1,
    "__int16": 2,
    "signed __int16": 2,
    "unsigned __int16": 2,
    "short": 2,
    "signed short": 2,
    "unsigned short": 2,
    "_word": 2,
    "word": 2,
    "wchar_t": 2,
    "__int32": 4,
    "signed __int32": 4,
    "unsigned __int32": 4,
    "int": 4,
    "signed int": 4,
    "unsigned int": 4,
    "long": 4,
    "signed long": 4,
    "unsigned long": 4,
    "_dword": 4,
    "dword": 4,
    "ulong": 4,
    "ntstatus": 4,
    "__int64": 8,
    "signed __int64": 8,
    "unsigned __int64": 8,
    "long long": 8,
    "signed long long": 8,
    "unsigned long long": 8,
    "_qword": 8,
    "qword": 8,
    "ulong64": 8,
    "size_t": 8,
    "__int128": 16,
    "signed __int128": 16,
    "unsigned __int128": 16,
    "_oword": 16,
    "oword": 16,
    "xmmword": 16,
}
WEAK_PARAMETER_TYPES = {
    "__int64",
    "PVOID",
    "void *",
    "void*",
    "_QWORD",
    "_QWORD *",
    "_QWORD*",
}
API_SEMANTIC_REVIEW_CATEGORIES = (
    "correctly_blocked_large_dispatcher",
    "likely_profile_gap",
    "weak_parameter_name_gap",
    "shadow_or_conflict_needs_manual_review",
    "unsafe_wrapper_role",
)
LABEL_RE = re.compile(r"\bLABEL_\d+\b")
DECIMAL_STATUS_RE = re.compile(
    r"(?:\breturn\b|(?<![=!<>])(?:==|!=|=))\s*"
    r"-?(?:107374\d+|\d{8,}|322122\d+)(?:u?LL|ULL|LL|u|U|L)?\b"
    r"|\b-?(?:107374\d+|\d{8,}|322122\d+)(?:u?LL|ULL|LL|u|U|L)?\s*(?:==|!=)"
)
HEX_STATUS_RE = re.compile(r"\b0xC[0-9A-Fa-f]{7}\b")
NUMERIC_LITERAL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
    r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\b"
)
_LAYOUT_REWRITE_BLOCKER_QUEUE_ORDER = (
    "base_identity_candidates",
    "temp_base_identity_candidates",
    "generic_base_identity_candidates",
    "source_identity_gap_candidates",
    "base_stability_blockers",
    "multiple_initializer_base_blockers",
    "reassigned_base_blockers",
    "address_taken_base_blockers",
    "type_evidence_blockers",
    "narrow_subfield_type_blockers",
    "wide_overlay_type_blockers",
    "irregular_overlay_type_blockers",
    "alignment_type_blockers",
    "threshold_gap_candidates",
    "offset_threshold_gap_candidates",
    "access_threshold_gap_candidates",
    "manual_review",
)
_LAYOUT_REWRITE_BLOCKER_MARKDOWN_ITEM_LIMIT = 5
_BODY_OFFSET_RESIDUE_MARKDOWN_ITEM_LIMIT = 20
_BODY_OFFSET_SHAPE_REVIEW_CLASS_ORDER = (
    "dense_offset_shape_missing_identity",
    "parameter_offset_shape_review",
    "context_offset_shape_review",
    "temp_offset_shape_review",
    "low_pressure_offset_residue",
    "unclassified_offset_residue",
)
_BODY_OFFSET_CORE_SUBSYSTEMS = {
    "registry",
    "memory",
    "object",
    "security",
}
_STRUCTURE_QUALITY_COMPONENT_ORDER = (
    "prototype_correctness",
    "call_argument_cleanup",
    "structure_identity_evidence",
    "synthetic_local_aggregate_view",
    "visible_body_improvement",
    "offset_residue",
    "pointer_indexed_residue",
    "generic_identifier_residue",
    "rewrite_safety_blockers",
    "ida_plugin_packaging_boundary",
)
_STRUCTURE_QUALITY_COMPONENT_WEIGHTS = {
    "prototype_correctness": 1.2,
    "call_argument_cleanup": 1.0,
    "structure_identity_evidence": 1.4,
    "synthetic_local_aggregate_view": 0.8,
    "visible_body_improvement": 1.0,
    "offset_residue": 1.5,
    "pointer_indexed_residue": 1.0,
    "generic_identifier_residue": 1.0,
    "rewrite_safety_blockers": 1.1,
    "ida_plugin_packaging_boundary": 0.8,
}
_STRUCTURE_QUALITY_FORBIDDEN_IMPORT_ROOTS = {
    "docs",
    "pseudoforge_out",
    "tests",
    "tools",
}
_BODY_OFFSET_NAMED_GOAL_TARGETS = {
    "CmpSetSecurityDescriptorInfo": "registry",
    "CmpInsertSecurityCellList": "registry",
    "HvReallocateCell": "registry",
    "CmpFreeKeyControlBlock": "registry",
    "MiWsleFree": "memory",
    "MiPrefetchVirtualMemory": "memory",
    "MiDeleteEmptyPageTableCommit": "memory",
    "MiMakeSystemAddressValid": "memory",
    "MiValidateAddPhysicalMemoryParameters": "memory",
    "ObpFreeObject": "object_callback_token",
    "SeQuerySecurityAttributesToken": "object_callback_token",
    "ExpGetNextCallback": "object_callback_token",
}
_BODY_OFFSET_QUEUE_DESCRIPTIONS = {
    "named_goal_targets": (
        "Named high-throughput goal targets; keep them visible even when residue pressure is low."
    ),
    "report_only_exact_promotion_candidates": (
        "Report-only identities with useful aliases; keep canonical rewrite closed until exact private layout source is proven."
    ),
    "report_only_field_alias_review": (
        "Report-only identities with field aliases already available for review, but still closed for canonical rewrite."
    ),
    "source_identity_required": (
        "Candidates blocked by missing trusted function/build/source identity before alias promotion."
    ),
    "source_provenance_review": (
        "Candidates with stable source provenance evidence that can guide exact source identity review."
    ),
    "parameter_field_pointer_alias_candidates": (
        "Parameter-field pointer aliases with concrete source+offset anchors that still need exact containing-object identity."
    ),
    "validated_rewrite_residue": (
        "Validated canonical rewrite outputs that still have residual raw offset dereferences to reread."
    ),
    "nested_field_pointer_residue_candidates": (
        "Parent rewrite exposed nested field-pointer residue; model the nested object separately before widening rewrite."
    ),
    "direct_call_result_layout_candidates": (
        "Direct call-result +0 dereferences where the callee return layout/type identity must be proven first."
    ),
    "direct_base_zero_deref_candidates": (
        "Direct base +0 dereferences that need field-zero/source identity review before any rewrite."
    ),
    "source_bound_live_in_parameter_gap_candidates": (
        "Live-in ABI register gap candidates that also have exact function/build/source-bound identity; review as missing-parameter type leads only."
    ),
    "live_in_parameter_gap_candidates": (
        "Body-offset residue with unresolved live-in ABI register diagnostics that may indicate a missing caller parameter."
    ),
    "callee_arity_residue_candidates": (
        "Body-offset residue with live-in ABI diagnostics that point at callee prototype or helper arity residue, not caller parameters."
    ),
    "source_stability_required": (
        "Candidates whose base object may move, reload, or be reassigned after layout access."
    ),
    "type_conflict_required": (
        "Candidates blocked by mixed width, overlay, or alignment evidence that must be resolved before rewrite."
    ),
    "pointer_indexed_layout_candidates": (
        "Pointer-indexed table, callback-like, or parameter-indexed element shapes; model separately from canonical field rewrite."
    ),
    "dense_shape_identity_candidates": (
        "Dense offset shapes with enough pressure but without a trusted structure/source identity."
    ),
    "parameter_profile_candidates": (
        "Parameter-shaped residue where prototype/domain semantics should be validated first."
    ),
    "context_profile_candidates": (
        "Context-shaped residue where an exact function context profile may improve review quality."
    ),
    "temp_source_identity_candidates": (
        "Temporary-base residue that needs a trusted initializer/source trace before promotion."
    ),
    "low_pressure_deferred": (
        "Low-pressure residue that should usually stay deferred unless a stronger profile appears."
    ),
    "manual_review_required": (
        "Residual items whose current evidence does not fit a sharper fail-closed queue yet."
    ),
}
_PROTOTYPE_CORRECTION_QUEUE_DESCRIPTIONS = {
    "type_assisted_preview_restore_failures": (
        "IDA type-assisted preview attempts that could not prove the original IDB type was restored."
    ),
    "report_only_identity_type_preview_candidates": (
        "Exact report-only function identities with build-bound source context and preview-only parameter corrections."
    ),
    "low_confidence_type_corrections": (
        "Exact prototype candidates blocked only by conservative profile type confidence."
    ),
    "build_mismatch_type_corrections": (
        "Prototype candidates that matched function semantics but not the active build identity."
    ),
    "type_conflict_type_corrections": (
        "Prototype candidates blocked by an unsafe old/new type relationship."
    ),
    "report_only_type_corrections": (
        "Prototype candidates tied to report-only identity evidence; keep IDB mutation closed."
    ),
    "preview_disabled_type_corrections": (
        "Prototype candidates whose profile explicitly disabled preview application."
    ),
}
_PROTOTYPE_CORRECTION_QUEUE_NEXT_STEPS = {
    "type_assisted_preview_restore_failures": (
        "Fix temporary type restoration before trusting this preview path; do not use the cleaned preview as evidence."
    ),
    "report_only_identity_type_preview_candidates": (
        "Use type-assisted decompile preview only; keep body rewrite and IDB mutation closed until exact private layout source identity is proven."
    ),
    "low_confidence_type_corrections": (
        "Reread the profile source and cleaned signature; raise profile confidence only when exact function/build evidence supports the canonical type."
    ),
    "build_mismatch_type_corrections": (
        "Confirm symbol/build compatibility before extending the profile target build list."
    ),
    "type_conflict_type_corrections": (
        "Do not force the correction; refine accepted_types or split the profile by exact function shape."
    ),
    "report_only_type_corrections": (
        "Keep body rewrite and IDB mutation closed; use the profile for preview diagnostics only."
    ),
    "preview_disabled_type_corrections": (
        "Enable preview only when the profile has exact parameter semantics and safe canonical/display types."
    ),
}
_BODY_OFFSET_QUEUE_RECOMMENDED_NEXT_STEPS = {
    "named_goal_targets": (
        "Read the cleaned body first, then apply only exact identity-backed type or body rewrite improvements."
    ),
    "report_only_exact_promotion_candidates": (
        "Read the cleaned body, verify field aliases against exact private layout source evidence, then promote only with source identity."
    ),
    "report_only_field_alias_review": (
        "Use the aliases as review shorthand only; do not enable canonical rewrite until exact build/source identity is proven."
    ),
    "source_identity_required": (
        "Collect exact function, build, source object, and initializer evidence before enabling canonical rewrite."
    ),
    "source_provenance_review": (
        "Follow the recorded direct or field-pointer source alias, then require exact function/build/source identity before promotion."
    ),
    "parameter_field_pointer_alias_candidates": (
        "Use the source+offset anchors to prove the containing object layout; keep temp/generic aliases report-only until exact identity exists."
    ),
    "validated_rewrite_residue": (
        "Compare the canonical cleaned output with the preview artifact and rewrite only advertised same-object residue."
    ),
    "nested_field_pointer_residue_candidates": (
        "Reread the parent field source, identify the nested object layout, and keep parent-body rewrite closed unless exact nested identity is proven."
    ),
    "direct_call_result_layout_candidates": (
        "Verify the callee return type, call arguments, exact source object, and build identity before any field-zero or body rewrite."
    ),
    "direct_base_zero_deref_candidates": (
        "Treat +0 dereferences as field-zero review candidates only; require exact source identity before rendering them as structure fields."
    ),
    "source_bound_live_in_parameter_gap_candidates": (
        "Reread the exact source-bound function and callee argument use; add only a preview-safe parameter correction if the missing ABI slot is proven."
    ),
    "live_in_parameter_gap_candidates": (
        "Reread live-in ABI register diagnostics and callee argument use before adding any caller parameter type correction."
    ),
    "callee_arity_residue_candidates": (
        "Verify the callee contract, helper prototype, and call-site ABI before adding caller parameters or widening the caller signature."
    ),
    "source_stability_required": (
        "Prove a single stable initializer and no risky post-access reassignment for the candidate base."
    ),
    "type_conflict_required": (
        "Resolve subfield width, overlay, and alignment conflicts or keep aliases report-only."
    ),
    "pointer_indexed_layout_candidates": (
        "Treat table slots, callback arrays, and parameter-indexed elements as indexed layouts instead of field rewrites."
    ),
    "dense_shape_identity_candidates": (
        "Add a function-scoped identity only when the dense base has exact source and build provenance."
    ),
    "parameter_profile_candidates": (
        "Validate parameter meaning and corrected type evidence before adding or widening a profile."
    ),
    "context_profile_candidates": (
        "Add a narrow context profile only when the context structure is function-scoped and source-backed."
    ),
    "temp_source_identity_candidates": (
        "Trace the temp initializer and prove it aliases a trusted source object before promotion."
    ),
    "low_pressure_deferred": (
        "Defer unless this function is a named subsystem target or repeated corpus evidence raises pressure."
    ),
    "manual_review_required": (
        "Classify the residue by subsystem, base shape, and source identity before adding a profile."
    ),
}
_BODY_OFFSET_PRIORITY_BONUSES = {
    "named_goal_target": 18,
    "registry_goal_target": 12,
    "memory_goal_target": 12,
    "object_callback_token_goal_target": 12,
    "core_subsystem": 8,
    "high_offset_residue": 14,
    "medium_offset_residue": 7,
    "high_field_access_pressure": 8,
    "source_build_mismatch": 12,
    "report_only_field_alias_available": 10,
    "exact_private_layout_required": 8,
    "source_stability_gate": 8,
    "type_conflict_gate": 8,
    "pointer_indexed_shape": 6,
    "parameter_indexed_element_shape": 6,
    "nested_field_pointer_residue": 7,
    "validated_rewrite_residue": 7,
    "parameter_type_followup": 5,
    "dense_shape_without_identity": 6,
    "stable_source_provenance_available": 7,
    "parameter_field_pointer_alias_review": 8,
    "direct_parameter_source_alias": 6,
    "validated_secondary_residue": 6,
    "generic_context_identity_gap": 6,
    "high_pressure_unresolved_residue": 5,
    "direct_base_zero_residue": 5,
    "source_bound_live_in_parameter_gap": 12,
    "live_in_parameter_gap": 9,
    "callee_arity_residue": 7,
    "named_target_direct_base_residue": 6,
    "high_pressure_report_only_alias": 7,
    "core_report_only_deferred_shape": 5,
    "manual_review_gap": 4,
}
_BASE_STABILITY_REVIEW_PROFILE_ORDER = (
    "initializer_dominance_review",
    "initializer_and_reassignment_risk",
    "post_access_reassignment_risk",
    "single_initializer_trace",
    "missing_initializer_trace",
)
_BASE_STABILITY_MARKDOWN_ITEM_LIMIT = 5
_DECIMAL_STATUS_REVIEW_QUEUE_ORDER = (
    "strong_profiled_status_literals",
    "weak_target_profiled_status_literals",
    "unprofiled_ntstatus_error_literals",
    "nonstatus_magic_literals",
    "nonstatus_ascii_magic_literals",
    "nonstatus_bitmask_comparisons",
    "nonstatus_small_enum_comparisons",
    "nonstatus_debug_exception_assignments",
    "manual_review",
)
_DECIMAL_STATUS_TARGET_REVIEW_QUEUE_ORDER = (
    "complex_or_memory_targets",
    "four_byte_scalar_targets",
    "wide_or_nonstatus_targets",
    "unknown_targets",
)
_STATUS_STORE_REVIEW_QUEUE_ORDER = (
    "dword_nested_pointer_status_stores",
    "wide_nested_pointer_status_stores",
    "manual_review",
)
FIELD_PREVIEW_RE = re.compile(r"-\s+inferred_offset_field_preview:")
FIELD_ALIAS_RE = re.compile(r"-\s+inferred_offset_field_aliases:")
FIELD_HOT_CLUSTER_RE = re.compile(r"-\s+inferred_offset_field_hot_cluster:")
FIELD_HOT_CLUSTER_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_field_hot_cluster:\s+Hot field cluster for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s+\((?P<base_kind>[a-z ]+)\s+base\):\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+concentrated in\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\);\s+top fields\s+"
    r"(?P<fields>.*?)\.\s+Review-only access-pressure evidence;\s+"
    r"no structure type or body rewrite was inferred\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_INDEXED_CALLBACK_TABLE_RE = re.compile(
    r"-\s+inferred_offset_indexed_callback_table_evidence:"
)
FIELD_INDEXED_CALLBACK_TABLE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_indexed_callback_table_evidence:\s+"
    r"Indexed layout evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s+\((?P<base_kind>[a-z ]+)\s+base\):\s+"
    r"(?P<access_count>\d+)\s+indexed/callback access\(es\)\s+across\s+"
    r"(?P<slot_count>\d+)\s+slot\(s\);\s+scalar indexes\s+"
    r"(?P<scalar_indexes>.*?);\s+callback slots\s+"
    r"(?P<callback_slots>.*?)\.\s+"
    r"(?:Alias bases\s+(?P<alias_bases>.*?)\.\s+)?"
    r"Review-only;\s+indexed table access is not used for canonical field rewrite\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_PARAMETER_INDEXED_ELEMENT_RE = re.compile(
    r"-\s+inferred_offset_parameter_indexed_element:"
)
FIELD_PARAMETER_INDEXED_ELEMENT_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_parameter_indexed_element:\s+"
    r"Parameter-indexed element evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+aliases\s+"
    r"(?P<parent>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+via alias\s+(?P<parent_alias>[A-Za-z_][A-Za-z0-9_]*))?\s+\+\s+"
    r"(?P<stride>\d+)\s+\*\s+(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*;\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across element offset\(s\)\s+"
    r"(?P<offsets>.*?);\s+observed types\s+"
    r"(?P<types>.*?)\.\s+"
    r"(?:Parent parameter type\s+(?P<parent_type>.*?)\.\s+)?"
    r"Review-only;\s+do not canonical-rewrite array element fields without exact function/build/source layout identity\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_SUBFIELD_OVERLAY_RE = re.compile(r"-\s+inferred_offset_subfield_overlays:")
FIELD_SUBFIELD_OVERLAY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_subfield_overlays:\s+"
    r"(?:Subfield overlay evidence for|Review subfield overlays for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Review-only(?: evidence)?;\s+"
    r"field rewrite remains blocked for mixed-width offsets\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_NARROW_SUBFIELD_RE = re.compile(r"-\s+inferred_offset_narrow_subfields:")
FIELD_NARROW_SUBFIELD_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_narrow_subfields:\s+"
    r"(?:Narrow subfield candidates for|Review narrow subfields for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Audit-only;\s+"
    r"body rewrite remains disabled until the parent structure is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_BITFIELD_ALIAS_RE = re.compile(r"-\s+inferred_offset_bitfield_aliases:")
FIELD_BITFIELD_ALIAS_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_bitfield_aliases:\s+"
    r"(?:Bitfield aliases for|Review bitfield aliases for)\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s+\([^)]*\))?:\s+"
    r"(?P<fields>.*?)\.\s+Review-only names;\s+"
    r"body rewrite remains disabled until the parent structure is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_STABLE_BASE_SOURCE_RE = re.compile(r"-\s+inferred_offset_stable_base_source:")
FIELD_STABLE_BASE_SOURCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_stable_base_source:\s+Stable base source for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<source>.*?)\s+"
    r"\((?P<source_kind>[a-z_]+)\s+source(?:,\s+(?P<source_provenance>[a-z_]+))?\),\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\.\s+"
    r"(?:Source detail\s+(?P<source_detail>.*?)\.\s+)?"
    r"(?:Review-only; temp/generic base keeps rewrite blocked until source identity is trusted|"
    r"Review-only source identity evidence for temp/generic base promotion)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_BASE_STABILITY_RE = re.compile(r"-\s+inferred_offset_base_stability:")
FIELD_BASE_STABILITY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_base_stability:\s+Base stability evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<pre_access_assignment_count>\d+)\s+initializer\(s\)\s+before first layout access across\s+"
    r"(?P<distinct_pre_access_rhs_count>\d+)\s+distinct RHS\s+\((?P<rhs>.*?)\);\s+"
    r"(?P<post_access_assignment_count>\d+)\s+post-access assignment\(s\),\s+"
    r"(?P<risky_post_access_assignment_count>\d+)\s+followed by later layout access\.\s+"
    r"(?:Post-access assignment samples:\s+.*?\.\s+)?"
    r"Review initializer dominance before enabling canonical rewrite\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_BASE_RELOCATION_EVIDENCE_RE = re.compile(r"-\s+inferred_offset_base_relocation_evidence:")
FIELD_BASE_MERGE_EVIDENCE_RE = re.compile(r"-\s+inferred_offset_base_merge_evidence:")
FIELD_BUGCHECK_PARAMETER_MERGE_IDENTITY_RE = re.compile(
    r"-\s+inferred_offset_bugcheck_parameter_merge_identity:"
)
FIELD_CALL_RESULT_MERGE_EQUIVALENCE_RE = re.compile(
    r"-\s+inferred_offset_call_result_merge_equivalence:"
)
FIELD_ALLOCATION_NULL_MERGE_DOMINANCE_RE = re.compile(
    r"-\s+inferred_offset_allocation_null_merge_dominance:"
)
FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_RE = re.compile(
    r"-\s+inferred_offset_call_result_parameter_merge_provenance:"
)
FIELD_CALL_RESULT_TEMPORARY_MERGE_PROVENANCE_RE = re.compile(
    r"-\s+inferred_offset_call_result_temporary_merge_provenance:"
)
FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_RE = re.compile(
    r"-\s+inferred_offset_same_source_family_merge_dominance:"
)
FIELD_TRUSTED_TEMP_SOURCE_RE = re.compile(r"-\s+inferred_offset_trusted_temp_source:")
FIELD_TRUSTED_TEMP_SOURCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_trusted_temp_source:\s+Trusted temp-base source for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+source\s+"
    r"(?P<source>.*?)\s+\((?P<source_kind>[a-z_]+)/(?P<source_provenance>[a-z_]+)\),\s+"
    r"origin\s+(?P<source_origin>[a-z_]+),\s+promotion ready\s+(?P<promotion_ready>yes|no),\s+"
    r"first layout access line\s+(?P<first_layout_access_line>-?\d+)\.\s+"
    r"Single-source lifetime, blocker-free mutation, and threshold gates are satisfied\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_TEMP_PROVENANCE_TRACE_RE = re.compile(r"-\s+inferred_offset_temp_provenance_trace:")
FIELD_TEMP_PROVENANCE_TRACE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_temp_provenance_trace:\s+Temp-base provenance trace for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+trust class\s+"
    r"(?P<trust_class>[a-z_]+),\s+source\s+"
    r"(?P<source>.*?)\s+\((?P<source_kind>[a-z_]+)/(?P<source_provenance>[a-z_]+)\),\s+"
    r"origin\s+(?P<source_origin>[a-z_]+),\s+first layout access line\s+"
    r"(?P<first_layout_access_line>-?\d+),\s+pre-access initializers\s+"
    r"(?P<pre_access_assignment_count>\d+)/(?P<distinct_pre_access_rhs_count>\d+),\s+"
    r"post-access assignments\s+(?P<post_access_assignment_count>\d+)\s+risky\s+"
    r"(?P<risky_post_access_assignment_count>\d+),\s+pointer mutation\s+"
    r"(?P<pointer_mutation>yes|no),\s+address-taken\s+(?P<address_taken>yes|no),\s+"
    r"array-indexed\s+(?P<array_indexed>yes|no),\s+call-mutation-risk\s+"
    r"(?P<call_mutation_risk>yes|no),\s+branch merge\s+(?P<branch_merge_shape>[a-z_]+),\s+"
    r"guard dominance\s+(?P<guard_dominance>[a-z_]+)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_TEMP_PROMOTION_BLOCKED_RE = re.compile(r"-\s+inferred_offset_temp_promotion_blocked:")
FIELD_TEMP_PROMOTION_BLOCKED_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_temp_promotion_blocked:\s+Temp-base promotion blocked for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+trust class\s+"
    r"(?P<trust_class>[a-z_]+),\s+reasons\s+(?P<block_reasons>.*?)\.\s+"
    r"Rewrite blockers\s+(?P<rewrite_blockers>.*?)\.\s+"
    r"Canonical rewrite remains disabled until provenance, dominance, and mutation gates are clear\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_SAME_FAMILY_MERGE_PROVENANCE_RE = re.compile(r"-\s+inferred_offset_same_family_merge_provenance:")
FIELD_CALL_RESULT_PARAMETER_DOMINANCE_RE = re.compile(
    r"-\s+inferred_offset_call_result_parameter_dominance:"
)
FIELD_POST_ACCESS_MUTATION_BLOCKER_RE = re.compile(
    r"-\s+inferred_offset_post_access_mutation_blocker:"
)
FIELD_GENERIC_BASE_EVIDENCE_RE = re.compile(r"-\s+inferred_offset_generic_base_evidence:")
FIELD_GENERIC_BASE_EVIDENCE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_generic_base_evidence:\s+Generic base evidence for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+blocker profile\s+"
    r"(?P<blocker_profile>[a-z_]+)\.\s+"
    r"Review-only; rewrite remains blocked until the base identity is trusted\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_GENERIC_BASE_TRUST_CANDIDATE_RE = re.compile(r"-\s+inferred_offset_generic_base_trust_candidate:")
FIELD_GENERIC_BASE_TRUST_CANDIDATE_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_generic_base_trust_candidate:\s+Generic base trust candidate for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<source_kind>[a-z_]+)\s+source,\s+"
    r"(?P<blocker_profile>[a-z-]+)\s+blockers,\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\.\s+"
    r"Promotion eligible only when no other rewrite blocker is present;\s+"
    r"canonical rewrite still requires explicit validation-gated export\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
SUBFIELD_OVERLAY_FIELD_RE = re.compile(
    r"\+0x(?P<offset>[0-9A-Fa-f]+)\s+field_[0-9A-Fa-f]+\s+uses\s+"
    r"(?P<sizes>[0-9/]+)-byte accesses\s+\((?P<types>[^)]*)\)"
    r"(?:\s+\[(?P<annotation>[^\]]+)\])?"
)
BITFIELD_ALIAS_FIELD_RE = re.compile(
    r"field_(?P<offset>[0-9A-Fa-f]+)=\+0x[0-9A-Fa-f]+\s+"
    r"(?P<aliases>[A-Za-z0-9_/,]+)\s+masks=(?P<masks>[0-9A-Fa-fx,]+|unknown)"
)
HOT_CLUSTER_FIELD_RE = re.compile(
    r"(?P<name>field_[0-9A-Fa-f]+)=\+0x(?P<offset>[0-9A-Fa-f]+)\s+"
    r"(?P<type>.*?)\s+x(?P<access_count>\d+)$"
)
FIELD_REWRITE_READY_RE = re.compile(r"-\s+inferred_offset_rewrite_ready:")
FIELD_REWRITE_READY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_ready:\s+Offset field rewrite candidate for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+no rewrite blockers found\.\s+"
    r"(?:Source provenance\s+(?P<source_provenance>[a-z_]+)\s+from\s+"
    r"(?P<source>.*?)\.\s+)?"
    r"(?:Threshold policy\s+(?P<threshold_policy>[a-z_]+)\.\s+)?"
    r"(?:Audit only; body rewrite was not applied|Validated layout rewrite applied to canonical cleaned output)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_PREVIEW_RE = re.compile(r"-\s+inferred_offset_rewrite_preview:")
FIELD_REWRITE_PREVIEW_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_preview:\s+Offset field rewrite preview for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+dereference\(s\)\s+can map to\s+"
    r"(?P<field_count>\d+)\s+field alias\(es\)\s+"
    r"(?P<fields>.*?)\.\s+"
    r"(?:Source provenance\s+(?P<source_provenance>[a-z_]+)\s+from\s+"
    r"(?P<source>.*?)\.\s+)?"
    r"(?:Preview artifact only; body rewrite was not applied|Validated layout rewrite applied to canonical cleaned output)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_NEAR_READY_RE = re.compile(r"-\s+inferred_offset_rewrite_near_ready:")
FIELD_REWRITE_NEAR_READY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_near_ready:\s+Offset field rewrite near-ready for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\),\s+missing\s+"
    r"(?P<missing>offset|access)\s+threshold only\.\s+"
    r"Audit only; body rewrite was not applied\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_PARTIAL_OPPORTUNITY_RE = re.compile(r"-\s+inferred_offset_rewrite_partial_opportunity:")
FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_partial_opportunity:\s+"
    r"Offset field partial rewrite opportunity for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<safe_access_count>\d+)\s+safe dereference\(s\)\s+across\s+"
    r"(?P<safe_offset_count>\d+)\s+safe offset\(s\),\s+"
    r"(?P<excluded_access_count>\d+)\s+excluded dereference\(s\)\s+across\s+"
    r"(?P<excluded_offset_count>\d+)\s+excluded offset\(s\),\s+"
    r"safe fields\s+(?P<safe_fields>.*?)\.\s+"
    r"(?:Safe offsets\s+(?P<safe_offsets>.*?)\;\s+excluded offsets\s+"
    r"(?P<excluded_offsets>.*?)\.\s+)?"
    r"Excluded reasons\s+(?P<reasons>.*?)\.\s+"
    r"(?:Source provenance\s+(?P<source_provenance>[a-z_]+)\s+from\s+"
    r"(?P<source>.*?)\.\s+)?"
    r"(?P<disposition>Review-only; canonical body rewrite remains disabled until partial rewrite validation is implemented|"
    r"Validated partial layout rewrite applied to canonical cleaned output)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
FIELD_REWRITE_BLOCKER_RE = re.compile(r"-\s+inferred_offset_rewrite_blockers:")
FIELD_ALIAS_NAME_RE = re.compile(r"\bfield_[0-9A-Fa-f]+\b")
DOMAIN_FIELD_OFFSET_RE = re.compile(r"\+0x[0-9A-Fa-f]+")
FIELD_REWRITE_BLOCKER_DETAIL_RE = re.compile(
    r"-\s+inferred_offset_rewrite_blockers:\s+Offset field rewrite blocked for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+"
    r"(?P<reasons>.*?)\.\s+"
    r"(?:Domain identity\s+(?P<domain_blocker_profile_id>[A-Za-z0-9_.-]+)\s+"
    r"\((?P<domain_blocker_role>[A-Za-z_][A-Za-z0-9_]*)/"
    r"(?P<domain_blocker_structure>[A-Za-z_][A-Za-z0-9_]*)\)\s+"
    r"is report-only;\s+exact function/build/private-layout source identity is required before canonical rewrite\.\s+)?"
    r"(?:Source identity\s+(?P<source>.*?)\s+"
    r"\((?P<source_provenance>[a-z_]+)\)\s+is report-only profile\s+"
    r"(?P<source_profile_id>[A-Za-z0-9_.-]+)\s+for\s+"
    r"(?P<source_role>[A-Za-z_][A-Za-z0-9_]*)/"
    r"(?P<source_structure>[A-Za-z_][A-Za-z0-9_]*)"
    r"; exact function/build/source identity is required before canonical rewrite\.\s+)?"
    r"Review-only aliases remain available\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
DOMAIN_STRUCTURE_IDENTITY_DETAIL_RE = re.compile(
    r"-\s+domain_structure_identity:\s+Domain identity for\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*:\s+role\s+"
    r"(?P<role>[A-Za-z_][A-Za-z0-9_]*)\s*,\s+structure\s+"
    r"(?P<structure>[A-Za-z_][A-Za-z0-9_]*)\s*,\s+mode\s+"
    r"(?P<mode>[A-Za-z0-9_-]+)\s*,\s+profile\s+"
    r"(?P<profile_id>[A-Za-z0-9_.-]+)\s+parameter\s+"
    r"(?P<parameter>.*?)\.\s+Fields\s+(?P<fields>.*?)\.\s+"
)
LAYOUT_HINT_RE = re.compile(
    r"-\s+inferred_offset_layout:\s+Offset layout hint:\s+"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s+has\s+"
    r"(?P<access_count>\d+)\s+typed dereference\(s\)\s+across\s+"
    r"(?P<offset_count>\d+)\s+offset\(s\)\s+"
    r"(?P<offsets>[^;]*);\s+observed types:\s+"
    r"(?P<types>.*?)\.\s+Review as (?P<review>[^.]+)\.\s+"
    r"confidence=(?P<confidence>\d+(?:\.\d+)?)"
)
VISIBLE_REVIEW_ONLY_FIELD_ALIAS_RE = re.compile(r"//\s*PseudoForge review-only:[^\n]*\bno rewrite\b")
VISIBLE_REVIEW_ONLY_FIELD_ALIAS_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\s+\([^)\n]*\+0x[0-9A-Fa-f]+[^)\n]*\)"
)
SYNTHETIC_AGGREGATE_COMMENT_RE = re.compile(r"\bsynthetic_(?:local|pool)_aggregate\b")
SYNTHETIC_POOL_AGGREGATE_COMMENT_RE = re.compile(r"\bsynthetic_pool_aggregate\b")
SYNTHETIC_BLOCKED_AGGREGATE_COMMENT_RE = re.compile(r"\bsynthetic_(?:local|pool)_aggregate\b[^\n]*\bdecision=blocked\b")
INLINE_REVIEW_ONLY_AGGREGATE_ALIAS_RE = re.compile(
    r"//\s*PseudoForge review-only:[^\n]*\binferred (?:stack aggregate|strided record)\b[^\n]*\bno rewrite\b"
)
INLINE_REVIEW_ONLY_AGGREGATE_ALIAS_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\.field_[0-9A-Fa-f]+\s+\([^)\n]*\binferred (?:stack aggregate|strided record)\b[^)\n]*\)"
)
AGGREGATE_MISLEADING_REWRITE_RE = re.compile(
    r"PseudoForge projected:[^\n]*\b(?:blocked|misleading)\b"
)
PROJECTED_AGGREGATE_ACCESS_RE = re.compile(r"//\s*PseudoForge projected:[^\n]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*[^\n]*")
PROJECTED_AGGREGATE_ACCESS_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*\s+\(\+0x[0-9A-Fa-f]+,\s*(?:high|medium|low),\s*(?P<policy>[A-Za-z_]+)\)"
)

ARTIFACT_SUFFIXES = {
    "cleaned_pseudocode": ".cleaned.cpp",
    "raw_pseudocode": ".raw.cpp",
    "rename_map": ".rename-map.json",
    "warnings": ".warnings.json",
    "buffer_contracts": ".buffer-contracts.json",
    "rule_report": ".rule-report.json",
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        manual_reread = _load_manual_reread(args.manual_reread)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    report = analyze_corpus(
        args.corpus_root,
        sample_limit=max(0, args.sample_limit),
        text_scan=not args.no_text_scan,
        top=max(1, args.top),
        ea_filter=_load_ea_filter(args.ea, args.ea_file),
        manual_reread=manual_reread,
    )
    outputs = []
    if args.out:
        output_dir = Path(args.out)
        output_dir.mkdir(parents=True, exist_ok=True)
        if args.format in {"json", "both"}:
            json_path = output_dir / "corpus-quality.json"
            json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            outputs.append(str(json_path))
        if args.format in {"markdown", "both"}:
            markdown_path = output_dir / "corpus-quality.md"
            markdown_path.write_text(render_quality_markdown(report), encoding="utf-8")
            outputs.append(str(markdown_path))
        print("Wrote corpus quality report: %s" % ", ".join(outputs))
        return 0

    if args.format == "markdown":
        print(render_quality_markdown(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze PseudoForge IDA batch corpus quality and cleanup failure patterns."
    )
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("--corpus-root", required=True, help="PseudoForge IDA batch output directory.")
    parser.add_argument("--out", default="", help="Optional output directory for corpus-quality.json/md.")
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "both"),
        default="json",
        help="Output format. With --out, both writes JSON and Markdown.",
    )
    parser.add_argument("--sample-limit", type=int, default=0, help="Analyze only the first N function summaries.")
    parser.add_argument("--ea", action="append", default=[], help="Only analyze this function EA. Can be repeated.")
    parser.add_argument(
        "--ea-file",
        default="",
        help="Only analyze function EAs listed in this text file. Whitespace, comma, and semicolon separators are accepted.",
    )
    parser.add_argument("--no-text-scan", action="store_true", help="Skip cleaned pseudocode text pattern scan.")
    parser.add_argument("--top", type=int, default=20, help="Number of top warning functions/classes to include.")
    parser.add_argument(
        "--manual-reread",
        default="",
        help="Optional JSON evidence file for the manual reread hard gate.",
    )
    return parser


def analyze_corpus(
    corpus_root: str | Path,
    *,
    sample_limit: int = 0,
    text_scan: bool = True,
    top: int = 20,
    ea_filter: set[int] | None = None,
    manual_reread: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(corpus_root)
    functions_root = root / "functions" if (root / "functions").exists() else root
    summary_paths = _selected_summary_paths(
        functions_root,
        ea_filter=ea_filter,
        sample_limit=sample_limit,
    )

    warning_classes: Counter[str] = Counter()
    llm_statuses: Counter[str] = Counter()
    rename_sources: Counter[str] = Counter()
    rename_sources_applied: Counter[str] = Counter()
    rewrite_kinds: Counter[str] = Counter()
    api_semantic_reasons: Counter[str] = Counter()
    api_semantic_stages: Counter[str] = Counter()
    api_semantic_statuses: Counter[str] = Counter()
    api_semantic_profiles: Counter[str] = Counter()
    layout_hint_bases: Counter[str] = Counter()
    layout_hint_types: Counter[str] = Counter()
    layout_totals = Counter()
    subfield_overlay_bases: Counter[str] = Counter()
    subfield_overlay_size_classes: Counter[str] = Counter()
    subfield_overlay_policy_classes: Counter[str] = Counter()
    subfield_overlay_interpretations: Counter[str] = Counter()
    subfield_overlay_bit_masks: Counter[str] = Counter()
    subfield_overlay_bit_operations: Counter[str] = Counter()
    subfield_overlay_mask_families: Counter[str] = Counter()
    subfield_overlay_totals = Counter()
    narrow_subfield_bases: Counter[str] = Counter()
    narrow_subfield_size_classes: Counter[str] = Counter()
    narrow_subfield_interpretations: Counter[str] = Counter()
    narrow_subfield_bit_masks: Counter[str] = Counter()
    narrow_subfield_bit_operations: Counter[str] = Counter()
    narrow_subfield_mask_families: Counter[str] = Counter()
    narrow_subfield_totals = Counter()
    bitfield_alias_bases: Counter[str] = Counter()
    bitfield_alias_names: Counter[str] = Counter()
    bitfield_alias_masks: Counter[str] = Counter()
    bitfield_alias_totals = Counter()
    hot_field_cluster_bases: Counter[str] = Counter()
    hot_field_cluster_base_kinds: Counter[str] = Counter()
    hot_field_cluster_field_types: Counter[str] = Counter()
    hot_field_cluster_totals = Counter()
    indexed_callback_table_bases: Counter[str] = Counter()
    indexed_callback_table_base_kinds: Counter[str] = Counter()
    indexed_callback_table_alias_bases: Counter[str] = Counter()
    indexed_callback_table_totals = Counter()
    parameter_indexed_element_bases: Counter[str] = Counter()
    parameter_indexed_element_parents: Counter[str] = Counter()
    parameter_indexed_element_parent_types: Counter[str] = Counter()
    parameter_indexed_element_strides: Counter[str] = Counter()
    parameter_indexed_element_totals = Counter()
    stable_base_source_bases: Counter[str] = Counter()
    stable_base_source_sources: Counter[str] = Counter()
    stable_base_source_kinds: Counter[str] = Counter()
    stable_base_source_provenance: Counter[str] = Counter()
    stable_base_source_totals = Counter()
    base_stability_bases: Counter[str] = Counter()
    base_stability_rhs: Counter[str] = Counter()
    base_stability_profiles: Counter[str] = Counter()
    base_stability_review_queues: dict[str, list[dict[str, Any]]] = {}
    base_stability_totals = Counter()
    generic_base_evidence_bases: Counter[str] = Counter()
    generic_base_evidence_profiles: Counter[str] = Counter()
    generic_base_evidence_totals = Counter()
    generic_base_trust_candidate_bases: Counter[str] = Counter()
    generic_base_trust_candidate_sources: Counter[str] = Counter()
    generic_base_trust_candidate_profiles: Counter[str] = Counter()
    generic_base_trust_candidate_totals = Counter()
    temp_provenance_bases: Counter[str] = Counter()
    temp_provenance_trust_classes: Counter[str] = Counter()
    temp_provenance_source_origins: Counter[str] = Counter()
    temp_provenance_source_kinds: Counter[str] = Counter()
    temp_provenance_source_provenance: Counter[str] = Counter()
    temp_provenance_branch_shapes: Counter[str] = Counter()
    temp_provenance_guard_dominance: Counter[str] = Counter()
    temp_provenance_block_reasons: Counter[str] = Counter()
    temp_provenance_totals = Counter()
    rewrite_ready_bases: Counter[str] = Counter()
    rewrite_ready_source_provenance: Counter[str] = Counter()
    rewrite_ready_threshold_policies: Counter[str] = Counter()
    rewrite_ready_totals = Counter()
    rewrite_preview_bases: Counter[str] = Counter()
    rewrite_preview_source_provenance: Counter[str] = Counter()
    rewrite_preview_totals = Counter()
    rewrite_preview_artifact_statuses: Counter[str] = Counter()
    rewrite_preview_artifact_canonical_statuses: Counter[str] = Counter()
    rewrite_preview_artifact_plan_kinds: Counter[str] = Counter()
    rewrite_preview_artifact_failed_checks: Counter[str] = Counter()
    rewrite_preview_artifact_totals = Counter()
    pointer_indexed_offset_totals = Counter()
    pointer_indexed_offset_bases: Counter[str] = Counter()
    pointer_indexed_offset_rewritten_bases: Counter[str] = Counter()
    rewrite_near_ready_bases: Counter[str] = Counter()
    rewrite_near_ready_missing: Counter[str] = Counter()
    rewrite_near_ready_totals = Counter()
    rewrite_partial_opportunity_bases: Counter[str] = Counter()
    rewrite_partial_opportunity_source_provenance: Counter[str] = Counter()
    rewrite_partial_opportunity_reasons: Counter[str] = Counter()
    rewrite_partial_opportunity_application_statuses: Counter[str] = Counter()
    rewrite_partial_opportunity_review_classes: Counter[str] = Counter()
    rewrite_partial_opportunity_totals = Counter()
    rewrite_blocker_bases: Counter[str] = Counter()
    rewrite_blocker_reasons: Counter[str] = Counter()
    rewrite_blocker_review_profiles: Counter[str] = Counter()
    rewrite_blocker_review_queues: dict[str, list[dict[str, Any]]] = {}
    rewrite_blocker_totals = Counter()
    body_offset_residue_totals = Counter()
    evidence_graph_totals = Counter()
    evidence_graph_node_kinds: Counter[str] = Counter()
    evidence_graph_edge_kinds: Counter[str] = Counter()
    evidence_graph_promotion_lanes: Counter[str] = Counter()
    evidence_graph_blockers: Counter[str] = Counter()
    body_offset_residue_subsystems: Counter[str] = Counter()
    body_offset_residue_next_actions: Counter[str] = Counter()
    body_offset_residue_review_classes: Counter[str] = Counter()
    body_offset_residue_blocker_reasons: Counter[str] = Counter()
    body_offset_residue_review_evidence: Counter[str] = Counter()
    body_offset_residue_promotion_hints: Counter[str] = Counter()
    body_offset_residue_promotion_lanes: Counter[str] = Counter()
    body_offset_residue_next_action_details: Counter[str] = Counter()
    body_offset_residue_priority_factors: Counter[str] = Counter()
    body_offset_residue_review_notes: Counter[str] = Counter()
    body_offset_residue_fail_closed_gates: Counter[str] = Counter()
    body_offset_residue_fail_closed_families: Counter[str] = Counter()
    body_offset_residue_review_focuses: Counter[str] = Counter()
    body_offset_residue_shape_classes: Counter[str] = Counter()
    body_offset_residue_base_classes: Counter[str] = Counter()
    body_offset_residue_direct_base_classes: Counter[str] = Counter()
    body_offset_residue_named_target_groups: Counter[str] = Counter()
    body_offset_residue_safety_policies: Counter[str] = Counter()
    body_offset_residue_evidence_maturity: Counter[str] = Counter()
    body_offset_residue_cause_tags: Counter[str] = Counter()
    body_offset_residue_stable_source_details: Counter[str] = Counter()
    decimal_status_residue_values: Counter[str] = Counter()
    decimal_status_residue_profiles: Counter[str] = Counter()
    decimal_status_residue_context_kinds: Counter[str] = Counter()
    decimal_status_residue_review_classes: Counter[str] = Counter()
    decimal_status_residue_target_evidence: Counter[str] = Counter()
    decimal_status_residue_target_review_hints: Counter[str] = Counter()
    nested_status_store_values: Counter[str] = Counter()
    nested_status_store_profiles: Counter[str] = Counter()
    nested_status_store_widths: Counter[str] = Counter()
    nested_status_store_review_classes: Counter[str] = Counter()
    ntstatus_body_unprofiled_values: Counter[str] = Counter()
    ntstatus_body_unprofiled_value_functions: dict[str, set[str]] = {}
    ntstatus_body_unprofiled_value_contexts: dict[str, Counter[str]] = {}
    ntstatus_body_unprofiled_context_kinds: Counter[str] = Counter()
    prototype_totals = Counter()
    prototype_blockers: Counter[str] = Counter()
    prototype_profiles: Counter[str] = Counter()
    prototype_function_profiles: Counter[str] = Counter()
    prototype_canonical_types: Counter[str] = Counter()
    prototype_body_rewrite_sources: Counter[str] = Counter()
    prototype_report_only_preview_profiles: Counter[str] = Counter()
    prototype_type_assisted_preview_statuses: Counter[str] = Counter()
    totals = Counter()
    text_totals = Counter()
    body_text_totals = Counter()
    top_warning_functions = []
    existing_parameter_alias_actions: Counter[str] = Counter()
    existing_parameter_alias_registers: Counter[str] = Counter()
    top_existing_parameter_alias_functions: list[dict[str, Any]] = []
    top_api_semantic_functions = []
    api_semantic_queue_items: list[dict[str, Any]] = []
    top_layout_hint_functions = []
    top_subfield_overlay_functions = []
    top_narrow_subfield_functions = []
    top_bitfield_alias_functions = []
    top_hot_field_cluster_functions = []
    top_indexed_callback_table_functions = []
    top_parameter_indexed_element_functions = []
    top_stable_base_source_functions = []
    top_base_stability_functions = []
    top_generic_base_evidence_functions = []
    top_generic_base_trust_candidate_functions = []
    top_temp_provenance_functions = []
    top_rewrite_ready_functions = []
    top_rewrite_preview_functions = []
    top_rewrite_preview_artifact_functions = []
    top_pointer_indexed_offset_functions = []
    top_rewrite_near_ready_functions = []
    top_rewrite_partial_opportunity_functions = []
    top_rewrite_blocker_functions = []
    top_body_offset_residue_functions = []
    top_evidence_graph_functions = []
    top_decimal_status_residue_functions = []
    top_nested_status_store_functions = []
    top_ntstatus_body_unprofiled_functions = []
    top_prototype_correction_functions = []
    prototype_negative_control_functions = []
    analyzed_functions: list[dict[str, Any]] = []

    for summary_path in summary_paths:
        summary = _coerce_dict(_read_json(summary_path))
        artifacts = _coerce_dict(summary.get("artifacts", {}))
        name = str(summary.get("function", "") or summary_path.parent.name)
        ea = str(summary.get("function_ea", ""))
        warnings = _read_warnings(_artifact_path(summary_path, artifacts, "warnings"))
        warning_diagnostics = _read_warning_diagnostics(_artifact_path(summary_path, artifacts, "warning_diagnostics"))
        rename_items = _read_rename_items(_artifact_path(summary_path, artifacts, "rename_map"))
        rule_report = _coerce_dict(_read_json(_artifact_path(summary_path, artifacts, "rule_report")))
        evidence_graph = _coerce_dict(summary.get("evidence_graph", {}))
        buffer_contracts = _read_list(_artifact_path(summary_path, artifacts, "buffer_contracts"))
        cleaned_path = _artifact_path(summary_path, artifacts, "cleaned_pseudocode")
        raw_path = _artifact_path(summary_path, artifacts, "raw_pseudocode")
        warning_diagnostics = _normalize_warning_diagnostics_for_quality(
            warning_diagnostics,
            rename_items,
            cleaned_path,
        )
        warning_class_items: list[Any] = warning_diagnostics if warning_diagnostics else warnings
        warning_count = _effective_warning_count(summary, warnings, warning_diagnostics)
        analyzed_functions.append(
            {
                "name": name,
                "ea": ea,
                "summary_path": str(summary_path),
                "cleaned_path": str(cleaned_path),
                "named_goal_target_group": _body_offset_named_goal_target_group(name),
            }
        )
        rewrite_preview_metadata = _coerce_dict(
            _read_json(_artifact_path(summary_path, artifacts, "layout_rewrite_preview_metadata"))
        )
        if not rewrite_preview_metadata:
            rewrite_preview_metadata = _embedded_primary_layout_rewrite_metadata(
                summary,
                cleaned_path,
            )
        prototype_metrics = _prototype_correction_function_metrics(
            summary,
            cleaned_path if text_scan else Path(),
        )
        _update_prototype_correction_metrics(
            prototype_metrics,
            prototype_totals,
            prototype_blockers,
            prototype_profiles,
            prototype_function_profiles,
            prototype_canonical_types,
            prototype_body_rewrite_sources,
            prototype_report_only_preview_profiles,
            prototype_type_assisted_preview_statuses,
        )
        if bool(prototype_metrics.get("has_correction_evidence")):
            top_prototype_correction_functions.append(
                _prototype_correction_function_summary(name, ea, summary_path, prototype_metrics)
            )
        else:
            prototype_negative_control_functions.append(
                {
                    "ea": ea,
                    "name": name,
                    "generic_parameter_survivors": int(prototype_metrics.get("generic_parameter_survivors", 0) or 0),
                    "offset_deref_survivors": int(prototype_metrics.get("offset_deref_survivors", 0) or 0),
                    "summary_path": str(summary_path),
                }
            )
        if evidence_graph:
            evidence_graph_item = _evidence_graph_function_summary(name, ea, summary_path, evidence_graph)
            _update_evidence_graph_metrics(
                evidence_graph_item,
                evidence_graph_totals,
                evidence_graph_node_kinds,
                evidence_graph_edge_kinds,
                evidence_graph_promotion_lanes,
                evidence_graph_blockers,
            )
            top_evidence_graph_functions.append(evidence_graph_item)

        rename_candidate_count = _int_value(summary.get("rename_candidates"), len(rename_items))
        applied_rename_count = _int_value(
            summary.get("renames"),
            sum(1 for item in rename_items if _rename_applied(item)),
        )
        totals["summaries"] += 1
        totals["rename_candidates"] += rename_candidate_count
        totals["applied_renames"] += applied_rename_count
        totals["warnings"] += warning_count
        totals["flow_rewrites"] += _int_value(summary.get("flow_rewrites"), 0)
        totals["buffer_contracts"] += _int_value(summary.get("buffer_contracts"), len(buffer_contracts))
        totals["matched_rules"] += _int_value(_coerce_dict(summary.get("rule_diagnostics", {})).get("matched_rules"), 0)
        if rewrite_preview_metadata:
            _update_layout_rewrite_preview_artifact_metrics(
                rewrite_preview_metadata,
                rewrite_preview_artifact_totals,
                rewrite_preview_artifact_statuses,
                rewrite_preview_artifact_canonical_statuses,
                rewrite_preview_artifact_plan_kinds,
                rewrite_preview_artifact_failed_checks,
            )
            top_rewrite_preview_artifact_functions.append(
                _rewrite_preview_artifact_function_summary(name, ea, summary_path, rewrite_preview_metadata)
            )
        if warnings or warning_diagnostics:
            totals["functions_with_warnings"] += 1
            top_warning_functions.append(
                {
                    "ea": ea,
                    "name": name,
                    "warning_count": warning_count,
                    "warning_classes": dict(Counter(_classify_warning(item) for item in warning_class_items).most_common(5)),
                    "summary_path": str(summary_path),
                }
            )
        existing_parameter_aliases = _existing_parameter_register_alias_diagnostics(warning_diagnostics)
        if existing_parameter_aliases:
            totals["functions_with_existing_parameter_aliases"] += 1
            totals["existing_parameter_aliases"] += len(existing_parameter_aliases)
            top_existing_parameter_alias_functions.append(
                _existing_parameter_alias_function_summary(
                    name,
                    ea,
                    summary_path,
                    existing_parameter_aliases,
                )
            )
            for item in existing_parameter_aliases:
                existing_parameter_alias_actions[str(item.get("candidate_action", "") or "unknown")] += 1
                existing_parameter_alias_registers[str(item.get("register", "") or "unknown")] += 1
        if cleaned_path and cleaned_path.exists():
            totals["cleaned_files"] += 1
            if text_scan:
                (
                    layout_hints,
                    subfield_overlays,
                    narrow_subfields,
                    bitfield_aliases,
                    hot_field_clusters,
                    indexed_callback_tables,
                    parameter_indexed_elements,
                    stable_base_sources,
                    base_stability,
                    generic_base_evidence,
                    generic_base_trust_candidates,
                    temp_provenance,
                    rewrite_ready,
                    rewrite_previews,
                    rewrite_near_ready,
                    rewrite_partial_opportunities,
                    rewrite_blockers,
                    domain_identities,
                    decimal_status_body_literals,
                    ntstatus_body_literals,
                ) = _update_text_metrics(
                    text_totals,
                    body_text_totals,
                    cleaned_path,
                )
                pointer_indexed_metrics = _pointer_indexed_offset_function_metrics(
                    name,
                    ea,
                    summary_path,
                    raw_path,
                    cleaned_path,
                    rewrite_preview_metadata,
                )
                offset_shape_profile = _offset_deref_shape_profile(cleaned_path)
                _update_pointer_indexed_offset_metrics(
                    pointer_indexed_metrics,
                    pointer_indexed_offset_totals,
                    pointer_indexed_offset_bases,
                    pointer_indexed_offset_rewritten_bases,
                )
                if pointer_indexed_metrics.get("has_pointer_indexed_offset_evidence"):
                    top_pointer_indexed_offset_functions.append(pointer_indexed_metrics)
                _update_layout_hint_metrics(
                    layout_hints,
                    layout_totals,
                    layout_hint_bases,
                    layout_hint_types,
                )
                _update_layout_subfield_overlay_metrics(
                    subfield_overlays,
                    subfield_overlay_totals,
                    subfield_overlay_bases,
                    subfield_overlay_size_classes,
                    subfield_overlay_policy_classes,
                    subfield_overlay_interpretations,
                    subfield_overlay_bit_masks,
                    subfield_overlay_bit_operations,
                    subfield_overlay_mask_families,
                )
                _update_layout_narrow_subfield_metrics(
                    narrow_subfields,
                    narrow_subfield_totals,
                    narrow_subfield_bases,
                    narrow_subfield_size_classes,
                    narrow_subfield_interpretations,
                    narrow_subfield_bit_masks,
                    narrow_subfield_bit_operations,
                    narrow_subfield_mask_families,
                )
                _update_layout_bitfield_alias_metrics(
                    bitfield_aliases,
                    bitfield_alias_totals,
                    bitfield_alias_bases,
                    bitfield_alias_names,
                    bitfield_alias_masks,
                )
                _update_layout_hot_field_cluster_metrics(
                    hot_field_clusters,
                    hot_field_cluster_totals,
                    hot_field_cluster_bases,
                    hot_field_cluster_base_kinds,
                    hot_field_cluster_field_types,
                )
                _update_layout_indexed_callback_table_metrics(
                    indexed_callback_tables,
                    indexed_callback_table_totals,
                    indexed_callback_table_bases,
                    indexed_callback_table_base_kinds,
                    indexed_callback_table_alias_bases,
                )
                _update_layout_parameter_indexed_element_metrics(
                    parameter_indexed_elements,
                    parameter_indexed_element_totals,
                    parameter_indexed_element_bases,
                    parameter_indexed_element_parents,
                    parameter_indexed_element_parent_types,
                    parameter_indexed_element_strides,
                )
                _update_layout_stable_base_source_metrics(
                    stable_base_sources,
                    stable_base_source_totals,
                    stable_base_source_bases,
                    stable_base_source_sources,
                    stable_base_source_kinds,
                    stable_base_source_provenance,
                )
                _update_layout_base_stability_metrics(
                    base_stability,
                    base_stability_totals,
                    base_stability_bases,
                    base_stability_rhs,
                    base_stability_profiles,
                    base_stability_review_queues,
                    name,
                    ea,
                    summary_path,
                )
                _update_layout_generic_base_evidence_metrics(
                    generic_base_evidence,
                    generic_base_evidence_totals,
                    generic_base_evidence_bases,
                    generic_base_evidence_profiles,
                )
                _update_layout_generic_base_trust_candidate_metrics(
                    generic_base_trust_candidates,
                    generic_base_trust_candidate_totals,
                    generic_base_trust_candidate_bases,
                    generic_base_trust_candidate_sources,
                    generic_base_trust_candidate_profiles,
                )
                _update_layout_temp_provenance_metrics(
                    temp_provenance,
                    temp_provenance_totals,
                    temp_provenance_bases,
                    temp_provenance_trust_classes,
                    temp_provenance_source_origins,
                    temp_provenance_source_kinds,
                    temp_provenance_source_provenance,
                    temp_provenance_branch_shapes,
                    temp_provenance_guard_dominance,
                    temp_provenance_block_reasons,
                )
                _update_layout_rewrite_ready_metrics(
                    rewrite_ready,
                    rewrite_ready_totals,
                    rewrite_ready_bases,
                    rewrite_ready_source_provenance,
                    rewrite_ready_threshold_policies,
                )
                _update_layout_rewrite_preview_metrics(
                    rewrite_previews,
                    rewrite_preview_totals,
                    rewrite_preview_bases,
                    rewrite_preview_source_provenance,
                )
                _update_layout_rewrite_near_ready_metrics(
                    rewrite_near_ready,
                    rewrite_near_ready_totals,
                    rewrite_near_ready_bases,
                    rewrite_near_ready_missing,
                )
                _update_layout_rewrite_partial_opportunity_metrics(
                    rewrite_partial_opportunities,
                    rewrite_partial_opportunity_totals,
                    rewrite_partial_opportunity_bases,
                    rewrite_partial_opportunity_source_provenance,
                    rewrite_partial_opportunity_reasons,
                    rewrite_partial_opportunity_application_statuses,
                    rewrite_partial_opportunity_review_classes,
                )
                _update_layout_rewrite_blocker_metrics(
                    rewrite_blockers,
                    layout_hints,
                    stable_base_sources,
                    generic_base_evidence,
                    generic_base_trust_candidates,
                    domain_identities,
                    rewrite_blocker_totals,
                    rewrite_blocker_bases,
                    rewrite_blocker_reasons,
                    rewrite_blocker_review_profiles,
                    rewrite_blocker_review_queues,
                    name,
                    ea,
                    summary_path,
                )
                body_offset_residue_item = _body_offset_residue_function_summary(
                    name,
                    ea,
                    summary_path,
                    cleaned_path,
                    prototype_metrics,
                    layout_hints,
                    hot_field_clusters,
                    indexed_callback_tables,
                    stable_base_sources,
                    base_stability,
                    generic_base_evidence,
                    generic_base_trust_candidates,
                    temp_provenance,
                    rewrite_ready,
                    rewrite_blockers,
                    parameter_indexed_elements,
                    domain_identities,
                    pointer_indexed_metrics,
                    offset_shape_profile,
                    warning_diagnostics,
                )
                if body_offset_residue_item:
                    _update_body_offset_residue_metrics(
                        body_offset_residue_item,
                        body_offset_residue_totals,
                        body_offset_residue_subsystems,
                        body_offset_residue_next_actions,
                        body_offset_residue_review_classes,
                        body_offset_residue_blocker_reasons,
                        body_offset_residue_review_evidence,
                        body_offset_residue_promotion_hints,
                        body_offset_residue_promotion_lanes,
                        body_offset_residue_next_action_details,
                        body_offset_residue_priority_factors,
                        body_offset_residue_review_notes,
                        body_offset_residue_fail_closed_gates,
                        body_offset_residue_fail_closed_families,
                        body_offset_residue_review_focuses,
                        body_offset_residue_shape_classes,
                        body_offset_residue_base_classes,
                        body_offset_residue_direct_base_classes,
                        body_offset_residue_named_target_groups,
                        body_offset_residue_safety_policies,
                        body_offset_residue_evidence_maturity,
                        body_offset_residue_cause_tags,
                        body_offset_residue_stable_source_details,
                    )
                    top_body_offset_residue_functions.append(body_offset_residue_item)
                if layout_hints:
                    top_layout_hint_functions.append(
                        _layout_hint_function_summary(name, ea, summary_path, layout_hints)
                    )
                if subfield_overlays:
                    top_subfield_overlay_functions.append(
                        _subfield_overlay_function_summary(name, ea, summary_path, subfield_overlays)
                    )
                if narrow_subfields:
                    top_narrow_subfield_functions.append(
                        _narrow_subfield_function_summary(name, ea, summary_path, narrow_subfields)
                    )
                if bitfield_aliases:
                    top_bitfield_alias_functions.append(
                        _bitfield_alias_function_summary(name, ea, summary_path, bitfield_aliases)
                    )
                if hot_field_clusters:
                    top_hot_field_cluster_functions.append(
                        _hot_field_cluster_function_summary(name, ea, summary_path, hot_field_clusters)
                    )
                if indexed_callback_tables:
                    top_indexed_callback_table_functions.append(
                        _indexed_callback_table_function_summary(
                            name,
                            ea,
                            summary_path,
                            indexed_callback_tables,
                        )
                    )
                if parameter_indexed_elements:
                    top_parameter_indexed_element_functions.append(
                        _parameter_indexed_element_function_summary(
                            name,
                            ea,
                            summary_path,
                            parameter_indexed_elements,
                        )
                    )
                if stable_base_sources:
                    top_stable_base_source_functions.append(
                        _stable_base_source_function_summary(name, ea, summary_path, stable_base_sources)
                    )
                if base_stability:
                    top_base_stability_functions.append(
                        _base_stability_function_summary(name, ea, summary_path, base_stability)
                    )
                if generic_base_evidence:
                    top_generic_base_evidence_functions.append(
                        _generic_base_evidence_function_summary(name, ea, summary_path, generic_base_evidence)
                    )
                if generic_base_trust_candidates:
                    top_generic_base_trust_candidate_functions.append(
                        _generic_base_trust_candidate_function_summary(
                            name,
                            ea,
                            summary_path,
                            generic_base_trust_candidates,
                        )
                    )
                if temp_provenance.get("traces") or temp_provenance.get("blocked"):
                    top_temp_provenance_functions.append(
                        _temp_provenance_function_summary(name, ea, summary_path, temp_provenance)
                    )
                if rewrite_ready:
                    top_rewrite_ready_functions.append(
                        _rewrite_ready_function_summary(name, ea, summary_path, rewrite_ready)
                    )
                if rewrite_previews:
                    top_rewrite_preview_functions.append(
                        _rewrite_preview_function_summary(name, ea, summary_path, rewrite_previews)
                    )
                if rewrite_near_ready:
                    top_rewrite_near_ready_functions.append(
                        _rewrite_near_ready_function_summary(name, ea, summary_path, rewrite_near_ready)
                    )
                if rewrite_partial_opportunities:
                    top_rewrite_partial_opportunity_functions.append(
                        _rewrite_partial_opportunity_function_summary(
                            name,
                            ea,
                            summary_path,
                            rewrite_partial_opportunities,
                        )
                    )
                if rewrite_blockers:
                    top_rewrite_blocker_functions.append(
                        _rewrite_blocker_function_summary(
                            name,
                            ea,
                            summary_path,
                            rewrite_blockers,
                            layout_hints,
                            stable_base_sources,
                            generic_base_evidence,
                            generic_base_trust_candidates,
                            domain_identities,
                        )
                    )
                if decimal_status_body_literals:
                    _update_decimal_status_residue_metrics(
                        decimal_status_body_literals,
                        decimal_status_residue_values,
                        decimal_status_residue_profiles,
                        decimal_status_residue_context_kinds,
                        decimal_status_residue_review_classes,
                        decimal_status_residue_target_evidence,
                        decimal_status_residue_target_review_hints,
                    )
                    top_decimal_status_residue_functions.append(
                        _decimal_status_residue_function_summary(
                            name,
                            ea,
                            summary_path,
                            decimal_status_body_literals,
                        )
                    )
                cleaned_body_text = _strip_pseudoforge_header(_read_text(cleaned_path))
                nested_status_stores = _nested_status_pointer_store_literals(cleaned_body_text)
                if nested_status_stores:
                    _update_nested_status_store_metrics(
                        nested_status_stores,
                        nested_status_store_values,
                        nested_status_store_profiles,
                        nested_status_store_widths,
                        nested_status_store_review_classes,
                    )
                    top_nested_status_store_functions.append(
                        _nested_status_store_function_summary(
                            name,
                            ea,
                            summary_path,
                            nested_status_stores,
                        )
                    )
                unprofiled_ntstatus_body_literals = [
                    item
                    for item in ntstatus_body_literals
                    if not bool(item.get("profiled")) and str(item.get("severity", "")) == "error"
                ]
                if unprofiled_ntstatus_body_literals:
                    _update_ntstatus_body_unprofiled_value_metrics(
                        unprofiled_ntstatus_body_literals,
                        ntstatus_body_unprofiled_values,
                        ntstatus_body_unprofiled_value_functions,
                        ntstatus_body_unprofiled_value_contexts,
                        ntstatus_body_unprofiled_context_kinds,
                        name,
                    )
                    top_ntstatus_body_unprofiled_functions.append(
                        _ntstatus_body_unprofiled_function_summary(
                            name,
                            ea,
                            summary_path,
                            unprofiled_ntstatus_body_literals,
                        )
                    )

        llm_statuses[str(summary.get("llm_status", "") or "unknown")] += 1
        _update_rename_metrics(rename_items, rename_sources, rename_sources_applied)
        for warning in warning_class_items:
            warning_classes[_classify_warning(warning)] += 1
        _update_rule_metrics(rule_report, rewrite_kinds, totals)
        api_diagnostic_count = _update_api_semantic_metrics(
            rule_report,
            api_semantic_reasons,
            api_semantic_stages,
            api_semantic_statuses,
            api_semantic_profiles,
            totals,
        )
        if api_diagnostic_count:
            totals["functions_with_api_semantic_diagnostics"] += 1
            top_api_semantic_functions.append(
                _api_semantic_function_summary(name, ea, summary_path, rule_report)
            )
            api_semantic_queue_items.extend(
                _api_semantic_review_queue_function_items(name, ea, summary_path, rule_report)
            )

    top_warning_functions.sort(key=lambda item: (-int(item["warning_count"]), str(item["name"])))
    top_api_semantic_functions.sort(
        key=lambda item: (
            -int(item["rejection_count"]),
            -int(item["diagnostic_count"]),
            str(item["name"]),
        )
    )
    top_layout_hint_functions.sort(
        key=lambda item: (
            -int(item["hint_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_subfield_overlay_functions.sort(
        key=lambda item: (
            -int(item["overlay_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_narrow_subfield_functions.sort(
        key=lambda item: (
            -int(item["candidate_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_bitfield_alias_functions.sort(
        key=lambda item: (
            -int(item["alias_comment_count"]),
            -int(item["field_count"]),
            str(item["name"]),
        )
    )
    top_hot_field_cluster_functions.sort(
        key=lambda item: (
            -int(item["cluster_count"]),
            -int(item["max_access_count"]),
            -int(item["max_top_field_access_count"]),
            -int(item["max_offsets"]),
            str(item["name"]),
        )
    )
    top_stable_base_source_functions.sort(
        key=lambda item: (
            -int(item["source_comment_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_base_stability_functions.sort(
        key=lambda item: (
            -int(item["stability_comment_count"]),
            -int(item["max_distinct_pre_access_rhs"]),
            -int(item["max_risky_post_access_assignments"]),
            str(item["name"]),
        )
    )
    top_generic_base_evidence_functions.sort(
        key=lambda item: (
            -int(item["evidence_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_generic_base_trust_candidate_functions.sort(
        key=lambda item: (
            -int(item["candidate_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_temp_provenance_functions.sort(
        key=lambda item: (
            -int(item["trace_count"]),
            -int(item["blocked_count"]),
            -int(item["trusted_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_ready_functions.sort(
        key=lambda item: (
            -int(item["ready_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_preview_functions.sort(
        key=lambda item: (
            -int(item["preview_count"]),
            -int(item["max_fields"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_preview_artifact_functions.sort(
        key=lambda item: (
            str(item["validation_status"]) != "failed",
            -int(item["rewritten_accesses"]),
            -int(item["rewritten_fields"]),
            str(item["name"]),
        )
    )
    top_rewrite_near_ready_functions.sort(
        key=lambda item: (
            -int(item["near_ready_count"]),
            -int(item["max_offsets"]),
            -int(item["max_access_count"]),
            str(item["name"]),
        )
    )
    top_rewrite_partial_opportunity_functions.sort(
        key=lambda item: (
            -int(item["partial_opportunity_count"]),
            -int(item["max_safe_access_count"]),
            -int(item["max_safe_offsets"]),
            str(item["name"]),
        )
    )
    top_rewrite_blocker_functions.sort(
        key=lambda item: (
            -int(item["blocker_count"]),
            -int(item["reason_count"]),
            str(item["name"]),
        )
    )
    top_body_offset_residue_functions.sort(
        key=lambda item: (
            -int(item["priority_score"]),
            -int(item["offset_deref_survivors"]),
            -int(item.get("direct_base_deref_survivors", 0)),
            -int(item["field_access_pressure"]),
            str(item["name"]),
        )
    )
    top_evidence_graph_functions.sort(
        key=lambda item: (
            -int(item["trusted_rewrite_edges"]),
            -int(item["rewrite_eligible_edges"]),
            -int(item["blocked_edges"]),
            -int(item["edges"]),
            str(item["name"]),
        )
    )
    top_decimal_status_residue_functions.sort(
        key=lambda item: (
            -int(item["literal_count"]),
            -int(item["profiled_count"]),
            str(item["name"]),
        )
    )
    top_nested_status_store_functions.sort(
        key=lambda item: (
            -int(item["store_count"]),
            -int(item["dword_store_count"]),
            str(item["name"]),
        )
    )
    top_ntstatus_body_unprofiled_functions.sort(
        key=lambda item: (
            -int(item["literal_count"]),
            str(item["name"]),
        )
    )
    top_prototype_correction_functions.sort(
        key=lambda item: (
            -int(item["applied_parameter_type_corrections"]),
            -int(item["report_only_identity_preview_parameter_corrections"]),
            -int(item["blocked_parameter_type_corrections"]),
            -int(item["generic_parameter_survivors"]),
            -int(item["offset_deref_survivors"]),
            str(item["name"]),
        )
    )
    prototype_negative_control_functions.sort(
        key=lambda item: (
            -int(item["generic_parameter_survivors"]),
            -int(item["offset_deref_survivors"]),
            str(item["name"]),
        )
    )
    ntstatus_unprofiled_value_summaries = _ntstatus_unprofiled_value_summaries(
        ntstatus_body_unprofiled_values,
        ntstatus_body_unprofiled_value_functions,
        ntstatus_body_unprofiled_value_contexts,
        top,
    )
    ntstatus_unprofiled_function_summaries = top_ntstatus_body_unprofiled_functions[:top]
    ntstatus_review_hint_counts = _ntstatus_review_hint_counts(ntstatus_body_unprofiled_value_contexts)
    api_semantic_review_queue = _api_semantic_review_queue(api_semantic_queue_items, top)
    result = {
        "schema": "pseudoforge_corpus_quality_v1",
        "pseudoforge_version": VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "corpus_root": str(root),
        "functions_root": str(functions_root),
        "sample_limit": int(sample_limit),
        "ea_filter_count": len(ea_filter or set()),
        "text_scan": bool(text_scan),
        "totals": _counter_to_dict(totals),
        "rename_stats": {
            "apply_rate": _ratio(totals["applied_renames"], totals["rename_candidates"]),
            "by_source": _counter_to_dict(rename_sources),
            "applied_by_source": _counter_to_dict(rename_sources_applied),
            "llm_apply_rate": _ratio(rename_sources_applied["llm"], rename_sources["llm"]),
            "llm_rejected": max(0, rename_sources["llm"] - rename_sources_applied["llm"]),
        },
        "llm_statuses": _counter_to_dict(llm_statuses),
        "warning_stats": {
            "top_classes": _counter_to_dict(Counter(dict(warning_classes.most_common(top)))),
            "all_classes": _counter_to_dict(warning_classes),
        },
        "existing_parameter_alias_stats": {
            "total_aliases": int(totals.get("existing_parameter_aliases", 0)),
            "function_count": int(totals.get("functions_with_existing_parameter_aliases", 0)),
            "candidate_actions": _counter_to_dict(
                Counter(dict(existing_parameter_alias_actions.most_common(top)))
            ),
            "registers": _counter_to_dict(
                Counter(dict(existing_parameter_alias_registers.most_common(top)))
            ),
            "top_functions": top_existing_parameter_alias_functions[:top],
        },
        "rule_stats": {
            "rewrite_emissions_by_kind": _counter_to_dict(rewrite_kinds),
            "rewrite_emissions": totals["rule_rewrite_emissions"],
            "rejected_emissions": totals["rule_rejected_emissions"],
            "load_errors": totals["rule_load_errors"],
            "validation_errors": totals["rule_validation_errors"],
        },
        "api_semantic_stats": {
            "diagnostics": totals["api_semantic_diagnostics"],
            "rejections": totals["api_semantic_rejections"],
            "functions_with_diagnostics": totals["functions_with_api_semantic_diagnostics"],
            "rejections_by_reason": _counter_to_dict(api_semantic_reasons),
            "rejections_by_stage": _counter_to_dict(api_semantic_stages),
            "top_rejection_profiles": _api_semantic_profile_summaries(api_semantic_profiles, top),
            "top_functions": top_api_semantic_functions[:top],
            "statuses": _counter_to_dict(api_semantic_statuses),
        },
        "api_semantic_review_queue": api_semantic_review_queue,
        "layout_hint_stats": {
            "totals": _counter_to_dict(layout_totals),
            "top_bases": _counter_to_dict(Counter(dict(layout_hint_bases.most_common(top)))),
            "observed_types": _counter_to_dict(Counter(dict(layout_hint_types.most_common(top)))),
            "top_functions": top_layout_hint_functions[:top],
        },
        "layout_subfield_overlay_stats": {
            "totals": _counter_to_dict(subfield_overlay_totals),
            "top_bases": _counter_to_dict(Counter(dict(subfield_overlay_bases.most_common(top)))),
            "size_classes": _counter_to_dict(Counter(dict(subfield_overlay_size_classes.most_common(top)))),
            "policy_classes": _counter_to_dict(Counter(dict(subfield_overlay_policy_classes.most_common(top)))),
            "interpretations": _counter_to_dict(Counter(dict(subfield_overlay_interpretations.most_common(top)))),
            "bit_masks": _counter_to_dict(Counter(dict(subfield_overlay_bit_masks.most_common(top)))),
            "bit_operations": _counter_to_dict(Counter(dict(subfield_overlay_bit_operations.most_common(top)))),
            "mask_families": _counter_to_dict(Counter(dict(subfield_overlay_mask_families.most_common(top)))),
            "top_functions": top_subfield_overlay_functions[:top],
        },
        "layout_narrow_subfield_stats": {
            "totals": _counter_to_dict(narrow_subfield_totals),
            "top_bases": _counter_to_dict(Counter(dict(narrow_subfield_bases.most_common(top)))),
            "size_classes": _counter_to_dict(Counter(dict(narrow_subfield_size_classes.most_common(top)))),
            "interpretations": _counter_to_dict(Counter(dict(narrow_subfield_interpretations.most_common(top)))),
            "bit_masks": _counter_to_dict(Counter(dict(narrow_subfield_bit_masks.most_common(top)))),
            "bit_operations": _counter_to_dict(Counter(dict(narrow_subfield_bit_operations.most_common(top)))),
            "mask_families": _counter_to_dict(Counter(dict(narrow_subfield_mask_families.most_common(top)))),
            "top_functions": top_narrow_subfield_functions[:top],
        },
        "layout_bitfield_alias_stats": {
            "totals": _counter_to_dict(bitfield_alias_totals),
            "top_bases": _counter_to_dict(Counter(dict(bitfield_alias_bases.most_common(top)))),
            "aliases": _counter_to_dict(Counter(dict(bitfield_alias_names.most_common(top)))),
            "masks": _counter_to_dict(Counter(dict(bitfield_alias_masks.most_common(top)))),
            "top_functions": top_bitfield_alias_functions[:top],
        },
        "layout_hot_field_cluster_stats": {
            "totals": _counter_to_dict(hot_field_cluster_totals),
            "top_bases": _counter_to_dict(Counter(dict(hot_field_cluster_bases.most_common(top)))),
            "base_kinds": _counter_to_dict(Counter(dict(hot_field_cluster_base_kinds.most_common(top)))),
            "field_types": _counter_to_dict(Counter(dict(hot_field_cluster_field_types.most_common(top)))),
            "top_functions": top_hot_field_cluster_functions[:top],
        },
        "layout_indexed_callback_table_stats": {
            "totals": _counter_to_dict(indexed_callback_table_totals),
            "top_bases": _counter_to_dict(Counter(dict(indexed_callback_table_bases.most_common(top)))),
            "base_kinds": _counter_to_dict(Counter(dict(indexed_callback_table_base_kinds.most_common(top)))),
            "alias_bases": _counter_to_dict(Counter(dict(indexed_callback_table_alias_bases.most_common(top)))),
            "top_functions": top_indexed_callback_table_functions[:top],
        },
        "layout_parameter_indexed_element_stats": {
            "totals": _counter_to_dict(parameter_indexed_element_totals),
            "top_bases": _counter_to_dict(Counter(dict(parameter_indexed_element_bases.most_common(top)))),
            "parents": _counter_to_dict(Counter(dict(parameter_indexed_element_parents.most_common(top)))),
            "parent_types": _counter_to_dict(Counter(dict(parameter_indexed_element_parent_types.most_common(top)))),
            "strides": _counter_to_dict(Counter(dict(parameter_indexed_element_strides.most_common(top)))),
            "top_functions": top_parameter_indexed_element_functions[:top],
        },
        "layout_stable_base_source_stats": {
            "totals": _counter_to_dict(stable_base_source_totals),
            "top_bases": _counter_to_dict(Counter(dict(stable_base_source_bases.most_common(top)))),
            "sources": _counter_to_dict(Counter(dict(stable_base_source_sources.most_common(top)))),
            "source_kinds": _counter_to_dict(Counter(dict(stable_base_source_kinds.most_common(top)))),
            "source_provenance": _counter_to_dict(Counter(dict(stable_base_source_provenance.most_common(top)))),
            "top_functions": top_stable_base_source_functions[:top],
        },
        "layout_base_stability_stats": {
            "totals": _counter_to_dict(base_stability_totals),
            "top_bases": _counter_to_dict(Counter(dict(base_stability_bases.most_common(top)))),
            "rhs_samples": _counter_to_dict(Counter(dict(base_stability_rhs.most_common(top)))),
            "profiles": _counter_to_dict(Counter(dict(base_stability_profiles.most_common(top)))),
            "review_queues": _layout_base_stability_review_queues(
                base_stability_review_queues,
                top,
            ),
            "top_functions": top_base_stability_functions[:top],
        },
        "layout_generic_base_evidence_stats": {
            "totals": _counter_to_dict(generic_base_evidence_totals),
            "top_bases": _counter_to_dict(Counter(dict(generic_base_evidence_bases.most_common(top)))),
            "blocker_profiles": _counter_to_dict(Counter(dict(generic_base_evidence_profiles.most_common(top)))),
            "top_functions": top_generic_base_evidence_functions[:top],
        },
        "layout_generic_base_trust_candidate_stats": {
            "totals": _counter_to_dict(generic_base_trust_candidate_totals),
            "top_bases": _counter_to_dict(Counter(dict(generic_base_trust_candidate_bases.most_common(top)))),
            "source_kinds": _counter_to_dict(Counter(dict(generic_base_trust_candidate_sources.most_common(top)))),
            "blocker_profiles": _counter_to_dict(Counter(dict(generic_base_trust_candidate_profiles.most_common(top)))),
            "top_functions": top_generic_base_trust_candidate_functions[:top],
        },
        "layout_temp_provenance_stats": {
            "totals": _counter_to_dict(temp_provenance_totals),
            "top_bases": _counter_to_dict(Counter(dict(temp_provenance_bases.most_common(top)))),
            "trust_classes": _counter_to_dict(Counter(dict(temp_provenance_trust_classes.most_common(top)))),
            "source_origins": _counter_to_dict(Counter(dict(temp_provenance_source_origins.most_common(top)))),
            "source_kinds": _counter_to_dict(Counter(dict(temp_provenance_source_kinds.most_common(top)))),
            "source_provenance": _counter_to_dict(
                Counter(dict(temp_provenance_source_provenance.most_common(top)))
            ),
            "branch_merge_shapes": _counter_to_dict(Counter(dict(temp_provenance_branch_shapes.most_common(top)))),
            "guard_dominance": _counter_to_dict(Counter(dict(temp_provenance_guard_dominance.most_common(top)))),
            "block_reasons": _counter_to_dict(Counter(dict(temp_provenance_block_reasons.most_common(top)))),
            "top_functions": top_temp_provenance_functions[:top],
        },
        "layout_rewrite_ready_stats": {
            "totals": _counter_to_dict(rewrite_ready_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_ready_bases.most_common(top)))),
            "source_provenance": _counter_to_dict(Counter(dict(rewrite_ready_source_provenance.most_common(top)))),
            "threshold_policies": _counter_to_dict(Counter(dict(rewrite_ready_threshold_policies.most_common(top)))),
            "top_functions": top_rewrite_ready_functions[:top],
        },
        "layout_rewrite_preview_stats": {
            "totals": _counter_to_dict(rewrite_preview_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_preview_bases.most_common(top)))),
            "source_provenance": _counter_to_dict(Counter(dict(rewrite_preview_source_provenance.most_common(top)))),
            "top_functions": top_rewrite_preview_functions[:top],
        },
        "layout_rewrite_preview_artifact_stats": {
            "totals": _counter_to_dict(rewrite_preview_artifact_totals),
            "validation_statuses": _counter_to_dict(
                Counter(dict(rewrite_preview_artifact_statuses.most_common(top)))
            ),
            "canonical_rewrite_statuses": _counter_to_dict(
                Counter(dict(rewrite_preview_artifact_canonical_statuses.most_common(top)))
            ),
            "preview_plan_kinds": _counter_to_dict(
                Counter(dict(rewrite_preview_artifact_plan_kinds.most_common(top)))
            ),
            "failed_checks": _counter_to_dict(
                Counter(dict(rewrite_preview_artifact_failed_checks.most_common(top)))
            ),
            "top_functions": top_rewrite_preview_artifact_functions[:top],
        },
        "pointer_indexed_offset_stats": {
            "totals": _pointer_indexed_offset_totals_dict(pointer_indexed_offset_totals),
            "top_bases": _counter_to_dict(Counter(dict(pointer_indexed_offset_bases.most_common(top)))),
            "rewritten_bases": _counter_to_dict(
                Counter(dict(pointer_indexed_offset_rewritten_bases.most_common(top)))
            ),
            "top_functions": sorted(
                top_pointer_indexed_offset_functions,
                key=lambda item: (
                    -int(item.get("pointer_indexed_rewrite_applied", 0) or 0),
                    -int(item.get("pointer_indexed_offset_deref_patterns", 0) or 0),
                    str(item.get("name", "")),
                ),
            )[:top],
        },
        "layout_rewrite_near_ready_stats": {
            "totals": _counter_to_dict(rewrite_near_ready_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_near_ready_bases.most_common(top)))),
            "missing_thresholds": _counter_to_dict(Counter(dict(rewrite_near_ready_missing.most_common(top)))),
            "top_functions": top_rewrite_near_ready_functions[:top],
        },
        "layout_rewrite_partial_opportunity_stats": {
            "totals": _counter_to_dict(rewrite_partial_opportunity_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_partial_opportunity_bases.most_common(top)))),
            "source_provenance": _counter_to_dict(
                Counter(dict(rewrite_partial_opportunity_source_provenance.most_common(top)))
            ),
            "reasons": _counter_to_dict(Counter(dict(rewrite_partial_opportunity_reasons.most_common(top)))),
            "application_statuses": _counter_to_dict(
                Counter(dict(rewrite_partial_opportunity_application_statuses.most_common(top)))
            ),
            "review_classes": _counter_to_dict(
                Counter(dict(rewrite_partial_opportunity_review_classes.most_common(top)))
            ),
            "top_functions": top_rewrite_partial_opportunity_functions[:top],
        },
        "layout_rewrite_blocker_stats": {
            "totals": _counter_to_dict(rewrite_blocker_totals),
            "top_bases": _counter_to_dict(Counter(dict(rewrite_blocker_bases.most_common(top)))),
            "reasons": _counter_to_dict(Counter(dict(rewrite_blocker_reasons.most_common(top)))),
            "review_profiles": _counter_to_dict(Counter(dict(rewrite_blocker_review_profiles.most_common(top)))),
            "review_queues": _layout_rewrite_blocker_review_queues(
                rewrite_blocker_review_queues,
                top,
            ),
            "top_functions": top_rewrite_blocker_functions[:top],
        },
        "body_offset_residue_review_stats": {
            "totals": _body_offset_residue_totals_dict(body_offset_residue_totals),
            "subsystems": _counter_to_dict(Counter(dict(body_offset_residue_subsystems.most_common(top)))),
            "next_actions": _counter_to_dict(Counter(dict(body_offset_residue_next_actions.most_common(top)))),
            "review_classes": _counter_to_dict(Counter(dict(body_offset_residue_review_classes.most_common(top)))),
            "blocker_reasons": _counter_to_dict(Counter(dict(body_offset_residue_blocker_reasons.most_common(top)))),
            "review_evidence": _counter_to_dict(Counter(dict(body_offset_residue_review_evidence.most_common(top)))),
            "promotion_hints": _counter_to_dict(Counter(dict(body_offset_residue_promotion_hints.most_common(top)))),
            "promotion_lanes": _counter_to_dict(Counter(dict(body_offset_residue_promotion_lanes.most_common(top)))),
            "next_action_details": _counter_to_dict(
                Counter(dict(body_offset_residue_next_action_details.most_common(top)))
            ),
            "priority_factors": _counter_to_dict(
                Counter(dict(body_offset_residue_priority_factors.most_common(top)))
            ),
            "residue_review_notes": _counter_to_dict(
                Counter(dict(body_offset_residue_review_notes.most_common(top)))
            ),
            "fail_closed_gates": _counter_to_dict(
                Counter(dict(body_offset_residue_fail_closed_gates.most_common(top)))
            ),
            "fail_closed_families": _counter_to_dict(
                Counter(dict(body_offset_residue_fail_closed_families.most_common(top)))
            ),
            "review_focuses": _counter_to_dict(
                Counter(dict(body_offset_residue_review_focuses.most_common(top)))
            ),
            "offset_shape_classes": _counter_to_dict(Counter(dict(body_offset_residue_shape_classes.most_common(top)))),
            "offset_base_classes": _counter_to_dict(Counter(dict(body_offset_residue_base_classes.most_common(top)))),
            "direct_base_classes": _counter_to_dict(
                Counter(dict(body_offset_residue_direct_base_classes.most_common(top)))
            ),
            "named_target_groups": _counter_to_dict(
                Counter(dict(body_offset_residue_named_target_groups.most_common(top)))
            ),
            "rewrite_safety_policies": _counter_to_dict(
                Counter(dict(body_offset_residue_safety_policies.most_common(top)))
            ),
            "evidence_maturity": _counter_to_dict(
                Counter(dict(body_offset_residue_evidence_maturity.most_common(top)))
            ),
            "residue_cause_tags": _counter_to_dict(
                Counter(dict(body_offset_residue_cause_tags.most_common(top)))
            ),
            "top_stable_source_details": _counter_to_dict(
                Counter(dict(body_offset_residue_stable_source_details.most_common(top)))
            ),
            "review_queues": _body_offset_residue_review_queues(
                top_body_offset_residue_functions,
                top,
            ),
            "direct_base_root_review_batches": _body_offset_direct_base_root_review_batches(
                top_body_offset_residue_functions,
                top,
            ),
            "next_goal_candidates": _body_offset_residue_next_goal_candidates(
                top_body_offset_residue_functions,
                top,
            ),
            "named_goal_target_status": _body_offset_named_goal_target_status(
                top_body_offset_residue_functions,
                top,
                analyzed_functions,
            ),
            "top_functions": top_body_offset_residue_functions[:top],
        },
        "evidence_graph_stats": {
            "totals": _evidence_graph_totals_dict(evidence_graph_totals),
            "node_kinds": _counter_to_dict(Counter(dict(evidence_graph_node_kinds.most_common(top)))),
            "edge_kinds": _counter_to_dict(Counter(dict(evidence_graph_edge_kinds.most_common(top)))),
            "promotion_lanes": _counter_to_dict(
                Counter(dict(evidence_graph_promotion_lanes.most_common(top)))
            ),
            "blockers": _counter_to_dict(Counter(dict(evidence_graph_blockers.most_common(top)))),
            "top_functions": top_evidence_graph_functions[:top],
        },
        "prototype_correction_stats": {
            "totals": _prototype_correction_totals_dict(prototype_totals),
            "blocker_counts": _counter_to_dict(Counter(dict(prototype_blockers.most_common(top)))),
            "profile_counts": _counter_to_dict(Counter(dict(prototype_profiles.most_common(top)))),
            "function_identity_profiles": _counter_to_dict(
                Counter(dict(prototype_function_profiles.most_common(top)))
            ),
            "canonical_types": _counter_to_dict(Counter(dict(prototype_canonical_types.most_common(top)))),
            "body_rewrite_source_provenance": _counter_to_dict(
                Counter(dict(prototype_body_rewrite_sources.most_common(top)))
            ),
            "report_only_identity_preview_profiles": _counter_to_dict(
                Counter(dict(prototype_report_only_preview_profiles.most_common(top)))
            ),
            "type_assisted_preview_statuses": _counter_to_dict(
                Counter(dict(prototype_type_assisted_preview_statuses.most_common(top)))
            ),
            "top_functions": top_prototype_correction_functions[:top],
            "review_queues": _prototype_correction_review_queues(
                top_prototype_correction_functions,
                top,
            ),
            "negative_controls": {
                "function_count": int(prototype_totals["negative_control_functions"]),
                "top_functions": prototype_negative_control_functions[:top],
            },
        },
        "ntstatus_body_residue_stats": {
            "top_unprofiled_error_values": ntstatus_unprofiled_value_summaries,
            "unprofiled_error_context_kinds": _counter_to_dict(
                Counter(dict(ntstatus_body_unprofiled_context_kinds.most_common(top)))
            ),
            "unprofiled_error_review_hints": _counter_to_dict(
                Counter(dict(ntstatus_review_hint_counts.most_common(top)))
            ),
            "review_queues": _ntstatus_review_queues(
                ntstatus_unprofiled_value_summaries,
                ntstatus_unprofiled_function_summaries,
            ),
            "top_unprofiled_error_functions": ntstatus_unprofiled_function_summaries,
        },
        "decimal_status_residue_stats": {
            "values": _counter_to_dict(Counter(dict(decimal_status_residue_values.most_common(top)))),
            "profile_names": _counter_to_dict(Counter(dict(decimal_status_residue_profiles.most_common(top)))),
            "context_kinds": _counter_to_dict(Counter(dict(decimal_status_residue_context_kinds.most_common(top)))),
            "review_classes": _counter_to_dict(Counter(dict(decimal_status_residue_review_classes.most_common(top)))),
            "target_evidence": _counter_to_dict(Counter(dict(decimal_status_residue_target_evidence.most_common(top)))),
            "target_review_hints": _counter_to_dict(
                Counter(dict(decimal_status_residue_target_review_hints.most_common(top)))
            ),
            "review_queues": _decimal_status_review_queues(top_decimal_status_residue_functions, top),
            "target_review_queues": _decimal_status_target_review_queues(top_decimal_status_residue_functions, top),
            "top_functions": top_decimal_status_residue_functions[:top],
        },
        "status_store_residue_stats": {
            "nested_pointer_store_values": _counter_to_dict(Counter(dict(nested_status_store_values.most_common(top)))),
            "nested_pointer_store_profiles": _counter_to_dict(Counter(dict(nested_status_store_profiles.most_common(top)))),
            "nested_pointer_store_widths": _counter_to_dict(Counter(dict(nested_status_store_widths.most_common(top)))),
            "nested_pointer_store_review_classes": _counter_to_dict(
                Counter(dict(nested_status_store_review_classes.most_common(top)))
            ),
            "review_queues": _nested_status_store_review_queues(top_nested_status_store_functions, top),
            "top_nested_pointer_store_functions": top_nested_status_store_functions[:top],
        },
        "text_stats": _counter_to_dict(text_totals),
        "body_text_stats": _counter_to_dict(body_text_totals),
        "top_warning_functions": top_warning_functions[:top],
    }
    normalized_manual_reread = _normalize_manual_reread(manual_reread or {})
    if normalized_manual_reread:
        result["manual_reread"] = normalized_manual_reread
    result["structure_quality_score"] = _structure_quality_scorecard(result)
    return result


def _structure_quality_scorecard(report: dict[str, Any]) -> dict[str, Any]:
    totals = _coerce_dict(report.get("totals", {}))
    functions = max(1, _int_value(totals.get("summaries"), 0))
    prototype_totals = _coerce_dict(_coerce_dict(report.get("prototype_correction_stats", {})).get("totals", {}))
    api_semantic_stats = _coerce_dict(report.get("api_semantic_stats", {}))
    layout_hint_totals = _coerce_dict(_coerce_dict(report.get("layout_hint_stats", {})).get("totals", {}))
    stable_source_totals = _coerce_dict(
        _coerce_dict(report.get("layout_stable_base_source_stats", {})).get("totals", {})
    )
    rewrite_ready_totals = _coerce_dict(
        _coerce_dict(report.get("layout_rewrite_ready_stats", {})).get("totals", {})
    )
    rewrite_preview_totals = _coerce_dict(
        _coerce_dict(report.get("layout_rewrite_preview_stats", {})).get("totals", {})
    )
    rewrite_preview_artifact_totals = _coerce_dict(
        _coerce_dict(report.get("layout_rewrite_preview_artifact_stats", {})).get("totals", {})
    )
    pointer_indexed_totals = _coerce_dict(
        _coerce_dict(report.get("pointer_indexed_offset_stats", {})).get("totals", {})
    )
    body_offset_stats = _coerce_dict(report.get("body_offset_residue_review_stats", {}))
    body_offset_totals = _coerce_dict(body_offset_stats.get("totals", {}))
    body_offset_review_classes = _coerce_dict(body_offset_stats.get("review_classes", {}))
    evidence_graph_totals = _coerce_dict(
        _coerce_dict(report.get("evidence_graph_stats", {})).get("totals", {})
    )
    body_text_stats = _coerce_dict(report.get("body_text_stats", {}))
    rule_stats = _coerce_dict(report.get("rule_stats", {}))
    runtime_boundary = _runtime_boundary_status()

    components = {
        "prototype_correctness": _structure_quality_component(
            "prototype_correctness",
            _prototype_correctness_score(prototype_totals, functions),
            {
                "function_identity_candidates": _int_value(
                    prototype_totals.get("function_identity_candidates"),
                    0,
                ),
                "applied_parameter_type_corrections": _int_value(
                    prototype_totals.get("applied_parameter_type_corrections"),
                    0,
                ),
                "blocked_parameter_type_corrections": _int_value(
                    prototype_totals.get("blocked_parameter_type_corrections"),
                    0,
                ),
                "corrected_parameter_map_entries": _int_value(
                    prototype_totals.get("corrected_parameter_map_entries"),
                    0,
                ),
                "type_assisted_preview_parameter_corrections": _int_value(
                    prototype_totals.get("type_assisted_preview_parameter_corrections"),
                    0,
                ),
                "report_only_identity_preview_parameter_corrections": _int_value(
                    prototype_totals.get("report_only_identity_preview_parameter_corrections"),
                    0,
                ),
                "functions_with_correction_evidence": _int_value(
                    prototype_totals.get("functions_with_correction_evidence"),
                    0,
                ),
                "type_assisted_preview_restore_failures": _int_value(
                    prototype_totals.get("type_assisted_preview_restore_failures"),
                    0,
                ),
                "idb_apply_parameter_type_corrections": _int_value(
                    prototype_totals.get("idb_apply_parameter_type_corrections"),
                    0,
                ),
            },
        ),
        "call_argument_cleanup": _structure_quality_component(
            "call_argument_cleanup",
            _call_argument_cleanup_score(prototype_totals, api_semantic_stats, functions),
            {
                "applied_parameter_type_corrections": _int_value(
                    prototype_totals.get("applied_parameter_type_corrections"),
                    0,
                ),
                "blocked_parameter_type_corrections": _int_value(
                    prototype_totals.get("blocked_parameter_type_corrections"),
                    0,
                ),
                "api_semantic_rejections": _int_value(api_semantic_stats.get("rejections"), 0),
            },
        ),
        "structure_identity_evidence": _structure_quality_component(
            "structure_identity_evidence",
            _structure_identity_evidence_score(
                prototype_totals,
                layout_hint_totals,
                stable_source_totals,
                rewrite_ready_totals,
                rewrite_preview_totals,
                rewrite_preview_artifact_totals,
                evidence_graph_totals,
                functions,
            ),
            {
                "function_identity_candidates": _int_value(
                    prototype_totals.get("function_identity_candidates"),
                    0,
                ),
                "layout_hint_functions": _int_value(layout_hint_totals.get("functions_with_hints"), 0),
                "stable_source_functions": _int_value(
                    stable_source_totals.get("functions_with_source_comments"),
                    0,
                ),
                "canonical_layout_rewrite_applied": _int_value(
                    rewrite_preview_artifact_totals.get("canonical_rewrite_applied"),
                    0,
                ),
                "evidence_graph_functions": _int_value(
                    evidence_graph_totals.get("functions_with_evidence_graph"),
                    0,
                ),
                "trusted_preview_edges": _int_value(evidence_graph_totals.get("trusted_preview_edges"), 0),
                "report_only_edges": _int_value(evidence_graph_totals.get("report_only_edges"), 0),
                "blocked_edges": _int_value(evidence_graph_totals.get("blocked_edges"), 0),
                "rewrite_eligible_edges": _int_value(
                    evidence_graph_totals.get("rewrite_eligible_edges"),
                    0,
                ),
            },
        ),
        "synthetic_local_aggregate_view": _structure_quality_component(
            "synthetic_local_aggregate_view",
            _synthetic_local_aggregate_view_score(body_text_stats, functions),
            {
                "synthetic_local_aggregate_candidates": _int_value(
                    body_text_stats.get("synthetic_local_aggregate_candidates"),
                    0,
                ),
                "synthetic_pool_aggregate_candidates": _int_value(
                    body_text_stats.get("synthetic_pool_aggregate_candidates"),
                    0,
                ),
                "functions_with_synthetic_local_aggregate_view": _int_value(
                    body_text_stats.get("functions_with_synthetic_local_aggregate_view"),
                    0,
                ),
                "inline_review_only_aggregate_aliases": _int_value(
                    body_text_stats.get("inline_review_only_aggregate_aliases"),
                    0,
                ),
                "inline_review_only_aggregate_alias_tokens": _int_value(
                    body_text_stats.get("inline_review_only_aggregate_alias_tokens"),
                    0,
                ),
                "projected_aggregate_accesses": _int_value(
                    body_text_stats.get("projected_aggregate_accesses"),
                    0,
                ),
                "blocked_aggregate_candidates": _int_value(
                    body_text_stats.get("blocked_aggregate_candidates"),
                    0,
                ),
                "aggregate_projection_policy_balanced": _int_value(
                    body_text_stats.get("aggregate_projection_policy_balanced"),
                    0,
                ),
                "aggregate_projection_policy_projection_heavy": _int_value(
                    body_text_stats.get("aggregate_projection_policy_projection_heavy"),
                    0,
                ),
                "aggregate_canonical_rewrite_attempts": _int_value(
                    body_text_stats.get("aggregate_canonical_rewrite_attempts"),
                    0,
                ),
                "aggregate_misleading_rewrites": _int_value(
                    body_text_stats.get("aggregate_misleading_rewrites"),
                    0,
                ),
            },
        ),
        "visible_body_improvement": _structure_quality_component(
            "visible_body_improvement",
            _visible_body_improvement_score(
                body_text_stats,
                rewrite_preview_artifact_totals,
                body_offset_totals,
                body_offset_review_classes,
                functions,
            ),
            {
                "visible_review_only_field_alias_annotations": _int_value(
                    body_text_stats.get("visible_review_only_field_alias_annotations"),
                    0,
                ),
                "visible_review_only_field_alias_tokens": _int_value(
                    body_text_stats.get("visible_review_only_field_alias_tokens"),
                    0,
                ),
                "functions_with_visible_review_only_field_aliases": _int_value(
                    body_text_stats.get("functions_with_visible_review_only_field_aliases"),
                    0,
                ),
                "canonical_layout_rewrite_applied": _int_value(
                    rewrite_preview_artifact_totals.get("canonical_rewrite_applied"),
                    0,
                ),
                "report_only_blocked_residue": _int_value(
                    body_offset_review_classes.get("report_only_blocked_residue"),
                    0,
                ),
            },
        ),
        "offset_residue": _structure_quality_component(
            "offset_residue",
            _offset_residue_score(
                body_offset_totals,
                body_text_stats,
                body_offset_review_classes,
                functions,
            ),
            {
                "functions_with_offset_residue": _int_value(
                    body_offset_totals.get("functions_with_offset_residue"),
                    0,
                ),
                "offset_deref_survivors": _int_value(body_offset_totals.get("offset_deref_survivors"), 0),
                "body_offset_deref_patterns": _int_value(body_text_stats.get("offset_deref_patterns"), 0),
                "unclassified_offset_residue": _int_value(
                    body_offset_review_classes.get("unclassified_offset_residue"),
                    0,
                ),
            },
        ),
        "pointer_indexed_residue": _structure_quality_component(
            "pointer_indexed_residue",
            _pointer_indexed_residue_score(pointer_indexed_totals, body_text_stats, functions),
            {
                "body_pointer_indexed_offset_deref_patterns": _int_value(
                    body_text_stats.get("pointer_indexed_offset_deref_patterns"),
                    0,
                ),
                "pointer_indexed_layout_rewrite_candidates": _int_value(
                    pointer_indexed_totals.get("pointer_indexed_layout_rewrite_candidates"),
                    0,
                ),
                "pointer_indexed_rewrite_applied": _int_value(
                    pointer_indexed_totals.get("pointer_indexed_rewrite_applied"),
                    0,
                ),
            },
        ),
        "generic_identifier_residue": _structure_quality_component(
            "generic_identifier_residue",
            _generic_identifier_residue_score(body_text_stats, prototype_totals, functions),
            {
                "body_generic_identifier_tokens": _int_value(
                    body_text_stats.get("generic_identifier_tokens"),
                    0,
                ),
                "prototype_generic_parameter_survivors": _int_value(
                    prototype_totals.get("generic_parameter_survivors"),
                    0,
                ),
            },
        ),
        "rewrite_safety_blockers": _structure_quality_component(
            "rewrite_safety_blockers",
            _rewrite_safety_blockers_score(
                rewrite_preview_artifact_totals,
                rule_stats,
                body_offset_review_classes,
                functions,
            ),
            {
                "layout_preview_validation_errors": _int_value(
                    rewrite_preview_artifact_totals.get("validation_errors"),
                    0,
                ),
                "canonical_rewrite_errors": _int_value(
                    rewrite_preview_artifact_totals.get("canonical_rewrite_errors"),
                    0,
                ),
                "rule_load_errors": _int_value(rule_stats.get("load_errors"), 0),
                "rule_validation_errors": _int_value(rule_stats.get("validation_errors"), 0),
                "unclassified_offset_residue": _int_value(
                    body_offset_review_classes.get("unclassified_offset_residue"),
                    0,
                ),
            },
        ),
        "ida_plugin_packaging_boundary": _structure_quality_component(
            "ida_plugin_packaging_boundary",
            10.0 if bool(runtime_boundary.get("passed")) else 0.0,
            {
                "forbidden_imports": _int_value(runtime_boundary.get("forbidden_imports"), 0),
                "scanned_python_files": _int_value(runtime_boundary.get("scanned_python_files"), 0),
            },
        ),
    }
    weighted_score = 0.0
    weight_total = 0.0
    for name in _STRUCTURE_QUALITY_COMPONENT_ORDER:
        component = _coerce_dict(components.get(name, {}))
        weight = _float_value(component.get("weight"), 0.0)
        weighted_score += _float_value(component.get("score"), 0.0) * weight
        weight_total += weight
    score = round(weighted_score / weight_total, 2) if weight_total > 0.0 else 0.0
    hard_gates = _structure_quality_hard_gates(
        report,
        runtime_boundary,
        rewrite_preview_artifact_totals,
        rule_stats,
        prototype_totals,
        body_text_stats,
    )
    manual_reread = _structure_quality_manual_reread(report)
    positive_gates = _structure_quality_positive_gates(
        components,
        prototype_totals,
        body_offset_totals,
        body_offset_review_classes,
        pointer_indexed_totals,
        body_text_stats,
        rewrite_preview_artifact_totals,
        functions,
    )
    hard_gates_all_pass = all(
        str(item.get("status", "") or "") == "pass"
        for item in hard_gates.values()
        if isinstance(item, dict)
    )
    positive_gates_all_pass = all(
        str(item.get("status", "") or "") == "pass"
        for item in positive_gates.values()
        if isinstance(item, dict)
    )
    manual_reread_passed = str(manual_reread.get("status", "") or "") == "pass"
    claim = (
        "meets_9_internal_bar"
        if score >= 9.0 and hard_gates_all_pass and positive_gates_all_pass and manual_reread_passed
        else "not_9_yet"
    )
    return {
        "schema": "pseudoforge_structure_quality_score_v1",
        "score": score,
        "claim": claim,
        "component_order": list(_STRUCTURE_QUALITY_COMPONENT_ORDER),
        "components": components,
        "hard_gates": hard_gates,
        "hard_gates_all_pass": hard_gates_all_pass,
        "positive_gates": positive_gates,
        "positive_gates_all_pass": positive_gates_all_pass,
        "manual_reread": manual_reread,
        "runtime_boundary": runtime_boundary,
        "blockers": _structure_quality_blockers(components, hard_gates, positive_gates, manual_reread),
    }


def _structure_quality_component(name: str, score: float, metrics: dict[str, Any]) -> dict[str, Any]:
    bounded = _clamp_score(score)
    return {
        "score": bounded,
        "weight": _float_value(_STRUCTURE_QUALITY_COMPONENT_WEIGHTS.get(name), 1.0),
        "status": _structure_quality_component_status(bounded),
        "metrics": metrics,
    }


def _prototype_correctness_score(totals: dict[str, Any], functions: int) -> float:
    identity_hits = _int_value(totals.get("function_identity_candidates"), 0)
    applied = _int_value(totals.get("applied_parameter_type_corrections"), 0)
    corrected_map = _int_value(totals.get("corrected_parameter_map_entries"), 0)
    type_assisted = _int_value(totals.get("type_assisted_preview_parameter_corrections"), 0)
    report_only_preview = _int_value(
        totals.get("report_only_identity_preview_parameter_corrections"),
        0,
    )
    evidence_functions = _int_value(totals.get("functions_with_correction_evidence"), 0)
    if evidence_functions <= 0:
        evidence_functions = min(functions, identity_hits)
    blocked = _int_value(totals.get("blocked_parameter_type_corrections"), 0)
    idb_apply = _int_value(totals.get("idb_apply_parameter_type_corrections"), 0)
    restore_failures = _int_value(totals.get("type_assisted_preview_restore_failures"), 0)
    generic_parameter_survivors = _int_value(totals.get("generic_parameter_survivors"), 0)
    corrected_parameters = applied + corrected_map + type_assisted + report_only_preview
    identity_coverage = min(1.0, _density(identity_hits, functions))
    correction_density = min(
        1.0,
        float(corrected_parameters) / max(1.0, float(evidence_functions) * 0.8),
    )
    preview_density = min(
        1.0,
        float(type_assisted + report_only_preview) / max(1.0, float(functions) * 0.25),
    )
    parameter_residue_score = _inverse_density_score(
        generic_parameter_survivors,
        functions,
        1.0,
        10.0,
    ) / 10.0
    score = (
        (identity_coverage * 2.5)
        + (correction_density * 4.0)
        + (preview_density * 1.0)
        + (parameter_residue_score * 2.5)
    )
    score -= min(4.0, _density(blocked, functions) * 2.0)
    score -= min(4.0, _density(restore_failures, functions) * 4.0)
    score -= 10.0 if idb_apply > 0 else 0.0
    return score


def _call_argument_cleanup_score(
    prototype_totals: dict[str, Any],
    api_semantic_stats: dict[str, Any],
    functions: int,
) -> float:
    applied = _int_value(prototype_totals.get("applied_parameter_type_corrections"), 0)
    blocked = _int_value(prototype_totals.get("blocked_parameter_type_corrections"), 0)
    total = applied + blocked
    correction_ratio = float(applied) / float(total) if total > 0 else 0.5
    score = 4.0 + (correction_ratio * 5.0)
    score += min(1.0, _density(applied, functions))
    if applied <= 0 and _int_value(api_semantic_stats.get("rejections"), 0) > 0:
        score -= min(1.0, _density(_int_value(api_semantic_stats.get("rejections"), 0), functions) * 0.1)
    return score


def _structure_identity_evidence_score(
    prototype_totals: dict[str, Any],
    layout_hint_totals: dict[str, Any],
    stable_source_totals: dict[str, Any],
    rewrite_ready_totals: dict[str, Any],
    rewrite_preview_totals: dict[str, Any],
    rewrite_preview_artifact_totals: dict[str, Any],
    evidence_graph_totals: dict[str, Any],
    functions: int,
) -> float:
    identity_coverage = min(
        1.0,
        _density(_int_value(prototype_totals.get("function_identity_candidates"), 0), functions),
    )
    graph_coverage = min(
        1.0,
        _density(_int_value(evidence_graph_totals.get("functions_with_evidence_graph"), 0), functions),
    )
    graph_density = min(
        1.0,
        float(_int_value(evidence_graph_totals.get("edges"), 0))
        / max(1.0, float(functions) * 1.5),
    )
    promotion_signal = (
        (_int_value(evidence_graph_totals.get("trusted_rewrite_edges"), 0) * 2)
        + _int_value(evidence_graph_totals.get("trusted_preview_edges"), 0)
        + _int_value(evidence_graph_totals.get("report_only_edges"), 0)
        + _int_value(evidence_graph_totals.get("rewrite_eligible_edges"), 0)
    )
    promotion_density = min(
        1.0,
        float(promotion_signal) / max(1.0, float(functions) * 0.6),
    )
    layout_signal = (
        _int_value(layout_hint_totals.get("functions_with_hints"), 0)
        + _int_value(stable_source_totals.get("functions_with_source_comments"), 0)
        + _int_value(rewrite_ready_totals.get("ready_candidates"), 0)
        + _int_value(rewrite_preview_totals.get("preview_plans"), 0)
        + (_int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_applied"), 0) * 3)
    )
    layout_density = min(1.0, float(layout_signal) / max(1.0, float(functions) * 0.3))
    classified_graph_functions = (
        _int_value(evidence_graph_totals.get("functions_with_trusted_rewrite_edges"), 0)
        + _int_value(evidence_graph_totals.get("functions_with_trusted_preview_edges"), 0)
        + _int_value(evidence_graph_totals.get("functions_with_report_only_edges"), 0)
        + _int_value(evidence_graph_totals.get("functions_with_blocked_edges"), 0)
    )
    graph_classification = min(1.0, _density(classified_graph_functions, functions))
    score = (
        (identity_coverage * 2.0)
        + (graph_coverage * 2.0)
        + (graph_density * 1.0)
        + (promotion_density * 2.0)
        + (layout_density * 2.0)
        + (graph_classification * 1.0)
    )
    source_none = _int_value(
        _coerce_dict(_coerce_dict(rewrite_ready_totals).get("source_provenance", {})).get("none"),
        0,
    )
    score -= min(2.0, _density(source_none, functions))
    return score


def _visible_body_improvement_score(
    body_text_stats: dict[str, Any],
    rewrite_preview_artifact_totals: dict[str, Any],
    body_offset_totals: dict[str, Any],
    body_offset_review_classes: dict[str, Any],
    functions: int,
) -> float:
    annotations = _int_value(body_text_stats.get("visible_review_only_field_alias_annotations"), 0)
    alias_tokens = _int_value(body_text_stats.get("visible_review_only_field_alias_tokens"), 0)
    annotated_functions = _int_value(body_text_stats.get("functions_with_visible_review_only_field_aliases"), 0)
    canonical = _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_applied"), 0)
    report_only = _int_value(body_offset_review_classes.get("report_only_blocked_residue"), 0)
    residue_functions = _int_value(body_offset_totals.get("functions_with_offset_residue"), 0)
    visible_events = annotations + (canonical * 2)
    score = _coverage_score(visible_events, functions, 0.08)
    if alias_tokens > annotations:
        score += min(1.0, _density(alias_tokens - annotations, functions) * 1.5)
    if annotated_functions > 0 and residue_functions > 0:
        score += min(1.0, float(annotated_functions) / float(max(1, residue_functions)) * 2.0)
    if report_only > 0 and annotations <= 0:
        score -= min(6.0, 2.0 + _density(report_only, functions) * 4.0)
    return score


def _synthetic_local_aggregate_view_score(
    body_text_stats: dict[str, Any],
    functions: int,
) -> float:
    candidates = _int_value(body_text_stats.get("synthetic_local_aggregate_candidates"), 0)
    view_functions = _int_value(body_text_stats.get("functions_with_synthetic_local_aggregate_view"), 0)
    inline_aliases = _int_value(body_text_stats.get("inline_review_only_aggregate_aliases"), 0)
    alias_tokens = _int_value(body_text_stats.get("inline_review_only_aggregate_alias_tokens"), 0)
    projected_accesses = _int_value(body_text_stats.get("projected_aggregate_accesses"), 0)
    projected_tokens = _int_value(body_text_stats.get("projected_aggregate_access_tokens"), 0)
    canonical_attempts = _int_value(body_text_stats.get("aggregate_canonical_rewrite_attempts"), 0)
    misleading = _int_value(body_text_stats.get("aggregate_misleading_rewrites"), 0)
    score = 9.0
    if candidates > 0:
        visible = inline_aliases + projected_accesses + view_functions
        score = 8.0 + min(2.0, _density(visible, functions) * 8.0)
        if inline_aliases <= 0 and projected_accesses <= 0:
            score -= 2.0
        if alias_tokens > inline_aliases:
            score += min(0.75, _density(alias_tokens - inline_aliases, functions) * 3.0)
        if projected_accesses:
            score += min(0.85, _density(projected_accesses + projected_tokens, functions) * 2.0)
    if canonical_attempts > 0:
        score -= min(5.0, 2.0 + canonical_attempts)
    if misleading > 0:
        score -= min(9.0, 4.0 + misleading * 2.0)
    return score


def _offset_residue_score(
    body_offset_totals: dict[str, Any],
    body_text_stats: dict[str, Any],
    body_offset_review_classes: dict[str, Any],
    functions: int,
) -> float:
    residue = max(
        _int_value(body_offset_totals.get("offset_deref_survivors"), 0),
        _int_value(body_text_stats.get("offset_deref_patterns"), 0),
    )
    functions_with_residue = _int_value(body_offset_totals.get("functions_with_offset_residue"), 0)
    score = _inverse_density_score(residue, functions, 0.25, 24.0)
    score -= min(2.0, _density(functions_with_residue, functions) * 2.0)
    if functions_with_residue > 0:
        unclassified = _int_value(body_offset_review_classes.get("unclassified_offset_residue"), 0)
        classified_ratio = max(
            0.0,
            float(functions_with_residue - unclassified) / float(functions_with_residue),
        )
        if classified_ratio >= 0.85:
            score += min(1.75, 0.75 + classified_ratio)
    return score


def _pointer_indexed_residue_score(
    pointer_indexed_totals: dict[str, Any],
    body_text_stats: dict[str, Any],
    functions: int,
) -> float:
    residue = _int_value(body_text_stats.get("pointer_indexed_offset_deref_patterns"), 0)
    candidates = _int_value(pointer_indexed_totals.get("pointer_indexed_layout_rewrite_candidates"), 0)
    applied = _int_value(pointer_indexed_totals.get("pointer_indexed_rewrite_applied"), 0)
    score = _inverse_density_score(residue, functions, 0.1, 12.0)
    if candidates > 0:
        score += min(2.0, (float(applied) / float(candidates)) * 2.0)
    return score


def _generic_identifier_residue_score(
    body_text_stats: dict[str, Any],
    prototype_totals: dict[str, Any],
    functions: int,
) -> float:
    body_score = _inverse_density_score(
        _int_value(body_text_stats.get("generic_identifier_tokens"), 0),
        functions,
        20.0,
        240.0,
    )
    parameter_score = _inverse_density_score(
        _int_value(prototype_totals.get("generic_parameter_survivors"), 0),
        functions,
        1.0,
        10.0,
    )
    return (body_score * 0.4) + (parameter_score * 0.6)


def _rewrite_safety_blockers_score(
    rewrite_preview_artifact_totals: dict[str, Any],
    rule_stats: dict[str, Any],
    body_offset_review_classes: dict[str, Any],
    functions: int,
) -> float:
    validation_errors = _int_value(rewrite_preview_artifact_totals.get("validation_errors"), 0)
    canonical_errors = _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_errors"), 0)
    rule_errors = _int_value(rule_stats.get("load_errors"), 0) + _int_value(rule_stats.get("validation_errors"), 0)
    unclassified = _int_value(body_offset_review_classes.get("unclassified_offset_residue"), 0)
    score = 10.0
    score -= min(6.0, float(validation_errors + canonical_errors) * 3.0)
    score -= min(3.0, float(rule_errors) * 1.5)
    score -= min(2.0, _density(unclassified, functions) * 2.0)
    return score


def _coverage_score(count: int, functions: int, target_per_function: float) -> float:
    target = max(1.0, float(functions) * float(target_per_function))
    return min(10.0, (float(max(0, count)) * 10.0) / target)


def _inverse_density_score(
    count: int,
    functions: int,
    excellent_per_function: float,
    poor_per_function: float,
) -> float:
    rate = _density(count, functions)
    if rate <= excellent_per_function:
        return 10.0
    if rate >= poor_per_function:
        return 0.0
    span = poor_per_function - excellent_per_function
    if span <= 0.0:
        return 0.0
    return 10.0 - ((rate - excellent_per_function) * 10.0 / span)


def _density(count: int, functions: int) -> float:
    return float(max(0, count)) / float(max(1, functions))


def _clamp_score(score: float) -> float:
    return round(max(0.0, min(10.0, float(score))), 2)


def _structure_quality_component_status(score: float) -> str:
    if score >= 9.0:
        return "target"
    if score >= 7.0:
        return "near"
    if score >= 5.0:
        return "weak"
    return "blocked"


def _structure_quality_hard_gates(
    report: dict[str, Any],
    runtime_boundary: dict[str, Any],
    rewrite_preview_artifact_totals: dict[str, Any],
    rule_stats: dict[str, Any],
    prototype_totals: dict[str, Any],
    body_text_stats: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    manual_reread = _structure_quality_manual_reread(report)
    return {
        "layout_rewrite_validation": _structure_quality_gate(
            _int_value(rewrite_preview_artifact_totals.get("validation_errors"), 0) == 0,
            "layout preview artifact validation has no errors",
            _int_value(rewrite_preview_artifact_totals.get("validation_errors"), 0),
        ),
        "canonical_rewrite_validation": _structure_quality_gate(
            _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_errors"), 0) == 0,
            "canonical layout rewrite metadata has no errors",
            _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_errors"), 0),
        ),
        "rule_validation": _structure_quality_gate(
            _int_value(rule_stats.get("load_errors"), 0) == 0
            and _int_value(rule_stats.get("validation_errors"), 0) == 0,
            "deterministic rule reports have no load or validation errors",
            {
                "load_errors": _int_value(rule_stats.get("load_errors"), 0),
                "validation_errors": _int_value(rule_stats.get("validation_errors"), 0),
            },
        ),
        "runtime_boundary": _structure_quality_gate(
            bool(runtime_boundary.get("passed")),
            "IDA plugin runtime has no forbidden developer-tool imports",
            runtime_boundary,
        ),
        "idb_mutation_default": _structure_quality_gate(
            _int_value(prototype_totals.get("idb_apply_parameter_type_corrections"), 0) == 0,
            "parameter type corrections do not request default IDB mutation",
            _int_value(prototype_totals.get("idb_apply_parameter_type_corrections"), 0),
        ),
        "type_assisted_preview_restore": _structure_quality_gate(
            _int_value(prototype_totals.get("type_assisted_preview_restore_failures"), 0) == 0,
            "type-assisted preview restores the original IDB type after temporary redecompile",
            _int_value(prototype_totals.get("type_assisted_preview_restore_failures"), 0),
        ),
        "synthetic_aggregate_safety": _structure_quality_gate(
            _int_value(body_text_stats.get("aggregate_canonical_rewrite_attempts"), 0) == 0
            and _int_value(body_text_stats.get("aggregate_misleading_rewrites"), 0) == 0,
            "synthetic aggregate projection remains render-only with no misleading rewrite",
            {
                "projected_aggregate_accesses": _int_value(
                    body_text_stats.get("projected_aggregate_accesses"),
                    0,
                ),
                "blocked_aggregate_candidates": _int_value(
                    body_text_stats.get("blocked_aggregate_candidates"),
                    0,
                ),
                "aggregate_canonical_rewrite_attempts": _int_value(
                    body_text_stats.get("aggregate_canonical_rewrite_attempts"),
                    0,
                ),
                "aggregate_misleading_rewrites": _int_value(
                    body_text_stats.get("aggregate_misleading_rewrites"),
                    0,
                ),
            },
        ),
        "manual_reread": {
            "status": str(manual_reread.get("status", "") or "missing"),
            "description": "manual reread requires at least 80 inspected functions and 0 misleading rewrites",
            "value": manual_reread,
        },
    }


def _structure_quality_gate(passed: bool, description: str, value: Any) -> dict[str, Any]:
    return {
        "status": "pass" if passed else "fail",
        "description": description,
        "value": value,
    }


def _offset_residue_under_control(
    body_offset_totals: dict[str, Any],
    body_offset_review_classes: dict[str, Any],
    functions: int,
) -> bool:
    residue = _int_value(body_offset_totals.get("offset_deref_survivors"), 0)
    if _density(residue, functions) <= 2.0:
        return True
    functions_with_residue = _int_value(body_offset_totals.get("functions_with_offset_residue"), 0)
    if functions_with_residue <= 0:
        return False
    unclassified = _int_value(body_offset_review_classes.get("unclassified_offset_residue"), 0)
    classified_ratio = max(
        0.0,
        float(functions_with_residue - unclassified) / float(functions_with_residue),
    )
    return unclassified <= max(5, functions // 20) and classified_ratio >= 0.85


def _structure_quality_positive_gates(
    components: dict[str, dict[str, Any]],
    prototype_totals: dict[str, Any],
    body_offset_totals: dict[str, Any],
    body_offset_review_classes: dict[str, Any],
    pointer_indexed_totals: dict[str, Any],
    body_text_stats: dict[str, Any],
    rewrite_preview_artifact_totals: dict[str, Any],
    functions: int,
) -> dict[str, dict[str, Any]]:
    return {
        "prototype_corrections_visible": _structure_quality_gate(
            _int_value(prototype_totals.get("applied_parameter_type_corrections"), 0) >= max(1, functions // 10),
            "profile-backed parameter type corrections are visible in the corpus",
            _int_value(prototype_totals.get("applied_parameter_type_corrections"), 0),
        ),
        "function_identity_visible": _structure_quality_gate(
            _int_value(prototype_totals.get("function_identity_candidates"), 0) >= max(1, functions // 5),
            "function identity evidence is present at corpus scale",
            _int_value(prototype_totals.get("function_identity_candidates"), 0),
        ),
        "offset_residue_under_control": _structure_quality_gate(
            _offset_residue_under_control(
                body_offset_totals,
                body_offset_review_classes,
                functions,
            ),
            "body offset-deref survivors are low or classified with fail-closed evidence",
            {
                "offset_deref_survivors": _int_value(
                    body_offset_totals.get("offset_deref_survivors"),
                    0,
                ),
                "unclassified_offset_residue": _int_value(
                    body_offset_review_classes.get("unclassified_offset_residue"),
                    0,
                ),
            },
        ),
        "pointer_indexed_residue_under_control": _structure_quality_gate(
            _density(_int_value(body_text_stats.get("pointer_indexed_offset_deref_patterns"), 0), functions) <= 1.5,
            "pointer-indexed offset residue is either low or modelled separately",
            _int_value(body_text_stats.get("pointer_indexed_offset_deref_patterns"), 0),
        ),
        "visible_body_improvement": _structure_quality_gate(
            (
                _int_value(body_text_stats.get("visible_review_only_field_alias_annotations"), 0)
                + _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_applied"), 0)
                + _int_value(body_text_stats.get("projected_aggregate_accesses"), 0)
            )
            > 0,
            "cleaned bodies show validated rewrites, projection, or review-only field aliases",
            {
                "visible_review_only_field_alias_annotations": _int_value(
                    body_text_stats.get("visible_review_only_field_alias_annotations"),
                    0,
                ),
                "projected_aggregate_accesses": _int_value(
                    body_text_stats.get("projected_aggregate_accesses"),
                    0,
                ),
                "canonical_layout_rewrite_applied": _int_value(
                    rewrite_preview_artifact_totals.get("canonical_rewrite_applied"),
                    0,
                ),
            },
        ),
        "synthetic_local_aggregate_view": _structure_quality_gate(
            (
                _int_value(body_text_stats.get("synthetic_local_aggregate_candidates"), 0) == 0
                or _int_value(body_text_stats.get("inline_review_only_aggregate_aliases"), 0) > 0
                or _int_value(body_text_stats.get("projected_aggregate_accesses"), 0) > 0
            ),
            "synthetic aggregate candidates are surfaced near body uses, projected, or no candidate exists",
            {
                "synthetic_local_aggregate_candidates": _int_value(
                    body_text_stats.get("synthetic_local_aggregate_candidates"),
                    0,
                ),
                "synthetic_pool_aggregate_candidates": _int_value(
                    body_text_stats.get("synthetic_pool_aggregate_candidates"),
                    0,
                ),
                "inline_review_only_aggregate_aliases": _int_value(
                    body_text_stats.get("inline_review_only_aggregate_aliases"),
                    0,
                ),
                "projected_aggregate_accesses": _int_value(
                    body_text_stats.get("projected_aggregate_accesses"),
                    0,
                ),
                "aggregate_misleading_rewrites": _int_value(
                    body_text_stats.get("aggregate_misleading_rewrites"),
                    0,
                ),
            },
        ),
        "canonical_layout_rewrites_visible": _structure_quality_gate(
            _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_applied"), 0) > 0,
            "validated canonical layout rewrites are visible in artifacts",
            _int_value(rewrite_preview_artifact_totals.get("canonical_rewrite_applied"), 0),
        ),
        "all_components_near_or_target": _structure_quality_gate(
            all(
                _float_value(_coerce_dict(components.get(name, {})).get("score"), 0.0) >= 7.0
                for name in _STRUCTURE_QUALITY_COMPONENT_ORDER
            ),
            "all structure score components are at least near the 9/10 bar",
            {
                name: _float_value(_coerce_dict(components.get(name, {})).get("score"), 0.0)
                for name in _STRUCTURE_QUALITY_COMPONENT_ORDER
            },
        ),
    }


def _structure_quality_manual_reread(report: dict[str, Any]) -> dict[str, Any]:
    manual = _coerce_dict(report.get("manual_reread", {}))
    inspected = _int_value(manual.get("inspected_functions"), 0)
    misleading = _int_value(manual.get("misleading_rewrites"), 0)
    improved = _int_value(manual.get("improved_functions"), 0)
    honest_blocked = _int_value(manual.get("honest_blocked_functions"), 0)
    passed = inspected >= 80 and misleading == 0
    return {
        "status": "pass" if passed else "missing",
        "inspected_functions": inspected,
        "required_inspected_functions": 80,
        "misleading_rewrites": misleading,
        "improved_functions": improved,
        "honest_blocked_functions": honest_blocked,
    }


def _structure_quality_blockers(
    components: dict[str, dict[str, Any]],
    hard_gates: dict[str, dict[str, Any]],
    positive_gates: dict[str, dict[str, Any]],
    manual_reread: dict[str, Any],
) -> list[dict[str, Any]]:
    blockers = []
    for name in _STRUCTURE_QUALITY_COMPONENT_ORDER:
        component = _coerce_dict(components.get(name, {}))
        score = _float_value(component.get("score"), 0.0)
        if score < 9.0:
            blockers.append(
                {
                    "kind": "component_below_9",
                    "name": name,
                    "score": score,
                    "status": str(component.get("status", "") or ""),
                }
            )
    for group_name, gates in (("hard_gate", hard_gates), ("positive_gate", positive_gates)):
        for name, gate in gates.items():
            if not isinstance(gate, dict):
                continue
            if str(gate.get("status", "") or "") != "pass":
                blockers.append(
                    {
                        "kind": group_name,
                        "name": name,
                        "status": str(gate.get("status", "") or ""),
                    }
                )
    if str(manual_reread.get("status", "") or "") != "pass":
        blockers.append(
            {
                "kind": "manual_reread",
                "name": "manual_reread",
                "status": str(manual_reread.get("status", "") or ""),
            }
        )
    return blockers


@lru_cache(maxsize=1)
def _runtime_boundary_status() -> dict[str, Any]:
    roots = [ROOT / "pseudoforge.py", ROOT / "ida_pseudoforge"]
    forbidden = []
    scanned = 0
    for root in roots:
        if not root.exists():
            continue
        paths = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for path in paths:
            scanned += 1
            for item in _forbidden_runtime_imports(path):
                forbidden.append(item)
    return {
        "passed": not forbidden,
        "forbidden_imports": len(forbidden),
        "scanned_python_files": scanned,
        "items": forbidden[:20],
    }


def _forbidden_runtime_imports(path: Path) -> list[dict[str, str]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError as exc:
        return [
            {
                "path": str(path),
                "line": str(getattr(exc, "lineno", 0) or 0),
                "module": "syntax_error",
            }
        ]
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = str(alias.name or "").split(".", 1)[0]
                if root in _STRUCTURE_QUALITY_FORBIDDEN_IMPORT_ROOTS:
                    results.append(
                        {
                            "path": str(path),
                            "line": str(getattr(node, "lineno", 0) or 0),
                            "module": str(alias.name or ""),
                        }
                    )
        elif isinstance(node, ast.ImportFrom):
            root = str(node.module or "").split(".", 1)[0]
            if root in _STRUCTURE_QUALITY_FORBIDDEN_IMPORT_ROOTS:
                results.append(
                    {
                        "path": str(path),
                        "line": str(getattr(node, "lineno", 0) or 0),
                        "module": str(node.module or ""),
                    }
                )
    return results


def render_quality_markdown(report: dict[str, Any]) -> str:
    totals = _coerce_dict(report.get("totals", {}))
    structure_quality_score = _coerce_dict(report.get("structure_quality_score", {}))
    rename_stats = _coerce_dict(report.get("rename_stats", {}))
    warning_stats = _coerce_dict(report.get("warning_stats", {}))
    existing_parameter_alias_stats = _coerce_dict(report.get("existing_parameter_alias_stats", {}))
    rule_stats = _coerce_dict(report.get("rule_stats", {}))
    api_semantic_stats = _coerce_dict(report.get("api_semantic_stats", {}))
    api_semantic_review_queue = _coerce_dict(report.get("api_semantic_review_queue", {}))
    layout_hint_stats = _coerce_dict(report.get("layout_hint_stats", {}))
    subfield_overlay_stats = _coerce_dict(report.get("layout_subfield_overlay_stats", {}))
    narrow_subfield_stats = _coerce_dict(report.get("layout_narrow_subfield_stats", {}))
    bitfield_alias_stats = _coerce_dict(report.get("layout_bitfield_alias_stats", {}))
    hot_field_cluster_stats = _coerce_dict(report.get("layout_hot_field_cluster_stats", {}))
    indexed_callback_table_stats = _coerce_dict(report.get("layout_indexed_callback_table_stats", {}))
    parameter_indexed_element_stats = _coerce_dict(report.get("layout_parameter_indexed_element_stats", {}))
    stable_base_source_stats = _coerce_dict(report.get("layout_stable_base_source_stats", {}))
    base_stability_stats = _coerce_dict(report.get("layout_base_stability_stats", {}))
    generic_base_evidence_stats = _coerce_dict(report.get("layout_generic_base_evidence_stats", {}))
    generic_base_trust_candidate_stats = _coerce_dict(report.get("layout_generic_base_trust_candidate_stats", {}))
    temp_provenance_stats = _coerce_dict(report.get("layout_temp_provenance_stats", {}))
    rewrite_ready_stats = _coerce_dict(report.get("layout_rewrite_ready_stats", {}))
    rewrite_preview_stats = _coerce_dict(report.get("layout_rewrite_preview_stats", {}))
    rewrite_preview_artifact_stats = _coerce_dict(report.get("layout_rewrite_preview_artifact_stats", {}))
    pointer_indexed_offset_stats = _coerce_dict(report.get("pointer_indexed_offset_stats", {}))
    rewrite_near_ready_stats = _coerce_dict(report.get("layout_rewrite_near_ready_stats", {}))
    rewrite_partial_opportunity_stats = _coerce_dict(report.get("layout_rewrite_partial_opportunity_stats", {}))
    rewrite_blocker_stats = _coerce_dict(report.get("layout_rewrite_blocker_stats", {}))
    ntstatus_body_residue_stats = _coerce_dict(report.get("ntstatus_body_residue_stats", {}))
    decimal_status_residue_stats = _coerce_dict(report.get("decimal_status_residue_stats", {}))
    status_store_residue_stats = _coerce_dict(report.get("status_store_residue_stats", {}))
    prototype_correction_stats = _coerce_dict(report.get("prototype_correction_stats", {}))
    evidence_graph_stats = _coerce_dict(report.get("evidence_graph_stats", {}))
    body_offset_residue_stats = _coerce_dict(report.get("body_offset_residue_review_stats", {}))
    prototype_correction_totals = _coerce_dict(prototype_correction_stats.get("totals", {}))
    evidence_graph_totals = _coerce_dict(evidence_graph_stats.get("totals", {}))
    body_offset_residue_totals = _coerce_dict(body_offset_residue_stats.get("totals", {}))
    ntstatus_review_queues = _coerce_dict(ntstatus_body_residue_stats.get("review_queues", {}))
    layout_totals = _coerce_dict(layout_hint_stats.get("totals", {}))
    subfield_overlay_totals = _coerce_dict(subfield_overlay_stats.get("totals", {}))
    narrow_subfield_totals = _coerce_dict(narrow_subfield_stats.get("totals", {}))
    bitfield_alias_totals = _coerce_dict(bitfield_alias_stats.get("totals", {}))
    hot_field_cluster_totals = _coerce_dict(hot_field_cluster_stats.get("totals", {}))
    indexed_callback_table_totals = _coerce_dict(indexed_callback_table_stats.get("totals", {}))
    parameter_indexed_element_totals = _coerce_dict(parameter_indexed_element_stats.get("totals", {}))
    stable_base_source_totals = _coerce_dict(stable_base_source_stats.get("totals", {}))
    base_stability_totals = _coerce_dict(base_stability_stats.get("totals", {}))
    generic_base_evidence_totals = _coerce_dict(generic_base_evidence_stats.get("totals", {}))
    generic_base_trust_candidate_totals = _coerce_dict(generic_base_trust_candidate_stats.get("totals", {}))
    temp_provenance_totals = _coerce_dict(temp_provenance_stats.get("totals", {}))
    rewrite_ready_totals = _coerce_dict(rewrite_ready_stats.get("totals", {}))
    rewrite_preview_totals = _coerce_dict(rewrite_preview_stats.get("totals", {}))
    rewrite_preview_artifact_totals = _coerce_dict(rewrite_preview_artifact_stats.get("totals", {}))
    pointer_indexed_offset_totals = _coerce_dict(pointer_indexed_offset_stats.get("totals", {}))
    rewrite_near_ready_totals = _coerce_dict(rewrite_near_ready_stats.get("totals", {}))
    rewrite_partial_opportunity_totals = _coerce_dict(rewrite_partial_opportunity_stats.get("totals", {}))
    rewrite_blocker_totals = _coerce_dict(rewrite_blocker_stats.get("totals", {}))
    text_stats = _coerce_dict(report.get("text_stats", {}))
    body_text_stats = _coerce_dict(report.get("body_text_stats", {}))
    lines = [
        "# PseudoForge Corpus Quality Report",
        "",
        "- Corpus root: `%s`" % report.get("corpus_root", ""),
        "- Generated at: `%s`" % report.get("generated_at", ""),
        "- Functions scanned: `%s`" % totals.get("summaries", 0),
        "- Cleaned files: `%s`" % totals.get("cleaned_files", 0),
        "- Warnings: `%s` across `%s` functions"
        % (totals.get("warnings", 0), totals.get("functions_with_warnings", 0)),
        "- Rename apply rate: `%s`" % rename_stats.get("apply_rate", 0),
        "- LLM apply rate: `%s`" % rename_stats.get("llm_apply_rate", 0),
        "",
        "## Structure Quality Scorecard",
        "",
        "- Overall score: `%s`" % structure_quality_score.get("score", 0),
        "- Claim: `%s`" % structure_quality_score.get("claim", "not_9_yet"),
        "- Hard gates all pass: `%s`"
        % str(bool(structure_quality_score.get("hard_gates_all_pass", False))).lower(),
        "",
        "### Components",
        "",
        "| Component | Score | Weight | Status | Key metrics |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    score_components = _coerce_dict(structure_quality_score.get("components", {}))
    for component_name in structure_quality_score.get("component_order", []) or []:
        component = _coerce_dict(score_components.get(str(component_name), {}))
        metrics = _coerce_dict(component.get("metrics", {}))
        metric_text = ", ".join("%s=%s" % (key, value) for key, value in metrics.items())
        lines.append(
            "| `%s` | %s | %s | `%s` | %s |"
            % (
                str(component_name),
                component.get("score", 0),
                component.get("weight", 0),
                str(component.get("status", "") or ""),
                _markdown_table_cell(metric_text),
            )
        )
    lines.extend(
        [
            "",
            "### Hard Gates",
            "",
            "| Gate | Status | Value |",
            "| --- | --- | --- |",
        ]
    )
    for gate_name, gate in _coerce_dict(structure_quality_score.get("hard_gates", {})).items():
        gate_dict = _coerce_dict(gate)
        lines.append(
            "| `%s` | `%s` | %s |"
            % (
                str(gate_name),
                str(gate_dict.get("status", "") or ""),
                _markdown_table_cell(gate_dict.get("value", "")),
            )
        )
    blockers = structure_quality_score.get("blockers", []) or []
    lines.extend(
        [
            "",
            "### 9/10 Blockers",
            "",
            "| Kind | Name | Status | Score |",
            "| --- | --- | --- | ---: |",
        ]
    )
    if blockers:
        for blocker in blockers[:20]:
            if not isinstance(blocker, dict):
                continue
            lines.append(
                "| `%s` | `%s` | `%s` | %s |"
                % (
                    str(blocker.get("kind", "") or ""),
                    str(blocker.get("name", "") or ""),
                    str(blocker.get("status", "") or ""),
                    blocker.get("score", ""),
                )
            )
    else:
        lines.append("| `none` | `none` | `pass` | 10 |")
    lines.extend(
        [
            "",
            "## Warning Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(warning_stats.get("top_classes", {})), "Class"))
    lines.extend(
        [
            "",
            "### Existing Parameter Register Aliases",
            "",
            "- Aliases: `%s` across `%s` functions"
            % (
                existing_parameter_alias_stats.get("total_aliases", 0),
                existing_parameter_alias_stats.get("function_count", 0),
            ),
            "",
            "| Function | EA | Aliases | Details |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for item in existing_parameter_alias_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        details = []
        for alias in item.get("aliases", []) or []:
            if not isinstance(alias, dict):
                continue
            details.append(
                "%s(%s)->%s arg%s %s"
                % (
                    str(alias.get("symbol", "") or ""),
                    str(alias.get("register", "") or ""),
                    str(alias.get("existing_parameter_rendered_name", "") or ""),
                    _int_value(alias.get("argument_index"), -1),
                    str(alias.get("callee_name", "") or ""),
                )
            )
        lines.append(
            "| `%s` | `%s` | %s | %s |"
            % (
                str(item.get("name", "") or ""),
                str(item.get("ea", "") or ""),
                _int_value(item.get("alias_count"), 0),
                _markdown_table_cell(", ".join(details)),
            )
        )
    lines.extend(
        [
            "",
            "## Rename Sources",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rename_stats.get("by_source", {})), "Source"))
    lines.extend(
        [
            "",
            "## Evidence Graph",
            "",
            "- Functions with graph: `%s`"
            % evidence_graph_totals.get("functions_with_evidence_graph", 0),
            "- Nodes / edges: `%s` / `%s`"
            % (
                evidence_graph_totals.get("nodes", 0),
                evidence_graph_totals.get("edges", 0),
            ),
            "- Trusted rewrite edges: `%s` across `%s` functions"
            % (
                evidence_graph_totals.get("trusted_rewrite_edges", 0),
                evidence_graph_totals.get("functions_with_trusted_rewrite_edges", 0),
            ),
            "- Trusted preview edges: `%s` across `%s` functions"
            % (
                evidence_graph_totals.get("trusted_preview_edges", 0),
                evidence_graph_totals.get("functions_with_trusted_preview_edges", 0),
            ),
            "- Report-only edges: `%s` across `%s` functions"
            % (
                evidence_graph_totals.get("report_only_edges", 0),
                evidence_graph_totals.get("functions_with_report_only_edges", 0),
            ),
            "- Blocked edges: `%s` across `%s` functions"
            % (
                evidence_graph_totals.get("blocked_edges", 0),
                evidence_graph_totals.get("functions_with_blocked_edges", 0),
            ),
            "- Rewrite-eligible graph edges: `%s`"
            % evidence_graph_totals.get("rewrite_eligible_edges", 0),
            "",
            "### Evidence Graph Promotion Lanes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(evidence_graph_stats.get("promotion_lanes", {})),
            "Lane",
        )
    )
    lines.extend(
        [
            "",
            "### Evidence Graph Blockers",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(evidence_graph_stats.get("blockers", {})),
            "Blocker",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Evidence Graph Functions",
            "",
            "| Function | EA | Nodes | Edges | Rewrite | Preview | Report-only | Blocked | Eligible | Lanes | Blockers |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in evidence_graph_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        lane_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("promotion_lanes", {})).items()
        )
        blocker_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blockers", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("nodes", 0) or 0),
                int(item.get("edges", 0) or 0),
                int(item.get("trusted_rewrite_edges", 0) or 0),
                int(item.get("trusted_preview_edges", 0) or 0),
                int(item.get("report_only_edges", 0) or 0),
                int(item.get("blocked_edges", 0) or 0),
                int(item.get("rewrite_eligible_edges", 0) or 0),
                _markdown_table_cell(lane_text),
                _markdown_table_cell(blocker_text),
            )
        )
    lines.extend(
        [
            "",
            "## Prototype Correction Evidence",
            "",
            "- Function identity hits: `%s`"
            % prototype_correction_totals.get("function_identity_candidates", 0),
            "- Parameter type corrections: `%s` applied `%s`, blocked `%s`"
            % (
                prototype_correction_totals.get("parameter_type_corrections", 0),
                prototype_correction_totals.get("applied_parameter_type_corrections", 0),
                prototype_correction_totals.get("blocked_parameter_type_corrections", 0),
            ),
            "- Corrected parameter map entries: `%s`"
            % prototype_correction_totals.get("corrected_parameter_map_entries", 0),
            "- Type-assisted preview candidates: `%s` functions, `%s` parameter corrections"
            % (
                prototype_correction_totals.get("type_assisted_preview_candidates", 0),
                prototype_correction_totals.get("type_assisted_preview_parameter_corrections", 0),
            ),
            "- Type-assisted restore: `%s` succeeded, `%s` failed"
            % (
                prototype_correction_totals.get("type_assisted_preview_restore_succeeded", 0),
                prototype_correction_totals.get("type_assisted_preview_restore_failures", 0),
            ),
            "- Report-only identity preview candidates: `%s` functions, `%s` parameter corrections"
            % (
                prototype_correction_totals.get("report_only_identity_preview_candidates", 0),
                prototype_correction_totals.get("report_only_identity_preview_parameter_corrections", 0),
            ),
            "- Source-bound report-only identities: `%s` of `%s` exact report-only identities"
            % (
                prototype_correction_totals.get("source_bound_report_only_identity_candidates", 0),
                prototype_correction_totals.get("exact_report_only_identity_candidates", 0),
            ),
            "- Generic parameter survivors: `%s`"
            % prototype_correction_totals.get("generic_parameter_survivors", 0),
            "- Offset-deref survivors: `%s`"
            % prototype_correction_totals.get("offset_deref_survivors", 0),
            "- Direct-base deref survivors: `%s`"
            % prototype_correction_totals.get("direct_base_deref_survivors", 0),
            "- Body canonical rewrite ready: `%s`"
            % prototype_correction_totals.get("body_rewrite_ready", 0),
            "- Negative controls: `%s`"
            % _coerce_dict(prototype_correction_stats.get("negative_controls", {})).get("function_count", 0),
            "",
            "### Prototype Correction Blockers",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("blocker_counts", {})),
            "Blocker",
        )
    )
    lines.extend(
        [
            "",
            "### Prototype Correction Profiles",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("profile_counts", {})),
            "Profile",
        )
    )
    lines.extend(
        [
            "",
            "### Prototype Function Identity Profiles",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("function_identity_profiles", {})),
            "Profile",
        )
    )
    lines.extend(
        [
            "",
            "### Report-Only Identity Preview Profiles",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("report_only_identity_preview_profiles", {})),
            "Profile",
        )
    )
    lines.extend(
        [
            "",
            "### Type-Assisted Preview Statuses",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("type_assisted_preview_statuses", {})),
            "Status",
        )
    )
    lines.extend(
        [
            "",
            "### Prototype Canonical Types",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("canonical_types", {})),
            "Type",
        )
    )
    lines.extend(
        [
            "",
            "### Prototype Body Rewrite Sources",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(prototype_correction_stats.get("body_rewrite_source_provenance", {})),
            "Source",
        )
    )
    prototype_review_queues = _coerce_dict(prototype_correction_stats.get("review_queues", {}))
    lines.extend(
        [
            "",
            "### Prototype Correction Review Queues",
            "",
        ]
    )
    if not prototype_review_queues:
        lines.append("No data.")
    else:
        lines.extend(
            [
                "| Queue | Functions | Blocked | TA preview params | TA restore failures | RO preview params | Generic survivors | Offset derefs | Profiles | Blockers | Next step |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |",
            ]
        )
        for queue_name, queue in prototype_review_queues.items():
            if not isinstance(queue, dict):
                continue
            profile_text = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(queue.get("profiles", {})).items()
            )
            blocker_text = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(queue.get("blockers", {})).items()
            )
            lines.append(
                "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    queue_name,
                    int(queue.get("function_count", 0) or 0),
                    int(queue.get("blocked_parameter_type_corrections", 0) or 0),
                    int(queue.get("type_assisted_preview_parameter_corrections", 0) or 0),
                    int(queue.get("type_assisted_preview_restore_failures", 0) or 0),
                    int(queue.get("report_only_identity_preview_parameter_corrections", 0) or 0),
                    int(queue.get("generic_parameter_survivors", 0) or 0),
                    int(queue.get("offset_deref_survivors", 0) or 0),
                    _markdown_table_cell(profile_text),
                    _markdown_table_cell(blocker_text),
                    _markdown_table_cell(queue.get("recommended_next_step", "")),
                )
            )
        lines.extend(
            [
                "",
                "| Queue | Function | EA | Blocked | TA preview params | TA restore failures | RO preview params | Generic survivors | Offset derefs | Profiles | Blockers |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
            ]
        )
        for queue_name, queue in prototype_review_queues.items():
            if not isinstance(queue, dict):
                continue
            for item in queue.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                profile_text = ", ".join(
                    "%s=%s" % (key, value)
                    for key, value in _coerce_dict(item.get("profiles", {})).items()
                )
                blocker_text = ", ".join(
                    "%s=%s" % (key, value)
                    for key, value in _coerce_dict(item.get("blockers", {})).items()
                )
                lines.append(
                    "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
                    % (
                        queue_name,
                        str(item.get("name", "")),
                        str(item.get("ea", "")),
                        int(item.get("blocked_parameter_type_corrections", 0) or 0),
                        int(item.get("type_assisted_preview_parameter_corrections", 0) or 0),
                        int(item.get("type_assisted_preview_restore_failures", 0) or 0),
                        int(item.get("report_only_identity_preview_parameter_corrections", 0) or 0),
                        int(item.get("generic_parameter_survivors", 0) or 0),
                        int(item.get("offset_deref_survivors", 0) or 0),
                        _markdown_table_cell(profile_text),
                        _markdown_table_cell(blocker_text),
                    )
                )
    lines.extend(
        [
            "",
            "### Highest Prototype Correction Functions",
            "",
            "| Function | EA | Identities | Corrections | Applied | Blocked | TA preview params | TA restore failures | RO preview params | Map | Body ready | Generic survivors | Offset derefs | Profiles | Types | Blockers |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in prototype_correction_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        profile_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("profiles", {})).items()
        )
        type_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("canonical_types", {})).items()
        )
        blocker_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blockers", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("function_identity_candidates", 0) or 0),
                int(item.get("parameter_type_corrections", 0) or 0),
                int(item.get("applied_parameter_type_corrections", 0) or 0),
                int(item.get("blocked_parameter_type_corrections", 0) or 0),
                int(item.get("type_assisted_preview_parameter_corrections", 0) or 0),
                int(item.get("type_assisted_preview_restore_failures", 0) or 0),
                int(item.get("report_only_identity_preview_parameter_corrections", 0) or 0),
                int(item.get("corrected_parameter_map_entries", 0) or 0),
                int(item.get("body_rewrite_ready", 0) or 0),
                int(item.get("generic_parameter_survivors", 0) or 0),
                int(item.get("offset_deref_survivors", 0) or 0),
                _markdown_table_cell(profile_text),
                _markdown_table_cell(type_text),
                _markdown_table_cell(blocker_text),
            )
        )
    negative_controls = _coerce_dict(prototype_correction_stats.get("negative_controls", {}))
    lines.extend(
        [
            "",
            "### Prototype Correction Negative Controls",
            "",
            "| Function | EA | Generic survivors | Offset derefs |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    for item in negative_controls.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | `%s` | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("generic_parameter_survivors", 0) or 0),
                int(item.get("offset_deref_survivors", 0) or 0),
            )
        )
    lines.extend(
        [
            "",
            "## Body Offset Residue Review Queue",
            "",
            "- Functions with offset residue: `%s`"
            % body_offset_residue_totals.get("functions_with_offset_residue", 0),
            "- Offset deref survivors: `%s`"
            % body_offset_residue_totals.get("offset_deref_survivors", 0),
            "- Direct-base deref survivors in residue functions: `%s` across `%s` functions"
            % (
                body_offset_residue_totals.get("direct_base_deref_survivors", 0),
                body_offset_residue_totals.get("functions_with_direct_base_deref_residue", 0),
            ),
            "- Generic parameter survivors in residue functions: `%s`"
            % body_offset_residue_totals.get("generic_parameter_survivors", 0),
            "- Nested field-pointer residue: `%s` across `%s` functions"
            % (
                body_offset_residue_totals.get("nested_field_pointer_residue", 0),
                body_offset_residue_totals.get("functions_with_nested_field_pointer_residue", 0),
            ),
            "- Rewrite-ready residue functions: `%s`"
            % body_offset_residue_totals.get("functions_with_rewrite_ready", 0),
            "- Rewrite-blocked residue functions: `%s`"
            % body_offset_residue_totals.get("functions_with_rewrite_blockers", 0),
            "- Domain-identity residue functions: `%s`"
            % body_offset_residue_totals.get("functions_with_domain_identity", 0),
            "- Named goal target residue functions: `%s`"
            % body_offset_residue_totals.get("functions_with_named_goal_targets", 0),
            "",
            "### Residue Subsystems",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("subsystems", {})),
            "Subsystem",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Next Actions",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("next_actions", {})),
            "Action",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Review Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("review_classes", {})),
            "Class",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Review Evidence",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("review_evidence", {})),
            "Evidence",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Promotion Hints",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("promotion_hints", {})),
            "Hint",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Promotion Lanes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("promotion_lanes", {})),
            "Lane",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Next Action Details",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("next_action_details", {})),
            "Detail",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Priority Factors",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("priority_factors", {})),
            "Priority factor",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Review Notes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("residue_review_notes", {})),
            "Review note",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Fail-Closed Gates",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("fail_closed_gates", {})),
            "Fail-closed gate",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Fail-Closed Families",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("fail_closed_families", {})),
            "Fail-closed family",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Named Goal Target Groups",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("named_target_groups", {})),
            "Target group",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Rewrite Safety Policies",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("rewrite_safety_policies", {})),
            "Safety policy",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Evidence Maturity",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("evidence_maturity", {})),
            "Evidence maturity",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Cause Tags",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("residue_cause_tags", {})),
            "Cause tag",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Stable Source Details",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("top_stable_source_details", {})),
            "Source detail",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Review Focuses",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("review_focuses", {})),
            "Review focus",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Offset Shape Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("offset_shape_classes", {})),
            "Shape",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Offset Base Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("offset_base_classes", {})),
            "Base class",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Direct-Base Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(body_offset_residue_stats.get("direct_base_classes", {})),
            "Direct-base class",
        )
    )
    lines.extend(
        [
            "",
            "### Residue Review Queues",
            "",
            "| Queue | Description | Functions | Offset derefs | Direct-base derefs | Direct-base bases | Offset samples | Generic params | Nested field residue | Target groups | Subsystems | Gates | Families | Policies | Maturity | Pressure | Primary reasons | Notes | Cause tags | Blocker families | Promotion lanes | Factors | Classes | Details | Source provenance | Source kinds | Stable sources | Profiles | Next step |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for queue_name, queue in _coerce_dict(body_offset_residue_stats.get("review_queues", {})).items():
        if not isinstance(queue, dict):
            continue
        subsystems = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("subsystems", {})).items()
        )
        review_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("review_classes", {})).items()
        )
        details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("next_action_details", {})).items()
        )
        gates = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("fail_closed_gates", {})).items()
        )
        families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("fail_closed_families", {})).items()
        )
        target_groups = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("target_groups", {})).items()
        )
        policies = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("rewrite_safety_policies", {})).items()
        )
        maturity = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("evidence_maturity", {})).items()
        )
        pressure = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("residue_pressure_classes", {})).items()
        )
        primary_reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("primary_review_reasons", {})).items()
        )
        review_notes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("residue_review_notes", {})).items()
        )
        cause_tags = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("residue_cause_tags", {})).items()
        )
        blocker_families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("blocker_families", {})).items()
        )
        promotion_lanes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("promotion_lanes", {})).items()
        )
        factors = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("priority_factors", {})).items()
        )
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("stable_source_provenance", {})).items()
        )
        source_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("stable_source_kinds", {})).items()
        )
        stable_sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("top_stable_sources", {})).items()
        )
        stable_source_details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("top_stable_source_details", {})).items()
        )
        if stable_source_details:
            stable_sources = (
                "%s; detail %s" % (stable_sources, stable_source_details)
                if stable_sources
                else "detail %s" % stable_source_details
            )
        parameter_field_pointer_anchors = _body_offset_parameter_field_pointer_anchor_summary(queue)
        if parameter_field_pointer_anchors:
            stable_sources = (
                "%s; field-ptr %s" % (stable_sources, parameter_field_pointer_anchors)
                if stable_sources
                else "field-ptr %s" % parameter_field_pointer_anchors
            )
        existing_alias_anchors = ", ".join(
            str(sample)
            for sample in queue.get("existing_parameter_alias_samples", []) or []
            if str(sample)
        )
        if existing_alias_anchors:
            stable_sources = (
                "%s; resolved-alias %s" % (stable_sources, existing_alias_anchors)
                if stable_sources
                else "resolved-alias %s" % existing_alias_anchors
            )
        live_in_anchors = ", ".join(
            str(sample)
            for sample in queue.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        )
        if live_in_anchors:
            stable_sources = (
                "%s; live-in %s" % (stable_sources, live_in_anchors)
                if stable_sources
                else "live-in %s" % live_in_anchors
            )
        callee_arity_anchors = ", ".join(
            str(sample)
            for sample in queue.get("callee_arity_residue_samples", []) or []
            if str(sample)
        )
        if callee_arity_anchors:
            stable_sources = (
                "%s; callee-arity %s" % (stable_sources, callee_arity_anchors)
                if stable_sources
                else "callee-arity %s" % callee_arity_anchors
            )
        domain_profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("domain_profiles", {})).items()
        )
        identity_context = _body_offset_identity_context_summary(queue)
        if identity_context:
            domain_profiles = (
                "%s; identity %s" % (domain_profiles, identity_context)
                if domain_profiles
                else "identity %s" % identity_context
            )
        identity_sources = _body_offset_identity_source_summary(queue)
        if identity_sources:
            domain_profiles = (
                "%s; source %s" % (domain_profiles, identity_sources)
                if domain_profiles
                else "source %s" % identity_sources
            )
        direct_base_bases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("direct_base_deref_bases", {})).items()
        )
        direct_base_types = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("direct_base_deref_types", {})).items()
        )
        direct_base_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("direct_base_deref_base_classes", {})).items()
        )
        direct_call_anchors = _body_offset_direct_call_result_anchor_summary(queue)
        direct_call_hints = _body_offset_direct_call_result_hint_summary(queue)
        direct_base_summary = direct_base_bases
        if direct_base_types:
            direct_base_summary = "%s; types %s" % (direct_base_summary, direct_base_types) if direct_base_summary else "types %s" % direct_base_types
        if direct_base_classes:
            direct_base_summary = "%s; classes %s" % (direct_base_summary, direct_base_classes) if direct_base_summary else "classes %s" % direct_base_classes
        if direct_call_anchors:
            direct_base_summary = "%s; calls %s" % (direct_base_summary, direct_call_anchors) if direct_base_summary else "calls %s" % direct_call_anchors
        if direct_call_hints:
            direct_base_summary = "%s; call-hints %s" % (direct_base_summary, direct_call_hints) if direct_base_summary else "call-hints %s" % direct_call_hints
        offset_samples = _body_offset_offset_deref_sample_summary(queue)
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(queue_name),
                _markdown_table_cell(str(queue.get("description", "") or "")),
                int(queue.get("functions", 0) or 0),
                int(queue.get("offset_deref_survivors", 0) or 0),
                int(queue.get("direct_base_deref_survivors", 0) or 0),
                _markdown_table_cell(direct_base_summary),
                _markdown_table_cell(offset_samples),
                int(queue.get("generic_parameter_survivors", 0) or 0),
                int(queue.get("nested_field_pointer_residue", 0) or 0),
                _markdown_table_cell(target_groups),
                _markdown_table_cell(subsystems),
                _markdown_table_cell(gates),
                _markdown_table_cell(families),
                _markdown_table_cell(policies),
                _markdown_table_cell(maturity),
                _markdown_table_cell(pressure),
                _markdown_table_cell(primary_reasons),
                _markdown_table_cell(review_notes),
                _markdown_table_cell(cause_tags),
                _markdown_table_cell(blocker_families),
                _markdown_table_cell(promotion_lanes),
                _markdown_table_cell(factors),
                _markdown_table_cell(review_classes),
                _markdown_table_cell(details),
                _markdown_table_cell(source_provenance),
                _markdown_table_cell(source_kinds),
                _markdown_table_cell(stable_sources),
                _markdown_table_cell(domain_profiles),
                _markdown_table_cell(str(queue.get("recommended_next_step", "") or "")),
            )
        )
    next_goal_candidates = _coerce_dict(body_offset_residue_stats.get("next_goal_candidates", {}))
    lines.extend(
        [
            "",
            "### Residue Next Goal Candidates",
            "",
            "- Candidate count: `%s`" % next_goal_candidates.get("candidate_count", 0),
            "- Workflow: %s"
            % _markdown_table_cell(str(next_goal_candidates.get("recommended_workflow", "") or "")),
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(next_goal_candidates.get("candidate_kinds", {})),
            "Candidate kind",
        )
    )
    direct_base_batches = _coerce_dict(
        body_offset_residue_stats.get("direct_base_root_review_batches", {})
    )
    root_batches = [
        item
        for item in direct_base_batches.get("batches", []) or []
        if isinstance(item, dict)
    ]
    if root_batches:
        lines.extend(
            [
                "",
                "#### Direct-Base Root Review Batches",
                "",
                "| Root class | Functions | Direct derefs | Named targets | Bases | Call-result anchors | Gates | Cause tags | Top functions | Next step |",
                "| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for batch in root_batches:
            bases = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("direct_base_bases", {})).items()
            )
            call_result_anchors = ", ".join(
                str(sample)
                for sample in batch.get("direct_call_result_samples", []) or []
                if str(sample)
            )
            if not call_result_anchors:
                call_result_anchors = ", ".join(
                    "%s=%s" % (key, value)
                    for key, value in _coerce_dict(batch.get("direct_call_result_callees", {})).items()
                )
            arg_roots = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("direct_call_result_arg_roots", {})).items()
            )
            if arg_roots:
                call_result_anchors = (
                    "%s; args %s" % (call_result_anchors, arg_roots)
                    if call_result_anchors
                    else "args %s" % arg_roots
                )
            call_result_hints = _body_offset_direct_call_result_hint_summary(batch)
            if call_result_hints:
                call_result_anchors = (
                    "%s; hints %s" % (call_result_anchors, call_result_hints)
                    if call_result_anchors
                    else "hints %s" % call_result_hints
                )
            gates = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("fail_closed_gates", {})).items()
            )
            cause_tags = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("residue_cause_tags", {})).items()
            )
            top_functions = ", ".join(
                "%s(%s)" % (
                    str(item.get("name", "") or ""),
                    _int_value(item.get("root_class_direct_base_derefs"), 0),
                )
                for item in batch.get("top_functions", []) or []
                if isinstance(item, dict)
            )
            lines.append(
                "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    str(batch.get("root_class", "") or ""),
                    _int_value(batch.get("function_count"), 0),
                    _int_value(batch.get("direct_base_deref_survivors"), 0),
                    _int_value(batch.get("named_goal_targets"), 0),
                    _markdown_table_cell(bases),
                    _markdown_table_cell(call_result_anchors),
                    _markdown_table_cell(gates),
                    _markdown_table_cell(cause_tags),
                    _markdown_table_cell(top_functions),
                    _markdown_table_cell(str(batch.get("recommended_next_step", "") or "")),
                )
            )
    review_batches = [
        item
        for item in next_goal_candidates.get("review_batches", []) or []
        if isinstance(item, dict)
    ]
    if review_batches:
        lines.extend(
            [
                "",
                "#### Candidate Review Batches",
                "",
                "| Batch | Functions | Named targets | Actionability | Residue | Direct-base roots | Call-result anchors | Field-pointer anchors | Indexed anchors | Offset samples | Gates | Cause tags | Requirements | Top functions | Next step |",
                "| --- | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for batch in review_batches:
            actionability = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("actionability_classes", {})).items()
            )
            gates = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("fail_closed_gates", {})).items()
            )
            cause_tags = ", ".join(
                "%s=%s" % (key, value)
                for key, value in _coerce_dict(batch.get("residue_cause_tags", {})).items()
            )
            named_targets = _body_offset_named_target_summary(batch)
            requirements: list[str] = []
            for field in [
                "source_identity_requirements",
                "source_stability_requirements",
                "type_conflict_requirements",
            ]:
                requirements.extend(
                    "%s=%s" % (key, value)
                    for key, value in _coerce_dict(batch.get(field, {})).items()
                )
            identity_context = _body_offset_identity_context_summary(batch)
            if identity_context:
                requirements.append("identity_context %s" % identity_context)
            identity_sources = _body_offset_identity_source_summary(batch)
            if identity_sources:
                requirements.append("identity_source %s" % identity_sources)
            top_functions = ", ".join(
                "%s(%s)" % (
                    str(item.get("name", "") or ""),
                    _int_value(item.get("actionability_score"), 0),
                )
                for item in batch.get("top_functions", []) or []
                if isinstance(item, dict)
            )
            residue = "offset=%s, direct=%s, generic=%s, nested=%s" % (
                _int_value(batch.get("offset_deref_survivors"), 0),
                _int_value(batch.get("direct_base_deref_survivors"), 0),
                _int_value(batch.get("generic_parameter_survivors"), 0),
                _int_value(batch.get("nested_field_pointer_residue"), 0),
            )
            direct_base_roots = _body_offset_direct_base_root_summary(batch)
            call_result_anchors = _body_offset_direct_call_result_anchor_summary(batch)
            call_result_hints = _body_offset_direct_call_result_hint_summary(batch)
            if call_result_hints:
                call_result_anchors = (
                    "%s; hints %s" % (call_result_anchors, call_result_hints)
                    if call_result_anchors
                    else "hints %s" % call_result_hints
                )
            parameter_field_pointer_anchors = _body_offset_parameter_field_pointer_anchor_summary(batch)
            parameter_indexed_anchors = _body_offset_parameter_indexed_anchor_summary(batch)
            offset_samples = _body_offset_offset_deref_sample_summary(batch)
            lines.append(
                "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    str(batch.get("batch", "") or ""),
                    _int_value(batch.get("function_count"), 0),
                    _markdown_table_cell(named_targets),
                    _markdown_table_cell(actionability),
                    _markdown_table_cell(residue),
                    _markdown_table_cell(direct_base_roots),
                    _markdown_table_cell(call_result_anchors),
                    _markdown_table_cell(parameter_field_pointer_anchors),
                    _markdown_table_cell(parameter_indexed_anchors),
                    _markdown_table_cell(offset_samples),
                    _markdown_table_cell(gates),
                    _markdown_table_cell(cause_tags),
                    _markdown_table_cell(", ".join(requirements)),
                    _markdown_table_cell(top_functions),
                    _markdown_table_cell(str(batch.get("recommended_next_step", "") or "")),
                )
            )
    lines.extend(
        [
            "",
            "| Function | Kind | Actionability | Subsystem | Target group | Gate | Lane | Score | Offset derefs | Direct-base derefs | Direct-base roots | Call-result anchors | Field-pointer anchors | Indexed anchors | Offset samples | Cause tags | Stable sources | Profiles | Next step | Requirements | Safety |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in next_goal_candidates.get("items", []) or []:
        if not isinstance(item, dict):
            continue
        stable_sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_stable_sources", {})).items()
        )
        stable_source_details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_stable_source_details", {})).items()
        )
        if stable_source_details:
            stable_sources = (
                "%s; detail %s" % (stable_sources, stable_source_details)
                if stable_sources
                else "detail %s" % stable_source_details
            )
        callee_arity_anchors = ", ".join(
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        )
        if callee_arity_anchors:
            stable_sources = (
                "%s; callee-arity %s" % (stable_sources, callee_arity_anchors)
                if stable_sources
                else "callee-arity %s" % callee_arity_anchors
            )
        domain_profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("domain_profiles", {})).items()
        )
        identity_context = _body_offset_identity_context_summary(item)
        if identity_context:
            domain_profiles = (
                "%s; identity %s" % (domain_profiles, identity_context)
                if domain_profiles
                else "identity %s" % identity_context
            )
        identity_sources = _body_offset_identity_source_summary(item)
        if identity_sources:
            domain_profiles = (
                "%s; source %s" % (domain_profiles, identity_sources)
                if domain_profiles
                else "source %s" % identity_sources
            )
        cause_tags = ", ".join(str(value) for value in item.get("residue_cause_tags", []) or [])
        requirements = "; ".join(
            str(item.get(key, "") or "")
            for key in [
                "source_identity_requirement",
                "source_stability_requirement",
                "type_conflict_requirement",
            ]
            if str(item.get(key, "") or "")
        )
        call_result_anchors = _body_offset_direct_call_result_anchor_summary(item)
        call_result_hints = _body_offset_direct_call_result_hint_summary(item)
        if call_result_hints:
            call_result_anchors = (
                "%s; hints %s" % (call_result_anchors, call_result_hints)
                if call_result_anchors
                else "hints %s" % call_result_hints
            )
        parameter_field_pointer_anchors = _body_offset_parameter_field_pointer_anchor_summary(item)
        parameter_indexed_anchors = _body_offset_parameter_indexed_anchor_summary(item)
        offset_samples = _body_offset_offset_deref_sample_summary(item)
        direct_base_roots = str(item.get("direct_base_root_summary", "") or "")
        if not direct_base_roots:
            direct_base_roots = _body_offset_direct_base_root_summary(item)
        target_group = _body_offset_named_target_summary(item)
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "") or ""),
                str(item.get("candidate_kind", "") or ""),
                str(item.get("actionability_class", "") or ""),
                str(item.get("subsystem", "") or ""),
                _markdown_table_cell(target_group),
                str(item.get("fail_closed_gate", "") or ""),
                str(item.get("promotion_lane", "") or ""),
                _int_value(item.get("actionability_score"), 0),
                _int_value(item.get("offset_deref_survivors"), 0),
                _int_value(item.get("direct_base_deref_survivors"), 0),
                _markdown_table_cell(direct_base_roots),
                _markdown_table_cell(call_result_anchors),
                _markdown_table_cell(parameter_field_pointer_anchors),
                _markdown_table_cell(parameter_indexed_anchors),
                _markdown_table_cell(offset_samples),
                _markdown_table_cell(cause_tags),
                _markdown_table_cell(stable_sources),
                _markdown_table_cell(domain_profiles),
                _markdown_table_cell(str(item.get("next_step", "") or "")),
                _markdown_table_cell(requirements),
                _markdown_table_cell(str(item.get("safety_note", "") or "")),
            )
        )
    target_status = _coerce_dict(body_offset_residue_stats.get("named_goal_target_status", {}))
    lines.extend(
        [
            "",
            "### Named Goal Target Status",
            "",
            "- Corpus present targets: `%s`" % target_status.get("corpus_present_count", 0),
            "- Body-offset residue targets: `%s`"
            % target_status.get(
                "body_offset_residue_present_count",
                target_status.get("present_count", 0),
            ),
            "- No body-offset residue targets: `%s`"
            % target_status.get("no_body_offset_residue_count", 0),
            "- Missing targets: `%s`" % target_status.get("missing_count", 0),
            "",
            "| Function | Group | Gate | Lane | Pressure | Score | Offset derefs | Direct-base derefs | Direct-base roots | Offset samples | Cause tags | Bases | Blockers | Stable sources | Recommended next |",
            "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in target_status.get("present_targets", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join(str(base) for base in item.get("top_bases", []) or [])
        blockers = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_families", {})).items()
        )
        stable_sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_stable_sources", {})).items()
        )
        stable_source_details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_stable_source_details", {})).items()
        )
        if stable_source_details:
            stable_sources = (
                "%s; detail %s" % (stable_sources, stable_source_details)
                if stable_sources
                else "detail %s" % stable_source_details
            )
        cause_tags = ", ".join(str(value) for value in item.get("residue_cause_tags", []) or [])
        direct_base_roots = _body_offset_direct_base_root_summary(item)
        offset_samples = _body_offset_offset_deref_sample_summary(item)
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "") or ""),
                str(item.get("target_group", "") or ""),
                str(item.get("fail_closed_gate", "") or ""),
                str(item.get("promotion_lane", "") or ""),
                str(item.get("residue_pressure_class", "") or ""),
                _int_value(item.get("priority_score"), 0),
                _int_value(item.get("offset_deref_survivors"), 0),
                _int_value(item.get("direct_base_deref_survivors"), 0),
                _markdown_table_cell(direct_base_roots),
                _markdown_table_cell(offset_samples),
                _markdown_table_cell(cause_tags),
                _markdown_table_cell(bases),
                _markdown_table_cell(blockers),
                _markdown_table_cell(stable_sources),
                _markdown_table_cell(str(item.get("recommended_next", "") or "")),
            )
        )
    no_residue_targets = [
        item
        for item in target_status.get("no_body_offset_residue_targets", []) or []
        if isinstance(item, dict)
    ]
    if no_residue_targets:
        lines.extend(
            [
                "",
                "No body-offset residue named targets:",
                "",
                "| Function | Group | EA | Recommended next |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in no_residue_targets:
            lines.append(
                "| `%s` | `%s` | `%s` | %s |"
                % (
                    str(item.get("name", "") or ""),
                    str(item.get("target_group", "") or ""),
                    str(item.get("ea", "") or ""),
                    _markdown_table_cell(str(item.get("recommended_next", "") or "")),
                )
            )
    if target_status.get("missing_targets"):
        missing = ", ".join(
            str(item.get("name", "") or "")
            for item in target_status.get("missing_targets", []) or []
            if isinstance(item, dict)
        )
        lines.extend(["", "Missing named targets: %s" % _markdown_table_cell(missing)])
    lines.extend(
        [
            "",
            "### Highest Body Offset Residue Functions",
            "",
            "| Function | Summary | Lane | EA | Goal | Subsystem | Focus | Gate | Family | Safety | Maturity | Pressure | Primary reasons | Notes | Cause tags | Factors | Class | Next action | Details | Score | Offset derefs | Direct-base derefs | RO preview params | Offset samples | Field pressure | Ready | Blockers | Evidence | Promotion hints | Bases | Reasons |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
        ]
    )
    for item in (body_offset_residue_stats.get("top_functions", []) or [])[:_BODY_OFFSET_RESIDUE_MARKDOWN_ITEM_LIMIT]:
        if not isinstance(item, dict):
            continue
        bases = ", ".join(str(base) for base in item.get("top_bases", []) or [])
        reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_reasons", {})).items()
        )
        evidence = ", ".join(str(value) for value in item.get("review_evidence", []) or [])
        promotion_hints = ", ".join(str(value) for value in item.get("promotion_hints", []) or [])
        next_action_details = ", ".join(str(value) for value in item.get("next_action_details", []) or [])
        priority_factors = ", ".join(str(value) for value in item.get("priority_factors", []) or [])
        primary_reasons = ", ".join(str(value) for value in item.get("primary_review_reasons", []) or [])
        review_notes = ", ".join(str(value) for value in item.get("residue_review_notes", []) or [])
        cause_tags = ", ".join(str(value) for value in item.get("residue_cause_tags", []) or [])
        goal_group = str(item.get("named_goal_target_group", "") or "")
        goal_text = goal_group if bool(item.get("named_goal_target")) else ""
        promotion_lane = str(item.get("promotion_lane", "") or "")
        offset_samples = _body_offset_offset_deref_sample_summary(item)
        lines.append(
            "| `%s` | %s | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s | %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                _markdown_table_cell(str(item.get("review_summary", "") or "")),
                promotion_lane,
                str(item.get("ea", "")),
                goal_text,
                str(item.get("subsystem", "")),
                str(item.get("review_focus", "")),
                str(item.get("fail_closed_gate", "")),
                str(item.get("fail_closed_family", "")),
                str(item.get("rewrite_safety_policy", "")),
                str(item.get("evidence_maturity", "")),
                str(item.get("residue_pressure_class", "")),
                _markdown_table_cell(primary_reasons),
                _markdown_table_cell(review_notes),
                _markdown_table_cell(cause_tags),
                _markdown_table_cell(priority_factors),
                str(item.get("review_class", "")),
                str(item.get("next_action", "")),
                _markdown_table_cell(next_action_details),
                int(item.get("priority_score", 0) or 0),
                int(item.get("offset_deref_survivors", 0) or 0),
                int(item.get("direct_base_deref_survivors", 0) or 0),
                int(item.get("report_only_identity_preview_parameter_corrections", 0) or 0),
                _markdown_table_cell(offset_samples),
                int(item.get("field_access_pressure", 0) or 0),
                int(item.get("body_rewrite_ready", 0) or 0),
                int(item.get("body_rewrite_blockers", 0) or 0),
                _markdown_table_cell(evidence),
                _markdown_table_cell(promotion_hints),
                _markdown_table_cell(bases),
                _markdown_table_cell(reasons),
            )
        )
    lines.extend(
        [
            "",
            "## Rule Coverage",
            "",
            "- Matched rules: `%s`" % totals.get("matched_rules", 0),
            "- Rewrite emissions: `%s`" % rule_stats.get("rewrite_emissions", 0),
            "- Rejected emissions: `%s`" % rule_stats.get("rejected_emissions", 0),
            "",
            "## API Semantic Diagnostics",
            "",
            "- Diagnostics: `%s`" % api_semantic_stats.get("diagnostics", 0),
            "- Rejections: `%s` across `%s` functions"
            % (
                api_semantic_stats.get("rejections", 0),
                api_semantic_stats.get("functions_with_diagnostics", 0),
            ),
            "",
            "### Rejections By Reason",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(api_semantic_stats.get("rejections_by_reason", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Rejections By Stage",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(api_semantic_stats.get("rejections_by_stage", {})), "Stage"))
    lines.extend(
        [
            "",
            "### Top API Rejection Profiles",
            "",
            "| Reason | Stage | New | Callee | Parameter | Type | Arg | Count |",
            "| --- | --- | --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for item in api_semantic_stats.get("top_rejection_profiles", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s |"
            % (
                str(item.get("reason", "")),
                str(item.get("stage", "")),
                str(item.get("new", "")),
                str(item.get("callee", "")),
                str(item.get("parameter", "")),
                str(item.get("parameter_type", "")),
                str(item.get("argument_index", "")),
                int(item.get("count", 0) or 0),
            )
        )
    lines.extend(
        [
            "",
            "### Highest API Rejection Functions",
            "",
            "| Function | EA | Rejections | Reasons | Targets | Profiles |",
            "| --- | --- | ---: | --- | --- | --- |",
        ]
    )
    for item in api_semantic_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("rejections_by_reason", {})).items()
        )
        targets = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("rejections_by_target", {})).items()
        )
        profile_text = "; ".join(
            "%s:%s:%s:%s=%s"
            % (
                str(profile.get("reason", "")),
                str(profile.get("new", "")),
                str(profile.get("callee", "")),
                str(profile.get("parameter", "")),
                int(profile.get("count", 0) or 0),
            )
            for profile in item.get("top_rejection_profiles", []) or []
            if isinstance(profile, dict)
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("rejection_count", 0) or 0),
                _markdown_table_cell(reasons),
                _markdown_table_cell(targets),
                _markdown_table_cell(profile_text),
            )
        )
    lines.extend(
        [
            "",
            "### API Semantic Review Queue",
            "",
            "- Queue items: `%s`" % api_semantic_review_queue.get("item_count", 0),
            "- Repeated targets: `%s`" % api_semantic_review_queue.get("repeated_target_count", 0),
            "",
            "#### Queue Categories",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(api_semantic_review_queue.get("category_counts", {})),
            "Category",
        )
    )
    lines.extend(
        [
            "",
            "#### Top Repeated Targets",
            "",
            "| Category | Reason | Stage | Callee | Parameter | New | Arg | Count | Functions |",
            "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for item in api_semantic_review_queue.get("top_repeated_targets", []) or []:
        if not isinstance(item, dict):
            continue
        functions = ", ".join(
            "%s@%s"
            % (
                str(function.get("name", "")),
                str(function.get("ea", "")),
            )
            for function in item.get("functions", []) or []
            if isinstance(function, dict)
        )
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s |"
            % (
                str(item.get("category", "")),
                str(item.get("reason", "")),
                str(item.get("stage", "")),
                str(item.get("callee", "")),
                str(item.get("parameter", "")),
                str(item.get("new", "")),
                str(item.get("argument_index", "")),
                int(item.get("count", 0) or 0),
                _markdown_table_cell(functions),
            )
        )
    lines.extend(
        [
            "",
            "#### Top Queue Items",
            "",
            "| Category | Function | EA | Reason | Stage | Callee | Parameter | Old | New | Arg | Count |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: |",
        ]
    )
    for item in api_semantic_review_queue.get("top_items", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s |"
            % (
                str(item.get("category", "")),
                str(item.get("function_name", "")),
                str(item.get("ea", "")),
                str(item.get("reason", "")),
                str(item.get("stage", "")),
                str(item.get("callee", "")),
                str(item.get("parameter", "")),
                str(item.get("old", "")),
                str(item.get("new", "")),
                str(item.get("argument_index", "")),
                int(item.get("count", 0) or 0),
            )
        )
    lines.extend(
        [
            "",
            "## Inferred Layout Hints",
            "",
            "- Hints: `%s` across `%s` functions"
            % (layout_totals.get("hints", 0), layout_totals.get("functions_with_hints", 0)),
            "- Named-base hints: `%s`" % layout_totals.get("named_base_hints", 0),
            "- Temp-base hints: `%s`" % layout_totals.get("temp_base_hints", 0),
            "- Offset observations: `%s`" % layout_totals.get("offset_observations", 0),
            "",
            "### Top Layout Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(layout_hint_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Observed Layout Types",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(layout_hint_stats.get("observed_types", {})), "Type"))
    lines.extend(
        [
            "",
            "### Highest Layout Hint Functions",
            "",
            "| Function | EA | Hints | Max offsets | Max accesses | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for item in layout_hint_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("hint_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Stable Base Sources",
            "",
            "- Stable base source comments: `%s` across `%s` functions"
            % (
                stable_base_source_totals.get("source_comments", 0),
                stable_base_source_totals.get("functions_with_source_comments", 0),
            ),
            "- Stable source offset observations: `%s`" % stable_base_source_totals.get("offset_observations", 0),
            "- Stable source access observations: `%s`" % stable_base_source_totals.get("access_observations", 0),
            "",
            "### Stable Base Source Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Stable Base Source Names",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("sources", {})), "Source"))
    lines.extend(
        [
            "",
            "### Stable Base Source Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(stable_base_source_stats.get("source_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Stable Base Source Provenance",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(stable_base_source_stats.get("source_provenance", {})),
            "Provenance",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Stable Base Source Functions",
            "",
            "| Function | EA | Source comments | Max offsets | Max accesses | Sources | Source kinds | Source provenance | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
        ]
    )
    for item in stable_base_source_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_sources", {})).items()
        )
        source_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_source_kinds", {})).items()
        )
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_source_provenance", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("source_comment_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                sources,
                source_kinds,
                source_provenance,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Base Stability Evidence",
            "",
            "- Base stability comments: `%s` across `%s` functions"
            % (
                base_stability_totals.get("stability_comments", 0),
                base_stability_totals.get("functions_with_stability_comments", 0),
            ),
            "- Pre-access assignments: `%s`" % base_stability_totals.get("pre_access_assignments", 0),
            "- Distinct pre-access RHS observations: `%s`"
            % base_stability_totals.get("distinct_pre_access_rhs_observations", 0),
            "- Post-access assignments: `%s`" % base_stability_totals.get("post_access_assignments", 0),
            "- Risky post-access assignments: `%s`"
            % base_stability_totals.get("risky_post_access_assignments", 0),
            "",
            "### Base Stability Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(base_stability_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Base Stability RHS Samples",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(base_stability_stats.get("rhs_samples", {})), "RHS"))
    lines.extend(
        [
            "",
            "### Base Stability Review Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(base_stability_stats.get("profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Base Stability Review Queues",
            "",
            "| Queue | Comments | Functions | Max distinct RHS | Max risky post-access | Top bases | RHS samples |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    base_stability_review_queues = _coerce_dict(base_stability_stats.get("review_queues", {}))
    for queue_name in _BASE_STABILITY_REVIEW_PROFILE_ORDER:
        queue = _coerce_dict(base_stability_review_queues.get(queue_name, {}))
        top_bases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("top_bases", {})).items()
        )
        rhs_samples = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("rhs_samples", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                queue_name,
                int(queue.get("comments", 0) or 0),
                int(queue.get("functions", 0) or 0),
                int(queue.get("max_distinct_pre_access_rhs", 0) or 0),
                int(queue.get("max_risky_post_access_assignments", 0) or 0),
                _markdown_table_cell(top_bases),
                _markdown_table_cell(rhs_samples),
            )
        )
    lines.extend(
        [
            "",
            "### Base Stability Queue Top Items",
            "",
        ]
    )
    rendered_stability_queue_items = False
    for queue_name in _BASE_STABILITY_REVIEW_PROFILE_ORDER:
        queue = _coerce_dict(base_stability_review_queues.get(queue_name, {}))
        items = [
            item
            for item in queue.get("items", []) or []
            if isinstance(item, dict)
        ][:_BASE_STABILITY_MARKDOWN_ITEM_LIMIT]
        if not items:
            continue
        rendered_stability_queue_items = True
        lines.extend(
            [
                "",
                "#### `%s`" % queue_name,
                "",
                "| Function | EA | Base | Distinct RHS | Risky post-access | RHS samples |",
                "| --- | --- | --- | ---: | ---: | --- |",
            ]
        )
        for item in items:
            rhs_samples = "; ".join(
                str(rhs)
                for rhs in item.get("distinct_pre_access_rhs", []) or []
                if str(rhs)
            )
            lines.append(
                "| `%s` | `%s` | `%s` | %s | %s | %s |"
                % (
                    str(item.get("name", "")),
                    str(item.get("ea", "")),
                    str(item.get("base", "")),
                    int(item.get("distinct_pre_access_rhs_count", 0) or 0),
                    int(item.get("risky_post_access_assignment_count", 0) or 0),
                    _markdown_table_cell(rhs_samples),
                )
            )
    if not rendered_stability_queue_items:
        lines.append("No data.")
    lines.extend(
        [
            "",
            "### Highest Base Stability Functions",
            "",
            "| Function | EA | Comments | Max distinct RHS | Max risky post-access | Profiles | Bases | RHS samples |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in base_stability_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        rhs_samples = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("rhs_samples", {})).items()
        )
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("profiles", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("stability_comment_count", 0) or 0),
                int(item.get("max_distinct_pre_access_rhs", 0) or 0),
                int(item.get("max_risky_post_access_assignments", 0) or 0),
                _markdown_table_cell(profiles),
                bases,
                _markdown_table_cell(rhs_samples),
            )
        )
    lines.extend(
        [
            "",
            "## Layout Generic Base Evidence",
            "",
            "- Generic base evidence comments: `%s` across `%s` functions"
            % (
                generic_base_evidence_totals.get("evidence_comments", 0),
                generic_base_evidence_totals.get("functions_with_evidence_comments", 0),
            ),
            "- Generic base evidence offset observations: `%s`" % generic_base_evidence_totals.get("offset_observations", 0),
            "- Generic base evidence access observations: `%s`" % generic_base_evidence_totals.get("access_observations", 0),
            "",
            "### Generic Base Evidence Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_evidence_stats.get("blocker_profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Generic Base Evidence Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_evidence_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Generic Base Evidence Functions",
            "",
            "| Function | EA | Evidence | Max offsets | Max accesses | Profiles | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in generic_base_evidence_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_profiles", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("evidence_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                profiles,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Generic Base Trust Candidates",
            "",
            "- Generic base trust candidates: `%s` across `%s` functions"
            % (
                generic_base_trust_candidate_totals.get("trust_candidates", 0),
                generic_base_trust_candidate_totals.get("functions_with_trust_candidates", 0),
            ),
            "- Trust candidate offset observations: `%s`" % generic_base_trust_candidate_totals.get("offset_observations", 0),
            "- Trust candidate access observations: `%s`" % generic_base_trust_candidate_totals.get("access_observations", 0),
            "",
            "### Generic Base Trust Source Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("source_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Generic Base Trust Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("blocker_profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Generic Base Trust Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(generic_base_trust_candidate_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Generic Base Trust Candidate Functions",
            "",
            "| Function | EA | Candidates | Max offsets | Max accesses | Sources | Profiles | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in generic_base_trust_candidate_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        sources = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_kinds", {})).items()
        )
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("blocker_profiles", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("candidate_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                sources,
                profiles,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Temp-Base Provenance",
            "",
            "- Provenance traces: `%s` across `%s` functions"
            % (
                temp_provenance_totals.get("trace_comments", 0),
                temp_provenance_totals.get("functions_with_temp_provenance", 0),
            ),
            "- Trusted temp sources: `%s`" % temp_provenance_totals.get("trusted_temp_sources", 0),
            "- Blocked temp candidates: `%s`" % temp_provenance_totals.get("blocked_candidates", 0),
            "- Review-only candidates: `%s`" % temp_provenance_totals.get("review_only_candidates", 0),
            "- Rewrite-ready unlocked: `%s`" % temp_provenance_totals.get("rewrite_ready_unlocked", 0),
            "",
            "### Temp Provenance Trust Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(temp_provenance_stats.get("trust_classes", {})), "Trust class"))
    lines.extend(
        [
            "",
            "### Temp Provenance Source Origins",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(temp_provenance_stats.get("source_origins", {})), "Origin"))
    lines.extend(
        [
            "",
            "### Temp Provenance Block Reasons",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(temp_provenance_stats.get("block_reasons", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Temp Provenance Branch Shapes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(_coerce_dict(temp_provenance_stats.get("branch_merge_shapes", {})), "Shape")
    )
    lines.extend(
        [
            "",
            "### Highest Temp Provenance Functions",
            "",
            "| Function | EA | Traces | Trusted | Blocked | Trust classes | Origins | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in temp_provenance_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        trust_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("trust_classes", {})).items()
        )
        origins = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_origins", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("trace_count", 0) or 0),
                int(item.get("trusted_count", 0) or 0),
                int(item.get("blocked_count", 0) or 0),
                _markdown_table_cell(trust_classes),
                _markdown_table_cell(origins),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Subfield Overlays",
            "",
            "- Overlay comments: `%s` across `%s` functions"
            % (
                subfield_overlay_totals.get("overlay_comments", 0),
                subfield_overlay_totals.get("functions_with_overlay_comments", 0),
            ),
            "- Overlay field observations: `%s`" % subfield_overlay_totals.get("field_observations", 0),
            "",
            "### Subfield Overlay Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Size Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("size_classes", {})), "Size class"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Policy Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("policy_classes", {})), "Policy class"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Interpretations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("interpretations", {})), "Interpretation"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Bit Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("bit_masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Bit Operations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("bit_operations", {})), "Operation"))
    lines.extend(
        [
            "",
            "### Subfield Overlay Mask Families",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(subfield_overlay_stats.get("mask_families", {})), "Family"))
    lines.extend(
        [
            "",
            "### Highest Subfield Overlay Functions",
            "",
            "| Function | EA | Overlays | Fields | Size classes | Policy classes | Interpretations | Bit masks | Bit operations | Mask families | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in subfield_overlay_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        size_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_size_classes", {})).items()
        )
        policy_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_policy_classes", {})).items()
        )
        interpretations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_interpretations", {})).items()
        )
        bit_masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_masks", {})).items()
        )
        bit_operations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_operations", {})).items()
        )
        mask_families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_mask_families", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("overlay_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                size_classes,
                policy_classes,
                interpretations,
                bit_masks,
                bit_operations,
                mask_families,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Narrow Subfields",
            "",
            "- Narrow subfield comments: `%s` across `%s` functions"
            % (
                narrow_subfield_totals.get("candidate_comments", 0),
                narrow_subfield_totals.get("functions_with_candidate_comments", 0),
            ),
            "- Narrow field observations: `%s`" % narrow_subfield_totals.get("field_observations", 0),
            "",
            "### Narrow Subfield Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Size Classes",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("size_classes", {})), "Size class"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Interpretations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("interpretations", {})), "Interpretation"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Bit Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("bit_masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Bit Operations",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("bit_operations", {})), "Operation"))
    lines.extend(
        [
            "",
            "### Narrow Subfield Mask Families",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(narrow_subfield_stats.get("mask_families", {})), "Family"))
    lines.extend(
        [
            "",
            "### Highest Narrow Subfield Functions",
            "",
            "| Function | EA | Candidates | Fields | Size classes | Interpretations | Bit masks | Bit operations | Mask families | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in narrow_subfield_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        size_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_size_classes", {})).items()
        )
        interpretations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_interpretations", {})).items()
        )
        bit_masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_masks", {})).items()
        )
        bit_operations = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_bit_operations", {})).items()
        )
        mask_families = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_mask_families", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("candidate_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                size_classes,
                interpretations,
                bit_masks,
                bit_operations,
                mask_families,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Bitfield Aliases",
            "",
            "- Bitfield alias comments: `%s` across `%s` functions"
            % (
                bitfield_alias_totals.get("alias_comments", 0),
                bitfield_alias_totals.get("functions_with_alias_comments", 0),
            ),
            "- Bitfield alias field observations: `%s`" % bitfield_alias_totals.get("field_observations", 0),
            "",
            "### Bitfield Alias Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Bitfield Alias Names",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("aliases", {})), "Alias"))
    lines.extend(
        [
            "",
            "### Bitfield Alias Masks",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(bitfield_alias_stats.get("masks", {})), "Mask"))
    lines.extend(
        [
            "",
            "### Highest Bitfield Alias Functions",
            "",
            "| Function | EA | Alias comments | Fields | Aliases | Masks | Bases |",
            "| --- | --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in bitfield_alias_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        aliases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_aliases", {})).items()
        )
        masks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_masks", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("alias_comment_count", 0) or 0),
                int(item.get("field_count", 0) or 0),
                aliases,
                masks,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Hot Field Clusters",
            "",
            "- Hot cluster comments: `%s` across `%s` functions"
            % (
                hot_field_cluster_totals.get("cluster_comments", 0),
                hot_field_cluster_totals.get("functions_with_cluster_comments", 0),
            ),
            "- Hot cluster offset observations: `%s`" % hot_field_cluster_totals.get("offset_observations", 0),
            "- Hot cluster access observations: `%s`" % hot_field_cluster_totals.get("access_observations", 0),
            "- Hot cluster field observations: `%s`" % hot_field_cluster_totals.get("field_observations", 0),
            "",
            "### Hot Cluster Base Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(hot_field_cluster_stats.get("base_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Hot Cluster Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(hot_field_cluster_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Hot Cluster Field Types",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(hot_field_cluster_stats.get("field_types", {})), "Type"))
    lines.extend(
        [
            "",
            "### Highest Hot Cluster Functions",
            "",
            "| Function | EA | Clusters | Max offsets | Max accesses | Max top-field accesses | Base kinds | Field types | Bases |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in hot_field_cluster_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        base_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("base_kinds", {})).items()
        )
        field_types = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_field_types", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("cluster_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                int(item.get("max_top_field_access_count", 0) or 0),
                _markdown_table_cell(base_kinds),
                _markdown_table_cell(field_types),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Indexed Callback Table Evidence",
            "",
            "- Indexed/callback evidence comments: `%s` across `%s` functions"
            % (
                indexed_callback_table_totals.get("evidence_comments", 0),
                indexed_callback_table_totals.get("functions_with_evidence_comments", 0),
            ),
            "- Indexed/callback access observations: `%s`"
            % indexed_callback_table_totals.get("access_observations", 0),
            "- Indexed/callback slot observations: `%s`"
            % indexed_callback_table_totals.get("slot_observations", 0),
            "",
            "### Indexed Callback Base Kinds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(indexed_callback_table_stats.get("base_kinds", {})), "Kind"))
    lines.extend(
        [
            "",
            "### Indexed Callback Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(indexed_callback_table_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Indexed Callback Alias Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(indexed_callback_table_stats.get("alias_bases", {})), "Alias"))
    lines.extend(
        [
            "",
            "### Highest Indexed Callback Functions",
            "",
            "| Function | EA | Evidence | Max slots | Max accesses | Base kinds | Alias bases | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in indexed_callback_table_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        base_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("base_kinds", {})).items()
        )
        alias_bases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("alias_bases", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("evidence_count", 0) or 0),
                int(item.get("max_slot_count", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(base_kinds),
                _markdown_table_cell(alias_bases),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Parameter Indexed Element Evidence",
            "",
            "- Parameter-indexed element comments: `%s` across `%s` functions"
            % (
                parameter_indexed_element_totals.get("evidence_comments", 0),
                parameter_indexed_element_totals.get("functions_with_evidence_comments", 0),
            ),
            "- Parameter-indexed element access observations: `%s`"
            % parameter_indexed_element_totals.get("access_observations", 0),
            "- Parameter-indexed element offset observations: `%s`"
            % parameter_indexed_element_totals.get("element_offset_observations", 0),
            "- Parameter-indexed alias rewrite risks: `%s`"
            % parameter_indexed_element_totals.get("alias_rewrite_risks", 0),
            "",
            "### Parameter Indexed Parents",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(parameter_indexed_element_stats.get("parents", {})), "Parent"))
    lines.extend(
        [
            "",
            "### Parameter Indexed Parent Types",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(parameter_indexed_element_stats.get("parent_types", {})),
            "Parent type",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Parameter Indexed Element Functions",
            "",
            "| Function | EA | Evidence | Max offsets | Max accesses | Parents | Parent types | Strides | Alias rewrite risks | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for item in parameter_indexed_element_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        parents = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("parents", {})).items()
        )
        parent_types = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("parent_types", {})).items()
        )
        strides = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("strides", {})).items()
        )
        alias_rewrite_risks = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("alias_rewrite_risks", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("evidence_count", 0) or 0),
                int(item.get("max_offset_count", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(parents),
                _markdown_table_cell(parent_types),
                _markdown_table_cell(strides),
                _markdown_table_cell(alias_rewrite_risks),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Readiness",
            "",
            "- Ready candidates: `%s` across `%s` functions"
            % (rewrite_ready_totals.get("ready_candidates", 0), rewrite_ready_totals.get("functions_with_ready_candidates", 0)),
            "- Ready offset observations: `%s`" % rewrite_ready_totals.get("offset_observations", 0),
            "- Ready access observations: `%s`" % rewrite_ready_totals.get("access_observations", 0),
            "",
            "### Rewrite-Ready Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_ready_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Rewrite-Ready Source Provenance",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_ready_stats.get("source_provenance", {})),
            "Provenance",
        )
    )
    lines.extend(
        [
            "",
            "### Rewrite-Ready Threshold Policies",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_ready_stats.get("threshold_policies", {})),
            "Policy",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Rewrite-Ready Functions",
            "",
            "| Function | EA | Ready | Max offsets | Max accesses | Source provenance | Threshold policies | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in rewrite_ready_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_provenance", {})).items()
        )
        threshold_policies = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("threshold_policies", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("ready_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(source_provenance),
                _markdown_table_cell(threshold_policies),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Preview Plans",
            "",
            "- Preview plans: `%s` across `%s` functions"
            % (
                rewrite_preview_totals.get("preview_plans", 0),
                rewrite_preview_totals.get("functions_with_preview_plans", 0),
            ),
            "- Preview access observations: `%s`" % rewrite_preview_totals.get("access_observations", 0),
            "- Preview field observations: `%s`" % rewrite_preview_totals.get("field_observations", 0),
            "",
            "### Rewrite Preview Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_preview_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Rewrite Preview Source Provenance",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_preview_stats.get("source_provenance", {})),
            "Provenance",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Rewrite Preview Functions",
            "",
            "| Function | EA | Plans | Max fields | Max accesses | Source provenance | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in rewrite_preview_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_provenance", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("preview_count", 0) or 0),
                int(item.get("max_fields", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(source_provenance),
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Preview Artifact Validation",
            "",
            "- Preview artifacts: `%s` across `%s` functions"
            % (
                rewrite_preview_artifact_totals.get("preview_artifacts", 0),
                rewrite_preview_artifact_totals.get("functions_with_preview_artifacts", 0),
            ),
            "- Artifact rewritten accesses: `%s`" % rewrite_preview_artifact_totals.get("rewritten_accesses", 0),
            "- Artifact rewritten fields: `%s`" % rewrite_preview_artifact_totals.get("rewritten_fields", 0),
            "- Artifact validation errors: `%s`" % rewrite_preview_artifact_totals.get("validation_errors", 0),
            "- Advertisement normalizations: `%s`"
            % rewrite_preview_artifact_totals.get("advertisement_normalizations", 0),
            "- Normalized access delta: `%s`"
            % rewrite_preview_artifact_totals.get("normalized_access_delta", 0),
            "- Normalized field delta: `%s`"
            % rewrite_preview_artifact_totals.get("normalized_field_delta", 0),
            "- Source alias residual extensions: `%s` across `%s` functions"
            % (
                rewrite_preview_artifact_totals.get("source_alias_residual_extensions", 0),
                rewrite_preview_artifact_totals.get(
                    "functions_with_source_alias_residual_extensions",
                    0,
                ),
            ),
            "- Source alias residual extended offsets: `%s`"
            % rewrite_preview_artifact_totals.get("source_alias_residual_extended_offsets", 0),
            "- Canonical rewrite requested: `%s`"
            % rewrite_preview_artifact_totals.get("canonical_rewrite_requested", 0),
            "- Canonical rewrite applied: `%s`" % rewrite_preview_artifact_totals.get("canonical_rewrite_applied", 0),
            "- Canonical rewrite applied full: `%s`"
            % rewrite_preview_artifact_totals.get("canonical_rewrite_applied_full", 0),
            "- Canonical rewrite applied partial: `%s`"
            % rewrite_preview_artifact_totals.get("canonical_rewrite_applied_partial", 0),
            "- Canonical rewrite blocked: `%s`" % rewrite_preview_artifact_totals.get("canonical_rewrite_blocked", 0),
            "- Canonical rewrite errors: `%s`" % rewrite_preview_artifact_totals.get("canonical_rewrite_errors", 0),
            "",
            "### Preview Artifact Validation Statuses",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_preview_artifact_stats.get("validation_statuses", {})),
            "Status",
        )
    )
    lines.extend(
        [
            "",
            "### Preview Artifact Canonical Rewrite Statuses",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_preview_artifact_stats.get("canonical_rewrite_statuses", {})),
            "Status",
        )
    )
    lines.extend(
        [
            "",
            "### Preview Artifact Plan Kinds",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_preview_artifact_stats.get("preview_plan_kinds", {})),
            "Plan kind",
        )
    )
    lines.extend(
        [
            "",
            "### Preview Artifact Failed Checks",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_preview_artifact_stats.get("failed_checks", {})),
            "Check",
        )
    )
    lines.extend(
        [
            "",
            "### Highest Rewrite Preview Artifact Functions",
            "",
            "| Function | EA | Status | Canonical rewrite | Rewritten accesses | Rewritten fields | Direct-zero rewrites | Canonical direct-zero | Bases | Errors |",
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in rewrite_preview_artifact_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("rewritten_bases", []) or [])
        errors = "; ".join(str(error) for error in item.get("validation_errors", []) or [])
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                str(item.get("validation_status", "")),
                str(item.get("canonical_rewrite_status", "")),
                int(item.get("rewritten_accesses", 0) or 0),
                int(item.get("rewritten_fields", 0) or 0),
                int(item.get("direct_zero_rewritten_accesses", 0) or 0),
                int(item.get("canonical_direct_zero_rewritten_accesses", 0) or 0),
                _markdown_table_cell(bases),
                _markdown_table_cell(errors),
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Near-Ready",
            "",
            "- Near-ready candidates: `%s` across `%s` functions"
            % (
                rewrite_near_ready_totals.get("near_ready_candidates", 0),
                rewrite_near_ready_totals.get("functions_with_near_ready_candidates", 0),
            ),
            "- Near-ready offset observations: `%s`" % rewrite_near_ready_totals.get("offset_observations", 0),
            "- Near-ready access observations: `%s`" % rewrite_near_ready_totals.get("access_observations", 0),
            "",
            "### Missing Thresholds",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_near_ready_stats.get("missing_thresholds", {})), "Threshold"))
    lines.extend(
        [
            "",
            "### Near-Ready Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_near_ready_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Near-Ready Functions",
            "",
            "| Function | EA | Near-ready | Max offsets | Max accesses | Missing | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in rewrite_near_ready_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        missing = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("missing_thresholds", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("near_ready_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                missing,
                bases,
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Partial Opportunities",
            "",
            "- Partial opportunities: `%s` across `%s` functions"
            % (
                rewrite_partial_opportunity_totals.get("partial_opportunities", 0),
                rewrite_partial_opportunity_totals.get("functions_with_partial_opportunities", 0),
            ),
            "- Safe offset observations: `%s`" % rewrite_partial_opportunity_totals.get("safe_offset_observations", 0),
            "- Safe access observations: `%s`" % rewrite_partial_opportunity_totals.get("safe_access_observations", 0),
            "- Excluded offset observations: `%s`"
            % rewrite_partial_opportunity_totals.get("excluded_offset_observations", 0),
            "- Excluded access observations: `%s`"
            % rewrite_partial_opportunity_totals.get("excluded_access_observations", 0),
            "",
            "### Partial Opportunity Reasons",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_partial_opportunity_stats.get("reasons", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Partial Opportunity Application Statuses",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_partial_opportunity_stats.get("application_statuses", {})),
            "Status",
        )
    )
    lines.extend(
        [
            "",
            "### Partial Opportunity Review Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(rewrite_partial_opportunity_stats.get("review_classes", {})),
            "Class",
        )
    )
    lines.extend(
        [
            "",
            "### Partial Opportunity Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_partial_opportunity_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Partial Opportunity Functions",
            "",
            "| Function | EA | Opportunities | Safe offsets | Safe accesses | Excluded offsets | Excluded accesses | Source provenance | Statuses | Review classes | Bases | Reasons |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for item in rewrite_partial_opportunity_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("source_provenance", {})).items()
        )
        statuses = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("application_statuses", {})).items()
        )
        review_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("review_classes", {})).items()
        )
        reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_reasons", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("partial_opportunity_count", 0) or 0),
                int(item.get("max_safe_offsets", 0) or 0),
                int(item.get("max_safe_access_count", 0) or 0),
                int(item.get("max_excluded_offsets", 0) or 0),
                int(item.get("max_excluded_access_count", 0) or 0),
                _markdown_table_cell(provenance),
                _markdown_table_cell(statuses),
                _markdown_table_cell(review_classes),
                bases,
                _markdown_table_cell(reasons),
            )
        )
    lines.extend(
        [
            "",
            "## Layout Rewrite Blockers",
            "",
            "- Blockers: `%s` across `%s` functions"
            % (rewrite_blocker_totals.get("blockers", 0), rewrite_blocker_totals.get("functions_with_blockers", 0)),
            "- Reason observations: `%s`" % rewrite_blocker_totals.get("reason_observations", 0),
            "",
            "### Rewrite Blocker Reasons",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_blocker_stats.get("reasons", {})), "Reason"))
    lines.extend(
        [
            "",
            "### Rewrite Blocker Review Profiles",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_blocker_stats.get("review_profiles", {})), "Profile"))
    lines.extend(
        [
            "",
            "### Rewrite Blocker Review Queues",
            "",
            "| Queue | Blockers | Functions | Max offsets | Max accesses | Top bases | Identity evidence | Source provenance | Promotion classes | Next actions | Next action details |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for queue_name in _LAYOUT_REWRITE_BLOCKER_QUEUE_ORDER:
        queue = _coerce_dict(_coerce_dict(rewrite_blocker_stats.get("review_queues", {})).get(queue_name, {}))
        top_bases = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("top_bases", {})).items()
        )
        identity_evidence = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("identity_evidence", {})).items()
        )
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("identity_source_provenance", {})).items()
        )
        promotion_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("promotion_review_classes", {})).items()
        )
        next_actions = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("promotion_next_actions", {})).items()
        )
        next_action_details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("promotion_next_action_details", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                queue_name,
                int(queue.get("blockers", 0) or 0),
                int(queue.get("functions", 0) or 0),
                int(queue.get("max_offsets", 0) or 0),
                int(queue.get("max_access_count", 0) or 0),
                _markdown_table_cell(top_bases),
                _markdown_table_cell(identity_evidence),
                _markdown_table_cell(source_provenance),
                _markdown_table_cell(promotion_classes),
                _markdown_table_cell(next_actions),
                _markdown_table_cell(next_action_details),
            )
        )
    lines.extend(
        [
            "",
            "### Rewrite Blocker Queue Top Items",
            "",
        ]
    )
    rendered_queue_items = False
    for queue_name in _LAYOUT_REWRITE_BLOCKER_QUEUE_ORDER:
        queue = _coerce_dict(_coerce_dict(rewrite_blocker_stats.get("review_queues", {})).get(queue_name, {}))
        items = [
            item
            for item in queue.get("items", []) or []
            if isinstance(item, dict)
        ][:_LAYOUT_REWRITE_BLOCKER_MARKDOWN_ITEM_LIMIT]
        if not items:
            continue
        rendered_queue_items = True
        lines.extend(
            [
                "",
                "#### `%s`" % queue_name,
                "",
                "| Function | EA | Base | Offsets | Accesses | Identity | Source | Promotion | Next action | Details | Risk factors | Reasons |",
                "| --- | --- | --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in items:
            source_parts = [
                str(item.get("identity_source_provenance", "") or ""),
                str(item.get("identity_source_kind", "") or ""),
                str(item.get("identity_source", "") or ""),
            ]
            source_text = ", ".join(part for part in source_parts if part) or "none"
            risk_factors = ", ".join(
                str(factor)
                for factor in item.get("promotion_risk_factors", []) or []
                if str(factor)
            )
            reasons = "; ".join(
                str(reason)
                for reason in item.get("reasons", []) or []
                if str(reason)
            )
            next_action_details = ", ".join(
                str(detail)
                for detail in item.get("promotion_next_action_details", []) or []
                if str(detail)
            )
            lines.append(
                "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    str(item.get("name", "")),
                    str(item.get("ea", "")),
                    str(item.get("base", "")),
                    int(item.get("offset_count", 0) or 0),
                    int(item.get("access_count", 0) or 0),
                    _markdown_table_cell(item.get("identity_evidence", "")),
                    _markdown_table_cell(source_text),
                    _markdown_table_cell(item.get("promotion_review_class", "")),
                    _markdown_table_cell(item.get("promotion_next_action", "")),
                    _markdown_table_cell(next_action_details),
                    _markdown_table_cell(risk_factors),
                    _markdown_table_cell(reasons),
                )
            )
    if not rendered_queue_items:
        lines.append("No data.")
    lines.extend(
        [
            "",
            "### Rewrite Blocker Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(rewrite_blocker_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Highest Rewrite Blocker Functions",
            "",
            "| Function | EA | Blockers | Reasons | Max offsets | Max accesses | Profiles | Identity evidence | Source provenance | Promotion classes | Next actions | Next action details | Bases | Top reasons |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in rewrite_blocker_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        bases = ", ".join("`%s`" % base for base in item.get("bases", []) or [])
        reasons = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("top_reasons", {})).items()
        )
        profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("review_profiles", {})).items()
        )
        identity_evidence = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("identity_evidence", {})).items()
        )
        source_provenance = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("identity_source_provenance", {})).items()
        )
        promotion_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("promotion_review_classes", {})).items()
        )
        next_actions = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("promotion_next_actions", {})).items()
        )
        next_action_details = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("promotion_next_action_details", {})).items()
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("blocker_count", 0) or 0),
                int(item.get("reason_count", 0) or 0),
                int(item.get("max_offsets", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(profiles),
                _markdown_table_cell(identity_evidence),
                _markdown_table_cell(source_provenance),
                _markdown_table_cell(promotion_classes),
                _markdown_table_cell(next_actions),
                _markdown_table_cell(next_action_details),
                bases,
                reasons,
            )
        )
    lines.extend(
        [
            "",
            "## Text Residue",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(text_stats, "Metric"))
    lines.extend(
        [
            "",
            "## Code Body Residue",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(body_text_stats, "Metric"))
    lines.extend(
        [
            "",
            "## Pointer-Indexed Offset Residue",
            "",
            "- Raw pointer-indexed offset-like derefs: `%s` across `%s` functions"
            % (
                pointer_indexed_offset_totals.get("raw_pointer_indexed_offset_deref_patterns", 0),
                pointer_indexed_offset_totals.get("functions_with_raw_pointer_indexed_offset_derefs", 0),
            ),
            "- Cleaned pointer-indexed offset-like derefs: `%s` across `%s` functions"
            % (
                pointer_indexed_offset_totals.get("pointer_indexed_offset_deref_patterns", 0),
                pointer_indexed_offset_totals.get("functions_with_pointer_indexed_offset_derefs", 0),
            ),
            "- Rewrite candidates: `%s`"
            % pointer_indexed_offset_totals.get("pointer_indexed_layout_rewrite_candidates", 0),
            "- Rewrite applied: `%s`"
            % pointer_indexed_offset_totals.get("pointer_indexed_rewrite_applied", 0),
            "",
            "### Pointer-Indexed Bases",
            "",
        ]
    )
    lines.extend(_markdown_counter_table(_coerce_dict(pointer_indexed_offset_stats.get("top_bases", {})), "Base"))
    lines.extend(
        [
            "",
            "### Pointer-Indexed Rewritten Bases",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(pointer_indexed_offset_stats.get("rewritten_bases", {})),
            "Base",
        )
    )
    lines.extend(
        [
            "",
            "### Top Pointer-Indexed Offset Functions",
            "",
            "| Function | EA | Raw | Cleaned | Candidates | Applied | Bases | Rewritten bases |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in pointer_indexed_offset_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("raw_pointer_indexed_offset_deref_patterns", 0) or 0),
                int(item.get("pointer_indexed_offset_deref_patterns", 0) or 0),
                int(item.get("pointer_indexed_layout_rewrite_candidates", 0) or 0),
                int(item.get("pointer_indexed_rewrite_applied", 0) or 0),
                _markdown_table_cell(
                    ", ".join(
                        "%s=%s" % (key, value)
                        for key, value in _coerce_dict(item.get("bases", {})).items()
                    )
                ),
                _markdown_table_cell(
                    ", ".join(
                        "%s=%s" % (key, value)
                        for key, value in _coerce_dict(item.get("rewritten_bases", {})).items()
                    )
                ),
            )
        )
    lines.extend(
        [
            "",
            "### Decimal Status-Like Residue",
            "",
            "#### Decimal Status-Like Context Kinds",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(decimal_status_residue_stats.get("context_kinds", {})),
            "Kind",
        )
    )
    lines.extend(
        [
            "",
            "#### Decimal Status-Like Profile Names",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(decimal_status_residue_stats.get("profile_names", {})),
            "Profile",
        )
    )
    lines.extend(
        [
            "",
            "#### Decimal Status-Like Review Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(decimal_status_residue_stats.get("review_classes", {})),
            "Class",
        )
    )
    lines.extend(
        [
            "",
            "#### Decimal Status-Like Target Evidence",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(decimal_status_residue_stats.get("target_evidence", {})),
            "Evidence",
        )
    )
    lines.extend(
        [
            "",
            "#### Decimal Status-Like Review Queues",
            "",
            "| Queue | Literals | Functions | Top Classes | Top Targets |",
            "| --- | ---: | ---: | --- | --- |",
        ]
    )
    decimal_review_queues = _coerce_dict(decimal_status_residue_stats.get("review_queues", {}))
    for queue_name in _DECIMAL_STATUS_REVIEW_QUEUE_ORDER:
        queue = _coerce_dict(decimal_review_queues.get(queue_name, {}))
        classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("review_classes", {})).items()
        )
        targets = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("target_evidence", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s |"
            % (
                queue_name,
                int(queue.get("literals", 0) or 0),
                int(queue.get("functions", 0) or 0),
                _markdown_table_cell(classes),
                _markdown_table_cell(targets),
            )
        )
    lines.extend(
        [
            "",
            "#### Decimal Status-Like Target Evidence Review Queues",
            "",
            "| Queue | Literals | Functions | Top Classes | Top Targets | Top Hints |",
            "| --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    decimal_target_review_queues = _coerce_dict(
        decimal_status_residue_stats.get("target_review_queues", {})
    )
    for queue_name in _DECIMAL_STATUS_TARGET_REVIEW_QUEUE_ORDER:
        queue = _coerce_dict(decimal_target_review_queues.get(queue_name, {}))
        classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("review_classes", {})).items()
        )
        targets = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("target_evidence", {})).items()
        )
        hints = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("target_review_hints", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s |"
            % (
                queue_name,
                int(queue.get("literals", 0) or 0),
                int(queue.get("functions", 0) or 0),
                _markdown_table_cell(classes),
                _markdown_table_cell(targets),
                _markdown_table_cell(hints),
            )
        )
    lines.extend(
        [
            "",
            "#### Functions With Decimal Status-Like Residue",
            "",
            "| Function | EA | Literals | Profiled | Unprofiled | Classes | Targets | Kinds | Values | Context |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for item in decimal_status_residue_stats.get("top_functions", []) or []:
        if not isinstance(item, dict):
            continue
        context_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("context_kinds", {})).items()
        )
        values = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("values", {})).items()
        )
        review_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("review_classes", {})).items()
        )
        target_evidence = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("target_evidence", {})).items()
        )
        context_text = "; ".join(
            "L%s [%s]: %s"
            % (
                context.get("line", ""),
                context.get("target_evidence", ""),
                context.get("source", ""),
            )
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("literal_count", 0) or 0),
                int(item.get("profiled_count", 0) or 0),
                int(item.get("unprofiled_count", 0) or 0),
                _markdown_table_cell(review_classes),
                _markdown_table_cell(target_evidence),
                _markdown_table_cell(context_kinds),
                _markdown_table_cell(values),
                _markdown_table_cell(context_text),
            )
        )
    lines.extend(
        [
            "",
            "### Nested Pointer Status Store Residue",
            "",
            "#### Nested Pointer Store Values",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(status_store_residue_stats.get("nested_pointer_store_values", {})),
            "Value",
        )
    )
    lines.extend(
        [
            "",
            "#### Nested Pointer Store Widths",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(status_store_residue_stats.get("nested_pointer_store_widths", {})),
            "Width",
        )
    )
    lines.extend(
        [
            "",
            "#### Nested Pointer Store Review Classes",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(status_store_residue_stats.get("nested_pointer_store_review_classes", {})),
            "Class",
        )
    )
    lines.extend(
        [
            "",
            "#### Nested Pointer Store Review Queues",
            "",
            "| Queue | Stores | Functions | Top Classes | Store Widths |",
            "| --- | ---: | ---: | --- | --- |",
        ]
    )
    nested_store_review_queues = _coerce_dict(status_store_residue_stats.get("review_queues", {}))
    for queue_name in _STATUS_STORE_REVIEW_QUEUE_ORDER:
        queue = _coerce_dict(nested_store_review_queues.get(queue_name, {}))
        classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("review_classes", {})).items()
        )
        widths = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("store_widths", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s |"
            % (
                queue_name,
                int(queue.get("stores", 0) or 0),
                int(queue.get("functions", 0) or 0),
                _markdown_table_cell(classes),
                _markdown_table_cell(widths),
            )
        )
    lines.extend(
        [
            "",
            "#### Functions With Nested Pointer Status Stores",
            "",
            "| Function | EA | Stores | DWORD | Wide | Profiled | Classes | Widths | Values | Context |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- |",
        ]
    )
    for item in status_store_residue_stats.get("top_nested_pointer_store_functions", []) or []:
        if not isinstance(item, dict):
            continue
        values = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("values", {})).items()
        )
        review_classes = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("review_classes", {})).items()
        )
        widths = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("store_widths", {})).items()
        )
        context_text = "; ".join(
            "L%s [%s]: %s"
            % (
                context.get("line", ""),
                context.get("store_width", ""),
                context.get("source", ""),
            )
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("store_count", 0) or 0),
                int(item.get("dword_store_count", 0) or 0),
                int(item.get("wide_store_count", 0) or 0),
                int(item.get("profiled_count", 0) or 0),
                _markdown_table_cell(review_classes),
                _markdown_table_cell(widths),
                _markdown_table_cell(values),
                _markdown_table_cell(context_text),
            )
        )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Values",
            "",
            "| Value | Signed | Facility | Code | Hint | Kinds | Count | Functions |",
            "| --- | ---: | ---: | ---: | --- | --- | ---: | ---: |",
        ]
    )
    for item in ntstatus_body_residue_stats.get("top_unprofiled_error_values", []) or []:
        if not isinstance(item, dict):
            continue
        context_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("context_kinds", {})).items()
        )
        lines.append(
            "| `%s` | %s | `%s` | `%s` | %s | %s | %s | %s |"
            % (
                str(item.get("hex_value", "")),
                int(item.get("signed_value", 0) or 0),
                str(item.get("facility_hex", "")),
                str(item.get("code_hex", "")),
                _markdown_table_cell(item.get("review_hint", "")),
                _markdown_table_cell(context_kinds),
                int(item.get("count", 0) or 0),
                int(item.get("function_count", 0) or 0),
            )
        )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Context Kinds",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(ntstatus_body_residue_stats.get("unprofiled_error_context_kinds", {})),
            "Kind",
        )
    )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Error Review Hints",
            "",
        ]
    )
    lines.extend(
        _markdown_counter_table(
            _coerce_dict(ntstatus_body_residue_stats.get("unprofiled_error_review_hints", {})),
            "Hint",
        )
    )
    lines.extend(
        [
            "",
            "### Unprofiled NTSTATUS Review Queues",
            "",
            "| Queue | Values | Functions |",
            "| --- | ---: | ---: |",
        ]
    )
    for queue_name in (
        "status_profile_candidates",
        "comparison_sentinel_candidates",
        "manual_review",
    ):
        queue = _coerce_dict(ntstatus_review_queues.get(queue_name, {}))
        values = queue.get("values", []) if isinstance(queue.get("values", []), list) else []
        functions = queue.get("functions", []) if isinstance(queue.get("functions", []), list) else []
        lines.append(
            "| `%s` | %s | %s |"
            % (
                queue_name,
                len(values),
                len(functions),
            )
        )
    lines.extend(
        [
            "",
            "### Functions With Unprofiled NTSTATUS Errors",
            "",
            "| Function | EA | Literals | Hint | Kinds | Values | Lines | Context | Raw literals |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in ntstatus_body_residue_stats.get("top_unprofiled_error_functions", []) or []:
        if not isinstance(item, dict):
            continue
        values = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("values", {})).items()
        )
        raw_literals = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("raw_literals", {})).items()
        )
        context_kinds = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(item.get("context_kinds", {})).items()
        )
        lines_text = ", ".join(
            str(context.get("line", ""))
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        context_text = "; ".join(
            "L%s: %s" % (context.get("line", ""), context.get("source", ""))
            for context in item.get("contexts", []) or []
            if isinstance(context, dict)
        )
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("literal_count", 0) or 0),
                _markdown_table_cell(item.get("review_hint", "")),
                _markdown_table_cell(context_kinds),
                _markdown_table_cell(values),
                _markdown_table_cell(lines_text),
                _markdown_table_cell(context_text),
                _markdown_table_cell(raw_literals),
            )
        )
    lines.extend(
        [
            "",
            "## Highest Warning Functions",
            "",
            "| Function | EA | Warnings | Top classes |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for item in report.get("top_warning_functions", []) or []:
        if not isinstance(item, dict):
            continue
        classes = ", ".join("%s=%s" % (key, value) for key, value in _coerce_dict(item.get("warning_classes", {})).items())
        lines.append(
            "| `%s` | `%s` | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("warning_count", 0) or 0),
                classes,
            )
        )
    lines.append("")
    return "\n".join(lines)


def _iter_summary_paths(functions_root: Path):
    if not functions_root.exists():
        return
    yield from sorted(functions_root.rglob("*.ida-batch-summary.json"))


def _selected_summary_paths(
    functions_root: Path,
    *,
    ea_filter: set[int] | None,
    sample_limit: int,
) -> list[Path]:
    selected: list[Path] = []
    for summary_path in _iter_summary_paths(functions_root):
        if ea_filter is not None:
            summary_ea = _summary_ea_value(summary_path)
            if summary_ea not in ea_filter:
                continue
        selected.append(summary_path)
        if sample_limit and len(selected) >= sample_limit:
            break
    return selected


def _summary_ea_value(summary_path: Path) -> int | None:
    summary = _coerce_dict(_read_json(summary_path))
    ea = _parse_ea_value(summary.get("function_ea"))
    if ea is not None:
        return ea
    prefix = str(summary_path.parent.name).split("_", 1)[0]
    return _parse_ea_value(prefix)


def _load_ea_filter(ea_values: list[str], ea_file: str) -> set[int] | None:
    result: set[int] = set()
    for value in ea_values or []:
        parsed = _parse_ea_value(value)
        if parsed is not None:
            result.add(parsed)
    if ea_file:
        path = Path(ea_file)
        if not path.exists():
            raise FileNotFoundError(path)
        for token in re.split(r"[\s,;]+", path.read_text(encoding="utf-8")):
            parsed = _parse_ea_value(token)
            if parsed is not None:
                result.add(parsed)
    return result if result else None


def _load_manual_reread(manual_reread_path: str) -> dict[str, Any]:
    path_text = str(manual_reread_path or "").strip()
    if not path_text:
        return {}
    path = Path(path_text)
    if not path.exists():
        raise FileNotFoundError(path)
    payload = _read_json(path)
    normalized = _normalize_manual_reread(payload)
    if not normalized:
        raise ValueError("manual reread JSON must be an object with manual reread evidence")
    normalized.setdefault("evidence_path", str(path))
    return normalized


def _normalize_manual_reread(value: Any) -> dict[str, Any]:
    payload = _coerce_dict(value)
    if not payload:
        return {}
    if isinstance(payload.get("manual_reread"), dict):
        payload = dict(payload.get("manual_reread") or {})
    else:
        payload = dict(payload)

    items = _manual_reread_items(payload)
    if "inspected_functions" not in payload and items:
        payload["inspected_functions"] = len(items)
    if "misleading_rewrites" not in payload and items:
        payload["misleading_rewrites"] = _count_manual_reread_items(items, ("misleading", "incorrect", "unsafe"))
    if "improved_functions" not in payload and items:
        payload["improved_functions"] = _count_manual_reread_items(items, ("improved", "better", "primary"))
    if "honest_blocked_functions" not in payload and items:
        payload["honest_blocked_functions"] = _count_manual_reread_items(items, ("honest_blocked", "blocked", "report_only"))

    return payload


def _manual_reread_items(payload: dict[str, Any]) -> list[Any]:
    for key in ("items", "functions", "reviews", "samples"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _count_manual_reread_items(items: list[Any], tokens: tuple[str, ...]) -> int:
    count = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        text = " ".join(
            str(item.get(key, "") or "").lower()
            for key in ("classification", "status", "outcome", "verdict", "notes")
        )
        if any(token in text for token in tokens):
            count += 1
    return count


def _parse_ea_value(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _artifact_path(summary_path: Path, artifacts: dict[str, Any], key: str) -> Path:
    raw_value = str(artifacts.get(key, "") or "").strip()
    if raw_value:
        path = Path(raw_value)
        if path.exists():
            return path
        if path.name:
            sibling = summary_path.parent / path.name
            if sibling.exists():
                return sibling
    suffix = ARTIFACT_SUFFIXES.get(key, "")
    if suffix:
        matches = sorted(summary_path.parent.glob("*%s" % suffix))
        if matches:
            return matches[0]
    return Path(raw_value)


def _read_json(path: Path) -> Any:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _read_text(path: Path) -> str:
    if not path or not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _embedded_primary_layout_rewrite_metadata(
    summary: dict[str, Any],
    cleaned_path: Path,
) -> dict[str, Any]:
    if str(summary.get("primary_cleaned_source", "") or "") != "type-assisted-preview":
        return {}
    text = _read_text(cleaned_path)
    if not text:
        return {}
    body_text = _strip_pseudoforge_header(text)
    matches = list(EMBEDDED_FIELD_REWRITE_RE.finditer(body_text))
    if not matches:
        return {}
    by_base: dict[str, Counter[str]] = {}
    for match in matches:
        base = str(match.group("base") or "")
        offset = str(match.group("offset") or "")
        if not base or not offset:
            continue
        by_base.setdefault(base, Counter())[offset] += 1
    if not by_base:
        return {}
    rewrite_results: dict[str, dict[str, Any]] = {}
    preview_plans: list[dict[str, Any]] = []
    rewritten_accesses = 0
    rewritten_fields = 0
    for base, offsets in sorted(by_base.items()):
        access_count = sum(offsets.values())
        field_count = len(offsets)
        rewritten_accesses += access_count
        rewritten_fields += field_count
        rewrite_results[base] = {
            "rewritten_accesses": access_count,
            "rewritten_fields": field_count,
            "offset_accesses": dict(sorted(offsets.items())),
        }
        preview_plans.append(
            {
                "base": base,
                "plan_kind": "embedded-primary",
                "advertised_access_count": access_count,
                "advertised_offsets": sorted(offsets.keys()),
            }
        )
    return {
        "schema": "pseudoforge_embedded_primary_layout_rewrite_v1",
        "source": "type-assisted-primary-cleaned",
        "validation": {"status": "passed_embedded_primary", "errors": [], "checks": {}},
        "canonical_rewrite_status": "applied_embedded_primary",
        "canonical_rewrite_requested": True,
        "canonical_cleaned_output_modified": True,
        "canonical_rewrite_errors": [],
        "rewritten_accesses": rewritten_accesses,
        "rewritten_fields": rewritten_fields,
        "rewritten_bases": sorted(by_base),
        "rewrite_results": rewrite_results,
        "preview_plans": preview_plans,
    }


def _read_warnings(path: Path) -> list[str]:
    data = _read_json(path)
    if isinstance(data, list):
        return [str(item) for item in data]
    if isinstance(data, dict) and isinstance(data.get("warnings"), list):
        return [str(item) for item in data.get("warnings", [])]
    return []


def _read_warning_diagnostics(path: Path) -> list[dict[str, Any]]:
    data = _read_json(path)
    if isinstance(data, dict):
        data = data.get("warning_diagnostics", data.get("diagnostics", []))
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _normalize_warning_diagnostics_for_quality(
    warning_diagnostics: list[dict[str, Any]],
    rename_items: list[dict[str, Any]],
    cleaned_path: Path,
) -> list[dict[str, Any]]:
    if not warning_diagnostics:
        return []
    contract_diagnostics = _quality_apply_current_callee_contracts(warning_diagnostics)
    contract_changed = contract_diagnostics is not warning_diagnostics
    parameters = _quality_signature_parameters(cleaned_path)
    if not parameters:
        return contract_diagnostics if contract_changed else warning_diagnostics
    slot_context_diagnostics = _quality_add_live_in_signature_slot_context(
        contract_diagnostics,
        parameters,
    )
    slot_context_changed = slot_context_diagnostics is not contract_diagnostics
    accepted_renames = _quality_accepted_parameter_renames_by_old_name(rename_items)
    if not accepted_renames:
        if contract_changed or slot_context_changed:
            return slot_context_diagnostics
        return warning_diagnostics

    result: list[dict[str, Any]] = []
    changed = False
    for item in slot_context_diagnostics:
        alias = _quality_existing_parameter_alias_for_diagnostic(
            item,
            parameters,
            accepted_renames,
        )
        if alias is None:
            result.append(item)
            continue
        updated = dict(item)
        updated["candidate_action"] = "existing_parameter_register_alias"
        updated["legacy_candidate_action"] = ""
        updated["existing_parameter_index"] = alias["parameter_index"]
        updated["existing_parameter_raw_name"] = alias["raw_name"]
        updated["existing_parameter_rendered_name"] = alias["rendered_name"]
        updated["existing_parameter_rename_source"] = alias["rename_source"]
        result.append(updated)
        changed = True
    if changed or slot_context_changed or contract_changed:
        return result
    return warning_diagnostics


def _quality_apply_current_callee_contracts(
    warning_diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    changed = False
    for item in warning_diagnostics:
        if not _quality_callee_contract_candidate(item):
            result.append(item)
            continue
        contract = callee_contract_for_call(
            str(item.get("callee_name", "") or ""),
            _int_value(item.get("argument_index"), -1),
            _int_value(item.get("call_index"), 0),
            _int_value(item.get("callee_call_index"), 0),
        )
        action = str(contract.get("action", "") or "").strip()
        if not action:
            result.append(item)
            continue
        updated = dict(item)
        updated["candidate_action"] = action
        updated["quality_candidate_action_source"] = "current_callee_contract"
        updated["quality_previous_candidate_action"] = str(item.get("candidate_action", "") or "")
        updated["callee_contract_action"] = action
        updated["callee_contract_confidence"] = _float_value(contract.get("confidence"), 0.0)
        updated["callee_contract_evidence"] = str(contract.get("evidence", "") or "").strip()
        result.append(updated)
        changed = True
    return result if changed else warning_diagnostics


def _quality_callee_contract_candidate(item: dict[str, Any]) -> bool:
    if str(item.get("kind", "") or "") != "unassigned_local_live_in_register":
        return False
    if str(item.get("usage_class", "") or "") != "call_argument":
        return False
    action = str(item.get("candidate_action", "") or "").strip()
    if action not in _LIVE_IN_PARAMETER_GAP_ACTIONS:
        return False
    return bool(str(item.get("callee_name", "") or "").strip())


def _quality_add_live_in_signature_slot_context(
    warning_diagnostics: list[dict[str, Any]],
    parameters: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    changed = False
    for item in warning_diagnostics:
        slot_context = _quality_live_in_signature_slot_context(item, parameters)
        if slot_context is None:
            result.append(item)
            continue
        updated = dict(item)
        updated.update(slot_context)
        result.append(updated)
        changed = True
    return result if changed else warning_diagnostics


def _quality_live_in_signature_slot_context(
    item: dict[str, Any],
    parameters: list[tuple[str, str]],
) -> dict[str, Any] | None:
    if str(item.get("kind", "") or "") != "unassigned_local_live_in_register":
        return None
    if str(item.get("register_class", "") or "") != "abi_argument":
        return None
    register = str(item.get("register", "") or "").lower()
    parameter_index = ABI_INTEGER_ARGUMENT_REGISTER_INDEX.get(register)
    if parameter_index is None:
        return None
    parameter_count = len(parameters)
    context: dict[str, Any] = {
        "abi_parameter_index": parameter_index,
        "signature_parameter_count": parameter_count,
        "missing_signature_parameter_slot": parameter_index >= parameter_count,
    }
    if parameter_index >= parameter_count:
        context["missing_signature_parameter_slot_label"] = (
            "abi_slot%d_after_%d_params" % (parameter_index, parameter_count)
        )
        return context
    parameter_name, parameter_type = parameters[parameter_index]
    context["signature_parameter_name"] = str(parameter_name or "")
    context["signature_parameter_type"] = str(parameter_type or "")
    return context


def _quality_signature_parameters(cleaned_path: Path) -> list[tuple[str, str]]:
    text = _read_text(cleaned_path)
    if not text:
        return []
    signature = extract_function_signature(text)
    return extract_parameters_from_signature(signature)


def _quality_accepted_parameter_renames_by_old_name(
    rename_items: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in rename_items:
        if not _rename_applied(item):
            continue
        if str(item.get("kind", "") or "").lower() != "arg":
            continue
        old_name = str(item.get("old", "") or "").strip()
        new_name = str(item.get("new", "") or "").strip()
        if not old_name or not new_name:
            continue
        if str(item.get("source", "") or "").lower() == "llm":
            continue
        if _float_value(item.get("confidence"), 0.0) < 0.75:
            continue
        result[old_name] = item
        # Quality reads the rendered signature, so keep the post-rename
        # parameter name addressable as the same ABI slot evidence.
        result.setdefault(new_name, item)
    return result


def _quality_existing_parameter_alias_for_diagnostic(
    item: dict[str, Any],
    parameters: list[tuple[str, str]],
    accepted_renames: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if str(item.get("kind", "") or "") != "unassigned_local_live_in_register":
        return None
    if str(item.get("candidate_action", "") or "") != "caller_parameter_gap_candidate":
        return None
    if str(item.get("usage_class", "") or "") != "call_argument":
        return None
    parameter_index = ABI_INTEGER_ARGUMENT_REGISTER_INDEX.get(
        str(item.get("register", "") or "").lower()
    )
    if parameter_index is None or parameter_index >= len(parameters):
        return None
    raw_name = str(parameters[parameter_index][0] or "").strip()
    if not _quality_is_identifier(raw_name):
        return None
    rename = accepted_renames.get(raw_name)
    if rename is None:
        return None
    rendered_name = str(rename.get("new", "") or raw_name).strip()
    if not _quality_is_existing_parameter_alias_name(rendered_name, raw_name, rename):
        return None
    return {
        "parameter_index": parameter_index,
        "raw_name": str(rename.get("old", "") or raw_name).strip(),
        "rendered_name": rendered_name,
        "rename_source": str(rename.get("source", "") or ""),
    }


def _quality_is_existing_parameter_alias_name(
    rendered_name: str,
    raw_name: str,
    rename: dict[str, Any],
) -> bool:
    if not _quality_is_identifier(rendered_name):
        return False
    if _quality_is_generic_parameter_alias_name(raw_name):
        if _quality_is_generic_parameter_alias_name(rendered_name):
            return str(rename.get("source", "") or "").lower() == "prototype"
        return True
    if _quality_is_generic_parameter_alias_name(rendered_name):
        return False
    return True


def _quality_is_identifier(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(value or "")) is not None


def _quality_is_generic_parameter_alias_name(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    return bool(
        re.fullmatch(r"a\d+", lowered)
        or re.fullmatch(r"argument\d+", lowered)
        or re.fullmatch(r"bugcheckparameter\d+", lowered)
        or re.fullmatch(r"param(?:eter)?\d+", lowered)
        or re.fullmatch(r"v\d+", lowered)
    )


def _read_list(path: Path) -> list[Any]:
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def _read_rename_items(path: Path) -> list[dict[str, Any]]:
    data = _read_json(path)
    if isinstance(data, dict):
        data = data.get("renames", [])
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _pointer_indexed_offset_function_metrics(
    name: str,
    ea: str,
    summary_path: Path,
    raw_path: Path,
    cleaned_path: Path,
    rewrite_preview_metadata: dict[str, Any],
) -> dict[str, Any]:
    raw_text = _read_text(raw_path)
    cleaned_text = _read_text(cleaned_path)
    raw_body = _strip_pseudoforge_header(raw_text) if raw_text else ""
    cleaned_body = _strip_pseudoforge_header(cleaned_text) if cleaned_text else ""
    raw_items = _pointer_indexed_deref_items(raw_body)
    cleaned_items = _pointer_indexed_deref_items(cleaned_body)
    plan_offsets = _pointer_indexed_plan_offsets(rewrite_preview_metadata)
    candidate_items = [
        item
        for item in raw_items
        if _pointer_indexed_item_matches_plan(item, plan_offsets)
    ]
    remaining_candidate_items = [
        item
        for item in cleaned_items
        if _pointer_indexed_item_matches_plan(item, plan_offsets)
    ]
    candidate_bases = Counter(str(item.get("base", "")) for item in candidate_items)
    remaining_candidate_bases = Counter(str(item.get("base", "")) for item in remaining_candidate_items)
    rewritten_bases: Counter[str] = Counter()
    for base, count in candidate_bases.items():
        rewritten = max(0, count - remaining_candidate_bases.get(base, 0))
        if rewritten:
            rewritten_bases[base] = rewritten
    candidate_count = len(candidate_items)
    pointer_indexed_delta = max(0, len(raw_items) - len(cleaned_items))
    if not bool(rewrite_preview_metadata.get("canonical_cleaned_output_modified", False)):
        pointer_indexed_delta = 0
        rewritten_bases = Counter()
    elif pointer_indexed_delta > candidate_count:
        fallback_count = pointer_indexed_delta - candidate_count
        rewrite_counts = _pointer_indexed_metadata_rewrite_counts(rewrite_preview_metadata)
        if len(rewrite_counts) == 1:
            metadata_base, metadata_rewritten = next(iter(rewrite_counts.items()))
            fallback_rewritten = min(
                fallback_count,
                max(0, metadata_rewritten - rewritten_bases.get(metadata_base, 0)),
            )
            if fallback_rewritten:
                candidate_count += fallback_rewritten
                rewritten_bases[metadata_base] += fallback_rewritten
                candidate_bases[metadata_base] += fallback_rewritten
        else:
            metadata_bases = _pointer_indexed_metadata_rewritten_bases(rewrite_preview_metadata)
            if len(metadata_bases) == 1:
                candidate_count += fallback_count
                rewritten_bases[metadata_bases[0]] += fallback_count
                candidate_bases[metadata_bases[0]] += fallback_count
            else:
                candidate_count += fallback_count
                rewritten_bases["unknown"] += fallback_count
                candidate_bases["unknown"] += fallback_count
    rewrite_applied = sum(rewritten_bases.values())
    bases = Counter(str(item.get("base", "")) for item in cleaned_items)
    raw_bases = Counter(str(item.get("base", "")) for item in raw_items)
    return {
        "ea": ea,
        "name": name,
        "raw_pointer_indexed_offset_deref_patterns": len(raw_items),
        "pointer_indexed_offset_deref_patterns": len(cleaned_items),
        "pointer_indexed_layout_rewrite_candidates": candidate_count,
        "pointer_indexed_rewrite_applied": rewrite_applied,
        "bases": _counter_to_dict(bases),
        "raw_bases": _counter_to_dict(raw_bases),
        "candidate_bases": _counter_to_dict(candidate_bases),
        "rewritten_bases": _counter_to_dict(rewritten_bases),
        "summary_path": str(summary_path),
        "has_pointer_indexed_offset_evidence": bool(raw_items or cleaned_items or candidate_items or rewrite_applied),
    }


def _update_pointer_indexed_offset_metrics(
    metrics: dict[str, Any],
    totals: Counter[str],
    bases: Counter[str],
    rewritten_bases: Counter[str],
) -> None:
    raw_count = _int_value(metrics.get("raw_pointer_indexed_offset_deref_patterns"), 0)
    cleaned_count = _int_value(metrics.get("pointer_indexed_offset_deref_patterns"), 0)
    candidate_count = _int_value(metrics.get("pointer_indexed_layout_rewrite_candidates"), 0)
    applied_count = _int_value(metrics.get("pointer_indexed_rewrite_applied"), 0)
    totals["raw_pointer_indexed_offset_deref_patterns"] += raw_count
    totals["pointer_indexed_offset_deref_patterns"] += cleaned_count
    totals["pointer_indexed_layout_rewrite_candidates"] += candidate_count
    totals["pointer_indexed_rewrite_applied"] += applied_count
    if raw_count:
        totals["functions_with_raw_pointer_indexed_offset_derefs"] += 1
    if cleaned_count:
        totals["functions_with_pointer_indexed_offset_derefs"] += 1
    if candidate_count:
        totals["functions_with_pointer_indexed_layout_rewrite_candidates"] += 1
    if applied_count:
        totals["functions_with_pointer_indexed_rewrite_applied"] += 1
    for base, count in _coerce_dict(metrics.get("bases", {})).items():
        bases[str(base)] += _int_value(count, 0)
    for base, count in _coerce_dict(metrics.get("rewritten_bases", {})).items():
        rewritten_bases[str(base)] += _int_value(count, 0)


def _pointer_indexed_offset_totals_dict(counter: Counter[str]) -> dict[str, int]:
    required_keys = [
        "raw_pointer_indexed_offset_deref_patterns",
        "functions_with_raw_pointer_indexed_offset_derefs",
        "pointer_indexed_offset_deref_patterns",
        "functions_with_pointer_indexed_offset_derefs",
        "pointer_indexed_layout_rewrite_candidates",
        "functions_with_pointer_indexed_layout_rewrite_candidates",
        "pointer_indexed_rewrite_applied",
        "functions_with_pointer_indexed_rewrite_applied",
    ]
    result = _counter_to_dict(counter)
    for key in required_keys:
        result.setdefault(key, 0)
    return result


def _pointer_indexed_deref_items(text: str) -> list[dict[str, Any]]:
    items = []
    for match in POINTER_INDEXED_OFFSET_DEREF_RE.finditer(text or ""):
        index = _parse_pointer_indexed_integer(match.group("index"))
        if index is None or index <= 0:
            continue
        element_size = _pointer_indexed_element_size(
            match.group("type"),
            match.group("pointer_stars"),
        )
        if element_size <= 0:
            continue
        items.append(
            {
                "base": match.group("base"),
                "index": index,
                "byte_offset": index * element_size,
                "type": _normalized_pointer_indexed_type(
                    match.group("type"),
                    match.group("pointer_stars"),
                ),
            }
        )
    return items


def _pointer_indexed_plan_offsets(metadata: dict[str, Any]) -> dict[str, set[int]]:
    plan_offsets: dict[str, set[int]] = {}
    for plan in metadata.get("preview_plans", []) or []:
        if not isinstance(plan, dict):
            continue
        base = str(plan.get("base", "") or "")
        if not base:
            continue
        offsets = {
            _int_value(offset, -1)
            for offset in plan.get("advertised_offsets", []) or []
        }
        normalized_offsets = {offset for offset in offsets if offset >= 0}
        plan_offsets[base] = normalized_offsets
        plan_offsets.setdefault(base.lower(), normalized_offsets)
    return plan_offsets


def _pointer_indexed_metadata_rewritten_bases(metadata: dict[str, Any]) -> list[str]:
    bases = [
        str(item)
        for item in metadata.get("rewritten_bases", []) or []
        if str(item)
    ]
    if bases:
        return bases
    result = []
    for plan in metadata.get("preview_plans", []) or []:
        if not isinstance(plan, dict):
            continue
        base = str(plan.get("base", "") or "")
        if base:
            result.append(base)
    return result


def _pointer_indexed_metadata_rewrite_counts(metadata: dict[str, Any]) -> dict[str, int]:
    results = _coerce_dict(metadata.get("rewrite_results", {}))
    counts: dict[str, int] = {}
    for base, result in results.items():
        result_dict = _coerce_dict(result)
        count = _int_value(result_dict.get("rewritten_accesses"), 0)
        if count > 0:
            counts[str(base)] = count
    if counts:
        return counts
    for plan in metadata.get("preview_plans", []) or []:
        if not isinstance(plan, dict):
            continue
        base = str(plan.get("base", "") or "")
        if not base:
            continue
        count = _int_value(plan.get("advertised_access_count"), 0)
        if count <= 0:
            count = len([offset for offset in plan.get("advertised_offsets", []) or [] if _int_value(offset, -1) >= 0])
        if count > 0:
            counts[base] = counts.get(base, 0) + count
    return counts


def _pointer_indexed_item_matches_plan(
    item: dict[str, Any],
    plan_offsets: dict[str, set[int]],
) -> bool:
    base = str(item.get("base", "") or "")
    if base not in plan_offsets and base.lower() not in plan_offsets:
        return False
    offsets = plan_offsets.get(base, plan_offsets.get(base.lower(), set()))
    if not offsets:
        return True
    return _int_value(item.get("byte_offset"), -1) in offsets


def _parse_pointer_indexed_integer(value: str) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _normalized_pointer_indexed_type(type_name: str, pointer_stars: str) -> str:
    text = " ".join(str(type_name or "").replace("const ", "").replace("volatile ", "").split())
    stars = str(pointer_stars or "")
    if len(stars) > 1:
        return "%s %s" % (text, "*" * (len(stars) - 1))
    return text


def _pointer_indexed_element_size(type_name: str, pointer_stars: str) -> int:
    normalized = _normalized_pointer_indexed_type(type_name, pointer_stars)
    lowered = normalized.lower()
    if normalized.endswith("*"):
        return 8
    size = POINTER_INDEXED_TYPE_STORAGE_SIZES.get(lowered)
    if size:
        return size
    if re.fullmatch(r"P[A-Z0-9_]+", normalized):
        return 8
    return 0


_REPORT_ONLY_IDENTITY_BLOCKERS = {"report_only_profile", "profile_report_only"}
_TYPE_ASSISTED_PREVIEW_MODES = {
    "",
    "preview",
    "preview_rewrite",
    "rewrite_preview",
    "report_only",
}
_EXACT_FUNCTION_IDENTITY_EVIDENCE = {
    "function_name",
    "demangled_name",
    "exact_function_name",
    "exact_demangled_name",
}


def _normalized_identity_token(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _has_build_bound_source_context(summary: dict[str, Any]) -> bool:
    source_context = _coerce_dict(summary.get("source_context", {}))
    profile_context = _coerce_dict(source_context.get("profile_context", {}))
    return bool(source_context.get("source_path")) and bool(
        profile_context.get("image")
    ) and bool(profile_context.get("build"))


def _function_identity_source_context(summary: dict[str, Any]) -> dict[str, str]:
    source_context = _coerce_dict(summary.get("source_context", {}))
    profile_context = _coerce_dict(source_context.get("profile_context", {}))
    source_path = str(source_context.get("source_path", "") or "").strip()
    image = str(profile_context.get("image", "") or "").strip()
    build = str(profile_context.get("build", "") or "").strip()
    arch = str(profile_context.get("arch", "") or "").strip()
    result = {
        "source_path": source_path,
        "source_file": Path(source_path).name if source_path else "",
        "profile_image": image,
        "profile_build": build,
        "profile_arch": arch,
    }
    source_key_parts = [part for part in [image, build, arch] if part]
    if source_key_parts:
        result["source_key"] = ":".join(source_key_parts)
    elif source_path:
        result["source_key"] = Path(source_path).name
    return {key: value for key, value in result.items() if value}


def _function_identity_profile_source_map(items: list[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        profile_id = str(item.get("profile_id", "") or "").strip()
        profile_source = str(item.get("profile_source", "") or "").strip()
        if profile_id and profile_source and profile_id not in result:
            result[profile_id] = profile_source
    return result


def _is_body_only_weak_identity_dict(item: dict[str, Any]) -> bool:
    match_kind = _normalized_identity_token(item.get("match_kind"))
    if "body" in match_kind and "weak" in match_kind:
        return True
    evidence = " ".join(
        _normalized_identity_token(value)
        for value in _string_list(item.get("evidence"))
    )
    return "body_only_weak" in evidence or ("body_only" in evidence and "weak" in evidence)


def _is_exact_report_only_identity_dict(item: dict[str, Any]) -> bool:
    profile_id = str(item.get("profile_id", "") or "")
    if not profile_id or profile_id == "ambiguous":
        return False
    if _string_list(item.get("ambiguous_profile_ids")):
        return False
    if _is_body_only_weak_identity_dict(item):
        return False
    blockers = {
        _normalized_identity_token(blocker)
        for blocker in _string_list(item.get("blockers"))
        if str(blocker or "")
    }
    effective_mode = _normalized_identity_token(item.get("effective_mode"))
    is_report_only = bool(blockers & _REPORT_ONLY_IDENTITY_BLOCKERS) or effective_mode == "report_only"
    if not is_report_only:
        return False
    if blockers - _REPORT_ONLY_IDENTITY_BLOCKERS:
        return False
    match_kind = _normalized_identity_token(item.get("match_kind"))
    evidence = {
        _normalized_identity_token(value)
        for value in _string_list(item.get("evidence"))
        if str(value or "")
    }
    return match_kind in {"function_name", "demangled_name"} or bool(
        evidence & _EXACT_FUNCTION_IDENTITY_EVIDENCE
    )


def _report_only_identity_preview_corrections(
    parameter_type_corrections: list[dict[str, Any]],
    exact_report_only_profile_ids: set[str],
) -> list[dict[str, Any]]:
    corrections = []
    for item in parameter_type_corrections:
        profile_id = str(item.get("profile_id", "") or "")
        if profile_id not in exact_report_only_profile_ids:
            continue
        if _string_list(item.get("blockers")):
            continue
        if not bool(item.get("apply_to_preview", True)):
            continue
        if bool(item.get("apply_to_idb", False)):
            continue
        if not str(item.get("new_name", "") or "").strip():
            continue
        if not (
            str(item.get("canonical_type", "") or "").strip()
            or str(item.get("display_type", "") or "").strip()
        ):
            continue
        effective_mode = _normalized_identity_token(item.get("effective_mode"))
        if effective_mode not in _TYPE_ASSISTED_PREVIEW_MODES:
            continue
        corrections.append(item)
    return corrections


def _type_assisted_preview_metrics(summary: dict[str, Any]) -> dict[str, Any]:
    preview = _coerce_dict(summary.get("type_assisted_preview", {}))
    if not preview:
        return {
            "candidates": 0,
            "parameter_corrections": 0,
            "restore_succeeded": 0,
            "restore_failures": 0,
            "status": "",
            "statuses": {},
            "profiles": {},
            "blockers": {},
        }
    status = _normalized_identity_token(preview.get("status")) or "unknown"
    proposal = _coerce_dict(preview.get("proposal", {}))
    corrections = _string_list(proposal.get("corrections"))
    blockers = _string_list(proposal.get("blockers"))
    applied_statuses = {"ok", "error", "restore_failed"}
    attempted_temporary_type = status in applied_statuses or bool(
        str(preview.get("original_type", "") or "").strip()
    )
    restore_succeeded = bool(preview.get("restore_succeeded", False))
    restore_failure = attempted_temporary_type and not restore_succeeded
    profile_counter = Counter(str(profile) for profile in _string_list(proposal.get("profile_ids")))
    blocker_counter = Counter(str(blocker) for blocker in blockers if str(blocker))
    if restore_failure:
        blocker_counter["type_assisted_restore_failed"] += 1
    if status == "error":
        blocker_counter["type_assisted_preview_error"] += 1
    realized_corrections = corrections if status == "ok" and restore_succeeded else []
    return {
        "candidates": 1 if attempted_temporary_type or corrections else 0,
        "parameter_corrections": len(realized_corrections),
        "restore_succeeded": 1 if attempted_temporary_type and restore_succeeded else 0,
        "restore_failures": 1 if restore_failure else 0,
        "status": status,
        "statuses": {status: 1},
        "profiles": _counter_to_dict(profile_counter),
        "blockers": _counter_to_dict(blocker_counter),
    }


def _evidence_graph_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    evidence_graph: dict[str, Any],
) -> dict[str, Any]:
    graph_summary = _coerce_dict(evidence_graph.get("summary", {}))
    raw_nodes = evidence_graph.get("nodes", [])
    raw_edges = evidence_graph.get("edges", [])
    nodes = [node for node in raw_nodes if isinstance(node, dict)] if isinstance(raw_nodes, list) else []
    edges = [edge for edge in raw_edges if isinstance(edge, dict)] if isinstance(raw_edges, list) else []
    node_kinds: Counter[str] = Counter()
    edge_kinds: Counter[str] = Counter()
    promotion_lanes: Counter[str] = Counter()
    blockers: Counter[str] = Counter()
    rewrite_eligible_edges = 0
    for node in nodes:
        node_kinds[str(node.get("kind", "") or "unknown")] += 1
    for edge in edges:
        edge_kinds[str(edge.get("kind", "") or "unknown")] += 1
        lane = str(edge.get("promotion_lane", "") or "blocked")
        promotion_lanes[lane] += 1
        if bool(edge.get("rewrite_eligible", False)):
            rewrite_eligible_edges += 1
        for blocker in _string_list(edge.get("blockers")):
            blockers[blocker] += 1
    if not promotion_lanes:
        for key, value in _coerce_dict(graph_summary.get("promotion_lanes", {})).items():
            promotion_lanes[str(key)] += _int_value(value, 0)
    if not blockers:
        for key, value in _coerce_dict(graph_summary.get("blockers", {})).items():
            blockers[str(key)] += _int_value(value, 0)
    return {
        "ea": ea,
        "name": name,
        "schema": str(evidence_graph.get("schema", "")),
        "nodes": len(nodes) if nodes else _int_value(graph_summary.get("nodes"), 0),
        "edges": len(edges) if edges else _int_value(graph_summary.get("edges"), 0),
        "trusted_rewrite_edges": _int_value(
            promotion_lanes.get("trusted-rewrite"),
            _int_value(graph_summary.get("trusted_rewrite_edges"), 0),
        ),
        "trusted_preview_edges": _int_value(promotion_lanes.get("trusted-preview"), 0),
        "report_only_edges": _int_value(
            promotion_lanes.get("report-only"),
            _int_value(graph_summary.get("report_only_edges"), 0),
        ),
        "blocked_edges": _int_value(
            promotion_lanes.get("blocked"),
            _int_value(graph_summary.get("blocked_edges"), 0),
        ),
        "rewrite_eligible_edges": rewrite_eligible_edges,
        "node_kinds": _counter_to_dict(node_kinds),
        "edge_kinds": _counter_to_dict(edge_kinds),
        "promotion_lanes": _counter_to_dict(promotion_lanes),
        "blockers": _counter_to_dict(blockers),
        "summary_path": str(summary_path),
    }


def _update_evidence_graph_metrics(
    item: dict[str, Any],
    totals: Counter[str],
    node_kinds: Counter[str],
    edge_kinds: Counter[str],
    promotion_lanes: Counter[str],
    blockers: Counter[str],
) -> None:
    totals["functions_with_evidence_graph"] += 1
    for key in (
        "nodes",
        "edges",
        "trusted_rewrite_edges",
        "trusted_preview_edges",
        "report_only_edges",
        "blocked_edges",
        "rewrite_eligible_edges",
    ):
        totals[key] += _int_value(item.get(key), 0)
    if _int_value(item.get("trusted_rewrite_edges"), 0) > 0:
        totals["functions_with_trusted_rewrite_edges"] += 1
    if _int_value(item.get("trusted_preview_edges"), 0) > 0:
        totals["functions_with_trusted_preview_edges"] += 1
    if _int_value(item.get("report_only_edges"), 0) > 0:
        totals["functions_with_report_only_edges"] += 1
    if _int_value(item.get("blocked_edges"), 0) > 0:
        totals["functions_with_blocked_edges"] += 1
    for key, value in _coerce_dict(item.get("node_kinds", {})).items():
        node_kinds[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(item.get("edge_kinds", {})).items():
        edge_kinds[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(item.get("promotion_lanes", {})).items():
        promotion_lanes[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(item.get("blockers", {})).items():
        blockers[str(key)] += _int_value(value, 0)


def _evidence_graph_totals_dict(counter: Counter[str]) -> dict[str, int]:
    required_keys = [
        "functions_with_evidence_graph",
        "nodes",
        "edges",
        "trusted_rewrite_edges",
        "trusted_preview_edges",
        "report_only_edges",
        "blocked_edges",
        "rewrite_eligible_edges",
        "functions_with_trusted_rewrite_edges",
        "functions_with_trusted_preview_edges",
        "functions_with_report_only_edges",
        "functions_with_blocked_edges",
    ]
    result = {key: int(counter.get(key, 0)) for key in required_keys}
    for key, value in counter.items():
        result.setdefault(str(key), int(value))
    return result


def _prototype_correction_function_metrics(summary: dict[str, Any], cleaned_path: Path) -> dict[str, Any]:
    function_identity_candidates = _dict_list(summary.get("function_identity_candidates"))
    domain_identity_summary = _coerce_dict(summary.get("domain_identity_summary", {}))
    parameter_type_corrections = _dict_list(summary.get("parameter_type_corrections"))
    corrected_parameter_map = _dict_list(summary.get("corrected_parameter_map"))
    body_rewrite_summary = _coerce_dict(summary.get("body_canonical_rewrite_summary", {}))
    function_identity_hits = len(function_identity_candidates)
    if function_identity_hits == 0:
        function_identity_hits = _int_value(domain_identity_summary.get("total_hits"), 0)
    applied_corrections = [
        item
        for item in parameter_type_corrections
        if bool(item.get("apply_to_preview", True)) and not _string_list(item.get("blockers"))
    ]
    blocked_corrections = [
        item
        for item in parameter_type_corrections
        if _string_list(item.get("blockers")) or not bool(item.get("apply_to_preview", True))
    ]
    idb_apply_corrections = [
        item for item in parameter_type_corrections if bool(item.get("apply_to_idb", False))
    ]
    function_identity_blockers = Counter(
        blocker
        for item in function_identity_candidates
        for blocker in _string_list(item.get("blockers"))
    )
    if not function_identity_blockers:
        function_identity_blockers.update(
            {
                str(key): _int_value(value, 0)
                for key, value in _coerce_dict(domain_identity_summary.get("blocker_counts", {})).items()
            }
        )
    correction_blockers = Counter(
        blocker
        for item in blocked_corrections
        for blocker in (_string_list(item.get("blockers")) or ["preview_disabled"])
    )
    exact_report_only_identities = [
        item
        for item in function_identity_candidates
        if _is_exact_report_only_identity_dict(item)
    ]
    has_build_bound_source_context = _has_build_bound_source_context(summary)
    source_bound_report_only_identities = exact_report_only_identities if has_build_bound_source_context else []
    function_identity_source_context = _function_identity_source_context(summary)
    source_bound_identity_sources = _function_identity_profile_source_map(
        source_bound_report_only_identities
    )
    source_bound_report_only_profile_ids = {
        str(item.get("profile_id", "") or "")
        for item in source_bound_report_only_identities
        if str(item.get("profile_id", "") or "")
    }
    report_only_preview_corrections = _report_only_identity_preview_corrections(
        parameter_type_corrections,
        source_bound_report_only_profile_ids,
    )
    type_assisted_preview = _type_assisted_preview_metrics(summary)
    type_assisted_candidates = _int_value(type_assisted_preview.get("candidates"), 0)
    type_assisted_parameter_corrections = _int_value(
        type_assisted_preview.get("parameter_corrections"),
        0,
    )
    if type_assisted_candidates <= 0 and report_only_preview_corrections:
        type_assisted_candidates = 1
        type_assisted_parameter_corrections = len(report_only_preview_corrections)
    body_blockers = Counter(
        {
            str(key): _int_value(value, 0)
            for key, value in _coerce_dict(body_rewrite_summary.get("blocker_counts", {})).items()
        }
    )
    cleaned_text = _read_text(cleaned_path)
    body_text = _strip_pseudoforge_header(cleaned_text) if cleaned_text else ""
    generic_parameter_survivors = _generic_parameter_survivor_count(body_text)
    offset_deref_survivors = len(OFFSET_DEREF_RE.findall(body_text))
    direct_base_deref_survivors = len(DIRECT_BASE_DEREF_RE.findall(body_text))
    body_rewrite_ready = _int_value(body_rewrite_summary.get("rewrite_ready"), 0)
    body_rewrite_preview = _int_value(body_rewrite_summary.get("rewrite_preview"), 0)
    body_rewrite_blockers = _int_value(body_rewrite_summary.get("rewrite_blockers"), 0)
    body_rewrite_partial = _int_value(body_rewrite_summary.get("partial_opportunities"), 0)
    has_correction_evidence = bool(
        function_identity_hits
        or parameter_type_corrections
        or corrected_parameter_map
        or type_assisted_candidates
        or body_rewrite_ready
        or body_rewrite_preview
        or body_rewrite_blockers
        or body_rewrite_partial
    )
    function_identity_profiles = _profile_counter(function_identity_candidates)
    if not function_identity_profiles:
        function_identity_profiles = _counter_like_dict(domain_identity_summary.get("profile_counts", {}))
    return {
        "function_identity_candidates": function_identity_hits,
        "function_identity_blockers": _counter_to_dict(function_identity_blockers),
        "parameter_type_corrections": len(parameter_type_corrections),
        "applied_parameter_type_corrections": len(applied_corrections),
        "blocked_parameter_type_corrections": len(blocked_corrections),
        "idb_apply_parameter_type_corrections": len(idb_apply_corrections),
        "correction_blockers": _counter_to_dict(correction_blockers),
        "corrected_parameter_map_entries": len(corrected_parameter_map),
        "exact_report_only_identity_candidates": len(exact_report_only_identities),
        "source_bound_report_only_identity_candidates": len(source_bound_report_only_identities),
        "function_identity_source_context": function_identity_source_context,
        "source_bound_identity_sources": source_bound_identity_sources,
        "type_assisted_preview_candidates": type_assisted_candidates,
        "type_assisted_preview_parameter_corrections": type_assisted_parameter_corrections,
        "type_assisted_preview_restore_succeeded": _int_value(
            type_assisted_preview.get("restore_succeeded"),
            0,
        ),
        "type_assisted_preview_restore_failures": _int_value(
            type_assisted_preview.get("restore_failures"),
            0,
        ),
        "type_assisted_preview_statuses": _coerce_dict(
            type_assisted_preview.get("statuses", {})
        ),
        "type_assisted_preview_profiles": _coerce_dict(
            type_assisted_preview.get("profiles", {})
        ),
        "type_assisted_preview_blockers": _coerce_dict(
            type_assisted_preview.get("blockers", {})
        ),
        "report_only_identity_preview_candidates": 1 if report_only_preview_corrections else 0,
        "report_only_identity_preview_parameter_corrections": len(report_only_preview_corrections),
        "report_only_identity_preview_profiles": _profile_counter(report_only_preview_corrections),
        "body_rewrite_ready": body_rewrite_ready,
        "body_rewrite_preview": body_rewrite_preview,
        "body_rewrite_blockers": body_rewrite_blockers,
        "body_rewrite_partial_opportunities": body_rewrite_partial,
        "body_rewrite_blocker_counts": _counter_to_dict(body_blockers),
        "body_rewrite_source_provenance": _coerce_dict(body_rewrite_summary.get("source_provenance_counts", {})),
        "generic_parameter_survivors": generic_parameter_survivors,
        "offset_deref_survivors": offset_deref_survivors,
        "direct_base_deref_survivors": direct_base_deref_survivors,
        "has_correction_evidence": has_correction_evidence,
        "profiles": _profile_counter(parameter_type_corrections),
        "function_identity_profiles": function_identity_profiles,
        "canonical_types": _canonical_type_counter(applied_corrections),
    }


def _update_prototype_correction_metrics(
    metrics: dict[str, Any],
    totals: Counter[str],
    blockers: Counter[str],
    profiles: Counter[str],
    function_profiles: Counter[str],
    canonical_types: Counter[str],
    body_rewrite_sources: Counter[str],
    report_only_preview_profiles: Counter[str],
    type_assisted_preview_statuses: Counter[str],
) -> None:
    totals["function_identity_candidates"] += _int_value(metrics.get("function_identity_candidates"), 0)
    totals["parameter_type_corrections"] += _int_value(metrics.get("parameter_type_corrections"), 0)
    totals["applied_parameter_type_corrections"] += _int_value(
        metrics.get("applied_parameter_type_corrections"),
        0,
    )
    totals["blocked_parameter_type_corrections"] += _int_value(
        metrics.get("blocked_parameter_type_corrections"),
        0,
    )
    totals["idb_apply_parameter_type_corrections"] += _int_value(
        metrics.get("idb_apply_parameter_type_corrections"),
        0,
    )
    totals["corrected_parameter_map_entries"] += _int_value(metrics.get("corrected_parameter_map_entries"), 0)
    totals["exact_report_only_identity_candidates"] += _int_value(
        metrics.get("exact_report_only_identity_candidates"),
        0,
    )
    totals["source_bound_report_only_identity_candidates"] += _int_value(
        metrics.get("source_bound_report_only_identity_candidates"),
        0,
    )
    totals["type_assisted_preview_candidates"] += _int_value(
        metrics.get("type_assisted_preview_candidates"),
        0,
    )
    totals["type_assisted_preview_parameter_corrections"] += _int_value(
        metrics.get("type_assisted_preview_parameter_corrections"),
        0,
    )
    totals["type_assisted_preview_restore_succeeded"] += _int_value(
        metrics.get("type_assisted_preview_restore_succeeded"),
        0,
    )
    totals["type_assisted_preview_restore_failures"] += _int_value(
        metrics.get("type_assisted_preview_restore_failures"),
        0,
    )
    totals["report_only_identity_preview_candidates"] += _int_value(
        metrics.get("report_only_identity_preview_candidates"),
        0,
    )
    totals["report_only_identity_preview_parameter_corrections"] += _int_value(
        metrics.get("report_only_identity_preview_parameter_corrections"),
        0,
    )
    totals["body_rewrite_ready"] += _int_value(metrics.get("body_rewrite_ready"), 0)
    totals["body_rewrite_preview"] += _int_value(metrics.get("body_rewrite_preview"), 0)
    totals["body_rewrite_blockers"] += _int_value(metrics.get("body_rewrite_blockers"), 0)
    totals["body_rewrite_partial_opportunities"] += _int_value(
        metrics.get("body_rewrite_partial_opportunities"),
        0,
    )
    totals["generic_parameter_survivors"] += _int_value(metrics.get("generic_parameter_survivors"), 0)
    totals["offset_deref_survivors"] += _int_value(metrics.get("offset_deref_survivors"), 0)
    totals["direct_base_deref_survivors"] += _int_value(metrics.get("direct_base_deref_survivors"), 0)
    if bool(metrics.get("has_correction_evidence")):
        totals["functions_with_correction_evidence"] += 1
    else:
        totals["negative_control_functions"] += 1
    for counter_name in (
        "function_identity_blockers",
        "correction_blockers",
        "body_rewrite_blocker_counts",
        "type_assisted_preview_blockers",
    ):
        for key, value in _coerce_dict(metrics.get(counter_name, {})).items():
            blockers[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("profiles", {})).items():
        profiles[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("function_identity_profiles", {})).items():
        function_profiles[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("canonical_types", {})).items():
        canonical_types[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("body_rewrite_source_provenance", {})).items():
        body_rewrite_sources[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("report_only_identity_preview_profiles", {})).items():
        report_only_preview_profiles[str(key)] += _int_value(value, 0)
    for key, value in _coerce_dict(metrics.get("type_assisted_preview_statuses", {})).items():
        type_assisted_preview_statuses[str(key)] += _int_value(value, 0)


def _prototype_correction_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "function_identity_candidates": _int_value(metrics.get("function_identity_candidates"), 0),
        "parameter_type_corrections": _int_value(metrics.get("parameter_type_corrections"), 0),
        "applied_parameter_type_corrections": _int_value(metrics.get("applied_parameter_type_corrections"), 0),
        "blocked_parameter_type_corrections": _int_value(metrics.get("blocked_parameter_type_corrections"), 0),
        "idb_apply_parameter_type_corrections": _int_value(
            metrics.get("idb_apply_parameter_type_corrections"),
            0,
        ),
        "corrected_parameter_map_entries": _int_value(metrics.get("corrected_parameter_map_entries"), 0),
        "exact_report_only_identity_candidates": _int_value(
            metrics.get("exact_report_only_identity_candidates"),
            0,
        ),
        "source_bound_report_only_identity_candidates": _int_value(
            metrics.get("source_bound_report_only_identity_candidates"),
            0,
        ),
        "type_assisted_preview_candidates": _int_value(metrics.get("type_assisted_preview_candidates"), 0),
        "type_assisted_preview_parameter_corrections": _int_value(
            metrics.get("type_assisted_preview_parameter_corrections"),
            0,
        ),
        "type_assisted_preview_restore_succeeded": _int_value(
            metrics.get("type_assisted_preview_restore_succeeded"),
            0,
        ),
        "type_assisted_preview_restore_failures": _int_value(
            metrics.get("type_assisted_preview_restore_failures"),
            0,
        ),
        "type_assisted_preview_statuses": _coerce_dict(
            metrics.get("type_assisted_preview_statuses", {})
        ),
        "report_only_identity_preview_candidates": _int_value(
            metrics.get("report_only_identity_preview_candidates"),
            0,
        ),
        "report_only_identity_preview_parameter_corrections": _int_value(
            metrics.get("report_only_identity_preview_parameter_corrections"),
            0,
        ),
        "report_only_identity_preview_profiles": _coerce_dict(
            metrics.get("report_only_identity_preview_profiles", {})
        ),
        "body_rewrite_ready": _int_value(metrics.get("body_rewrite_ready"), 0),
        "body_rewrite_blockers": _int_value(metrics.get("body_rewrite_blockers"), 0),
        "generic_parameter_survivors": _int_value(metrics.get("generic_parameter_survivors"), 0),
        "offset_deref_survivors": _int_value(metrics.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(metrics.get("direct_base_deref_survivors"), 0),
        "profiles": _coerce_dict(metrics.get("profiles", {})),
        "canonical_types": _coerce_dict(metrics.get("canonical_types", {})),
        "blockers": _coerce_dict(metrics.get("correction_blockers", {})),
        "summary_path": str(summary_path),
    }


def _prototype_correction_review_queues(
    functions: list[dict[str, Any]],
    top: int,
) -> dict[str, dict[str, Any]]:
    type_assisted_restore_failure_queue = "type_assisted_preview_restore_failures"
    report_only_preview_queue = "report_only_identity_type_preview_candidates"
    queue_blockers = {
        "low_confidence_type_corrections": {"low_confidence"},
        "build_mismatch_type_corrections": {"build_mismatch"},
        "type_conflict_type_corrections": {"type_conflict"},
        "report_only_type_corrections": {
            "report_only_profile",
            "profile_report_only",
        },
        "preview_disabled_type_corrections": {"preview_disabled"},
    }
    raw_queues: dict[str, list[dict[str, Any]]] = {
        type_assisted_restore_failure_queue: [],
        report_only_preview_queue: [],
    }
    raw_queues.update({name: [] for name in queue_blockers})
    for item in functions:
        if _int_value(item.get("type_assisted_preview_restore_failures"), 0) > 0:
            raw_queues[type_assisted_restore_failure_queue].append(
                _prototype_correction_queue_item(
                    item,
                    type_assisted_restore_failure_queue,
                )
            )
        if _int_value(item.get("report_only_identity_preview_candidates"), 0) > 0:
            raw_queues[report_only_preview_queue].append(
                _prototype_correction_queue_item(
                    item,
                    report_only_preview_queue,
                )
            )
        blockers = _coerce_dict(item.get("blockers", {}))
        blocked_count = _int_value(item.get("blocked_parameter_type_corrections"), 0)
        if blocked_count <= 0 or not blockers:
            continue
        blocker_names = {str(key) for key, value in blockers.items() if _int_value(value, 0) > 0}
        for queue_name, expected_blockers in queue_blockers.items():
            if blocker_names.intersection(expected_blockers):
                raw_queues[queue_name].append(
                    _prototype_correction_queue_item(
                        item,
                        queue_name,
                    )
                )

    result: dict[str, dict[str, Any]] = {}
    for queue_name, items in raw_queues.items():
        if not items:
            continue
        items.sort(
            key=lambda item: (
                -int(item["type_assisted_preview_restore_failures"]),
                -int(item["type_assisted_preview_parameter_corrections"]),
                -int(item["report_only_identity_preview_parameter_corrections"]),
                -int(item["blocked_parameter_type_corrections"]),
                -int(item["generic_parameter_survivors"]),
                -int(item["offset_deref_survivors"]),
                str(item["name"]),
            )
        )
        result[queue_name] = _prototype_correction_queue_summary(
            queue_name,
            items,
            top,
        )
    return result


def _prototype_correction_queue_item(
    item: dict[str, Any],
    queue_name: str,
) -> dict[str, Any]:
    return {
        "ea": str(item.get("ea", "")),
        "name": str(item.get("name", "")),
        "function_identity_candidates": _int_value(item.get("function_identity_candidates"), 0),
        "parameter_type_corrections": _int_value(item.get("parameter_type_corrections"), 0),
        "applied_parameter_type_corrections": _int_value(item.get("applied_parameter_type_corrections"), 0),
        "blocked_parameter_type_corrections": _int_value(item.get("blocked_parameter_type_corrections"), 0),
        "exact_report_only_identity_candidates": _int_value(
            item.get("exact_report_only_identity_candidates"),
            0,
        ),
        "source_bound_report_only_identity_candidates": _int_value(
            item.get("source_bound_report_only_identity_candidates"),
            0,
        ),
        "type_assisted_preview_candidates": _int_value(item.get("type_assisted_preview_candidates"), 0),
        "type_assisted_preview_parameter_corrections": _int_value(
            item.get("type_assisted_preview_parameter_corrections"),
            0,
        ),
        "type_assisted_preview_restore_succeeded": _int_value(
            item.get("type_assisted_preview_restore_succeeded"),
            0,
        ),
        "type_assisted_preview_restore_failures": _int_value(
            item.get("type_assisted_preview_restore_failures"),
            0,
        ),
        "type_assisted_preview_statuses": _coerce_dict(
            item.get("type_assisted_preview_statuses", {})
        ),
        "report_only_identity_preview_candidates": _int_value(
            item.get("report_only_identity_preview_candidates"),
            0,
        ),
        "report_only_identity_preview_parameter_corrections": _int_value(
            item.get("report_only_identity_preview_parameter_corrections"),
            0,
        ),
        "generic_parameter_survivors": _int_value(item.get("generic_parameter_survivors"), 0),
        "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
        "profiles": _coerce_dict(item.get("profiles", {})),
        "report_only_identity_preview_profiles": _coerce_dict(
            item.get("report_only_identity_preview_profiles", {})
        ),
        "canonical_types": _coerce_dict(item.get("canonical_types", {})),
        "blockers": _coerce_dict(item.get("blockers", {})),
        "review_hint": _PROTOTYPE_CORRECTION_QUEUE_NEXT_STEPS.get(queue_name, ""),
        "summary_path": str(item.get("summary_path", "")),
    }


def _prototype_correction_queue_summary(
    queue_name: str,
    items: list[dict[str, Any]],
    top: int,
) -> dict[str, Any]:
    profiles = Counter()
    report_only_preview_profiles = Counter()
    canonical_types = Counter()
    blockers = Counter()
    for item in items:
        for key, value in _coerce_dict(item.get("profiles", {})).items():
            profiles[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("report_only_identity_preview_profiles", {})).items():
            report_only_preview_profiles[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("canonical_types", {})).items():
            canonical_types[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("blockers", {})).items():
            blockers[str(key)] += _int_value(value, 0)
    return {
        "description": _PROTOTYPE_CORRECTION_QUEUE_DESCRIPTIONS.get(queue_name, ""),
        "recommended_next_step": _PROTOTYPE_CORRECTION_QUEUE_NEXT_STEPS.get(queue_name, ""),
        "function_count": len(items),
        "blocked_parameter_type_corrections": sum(
            _int_value(item.get("blocked_parameter_type_corrections"), 0)
            for item in items
        ),
        "exact_report_only_identity_candidates": sum(
            _int_value(item.get("exact_report_only_identity_candidates"), 0)
            for item in items
        ),
        "source_bound_report_only_identity_candidates": sum(
            _int_value(item.get("source_bound_report_only_identity_candidates"), 0)
            for item in items
        ),
        "type_assisted_preview_candidates": sum(
            _int_value(item.get("type_assisted_preview_candidates"), 0)
            for item in items
        ),
        "type_assisted_preview_parameter_corrections": sum(
            _int_value(item.get("type_assisted_preview_parameter_corrections"), 0)
            for item in items
        ),
        "type_assisted_preview_restore_succeeded": sum(
            _int_value(item.get("type_assisted_preview_restore_succeeded"), 0)
            for item in items
        ),
        "type_assisted_preview_restore_failures": sum(
            _int_value(item.get("type_assisted_preview_restore_failures"), 0)
            for item in items
        ),
        "report_only_identity_preview_candidates": sum(
            _int_value(item.get("report_only_identity_preview_candidates"), 0)
            for item in items
        ),
        "report_only_identity_preview_parameter_corrections": sum(
            _int_value(item.get("report_only_identity_preview_parameter_corrections"), 0)
            for item in items
        ),
        "generic_parameter_survivors": sum(
            _int_value(item.get("generic_parameter_survivors"), 0)
            for item in items
        ),
        "offset_deref_survivors": sum(
            _int_value(item.get("offset_deref_survivors"), 0)
            for item in items
        ),
        "direct_base_deref_survivors": sum(
            _int_value(item.get("direct_base_deref_survivors"), 0)
            for item in items
        ),
        "profiles": _counter_to_dict(Counter(dict(profiles.most_common(8)))),
        "report_only_identity_preview_profiles": _counter_to_dict(
            Counter(dict(report_only_preview_profiles.most_common(8)))
        ),
        "canonical_types": _counter_to_dict(Counter(dict(canonical_types.most_common(8)))),
        "blockers": _counter_to_dict(Counter(dict(blockers.most_common(8)))),
        "items": items[:top],
    }


def _prototype_correction_totals_dict(counter: Counter[str]) -> dict[str, int]:
    required_keys = [
        "function_identity_candidates",
        "parameter_type_corrections",
        "applied_parameter_type_corrections",
        "blocked_parameter_type_corrections",
        "idb_apply_parameter_type_corrections",
        "corrected_parameter_map_entries",
        "exact_report_only_identity_candidates",
        "source_bound_report_only_identity_candidates",
        "type_assisted_preview_candidates",
        "type_assisted_preview_parameter_corrections",
        "type_assisted_preview_restore_succeeded",
        "type_assisted_preview_restore_failures",
        "report_only_identity_preview_candidates",
        "report_only_identity_preview_parameter_corrections",
        "body_rewrite_ready",
        "body_rewrite_preview",
        "body_rewrite_blockers",
        "body_rewrite_partial_opportunities",
        "generic_parameter_survivors",
        "offset_deref_survivors",
        "direct_base_deref_survivors",
        "functions_with_correction_evidence",
        "negative_control_functions",
    ]
    result = _counter_to_dict(counter)
    for key in required_keys:
        result.setdefault(key, 0)
    return result


def _body_offset_residue_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    cleaned_path: Path,
    prototype_metrics: dict[str, Any],
    layout_hints: list[dict[str, Any]],
    hot_field_clusters: list[dict[str, Any]],
    indexed_callback_tables: list[dict[str, Any]],
    stable_base_sources: list[dict[str, Any]],
    base_stability: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
    temp_provenance: dict[str, list[dict[str, Any]]],
    rewrite_ready: list[dict[str, Any]],
    rewrite_blockers: list[dict[str, Any]],
    parameter_indexed_elements: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
    warning_diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    offset_deref_survivors = _int_value(prototype_metrics.get("offset_deref_survivors"), 0)
    if offset_deref_survivors <= 0:
        return {}
    direct_base_deref_survivors = _int_value(
        prototype_metrics.get("direct_base_deref_survivors"),
        0,
    )
    report_only_preview_parameter_corrections = _int_value(
        prototype_metrics.get("report_only_identity_preview_parameter_corrections"),
        0,
    )
    source_bound_report_only_identity_candidates = _int_value(
        prototype_metrics.get("source_bound_report_only_identity_candidates"),
        0,
    )
    blocker_reasons = Counter(
        str(reason)
        for blocker in rewrite_blockers
        for reason in blocker.get("reasons", []) or []
        if str(reason)
    )
    subsystem = _body_offset_residue_subsystem(name, prototype_metrics, domain_identities)
    source_evidence_count = (
        len(stable_base_sources)
        + len(generic_base_trust_candidates)
        + len(parameter_indexed_elements)
    )
    field_access_pressure = max(
        [
            _int_value(item.get("access_count"), 0)
            for item in [*layout_hints, *hot_field_clusters]
        ]
        or [0]
    )
    nested_field_pointer_profile = _nested_field_pointer_residue_profile(cleaned_path)
    nested_field_pointer_count = _int_value(
        nested_field_pointer_profile.get("count"),
        0,
    )
    direct_base_deref_profile = _direct_base_deref_profile(cleaned_path)
    parameter_field_pointer_source_profile = _parameter_field_pointer_source_anchor_profile(
        cleaned_path,
        stable_base_sources,
    )
    existing_parameter_alias_profile = _existing_parameter_alias_profile(warning_diagnostics or [])
    live_in_parameter_gap_profile = _live_in_parameter_gap_profile(warning_diagnostics or [])
    callee_arity_residue_profile = _callee_arity_residue_profile(warning_diagnostics or [])
    review_class = _body_offset_residue_review_class(
        prototype_metrics,
        layout_hints,
        hot_field_clusters,
        stable_base_sources,
        generic_base_evidence,
        generic_base_trust_candidates,
        rewrite_blockers,
        domain_identities,
        pointer_indexed_metrics,
        offset_shape_profile,
    )
    next_action = _body_offset_residue_next_action(
        review_class,
        prototype_metrics,
        layout_hints,
        hot_field_clusters,
        stable_base_sources,
        generic_base_evidence,
        generic_base_trust_candidates,
        rewrite_ready,
        rewrite_blockers,
        domain_identities,
        pointer_indexed_metrics,
        offset_shape_profile,
    )
    review_evidence = _body_offset_residue_review_evidence(
        review_class,
        hot_field_clusters,
        rewrite_ready,
        rewrite_blockers,
        domain_identities,
        pointer_indexed_metrics,
        offset_shape_profile,
    )
    if _body_offset_has_build_mismatch(prototype_metrics, domain_identities):
        review_evidence.append("source_build_mismatch")
        review_evidence = list(dict.fromkeys(review_evidence))
    if parameter_indexed_elements:
        review_evidence.append("parameter_indexed_element_shape")
        review_evidence = list(dict.fromkeys(review_evidence))
    if nested_field_pointer_count > 0:
        review_evidence.append("nested_field_pointer_residue")
        review_evidence = list(dict.fromkeys(review_evidence))
    live_in_parameter_gap_count = _int_value(live_in_parameter_gap_profile.get("count"), 0)
    source_bound_live_in_parameter_gap_count = (
        live_in_parameter_gap_count
        if live_in_parameter_gap_count > 0 and source_bound_report_only_identity_candidates > 0
        else 0
    )
    if live_in_parameter_gap_count > 0:
        review_evidence.append("live_in_parameter_gap")
        review_evidence = list(dict.fromkeys(review_evidence))
    if source_bound_live_in_parameter_gap_count > 0:
        review_evidence.append("source_bound_live_in_parameter_gap")
        review_evidence = list(dict.fromkeys(review_evidence))
    callee_arity_residue_count = _int_value(callee_arity_residue_profile.get("count"), 0)
    if callee_arity_residue_count > 0:
        review_evidence.append("callee_arity_residue")
        review_evidence = list(dict.fromkeys(review_evidence))
    if report_only_preview_parameter_corrections > 0:
        review_evidence.append("report_only_identity_type_preview_available")
        review_evidence = list(dict.fromkeys(review_evidence))
    named_target_group = _body_offset_named_goal_target_group(name)
    promotion_hints = _body_offset_residue_promotion_hints(
        review_class,
        next_action,
        rewrite_blockers,
        domain_identities,
        pointer_indexed_metrics,
        offset_shape_profile,
    )
    next_action_details = _body_offset_residue_next_action_details(
        review_class,
        next_action,
        review_evidence,
        promotion_hints,
        rewrite_blockers,
        domain_identities,
        pointer_indexed_metrics,
        offset_shape_profile,
        stable_base_sources,
    )
    if named_target_group:
        next_action_details.append("goal_target_%s" % named_target_group)
        next_action_details = list(dict.fromkeys(next_action_details))
    if parameter_indexed_elements:
        next_action_details.append("parameter_indexed_parent_stride_available")
        if _body_offset_parameter_indexed_counter(parameter_indexed_elements, "alias_rewrite_risk"):
            next_action_details.append("avoid_naive_parameter_alias_rewrite")
        next_action_details = list(dict.fromkeys(next_action_details))
    if nested_field_pointer_count > 0:
        next_action_details.append("nested_field_pointer_layout_model_required")
        next_action_details = list(dict.fromkeys(next_action_details))
    if live_in_parameter_gap_count > 0:
        next_action_details.append("review_live_in_parameter_gap_before_type_correction")
        next_action_details = list(dict.fromkeys(next_action_details))
    if source_bound_live_in_parameter_gap_count > 0:
        next_action_details.append("source_bound_live_in_gap_requires_missing_parameter_support")
        next_action_details = list(dict.fromkeys(next_action_details))
    if callee_arity_residue_count > 0:
        next_action_details.append("review_callee_contract_before_caller_parameter_correction")
        next_action_details = list(dict.fromkeys(next_action_details))
    if report_only_preview_parameter_corrections > 0:
        next_action_details.append("use_type_assisted_preview_keep_body_rewrite_closed")
        next_action_details = list(dict.fromkeys(next_action_details))
    fail_closed_gate = _body_offset_residue_fail_closed_gate(
        review_class,
        review_evidence,
        next_action_details,
        promotion_hints,
    )
    fail_closed_family = _body_offset_fail_closed_family(fail_closed_gate)
    rewrite_safety_policy = _body_offset_rewrite_safety_policy(
        fail_closed_gate,
        review_class,
        review_evidence,
        next_action_details,
    )
    evidence_maturity = _body_offset_evidence_maturity(
        fail_closed_gate,
        review_evidence,
        next_action_details,
        stable_base_sources,
    )
    primary_review_reasons = _body_offset_primary_review_reasons(
        fail_closed_gate,
        review_evidence,
        next_action_details,
        promotion_hints,
    )
    residue_pressure_class = _body_offset_residue_pressure_class(
        offset_deref_survivors,
        direct_base_deref_survivors,
        field_access_pressure,
        _int_value(prototype_metrics.get("generic_parameter_survivors"), 0),
        bool(named_target_group),
    )
    residue_review_notes = _body_offset_residue_review_notes(
        fail_closed_gate,
        review_class,
        review_evidence,
        next_action_details,
        promotion_hints,
        offset_deref_survivors,
        direct_base_deref_survivors,
        field_access_pressure,
        _int_value(prototype_metrics.get("generic_parameter_survivors"), 0),
        len(stable_base_sources),
        len(generic_base_evidence),
        len(generic_base_trust_candidates),
        len(temp_provenance.get("blocked", []) or []),
        _int_value(pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"), 0),
        _int_value(prototype_metrics.get("body_rewrite_ready"), 0),
        blocker_reasons,
    )
    if live_in_parameter_gap_count > 0:
        residue_review_notes.append("live_in_parameter_gap_candidate")
        residue_review_notes = list(dict.fromkeys(residue_review_notes))
    if source_bound_live_in_parameter_gap_count > 0:
        residue_review_notes.append("source_bound_live_in_parameter_gap_candidate")
        residue_review_notes = list(dict.fromkeys(residue_review_notes))
    if callee_arity_residue_count > 0:
        residue_review_notes.append("callee_arity_residue_candidate")
        residue_review_notes = list(dict.fromkeys(residue_review_notes))
    if report_only_preview_parameter_corrections > 0:
        residue_review_notes.append("type_assisted_preview_candidate_body_rewrite_closed")
        residue_review_notes = list(dict.fromkeys(residue_review_notes))
    priority_factors = _body_offset_residue_priority_factors(
        subsystem,
        review_class,
        review_evidence,
        promotion_hints,
        next_action_details,
        residue_review_notes,
        offset_deref_survivors,
        direct_base_deref_survivors,
        _int_value(prototype_metrics.get("generic_parameter_survivors"), 0),
        field_access_pressure,
        named_target_group,
    )
    if nested_field_pointer_count > 0:
        priority_factors.append("nested_field_pointer_residue")
        priority_factors = list(dict.fromkeys(priority_factors))
    if live_in_parameter_gap_count > 0:
        priority_factors.append("live_in_parameter_gap")
        priority_factors = list(dict.fromkeys(priority_factors))
    if source_bound_live_in_parameter_gap_count > 0:
        priority_factors.append("source_bound_live_in_parameter_gap")
        priority_factors = list(dict.fromkeys(priority_factors))
    if callee_arity_residue_count > 0:
        priority_factors.append("callee_arity_residue")
        priority_factors = list(dict.fromkeys(priority_factors))
    if report_only_preview_parameter_corrections > 0:
        priority_factors.append("report_only_identity_type_preview_available")
        priority_factors = list(dict.fromkeys(priority_factors))
    review_focus = _body_offset_residue_review_focus(subsystem, fail_closed_gate, priority_factors)
    priority_score = offset_deref_survivors
    priority_score += direct_base_deref_survivors
    priority_score += field_access_pressure // 2
    priority_score += 30 if subsystem in {"registry", "memory", "object", "security"} else 0
    priority_score += 20 if rewrite_blockers else 0
    priority_score += 15 if hot_field_clusters else 0
    priority_score += 10 if source_evidence_count else 0
    if "trusted_source_required" in review_evidence:
        priority_score += 10
    if "report_only_profile_kept_closed" in review_evidence:
        priority_score += 6
    if "pointer_indexed_array_or_table_shape" in review_evidence:
        priority_score += 6
    if named_target_group:
        priority_score += 18
    if nested_field_pointer_count > 0:
        priority_score += min(20, 4 + nested_field_pointer_count)
    if live_in_parameter_gap_count > 0:
        priority_score += min(18, 6 * live_in_parameter_gap_count)
    if source_bound_live_in_parameter_gap_count > 0:
        priority_score += min(20, 8 + (4 * source_bound_live_in_parameter_gap_count))
    if callee_arity_residue_count > 0:
        priority_score += min(15, 5 * callee_arity_residue_count)
    if report_only_preview_parameter_corrections > 0:
        priority_score += min(18, 4 + report_only_preview_parameter_corrections)
    priority_score += _body_offset_residue_priority_bonus(priority_factors)
    result = {
        "ea": ea,
        "name": name,
        "subsystem": subsystem,
        "review_class": review_class,
        "next_action": next_action,
        "priority_score": priority_score,
        "review_focus": review_focus,
        "fail_closed_gate": fail_closed_gate,
        "fail_closed_family": fail_closed_family,
        "rewrite_safety_policy": rewrite_safety_policy,
        "evidence_maturity": evidence_maturity,
        "primary_review_reasons": primary_review_reasons,
        "residue_pressure_class": residue_pressure_class,
        "residue_review_notes": residue_review_notes,
        "named_goal_target": bool(named_target_group),
        "named_goal_target_group": named_target_group,
        "priority_factors": priority_factors,
        "offset_deref_survivors": offset_deref_survivors,
        "direct_base_deref_survivors": direct_base_deref_survivors,
        "direct_base_deref_bases": _coerce_dict(direct_base_deref_profile.get("bases", {})),
        "direct_base_deref_types": _coerce_dict(direct_base_deref_profile.get("types", {})),
        "direct_base_deref_base_classes": _coerce_dict(
            direct_base_deref_profile.get("base_classes", {})
        ),
        "direct_base_deref_class_bases": _coerce_dict(
            direct_base_deref_profile.get("class_bases", {})
        ),
        "direct_call_result_callees": _coerce_dict(
            direct_base_deref_profile.get("call_result_callees", {})
        ),
        "direct_call_result_arg_roots": _coerce_dict(
            direct_base_deref_profile.get("call_result_arg_roots", {})
        ),
        "direct_call_result_member_paths": _coerce_dict(
            direct_base_deref_profile.get("call_result_member_paths", {})
        ),
        "direct_call_result_deref_types": _coerce_dict(
            direct_base_deref_profile.get("call_result_deref_types", {})
        ),
        "direct_call_result_layout_hints": _coerce_dict(
            direct_base_deref_profile.get("call_result_layout_hints", {})
        ),
        "direct_call_result_hint_modes": _coerce_dict(
            direct_base_deref_profile.get("call_result_hint_modes", {})
        ),
        "direct_call_result_samples": [
            str(sample)
            for sample in direct_base_deref_profile.get("call_result_samples", []) or []
            if str(sample)
        ][:5],
        "direct_call_result_layout_samples": [
            str(sample)
            for sample in direct_base_deref_profile.get("call_result_layout_samples", []) or []
            if str(sample)
        ][:5],
        "direct_base_deref_samples": [
            str(sample)
            for sample in direct_base_deref_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "existing_parameter_alias_count": _int_value(
            existing_parameter_alias_profile.get("count"),
            0,
        ),
        "existing_parameter_alias_actions": _coerce_dict(
            existing_parameter_alias_profile.get("actions", {})
        ),
        "existing_parameter_alias_registers": _coerce_dict(
            existing_parameter_alias_profile.get("registers", {})
        ),
        "existing_parameter_alias_callees": _coerce_dict(
            existing_parameter_alias_profile.get("callees", {})
        ),
        "existing_parameter_alias_samples": [
            str(sample)
            for sample in existing_parameter_alias_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "live_in_parameter_gap_count": live_in_parameter_gap_count,
        "source_bound_live_in_parameter_gap_count": source_bound_live_in_parameter_gap_count,
        "live_in_parameter_gap_actions": _coerce_dict(
            live_in_parameter_gap_profile.get("actions", {})
        ),
        "live_in_parameter_gap_registers": _coerce_dict(
            live_in_parameter_gap_profile.get("registers", {})
        ),
        "live_in_parameter_gap_callees": _coerce_dict(
            live_in_parameter_gap_profile.get("callees", {})
        ),
        "live_in_parameter_gap_abi_slots": _coerce_dict(
            live_in_parameter_gap_profile.get("abi_slots", {})
        ),
        "live_in_parameter_gap_missing_signature_slots": _coerce_dict(
            live_in_parameter_gap_profile.get("missing_signature_slots", {})
        ),
        "live_in_parameter_gap_symbols": _coerce_dict(
            live_in_parameter_gap_profile.get("symbols", {})
        ),
        "live_in_parameter_gap_samples": [
            str(sample)
            for sample in live_in_parameter_gap_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "callee_arity_residue_count": callee_arity_residue_count,
        "callee_arity_residue_actions": _coerce_dict(
            callee_arity_residue_profile.get("actions", {})
        ),
        "callee_arity_residue_registers": _coerce_dict(
            callee_arity_residue_profile.get("registers", {})
        ),
        "callee_arity_residue_callees": _coerce_dict(
            callee_arity_residue_profile.get("callees", {})
        ),
        "callee_arity_residue_evidence": _coerce_dict(
            callee_arity_residue_profile.get("evidence", {})
        ),
        "callee_arity_residue_samples": [
            str(sample)
            for sample in callee_arity_residue_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "parameter_field_pointer_source_anchor_count": _int_value(
            parameter_field_pointer_source_profile.get("count"),
            0,
        ),
        "parameter_field_pointer_sources": _coerce_dict(
            parameter_field_pointer_source_profile.get("sources", {})
        ),
        "parameter_field_pointer_targets": _coerce_dict(
            parameter_field_pointer_source_profile.get("targets", {})
        ),
        "parameter_field_pointer_offsets": _coerce_dict(
            parameter_field_pointer_source_profile.get("offsets", {})
        ),
        "parameter_field_pointer_types": _coerce_dict(
            parameter_field_pointer_source_profile.get("types", {})
        ),
        "parameter_field_pointer_samples": [
            str(sample)
            for sample in parameter_field_pointer_source_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "generic_parameter_survivors": _int_value(prototype_metrics.get("generic_parameter_survivors"), 0),
        "exact_report_only_identity_candidates": _int_value(
            prototype_metrics.get("exact_report_only_identity_candidates"),
            0,
        ),
        "source_bound_report_only_identity_candidates": source_bound_report_only_identity_candidates,
        "function_identity_source_context": _coerce_dict(
            prototype_metrics.get("function_identity_source_context", {})
        ),
        "source_bound_identity_sources": _coerce_dict(
            prototype_metrics.get("source_bound_identity_sources", {})
        ),
        "report_only_identity_preview_candidates": _int_value(
            prototype_metrics.get("report_only_identity_preview_candidates"),
            0,
        ),
        "report_only_identity_preview_parameter_corrections": report_only_preview_parameter_corrections,
        "report_only_identity_preview_profiles": _coerce_dict(
            prototype_metrics.get("report_only_identity_preview_profiles", {})
        ),
        "body_rewrite_ready": _int_value(prototype_metrics.get("body_rewrite_ready"), 0),
        "body_rewrite_blockers": _int_value(prototype_metrics.get("body_rewrite_blockers"), 0),
        "layout_hint_count": len(layout_hints),
        "hot_field_cluster_count": len(hot_field_clusters),
        "indexed_callback_table_count": len(indexed_callback_tables),
        "parameter_indexed_element_count": len(parameter_indexed_elements),
        "parameter_indexed_parents": _body_offset_parameter_indexed_counter(
            parameter_indexed_elements,
            "parent",
        ),
        "parameter_indexed_parent_types": _body_offset_parameter_indexed_counter(
            parameter_indexed_elements,
            "parent_type",
        ),
        "parameter_indexed_strides": _body_offset_parameter_indexed_stride_counter(
            parameter_indexed_elements,
        ),
        "parameter_indexed_alias_rewrite_risks": _body_offset_parameter_indexed_counter(
            parameter_indexed_elements,
            "alias_rewrite_risk",
        ),
        "parameter_indexed_offsets": _body_offset_parameter_indexed_offsets(
            parameter_indexed_elements,
        ),
        "nested_field_pointer_residue_count": nested_field_pointer_count,
        "nested_field_pointer_parents": _coerce_dict(
            nested_field_pointer_profile.get("parents", {})
        ),
        "nested_field_pointer_fields": _coerce_dict(
            nested_field_pointer_profile.get("fields", {})
        ),
        "nested_field_pointer_parent_fields": _coerce_dict(
            nested_field_pointer_profile.get("parent_fields", {})
        ),
        "nested_field_pointer_offsets": _coerce_dict(
            nested_field_pointer_profile.get("offsets", {})
        ),
        "nested_field_pointer_samples": [
            str(sample)
            for sample in nested_field_pointer_profile.get("samples", []) or []
            if str(sample)
        ][:5],
        "stable_base_source_count": len(stable_base_sources),
        "stable_source_provenance": _body_offset_source_counter(
            stable_base_sources,
            "source_provenance",
        ),
        "stable_source_kinds": _body_offset_source_counter(
            stable_base_sources,
            "source_kind",
        ),
        "top_stable_sources": _body_offset_source_counter(
            stable_base_sources,
            "source",
        ),
        "top_stable_source_details": _body_offset_source_detail_counter(
            stable_base_sources,
        ),
        "generic_base_evidence_count": len(generic_base_evidence),
        "generic_base_trust_candidate_count": len(generic_base_trust_candidates),
        "temp_provenance_blocked_count": len(temp_provenance.get("blocked", []) or []),
        "domain_identity_count": len(domain_identities),
        "domain_report_only_count": sum(
            1
            for item in domain_identities
            if str(item.get("mode", "") or "") == "report-only"
        ),
        "field_access_pressure": field_access_pressure,
        "pointer_indexed_offset_deref_patterns": _int_value(
            pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"),
            0,
        ),
        "offset_deref_samples": [
            str(sample)
            for sample in offset_shape_profile.get("offset_deref_samples", []) or []
            if str(sample)
        ][:8],
        "top_base_offset_samples": {
            str(base): [
                str(sample)
                for sample in samples or []
                if str(sample)
            ][:3]
            for base, samples in _coerce_dict(
                offset_shape_profile.get("top_base_offset_samples", {})
            ).items()
            if str(base)
        },
        "top_bases": _body_offset_top_bases(
            layout_hints,
            hot_field_clusters,
            indexed_callback_tables,
            rewrite_blockers,
            domain_identities,
            offset_shape_profile,
        ),
        "blocker_reasons": _counter_to_dict(Counter(dict(blocker_reasons.most_common(5)))),
        "blocker_families": _body_offset_blocker_family_counter(blocker_reasons),
        "review_evidence": review_evidence,
        "promotion_hints": promotion_hints,
        "next_action_details": next_action_details,
        "offset_shape_profile": offset_shape_profile,
        "profile_counts": _coerce_dict(prototype_metrics.get("function_identity_profiles", {})),
        "domain_profiles": _profile_counter(domain_identities),
        "summary_path": str(summary_path),
        "cleaned_path": str(cleaned_path),
    }
    result["residue_cause_tags"] = _body_offset_residue_cause_tags(result)
    result["promotion_lane"] = _body_offset_residue_promotion_lane(result)
    result["review_summary"] = _body_offset_residue_review_summary(result)
    return result


def _update_body_offset_residue_metrics(
    item: dict[str, Any],
    totals: Counter[str],
    subsystems: Counter[str],
    next_actions: Counter[str],
    review_classes: Counter[str],
    blocker_reasons: Counter[str],
    review_evidence: Counter[str],
    promotion_hints: Counter[str],
    promotion_lanes: Counter[str],
    next_action_details: Counter[str],
    priority_factors: Counter[str],
    review_notes: Counter[str],
    fail_closed_gates: Counter[str],
    fail_closed_families: Counter[str],
    review_focuses: Counter[str],
    shape_classes: Counter[str],
    base_classes: Counter[str],
    direct_base_classes: Counter[str],
    named_target_groups: Counter[str],
    safety_policies: Counter[str],
    evidence_maturity: Counter[str],
    cause_tags: Counter[str],
    stable_source_details: Counter[str],
) -> None:
    totals["functions_with_offset_residue"] += 1
    totals["offset_deref_survivors"] += _int_value(item.get("offset_deref_survivors"), 0)
    direct_base_deref_survivors = _int_value(item.get("direct_base_deref_survivors"), 0)
    totals["direct_base_deref_survivors"] += direct_base_deref_survivors
    if direct_base_deref_survivors > 0:
        totals["functions_with_direct_base_deref_residue"] += 1
    totals["generic_parameter_survivors"] += _int_value(item.get("generic_parameter_survivors"), 0)
    if _int_value(item.get("body_rewrite_ready"), 0) > 0:
        totals["functions_with_rewrite_ready"] += 1
    if _int_value(item.get("body_rewrite_blockers"), 0) > 0:
        totals["functions_with_rewrite_blockers"] += 1
    if _int_value(item.get("domain_identity_count"), 0) > 0:
        totals["functions_with_domain_identity"] += 1
    if _int_value(item.get("hot_field_cluster_count"), 0) > 0:
        totals["functions_with_hot_field_clusters"] += 1
    if _int_value(item.get("stable_base_source_count"), 0) > 0:
        totals["functions_with_stable_base_sources"] += 1
    if _int_value(item.get("indexed_callback_table_count"), 0) > 0:
        totals["functions_with_indexed_callback_tables"] += 1
    if _int_value(item.get("parameter_indexed_element_count"), 0) > 0:
        totals["functions_with_parameter_indexed_elements"] += 1
    nested_field_pointer_residue_count = _int_value(
        item.get("nested_field_pointer_residue_count"),
        0,
    )
    totals["nested_field_pointer_residue"] += nested_field_pointer_residue_count
    if nested_field_pointer_residue_count > 0:
        totals["functions_with_nested_field_pointer_residue"] += 1
    if bool(item.get("named_goal_target")):
        totals["functions_with_named_goal_targets"] += 1
    subsystems[str(item.get("subsystem", "") or "other")] += 1
    next_actions[str(item.get("next_action", "") or "manual_review")] += 1
    review_classes[str(item.get("review_class", "") or "manual_review")] += 1
    for reason, count in _coerce_dict(item.get("blocker_reasons", {})).items():
        blocker_reasons[str(reason)] += _int_value(count, 0)
    for evidence in item.get("review_evidence", []) or []:
        if str(evidence):
            review_evidence[str(evidence)] += 1
    for hint in item.get("promotion_hints", []) or []:
        if str(hint):
            promotion_hints[str(hint)] += 1
    promotion_lane = str(item.get("promotion_lane", "") or "")
    if promotion_lane:
        promotion_lanes[promotion_lane] += 1
    for detail in item.get("next_action_details", []) or []:
        if str(detail):
            next_action_details[str(detail)] += 1
    for factor in item.get("priority_factors", []) or []:
        if str(factor):
            priority_factors[str(factor)] += 1
    for note in item.get("residue_review_notes", []) or []:
        if str(note):
            review_notes[str(note)] += 1
    fail_closed_gate = str(item.get("fail_closed_gate", "") or "")
    if fail_closed_gate:
        fail_closed_gates[fail_closed_gate] += 1
    fail_closed_family = str(item.get("fail_closed_family", "") or "")
    if fail_closed_family:
        fail_closed_families[fail_closed_family] += 1
    review_focus = str(item.get("review_focus", "") or "")
    if review_focus:
        review_focuses[review_focus] += 1
    named_target_group = str(item.get("named_goal_target_group", "") or "")
    if named_target_group:
        named_target_groups[named_target_group] += 1
    safety_policy = str(item.get("rewrite_safety_policy", "") or "")
    if safety_policy:
        safety_policies[safety_policy] += 1
    maturity = str(item.get("evidence_maturity", "") or "")
    if maturity:
        evidence_maturity[maturity] += 1
    for tag in item.get("residue_cause_tags", []) or []:
        if str(tag):
            cause_tags[str(tag)] += 1
    for detail, count in _coerce_dict(item.get("top_stable_source_details", {})).items():
        stable_source_details[str(detail)] += _int_value(count, 0)
    shape_profile = _coerce_dict(item.get("offset_shape_profile", {}))
    shape_class = str(shape_profile.get("shape_class", "") or "")
    if shape_class:
        shape_classes[shape_class] += 1
    for base_class, count in _coerce_dict(shape_profile.get("base_classes", {})).items():
        base_classes[str(base_class)] += _int_value(count, 0)
    for base_class, count in _coerce_dict(item.get("direct_base_deref_base_classes", {})).items():
        direct_base_classes[str(base_class)] += _int_value(count, 0)


def _body_offset_residue_totals_dict(counter: Counter[str]) -> dict[str, int]:
    required_keys = [
        "functions_with_offset_residue",
        "offset_deref_survivors",
        "direct_base_deref_survivors",
        "functions_with_direct_base_deref_residue",
        "generic_parameter_survivors",
        "functions_with_rewrite_ready",
        "functions_with_rewrite_blockers",
        "functions_with_domain_identity",
        "functions_with_hot_field_clusters",
        "functions_with_stable_base_sources",
        "functions_with_indexed_callback_tables",
        "functions_with_parameter_indexed_elements",
        "nested_field_pointer_residue",
        "functions_with_nested_field_pointer_residue",
        "functions_with_named_goal_targets",
    ]
    result = _counter_to_dict(counter)
    for key in required_keys:
        result.setdefault(key, 0)
    return result


def _body_offset_residue_subsystem(
    name: str,
    prototype_metrics: dict[str, Any],
    domain_identities: list[dict[str, Any]],
) -> str:
    profile_text = " ".join(
        [
            *[str(key) for key in _coerce_dict(prototype_metrics.get("function_identity_profiles", {})).keys()],
            *[str(item.get("profile_id", "")) for item in domain_identities],
        ]
    )
    profile_map = {
        "registry_config": "registry",
        "memory_manager": "memory",
        "object_manager": "object",
        "token_security": "security",
        "compression_xpress": "compression",
        "alpc_port": "alpc",
        "hal_dma_iommu": "hal",
        "pnp_power": "pnp",
        "etw_wmi_telemetry": "etw",
    }
    for token, subsystem in profile_map.items():
        if token in profile_text:
            return subsystem
    prefix_map = (
        ("Cmp", "registry"),
        ("Cm", "registry"),
        ("Hvl", "hypervisor"),
        ("Hvp", "registry"),
        ("Hv", "registry"),
        ("Mi", "memory"),
        ("Mm", "memory"),
        ("Vmp", "memory"),
        ("Ob", "object"),
        ("Se", "security"),
        ("Alpc", "alpc"),
        ("NtAlpc", "alpc"),
        ("Hal", "hal"),
        ("Pnp", "pnp"),
        ("Pi", "pnp"),
        ("Pop", "power"),
        ("Etw", "etw"),
        ("Etwp", "etw"),
        ("Xp", "compression"),
        ("Xpress", "compression"),
        ("LZ4", "compression"),
    )
    for prefix, subsystem in prefix_map:
        if name.startswith(prefix):
            return subsystem
    if name.startswith("?St") or name.startswith("?Sm"):
        return "store_manager"
    return "other"


def _body_offset_residue_review_class(
    prototype_metrics: dict[str, Any],
    layout_hints: list[dict[str, Any]],
    hot_field_clusters: list[dict[str, Any]],
    stable_base_sources: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
) -> str:
    if _int_value(prototype_metrics.get("body_rewrite_ready"), 0) > 0:
        return "rewrite_ready_residue"
    if rewrite_blockers:
        if any(
            _has_layout_trusted_source_gap([str(reason) for reason in blocker.get("reasons", []) or []])
            for blocker in rewrite_blockers
        ):
            return "source_identity_blocked_residue"
        if any(
            "domain identity profile is report-only" in str(reason)
            for blocker in rewrite_blockers
            for reason in blocker.get("reasons", []) or []
        ):
            return "report_only_blocked_residue"
        if any(
            _has_layout_source_stability_risk([str(reason) for reason in blocker.get("reasons", []) or []])
            for blocker in rewrite_blockers
        ):
            return "source_stability_blocked_residue"
        if any(
            _has_layout_type_evidence_risk([str(reason) for reason in blocker.get("reasons", []) or []])
            for blocker in rewrite_blockers
        ):
            return "type_conflict_blocked_residue"
        return "identity_or_threshold_blocked_residue"
    if hot_field_clusters and not domain_identities:
        return "hot_cluster_missing_identity"
    if layout_hints and not domain_identities:
        return "layout_hint_missing_identity"
    if generic_base_evidence or generic_base_trust_candidates:
        return "generic_base_identity_review"
    if stable_base_sources:
        return "stable_source_identity_review"
    if _int_value(pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"), 0) > 0:
        return "pointer_indexed_residue"
    shape_class = str(offset_shape_profile.get("shape_class", "") or "")
    if shape_class in _BODY_OFFSET_SHAPE_REVIEW_CLASS_ORDER:
        return shape_class
    return "unclassified_offset_residue"


def _body_offset_residue_next_action(
    review_class: str,
    prototype_metrics: dict[str, Any],
    layout_hints: list[dict[str, Any]],
    hot_field_clusters: list[dict[str, Any]],
    stable_base_sources: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
    rewrite_ready: list[dict[str, Any]],
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
) -> str:
    del prototype_metrics, layout_hints, stable_base_sources, generic_base_evidence
    del generic_base_trust_candidates, rewrite_ready, rewrite_blockers, domain_identities
    del pointer_indexed_metrics, offset_shape_profile
    if review_class == "rewrite_ready_residue":
        return "verify_validated_rewrite_or_partial_residue"
    if review_class == "report_only_blocked_residue":
        return "keep_report_only_and_collect_exact_promotion_evidence"
    if review_class == "source_identity_blocked_residue":
        return "add_exact_source_identity_or_keep_review_only"
    if review_class == "source_stability_blocked_residue":
        return "prove_source_stability_before_rewrite"
    if review_class == "type_conflict_blocked_residue":
        return "resolve_type_width_or_subfield_conflict"
    if review_class == "identity_or_threshold_blocked_residue":
        return "add_exact_identity_or_collect_threshold_evidence"
    if review_class == "hot_cluster_missing_identity":
        return "add_function_scoped_identity_for_hot_cluster" if hot_field_clusters else "manual_review"
    if review_class == "layout_hint_missing_identity":
        return "add_domain_profile_or_keep_review_only"
    if review_class == "generic_base_identity_review":
        return "prove_generic_base_identity_before_promotion"
    if review_class == "stable_source_identity_review":
        return "consider_validated_profile_promotion"
    if review_class == "pointer_indexed_residue":
        return "model_pointer_indexed_layout_or_callback_table"
    if review_class == "dense_offset_shape_missing_identity":
        return "add_function_scoped_identity_or_keep_review_only"
    if review_class == "parameter_offset_shape_review":
        return "add_parameter_profile_or_keep_review_only"
    if review_class == "context_offset_shape_review":
        return "add_context_profile_or_keep_review_only"
    if review_class == "temp_offset_shape_review":
        return "prove_temp_source_identity_before_promotion"
    if review_class == "low_pressure_offset_residue":
        return "leave_as_low_pressure_residue"
    return "manual_review"


def _body_offset_residue_review_evidence(
    review_class: str,
    hot_field_clusters: list[dict[str, Any]],
    rewrite_ready: list[dict[str, Any]],
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
) -> list[str]:
    reasons = _body_offset_rewrite_blocker_reasons(rewrite_blockers)
    evidence: list[str] = []
    if rewrite_ready:
        evidence.append("validated_rewrite_still_has_residue")
    if _has_layout_trusted_source_gap(reasons):
        evidence.append("trusted_source_required")
    if _body_offset_has_exact_reason(reasons, "domain identity profile is report-only"):
        evidence.append("report_only_profile_kept_closed")
    if _body_offset_has_exact_reason(reasons, "source domain identity profile is report-only"):
        evidence.append("report_only_source_identity")
    if _has_layout_source_stability_risk(reasons):
        evidence.append("source_stability_risk")
    if _has_layout_type_evidence_risk(reasons):
        evidence.append("type_width_or_alignment_conflict")
    if _has_layout_threshold_gap(reasons):
        evidence.append("threshold_gap")
    if _int_value(pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"), 0) > 0:
        evidence.append("pointer_indexed_array_or_table_shape")
    if hot_field_clusters and not domain_identities:
        evidence.append("hot_field_cluster_missing_identity")
    shape_class = str(offset_shape_profile.get("shape_class", "") or "")
    if shape_class and shape_class != "unclassified_offset_residue":
        evidence.append(shape_class)
    if domain_identities and review_class == "unclassified_offset_residue":
        evidence.append("domain_identity_not_enough_for_body_rewrite")
    if not evidence:
        evidence.append("manual_code_review_required")
    return list(dict.fromkeys(evidence))


def _body_offset_residue_promotion_hints(
    review_class: str,
    next_action: str,
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
) -> list[str]:
    reasons = _body_offset_rewrite_blocker_reasons(rewrite_blockers)
    hints: list[str] = []
    if review_class == "rewrite_ready_residue":
        hints.append("verify_validated_rewrite_output")
    if _body_offset_has_exact_reason(reasons, "domain identity profile is report-only"):
        hints.append("do_not_promote_report_only_profile")
        if _domain_identities_have_field_aliases(domain_identities):
            hints.append("collect_exact_private_field_layout_evidence")
    if _body_offset_has_exact_reason(reasons, "source domain identity profile is report-only"):
        hints.append("promote_source_profile_before_alias_rewrite")
    if next_action == "add_exact_source_identity_or_keep_review_only":
        hints.append("require_exact_function_build_source_identity")
        hints.append("keep_review_only_without_trusted_source")
    if next_action == "prove_source_stability_before_rewrite":
        hints.append("prove_single_initializer_and_no_post_access_reassignment")
    if next_action == "resolve_type_width_or_subfield_conflict":
        hints.append("resolve_width_alignment_or_overlay_conflict")
    if next_action == "model_pointer_indexed_layout_or_callback_table":
        hints.append("model_pointer_indexed_entry_or_callback_table")
    if _int_value(pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"), 0) > 0:
        hints.append("separate_array_shape_from_canonical_body_rewrite")
    if review_class in {"hot_cluster_missing_identity", "layout_hint_missing_identity"}:
        hints.append("add_function_scoped_identity_or_keep_manual")
    if review_class == "unclassified_offset_residue":
        hints.append("classify_subsystem_and_source_before_promotion")
    shape_class = str(offset_shape_profile.get("shape_class", "") or "")
    if shape_class == "dense_offset_shape_missing_identity":
        hints.append("add_exact_identity_for_dense_shape_or_keep_review_only")
    if shape_class == "parameter_offset_shape_review":
        hints.append("validate_parameter_semantics_before_type_correction")
    if shape_class == "context_offset_shape_review":
        hints.append("add_exact_function_context_profile")
    if shape_class == "temp_offset_shape_review":
        hints.append("trace_temp_initializer_before_rewrite")
    if shape_class == "low_pressure_offset_residue":
        hints.append("defer_until_more_access_pressure")
    if not hints:
        hints.append("manual_review")
    return list(dict.fromkeys(hints))


def _body_offset_residue_next_action_details(
    review_class: str,
    next_action: str,
    review_evidence: list[str],
    promotion_hints: list[str],
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    pointer_indexed_metrics: dict[str, Any],
    offset_shape_profile: dict[str, Any],
    stable_base_sources: list[dict[str, Any]] | None = None,
) -> list[str]:
    del review_class
    reasons = _body_offset_rewrite_blocker_reasons(rewrite_blockers)
    evidence = {str(item) for item in review_evidence if str(item)}
    hints = {str(item) for item in promotion_hints if str(item)}
    stable_sources = stable_base_sources or []
    stable_source_provenance = {
        str(item.get("source_provenance", "") or "")
        for item in stable_sources
        if str(item.get("source_provenance", "") or "")
    }
    details: list[str] = []
    if "validated_rewrite_still_has_residue" in evidence:
        details.append("manual_reread_validated_rewrite_output")
    if "report_only_profile_kept_closed" in evidence:
        details.append("keep_report_only_until_exact_private_layout_source")
        if _domain_identities_have_field_aliases(domain_identities):
            details.append("field_aliases_available_for_manual_review")
    if "report_only_source_identity" in evidence:
        details.append("promote_source_identity_before_alias_rewrite")
    if "source_build_mismatch" in evidence:
        details.append("resolve_profile_build_or_source_identity_before_rewrite")
    if "trusted_source_required" in evidence:
        details.append("exact_function_build_source_identity_required")
    if "source_stability_risk" in evidence:
        details.append("prove_single_stable_source_before_body_rewrite")
    if "type_width_or_alignment_conflict" in evidence:
        details.append("resolve_width_alignment_or_overlay_before_rewrite")
    if "threshold_gap" in evidence:
        details.append("collect_access_and_offset_threshold_evidence")
    if "pointer_indexed_array_or_table_shape" in evidence:
        details.append("model_pointer_indexed_table_separately")
    if "hot_field_cluster_missing_identity" in evidence:
        details.append("add_function_scoped_identity_for_hot_cluster")
    if stable_sources:
        details.append("stable_source_provenance_available_for_review")
    if "parameter_field_pointer_alias" in stable_source_provenance:
        details.append("parameter_field_pointer_alias_requires_source_profile")
    if stable_source_provenance.intersection({"parameter_direct_alias", "direct_argument_alias"}):
        details.append("direct_parameter_source_alias_available")
    if "named_call_result_alias" in stable_source_provenance:
        details.append("named_call_result_source_alias_available")
    if _has_layout_trusted_source_gap(reasons):
        details.append("trusted_source_gate_is_blocking")
    if _has_layout_source_stability_risk(reasons):
        details.append("source_stability_gate_is_blocking")
    if _has_layout_type_evidence_risk(reasons):
        details.append("type_evidence_gate_is_blocking")
    shape_class = str(offset_shape_profile.get("shape_class", "") or "")
    if shape_class == "parameter_offset_shape_review":
        details.append("validate_parameter_semantics_before_type_correction")
    elif shape_class == "context_offset_shape_review":
        details.append("add_exact_context_profile_or_keep_review_only")
    elif shape_class == "temp_offset_shape_review":
        details.append("trace_temp_initializer_before_promotion")
    elif shape_class == "dense_offset_shape_missing_identity":
        details.append("add_dense_shape_identity_or_keep_review_only")
    elif shape_class == "low_pressure_offset_residue":
        details.append("defer_low_pressure_residue")
    if next_action == "verify_validated_rewrite_or_partial_residue":
        details.append("compare_cleaned_output_against_original_offset_accesses")
    if "separate_array_shape_from_canonical_body_rewrite" in hints:
        details.append("keep_array_shape_out_of_canonical_field_rewrite")
    if _int_value(pointer_indexed_metrics.get("pointer_indexed_offset_deref_patterns"), 0) > 0:
        details.append("pointer_indexed_metrics_present")
    if not details:
        details.append("manual_review_required")
    return list(dict.fromkeys(details))


def _body_offset_has_build_mismatch(
    prototype_metrics: dict[str, Any],
    domain_identities: list[dict[str, Any]],
) -> bool:
    for counter_name in ("function_identity_blockers", "correction_blockers", "body_rewrite_blocker_counts"):
        if _int_value(_coerce_dict(prototype_metrics.get(counter_name, {})).get("build_mismatch"), 0) > 0:
            return True
    for item in domain_identities:
        blockers = _string_list(item.get("blockers"))
        blockers.extend(_string_list(item.get("forced_report_only_reasons")))
        if "build_mismatch" in blockers:
            return True
    return False


def _body_offset_residue_fail_closed_gate(
    review_class: str,
    review_evidence: list[str],
    next_action_details: list[str],
    promotion_hints: list[str],
) -> str:
    evidence = {str(item) for item in review_evidence if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    hints = {str(item) for item in promotion_hints if str(item)}
    if "validated_rewrite_still_has_residue" in evidence:
        return "validated_rewrite_residue_review"
    if "source_build_mismatch" in evidence or "resolve_profile_build_or_source_identity_before_rewrite" in details:
        return "source_build_mismatch"
    if "report_only_profile_kept_closed" in evidence:
        return "report_only_private_layout"
    if "report_only_source_identity" in evidence:
        return "report_only_source_identity"
    if "trusted_source_required" in evidence or "trusted_source_gate_is_blocking" in details:
        return "exact_source_identity_required"
    if "source_stability_risk" in evidence or "source_stability_gate_is_blocking" in details:
        return "source_stability_required"
    if "type_width_or_alignment_conflict" in evidence or "type_evidence_gate_is_blocking" in details:
        return "type_conflict_required"
    if "parameter_indexed_element_shape" in evidence or "parameter_indexed_parent_stride_available" in details:
        return "parameter_indexed_separate_model"
    if "pointer_indexed_array_or_table_shape" in evidence:
        return "pointer_indexed_separate_model"
    if "threshold_gap" in evidence:
        return "threshold_evidence_gap"
    if "trace_temp_initializer_before_rewrite" in hints or "trace_temp_initializer_before_promotion" in details:
        return "temp_source_identity_required"
    if review_class == "low_pressure_offset_residue":
        return "low_pressure_deferred"
    if review_class == "unclassified_offset_residue":
        return "manual_review_required"
    return "review_only"


def _body_offset_residue_priority_factors(
    subsystem: str,
    review_class: str,
    review_evidence: list[str],
    promotion_hints: list[str],
    next_action_details: list[str],
    residue_review_notes: list[str],
    offset_deref_survivors: int,
    direct_base_deref_survivors: int,
    generic_parameter_survivors: int,
    field_access_pressure: int,
    named_target_group: str = "",
) -> list[str]:
    evidence = {str(item) for item in review_evidence if str(item)}
    hints = {str(item) for item in promotion_hints if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    notes = {str(item) for item in residue_review_notes if str(item)}
    factors: list[str] = []
    if named_target_group:
        factors.append("named_goal_target")
        factors.append("%s_goal_target" % named_target_group)
    if subsystem in _BODY_OFFSET_CORE_SUBSYSTEMS:
        factors.append("core_subsystem")
    if offset_deref_survivors >= 24:
        factors.append("high_offset_residue")
    elif offset_deref_survivors >= 8:
        factors.append("medium_offset_residue")
    if direct_base_deref_survivors > 0:
        factors.append("direct_base_zero_residue")
        if named_target_group:
            factors.append("named_target_direct_base_residue")
    if field_access_pressure >= 12:
        factors.append("high_field_access_pressure")
    if "source_build_mismatch" in evidence or "resolve_profile_build_or_source_identity_before_rewrite" in details:
        factors.append("source_build_mismatch")
    if "field_aliases_available_for_manual_review" in details:
        factors.append("report_only_field_alias_available")
    if (
        "trusted_source_required" in evidence
        or "exact_function_build_source_identity_required" in details
        or "keep_review_only_without_trusted_source" in hints
    ):
        factors.append("exact_private_layout_required")
    if "source_stability_risk" in evidence or "source_stability_gate_is_blocking" in details:
        factors.append("source_stability_gate")
    if "type_width_or_alignment_conflict" in evidence or "type_evidence_gate_is_blocking" in details:
        factors.append("type_conflict_gate")
    if "pointer_indexed_array_or_table_shape" in evidence or "pointer_indexed_metrics_present" in details:
        factors.append("pointer_indexed_shape")
    if "parameter_indexed_element_shape" in evidence or "parameter_indexed_parent_stride_available" in details:
        factors.append("parameter_indexed_element_shape")
    if "validated_rewrite_still_has_residue" in evidence:
        factors.append("validated_rewrite_residue")
    if "validated_rewrite_left_secondary_residue" in notes:
        factors.append("validated_secondary_residue")
    if "stable_source_provenance_available_for_review" in details:
        factors.append("stable_source_provenance_available")
    if "parameter_field_pointer_alias_requires_source_profile" in details:
        factors.append("parameter_field_pointer_alias_review")
    if "direct_parameter_source_alias_available" in details:
        factors.append("direct_parameter_source_alias")
    if generic_parameter_survivors > 0 and review_class in {
        "parameter_offset_shape_review",
        "context_offset_shape_review",
        "temp_offset_shape_review",
        "hot_cluster_missing_identity",
        "pointer_indexed_residue",
        "generic_base_identity_review",
    }:
        factors.append("parameter_type_followup")
    if "generic_base_identity_gap" in notes:
        factors.append("generic_context_identity_gap")
    if review_class == "dense_offset_shape_missing_identity" or "add_dense_shape_identity_or_keep_review_only" in details:
        factors.append("dense_shape_without_identity")
    if review_class == "low_pressure_offset_residue":
        factors.append("low_pressure_deferred")
    if "report_only_field_alias_available" in factors and (
        offset_deref_survivors >= 24
        or field_access_pressure >= 12
    ):
        factors.append("high_pressure_report_only_alias")
    if (
        "report_only_field_alias_available" in factors
        and "core_subsystem" in factors
        and "defer_low_pressure_residue" in details
    ):
        factors.append("core_report_only_deferred_shape")
    if "manual_review_required" in details:
        factors.append("manual_review_gap")
    if "high_pressure_unresolved_residue" in notes:
        factors.append("high_pressure_unresolved_residue")
    return list(dict.fromkeys(factors))


def _body_offset_residue_priority_bonus(priority_factors: list[str]) -> int:
    return sum(_BODY_OFFSET_PRIORITY_BONUSES.get(str(factor), 0) for factor in priority_factors)


def _body_offset_named_goal_target_group(name: str) -> str:
    return _BODY_OFFSET_NAMED_GOAL_TARGETS.get(str(name or ""), "")


def _body_offset_fail_closed_family(fail_closed_gate: str) -> str:
    gate = str(fail_closed_gate or "")
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        return "report_only_identity"
    if gate in {"source_build_mismatch", "exact_source_identity_required"}:
        return "source_identity"
    if gate == "source_stability_required":
        return "source_stability"
    if gate == "type_conflict_required":
        return "type_conflict"
    if gate in {"pointer_indexed_separate_model", "parameter_indexed_separate_model"}:
        return "indexed_layout"
    if gate == "validated_rewrite_residue_review":
        return "validated_rewrite_residue"
    if gate == "temp_source_identity_required":
        return "temp_source_identity"
    if gate in {"manual_review_required", "threshold_evidence_gap"}:
        return "manual_or_threshold_gap"
    if gate == "low_pressure_deferred":
        return "low_pressure"
    return "review_only"


def _body_offset_rewrite_safety_policy(
    fail_closed_gate: str,
    review_class: str,
    review_evidence: list[str],
    next_action_details: list[str],
) -> str:
    del review_class
    gate = str(fail_closed_gate or "")
    evidence = {str(item) for item in review_evidence if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    if gate == "validated_rewrite_residue_review":
        return "reread_validated_rewrite_residue"
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        return "do_not_rewrite_report_only_profile"
    if gate == "source_build_mismatch":
        return "resolve_build_identity_before_rewrite"
    if gate == "exact_source_identity_required" or "exact_function_build_source_identity_required" in details:
        return "require_exact_function_build_source_identity"
    if gate == "source_stability_required":
        return "prove_source_stability_before_rewrite"
    if gate == "type_conflict_required":
        return "resolve_type_conflicts_before_rewrite"
    if gate in {"pointer_indexed_separate_model", "parameter_indexed_separate_model"}:
        return "model_indexed_layout_separately"
    if gate == "temp_source_identity_required":
        return "trace_temp_source_before_rewrite"
    if gate == "threshold_evidence_gap" or "threshold_gap" in evidence:
        return "collect_threshold_evidence_before_rewrite"
    if gate == "low_pressure_deferred":
        return "defer_low_pressure_residue"
    if gate == "manual_review_required":
        return "manual_review_before_promotion"
    return "review_only_no_canonical_rewrite"


def _body_offset_evidence_maturity(
    fail_closed_gate: str,
    review_evidence: list[str],
    next_action_details: list[str],
    stable_base_sources: list[dict[str, Any]],
) -> str:
    gate = str(fail_closed_gate or "")
    evidence = {str(item) for item in review_evidence if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    if gate == "validated_rewrite_residue_review":
        return "validated_rewrite_residue"
    if gate == "source_build_mismatch":
        return "build_identity_mismatch"
    if gate in {"exact_source_identity_required", "report_only_source_identity"}:
        return "missing_exact_source_identity"
    if gate == "report_only_private_layout" and stable_base_sources:
        return "report_only_alias_with_stable_source"
    if gate == "report_only_private_layout":
        return "report_only_alias"
    if gate == "source_stability_required":
        return "source_stability_unproven"
    if gate == "type_conflict_required":
        return "type_conflict_unresolved"
    if gate in {"pointer_indexed_separate_model", "parameter_indexed_separate_model"}:
        return "indexed_shape_model_needed"
    if gate == "temp_source_identity_required":
        return "temp_source_unproven"
    if gate == "threshold_evidence_gap":
        return "threshold_evidence_gap"
    if gate == "low_pressure_deferred":
        return "low_pressure"
    if "manual_review_required" in details or "manual_code_review_required" in evidence:
        return "manual_classification_needed"
    return "review_only"


def _body_offset_primary_review_reasons(
    fail_closed_gate: str,
    review_evidence: list[str],
    next_action_details: list[str],
    promotion_hints: list[str],
) -> list[str]:
    gate = str(fail_closed_gate or "")
    evidence = {str(item) for item in review_evidence if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    hints = {str(item) for item in promotion_hints if str(item)}
    reasons: list[str] = []

    if gate == "validated_rewrite_residue_review":
        reasons.append("validated_rewrite_residue_reread")
    if gate == "source_build_mismatch":
        reasons.append("build_identity_mismatch")
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        reasons.append("report_only_profile_kept_closed")
    if gate == "report_only_private_layout":
        reasons.append("exact_private_layout_source_required")
    if gate in {"report_only_source_identity", "exact_source_identity_required"}:
        reasons.append("exact_source_identity_required")
    if gate == "source_stability_required":
        reasons.append("source_stability_unproven")
    if gate == "type_conflict_required":
        reasons.append("type_width_or_alignment_conflict")
    if gate == "pointer_indexed_separate_model":
        reasons.append("indexed_layout_model_required")
    if gate == "parameter_indexed_separate_model":
        reasons.append("parameter_indexed_layout_model_required")
    if gate == "temp_source_identity_required":
        reasons.append("temp_source_identity_required")
    if gate == "threshold_evidence_gap":
        reasons.append("threshold_evidence_gap")
    if gate == "low_pressure_deferred":
        reasons.append("low_pressure_deferred")
    if gate == "manual_review_required":
        reasons.append("manual_classification_required")

    if "field_aliases_available_for_manual_review" in details:
        reasons.append("field_alias_review_only")
    if "parameter_field_pointer_alias_requires_source_profile" in details:
        reasons.append("parameter_field_pointer_alias_requires_source_profile")
    if "direct_parameter_source_alias_available" in details:
        reasons.append("direct_parameter_alias_available")
    if "named_call_result_source_alias_available" in details:
        reasons.append("named_call_result_alias_available")
    if "pointer_indexed_metrics_present" in details:
        reasons.append("pointer_indexed_metrics_present")
    if "type_evidence_gate_is_blocking" in details:
        reasons.append("type_evidence_gate_is_blocking")
    if "source_stability_gate_is_blocking" in details:
        reasons.append("source_stability_gate_is_blocking")
    if "trusted_source_gate_is_blocking" in details:
        reasons.append("trusted_source_gate_is_blocking")
    if "do_not_promote_report_only_profile" in hints:
        reasons.append("do_not_promote_report_only_profile")
    if "collect_exact_private_field_layout_evidence" in hints:
        reasons.append("collect_exact_private_field_layout_evidence")
    if "source_build_mismatch" in evidence:
        reasons.append("build_identity_mismatch")

    if not reasons:
        reasons.append("manual_review_required")
    return list(dict.fromkeys(reasons))


def _body_offset_residue_pressure_class(
    offset_deref_survivors: int,
    direct_base_deref_survivors: int,
    field_access_pressure: int,
    generic_parameter_survivors: int,
    named_goal_target: bool,
) -> str:
    if offset_deref_survivors >= 24 or direct_base_deref_survivors >= 8 or field_access_pressure >= 24:
        return "high"
    if named_goal_target and (offset_deref_survivors >= 4 or direct_base_deref_survivors > 0):
        return "high_goal_target"
    if (
        offset_deref_survivors >= 8
        or direct_base_deref_survivors >= 2
        or field_access_pressure >= 12
        or generic_parameter_survivors >= 4
    ):
        return "medium"
    return "low"


def _body_offset_residue_review_notes(
    fail_closed_gate: str,
    review_class: str,
    review_evidence: list[str],
    next_action_details: list[str],
    promotion_hints: list[str],
    offset_deref_survivors: int,
    direct_base_deref_survivors: int,
    field_access_pressure: int,
    generic_parameter_survivors: int,
    stable_base_source_count: int,
    generic_base_evidence_count: int,
    generic_base_trust_candidate_count: int,
    temp_provenance_blocked_count: int,
    pointer_indexed_offset_deref_patterns: int,
    body_rewrite_ready: int,
    blocker_reasons: Counter[str],
) -> list[str]:
    gate = str(fail_closed_gate or "")
    review = str(review_class or "")
    evidence = {str(item) for item in review_evidence if str(item)}
    details = {str(item) for item in next_action_details if str(item)}
    hints = {str(item) for item in promotion_hints if str(item)}
    reasons = {str(reason) for reason, count in blocker_reasons.items() if _int_value(count, 0) > 0}
    notes: list[str] = []

    if offset_deref_survivors >= 24 or direct_base_deref_survivors >= 8 or field_access_pressure >= 24:
        notes.append("high_pressure_unresolved_residue")
    elif offset_deref_survivors >= 8 or direct_base_deref_survivors >= 2 or field_access_pressure >= 12:
        notes.append("medium_pressure_unresolved_residue")
    else:
        notes.append("low_pressure_unresolved_residue")
    if direct_base_deref_survivors > 0:
        notes.append("direct_base_zero_deref_residue")

    if body_rewrite_ready > 0 or gate == "validated_rewrite_residue_review":
        notes.append("validated_rewrite_left_secondary_residue")
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        notes.append("report_only_alias_not_canonical_rewrite")
    if "exact_private_layout_source_required" in _body_offset_primary_review_reasons(
        fail_closed_gate,
        review_evidence,
        next_action_details,
        promotion_hints,
    ):
        notes.append("exact_private_layout_source_missing")
    if "trusted_source_required" in evidence or "trusted_source_gate_is_blocking" in details:
        notes.append("trusted_source_identity_missing")
    if "source_stability_risk" in evidence or "source_stability_gate_is_blocking" in details:
        notes.append("source_stability_not_proven")
    if "type_width_or_alignment_conflict" in evidence or "type_evidence_gate_is_blocking" in details:
        notes.append("type_width_or_alignment_unresolved")
    if "threshold_gap" in evidence or "collect_access_and_offset_threshold_evidence" in details:
        notes.append("threshold_evidence_gap")
    if pointer_indexed_offset_deref_patterns > 0 or "pointer_indexed_metrics_present" in details:
        notes.append("indexed_layout_model_needed")
    if stable_base_source_count > 0:
        notes.append("stable_source_provenance_available")
    if generic_base_evidence_count > 0 or generic_base_trust_candidate_count > 0:
        notes.append("generic_base_identity_gap")
    if generic_parameter_survivors > 0 and review in {
        "parameter_offset_shape_review",
        "context_offset_shape_review",
        "temp_offset_shape_review",
        "hot_cluster_missing_identity",
        "pointer_indexed_residue",
        "generic_base_identity_review",
    }:
        notes.append("parameter_type_followup_candidate")
    if temp_provenance_blocked_count > 0:
        notes.append("temp_initializer_identity_blocked")
    if "do_not_promote_report_only_profile" in hints:
        notes.append("do_not_promote_report_only_profile")
    if any("base is a decompiler temporary" in reason for reason in reasons):
        notes.append("decompiler_temp_base_blocks_rewrite")
    if any("base name is generic" in reason for reason in reasons):
        notes.append("generic_base_name_blocks_rewrite")

    return list(dict.fromkeys(notes))


def _body_offset_residue_cause_tags(item: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    gate = str(item.get("fail_closed_gate", "") or "")
    review_class = str(item.get("review_class", "") or "")
    evidence = {
        str(value)
        for value in item.get("review_evidence", []) or []
        if str(value)
    }
    details = {
        str(value)
        for value in item.get("next_action_details", []) or []
        if str(value)
    }
    primary_reasons = {
        str(value)
        for value in item.get("primary_review_reasons", []) or []
        if str(value)
    }
    notes = {
        str(value)
        for value in item.get("residue_review_notes", []) or []
        if str(value)
    }
    blocker_families = _coerce_dict(item.get("blocker_families", {}))
    source_provenance = _coerce_dict(item.get("stable_source_provenance", {}))
    direct_base_classes = _coerce_dict(item.get("direct_base_deref_base_classes", {}))

    if gate == "report_only_private_layout" or "report_only_profile_kept_closed" in evidence:
        tags.append("report_only_private_layout")
    if (
        gate in {"exact_source_identity_required", "report_only_source_identity", "source_build_mismatch"}
        or "exact_private_layout_source_required" in primary_reasons
        or "trusted_source_required" in evidence
    ):
        tags.append("exact_source_identity_missing")
    if gate == "validated_rewrite_residue_review" or "validated_rewrite_residue" in notes:
        tags.append("validated_secondary_residue")
    if _int_value(item.get("nested_field_pointer_residue_count"), 0) > 0:
        tags.append("nested_field_pointer_residue")
        if gate == "validated_rewrite_residue_review":
            tags.append("validated_nested_field_residue")
    if gate == "source_stability_required" or "source_stability_gate_is_blocking" in details:
        tags.append("source_stability_unproven")
    if gate == "type_conflict_required" or "type_evidence_gate_is_blocking" in details:
        tags.append("type_conflict_unresolved")
    if _int_value(blocker_families.get("source_reassigned"), 0) > 0:
        tags.append("source_reassigned")
    if _int_value(blocker_families.get("source_address_taken"), 0) > 0:
        tags.append("source_address_taken")
    if _int_value(blocker_families.get("source_compound_assignment"), 0) > 0:
        tags.append("source_compound_assignment")
    if _int_value(blocker_families.get("type_wide_overlay"), 0) > 0:
        tags.append("wide_overlay_conflict")
    if _int_value(blocker_families.get("type_narrow_subfield"), 0) > 0:
        tags.append("narrow_subfield_conflict")
    if _int_value(blocker_families.get("type_unaligned"), 0) > 0:
        tags.append("unaligned_type_conflict")
    if _int_value(item.get("parameter_indexed_element_count"), 0) > 0:
        tags.append("parameter_indexed_layout")
    if "avoid_naive_parameter_alias_rewrite" in details:
        tags.append("typed_pointer_stride_alias_risk")
    if (
        "pointer_indexed_array_or_table_shape" in evidence
        or "pointer_indexed_metrics_present" in details
    ):
        tags.append("pointer_indexed_layout")
    if _int_value(source_provenance.get("parameter_direct_alias"), 0) > 0:
        tags.append("direct_parameter_alias_review")
    if _int_value(source_provenance.get("parameter_field_pointer_alias"), 0) > 0:
        tags.append("parameter_field_pointer_alias_review")
    if _int_value(source_provenance.get("named_call_result_alias"), 0) > 0:
        tags.append("named_call_result_alias_review")
    if _int_value(item.get("live_in_parameter_gap_count"), 0) > 0:
        tags.append("live_in_parameter_gap")
    if _int_value(item.get("source_bound_live_in_parameter_gap_count"), 0) > 0:
        tags.append("source_bound_live_in_parameter_gap")
    if _int_value(item.get("callee_arity_residue_count"), 0) > 0:
        tags.append("callee_arity_residue")
    if gate == "threshold_evidence_gap":
        tags.append("threshold_evidence_gap")
    if gate == "low_pressure_deferred":
        tags.append("low_pressure_deferred")
    if gate == "manual_review_required" or review_class == "unclassified_offset_residue":
        tags.append("manual_classification_required")
    if _int_value(item.get("direct_base_deref_survivors"), 0) > 0:
        tags.append("direct_base_zero_deref_residue")
    if _int_value(direct_base_classes.get("decompiler_temp"), 0) > 0:
        tags.append("direct_base_temp_root")
    if (
        _int_value(direct_base_classes.get("decompiler_argument"), 0) > 0
        or _int_value(direct_base_classes.get("renamed_argument"), 0) > 0
    ):
        tags.append("direct_base_parameter_root")
    if _int_value(direct_base_classes.get("direct_call_result"), 0) > 0:
        tags.append("direct_base_call_result_root")
    if _int_value(direct_base_classes.get("context_like"), 0) > 0:
        tags.append("direct_base_context_root")
    if _int_value(direct_base_classes.get("thread_process_like"), 0) > 0:
        tags.append("direct_base_thread_process_root")
    if _int_value(direct_base_classes.get("object_or_token_like"), 0) > 0:
        tags.append("direct_base_object_token_root")
    if _int_value(direct_base_classes.get("named_base"), 0) > 0:
        tags.append("direct_base_named_root")
    if _int_value(item.get("generic_parameter_survivors"), 0) > 0:
        tags.append("generic_parameter_survivor")
    return list(dict.fromkeys(tags))


def _body_offset_residue_review_focus(
    subsystem: str,
    fail_closed_gate: str,
    priority_factors: list[str],
) -> str:
    factor_text = "+".join(str(item) for item in priority_factors[:3] if str(item))
    base = "%s/%s" % (str(subsystem or "other"), str(fail_closed_gate or "review_only"))
    if factor_text:
        return "%s/%s" % (base, factor_text)
    return base


def _body_offset_rewrite_blocker_reasons(rewrite_blockers: list[dict[str, Any]]) -> list[str]:
    return [
        str(reason)
        for blocker in rewrite_blockers
        for reason in blocker.get("reasons", []) or []
        if str(reason)
    ]


def _body_offset_has_exact_reason(reasons: list[str], expected: str) -> bool:
    expected_text = str(expected or "").strip().lower()
    return any(str(reason or "").strip().lower() == expected_text for reason in reasons)


def _domain_identities_have_field_aliases(domain_identities: list[dict[str, Any]]) -> bool:
    for item in domain_identities:
        if _int_value(item.get("field_count"), 0) > 0:
            return True
        fields = item.get("fields", [])
        if isinstance(fields, list) and fields:
            return True
    return False


def _offset_deref_shape_profile(cleaned_path: Path | None) -> dict[str, Any]:
    if cleaned_path is None or not cleaned_path.exists():
        return {}
    text = _read_text(cleaned_path)
    body = _strip_pseudoforge_header(text) if text else ""
    items = _offset_deref_items(body)
    if not items:
        return {}
    base_accesses: Counter[str] = Counter(str(item["base"]) for item in items)
    base_offsets: dict[str, set[int]] = {}
    for item in items:
        base_offsets.setdefault(str(item["base"]), set()).add(int(item["offset"]))
    base_classes = Counter(_offset_deref_base_class(base) for base in base_accesses)
    max_base = ""
    max_access = 0
    max_offsets = 0
    for base, access_count in base_accesses.items():
        offset_count = len(base_offsets.get(base, set()))
        if (access_count, offset_count, base) > (max_access, max_offsets, max_base):
            max_base = base
            max_access = access_count
            max_offsets = offset_count
    dense_bases = [
        base
        for base, access_count in base_accesses.items()
        if access_count >= 12 and len(base_offsets.get(base, set())) >= 8
    ]
    low_pressure = max_access < 4 or max_offsets < 2
    shape_class = _offset_deref_shape_class(
        max_base,
        max_access,
        max_offsets,
        dense_bases,
        low_pressure,
    )
    return {
        "shape_class": shape_class,
        "base_classes": _counter_to_dict(base_classes),
        "top_bases": _counter_to_dict(Counter(dict(base_accesses.most_common(8)))),
        "max_base": max_base,
        "max_base_class": _offset_deref_base_class(max_base),
        "max_base_access_count": max_access,
        "max_base_offset_count": max_offsets,
        "dense_base_count": len(dense_bases),
        "dense_bases": dense_bases[:8],
        "low_pressure": low_pressure,
        "top_base_offsets": _offset_deref_top_base_offsets(base_offsets, base_accesses),
        "top_base_offset_samples": _offset_deref_top_base_offset_samples(items, base_accesses),
        "offset_deref_samples": _offset_deref_review_samples(items),
    }


def _nested_field_pointer_residue_profile(cleaned_path: Path | None) -> dict[str, Any]:
    if cleaned_path is None or not cleaned_path.exists():
        return {}
    text = _read_text(cleaned_path)
    body = _strip_pseudoforge_header(text) if text else ""
    parents: Counter[str] = Counter()
    fields: Counter[str] = Counter()
    parent_fields: Counter[str] = Counter()
    offsets: Counter[str] = Counter()
    samples: list[str] = []
    count = 0
    for match in NESTED_FIELD_POINTER_DEREF_RE.finditer(body):
        parent = str(match.group("parent") or "").strip()
        field = str(match.group("field") or "").strip()
        offset_value = _parse_pointer_indexed_integer(str(match.group("offset") or ""))
        if not parent or not field or offset_value is None or offset_value <= 0:
            continue
        parent_field = "%s->%s" % (parent, field)
        offset_text = "+0x%X" % offset_value
        parents[parent] += 1
        fields[field] += 1
        parent_fields[parent_field] += 1
        offsets[offset_text] += 1
        count += 1
        if len(samples) < 5:
            samples.append("%s+%s" % (parent_field, offset_text))
    if count <= 0:
        return {}
    return {
        "count": count,
        "parents": _counter_to_dict(Counter(dict(parents.most_common(8)))),
        "fields": _counter_to_dict(Counter(dict(fields.most_common(8)))),
        "parent_fields": _counter_to_dict(Counter(dict(parent_fields.most_common(8)))),
        "offsets": _counter_to_dict(Counter(dict(offsets.most_common(12)))),
        "samples": samples,
    }


def _direct_base_deref_profile(cleaned_path: Path | None) -> dict[str, Any]:
    if cleaned_path is None or not cleaned_path.exists():
        return {}
    text = _read_text(cleaned_path)
    body = _strip_pseudoforge_header(text) if text else ""
    bases: Counter[str] = Counter()
    types: Counter[str] = Counter()
    base_classes: Counter[str] = Counter()
    class_bases: dict[str, Counter[str]] = {}
    call_result_callees: Counter[str] = Counter()
    call_result_arg_roots: Counter[str] = Counter()
    call_result_member_paths: Counter[str] = Counter()
    call_result_deref_types: Counter[str] = Counter()
    call_result_layout_hints: Counter[str] = Counter()
    call_result_hint_modes: Counter[str] = Counter()
    call_result_samples: list[str] = []
    call_result_layout_samples: list[str] = []
    samples: list[str] = []
    count = 0
    for match in DIRECT_BASE_DEREF_ITEM_RE.finditer(body):
        base = str(match.group("base") or "").strip()
        type_name = _normalized_offset_deref_type(match.group("type"))
        if not base:
            continue
        base_class = "direct_call_result" if str(match.group("call") or "").strip() else _offset_deref_base_class(base)
        bases[base] += 1
        types[type_name] += 1
        base_classes[base_class] += 1
        class_bases.setdefault(base_class, Counter())[base] += 1
        count += 1
        if len(samples) < 5:
            samples.append("%s:%s:%s" % (base, type_name, base_class))
    for match in DIRECT_CALL_RESULT_DEREF_ITEM_RE.finditer(body):
        callee = str(match.group("callee") or "").strip()
        if not callee:
            continue
        args = _direct_call_result_args_text(match.group("args"))
        type_name = _normalized_offset_deref_type(match.group("type"))
        member_suffix = _direct_call_result_member_path_suffix(match.group("member_path"))
        anchor = _direct_call_result_anchor_text(callee, args, member_suffix)
        call_result_callees[callee] += 1
        for root in _direct_call_result_argument_roots(args):
            call_result_arg_roots[root] += 1
        if member_suffix:
            call_result_member_paths["%s()%s" % (callee, member_suffix)] += 1
        if anchor and type_name:
            call_result_deref_types["%s:%s" % (anchor, type_name)] += 1
        hint = _direct_call_result_layout_hint(callee)
        if hint:
            hint_key = _direct_call_result_layout_hint_key(callee, hint)
            if hint_key:
                call_result_layout_hints[hint_key] += 1
            mode = str(hint.get("mode", "") or "report-only").strip()
            if mode:
                call_result_hint_modes[mode] += 1
            member_hint = _direct_call_result_member_hint(hint, member_suffix)
            member_key = _direct_call_result_member_layout_hint_key(callee, member_suffix, member_hint)
            if member_key:
                call_result_layout_hints[member_key] += 1
            hint_sample = _direct_call_result_layout_hint_sample(
                callee,
                args,
                type_name,
                member_suffix,
                hint,
                member_hint,
            )
            if hint_sample and len(call_result_layout_samples) < 5 and hint_sample not in call_result_layout_samples:
                call_result_layout_samples.append(hint_sample)
        if len(call_result_samples) < 5 and anchor not in call_result_samples:
            call_result_samples.append(anchor)
    if count <= 0:
        return {}
    return {
        "count": count,
        "bases": _counter_to_dict(Counter(dict(bases.most_common(8)))),
        "types": _counter_to_dict(Counter(dict(types.most_common(8)))),
        "base_classes": _counter_to_dict(Counter(dict(base_classes.most_common(8)))),
        "class_bases": {
            str(base_class): _counter_to_dict(Counter(dict(counter.most_common(8))))
            for base_class, counter in sorted(class_bases.items())
        },
        "call_result_callees": _counter_to_dict(Counter(dict(call_result_callees.most_common(8)))),
        "call_result_arg_roots": _counter_to_dict(Counter(dict(call_result_arg_roots.most_common(8)))),
        "call_result_member_paths": _counter_to_dict(Counter(dict(call_result_member_paths.most_common(8)))),
        "call_result_deref_types": _counter_to_dict(Counter(dict(call_result_deref_types.most_common(8)))),
        "call_result_layout_hints": _counter_to_dict(Counter(dict(call_result_layout_hints.most_common(8)))),
        "call_result_hint_modes": _counter_to_dict(Counter(dict(call_result_hint_modes.most_common(8)))),
        "call_result_samples": call_result_samples,
        "call_result_layout_samples": call_result_layout_samples,
        "samples": samples,
    }


def _direct_call_result_args_text(args: str | None) -> str:
    return re.sub(r"\s+", " ", str(args or "").strip())


def _direct_call_result_argument_roots(args: str | None) -> list[str]:
    roots: list[str] = []
    for part in str(args or "").split(","):
        token = part.strip()
        match = re.match(r"&?\s*(?P<root>[A-Za-z_][A-Za-z0-9_]*)\b", token)
        if match:
            roots.append(match.group("root"))
    return roots[:6]


def _direct_call_result_layout_hints_by_callee() -> dict[str, dict[str, Any]]:
    return _direct_call_result_layout_hints_by_callee_for_root(profile_loader.active_profile_root())


@lru_cache(maxsize=4)
def _direct_call_result_layout_hints_by_callee_for_root(_profile_root: str) -> dict[str, dict[str, Any]]:
    payload = profile_loader.load_json_profile(DIRECT_CALL_RESULT_LAYOUT_HINTS_PROFILE_NAME)
    if not isinstance(payload, dict):
        return {}
    hints = payload.get("hints", [])
    if not isinstance(hints, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in hints:
        if not isinstance(item, dict):
            continue
        callee = str(item.get("callee", "") or "").strip()
        if not callee:
            continue
        result[callee] = item
    return result


def _direct_call_result_layout_hint(callee: str) -> dict[str, Any]:
    hint = _direct_call_result_layout_hints_by_callee().get(str(callee or "").strip(), {})
    return dict(hint) if isinstance(hint, dict) else {}


def _direct_call_result_layout_hint_key(callee: str, hint: dict[str, Any]) -> str:
    return_type = str(hint.get("return_type", "") or "").strip()
    if return_type:
        return "%s:%s" % (callee, return_type)
    role = str(hint.get("return_role", "") or "").strip()
    if role:
        return "%s:%s" % (callee, role)
    return str(callee or "").strip()


def _direct_call_result_member_path_suffix(value: str | None) -> str:
    parts = re.findall(r"->\s*([A-Za-z_][A-Za-z0-9_]*)", str(value or ""))
    if not parts:
        return ""
    return "".join("->%s" % part for part in parts)


def _direct_call_result_member_path_name(value: str | None) -> str:
    parts = re.findall(r"->\s*([A-Za-z_][A-Za-z0-9_]*)", str(value or ""))
    return "->".join(parts)


def _direct_call_result_anchor_text(callee: str, args: str, member_suffix: str = "") -> str:
    return "%s(%s)%s" % (callee, args, member_suffix)


def _direct_call_result_member_hint(hint: dict[str, Any], member_suffix: str) -> dict[str, Any]:
    member_name = _direct_call_result_member_path_name(member_suffix)
    if not member_name:
        return {}
    for item in hint.get("member_paths", []) or []:
        if not isinstance(item, dict):
            continue
        path = _direct_call_result_member_path_name(str(item.get("path", "") or ""))
        if not path:
            path = str(item.get("path", "") or "").strip().lstrip("->")
        if path == member_name:
            return dict(item)
    return {}


def _direct_call_result_member_layout_hint_key(
    callee: str,
    member_suffix: str,
    member_hint: dict[str, Any],
) -> str:
    if not member_hint:
        return ""
    member_type = str(member_hint.get("type", "") or "").strip()
    member_role = str(member_hint.get("role", "") or "").strip()
    suffix = member_suffix or ""
    if member_type:
        return "%s%s:%s" % (callee, suffix, member_type)
    if member_role:
        return "%s%s:%s" % (callee, suffix, member_role)
    return "%s%s" % (callee, suffix)


def _direct_call_result_layout_hint_sample(
    callee: str,
    args: str,
    deref_type: str,
    member_suffix: str,
    hint: dict[str, Any],
    member_hint: dict[str, Any],
) -> str:
    anchor = _direct_call_result_anchor_text(callee, args, member_suffix)
    parts: list[str] = []
    return_key = _direct_call_result_layout_hint_key(callee, hint)
    if return_key:
        parts.append(return_key)
    return_role = str(hint.get("return_role", "") or "").strip()
    if return_role:
        parts.append("role=%s" % return_role)
    member_key = _direct_call_result_member_layout_hint_key(callee, member_suffix, member_hint)
    if member_key:
        parts.append(member_key)
    mode = str(member_hint.get("mode", "") or hint.get("mode", "") or "report-only").strip()
    if mode:
        parts.append("mode=%s" % mode)
    if not parts:
        return ""
    return "%s:%s => %s" % (anchor, deref_type, ", ".join(parts))


def _parameter_field_pointer_source_anchor_profile(
    cleaned_path: Path | None,
    stable_base_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    source_names = {
        str(item.get("source", "") or "")
        for item in stable_base_sources
        if str(item.get("source_provenance", "") or "") == "parameter_field_pointer_alias"
        and str(item.get("source", "") or "")
    }
    if cleaned_path is None or not cleaned_path.exists() or not source_names:
        return {}
    text = _read_text(cleaned_path)
    body = _strip_pseudoforge_header(text) if text else ""
    sources: Counter[str] = Counter()
    targets: Counter[str] = Counter()
    offsets: Counter[str] = Counter()
    types: Counter[str] = Counter()
    samples: list[str] = []
    count = 0
    for match in PARAMETER_FIELD_POINTER_SOURCE_LOAD_RE.finditer(body):
        source = str(match.group("source") or "").strip()
        if source not in source_names:
            continue
        target = str(match.group("target") or "").strip()
        offset = _parse_pointer_indexed_integer(match.group("offset"))
        if not source or not target or offset is None:
            continue
        offset_text = "+0x%X" % offset
        type_name = _normalized_offset_deref_type(match.group("type"))
        sources[source] += 1
        targets[target] += 1
        offsets[offset_text] += 1
        types[type_name] += 1
        count += 1
        sample = "%s<-%s%s:%s" % (target, source, offset_text, type_name)
        if len(samples) < 5 and sample not in samples:
            samples.append(sample)
    if count <= 0:
        return {}
    return {
        "count": count,
        "sources": _counter_to_dict(Counter(dict(sources.most_common(8)))),
        "targets": _counter_to_dict(Counter(dict(targets.most_common(8)))),
        "offsets": _counter_to_dict(Counter(dict(offsets.most_common(8)))),
        "types": _counter_to_dict(Counter(dict(types.most_common(8)))),
        "samples": samples,
    }


def _offset_deref_items(text: str) -> list[dict[str, Any]]:
    items = []
    for match in OFFSET_DEREF_ITEM_RE.finditer(text or ""):
        offset = _parse_pointer_indexed_integer(match.group("offset"))
        if offset is None or offset <= 0:
            continue
        base = str(match.group("base") or "")
        if not base:
            continue
        type_name = _normalized_offset_deref_type(match.group("type"))
        items.append(
            {
                "base": base,
                "offset": offset,
                "type": type_name,
                "sample": _offset_deref_sample_text(
                    base,
                    offset,
                    type_name,
                    text or "",
                    match.start(),
                    match.end(),
                ),
            }
        )
    return items


def _offset_deref_sample_text(
    base: str,
    offset: int,
    type_name: str,
    text: str,
    start: int,
    end: int,
) -> str:
    line_start = str(text or "").rfind("\n", 0, max(start, 0)) + 1
    line_end = str(text or "").find("\n", max(end, 0))
    if line_end < 0:
        line_end = len(text or "")
    line = re.sub(r"\s+", " ", str(text or "")[line_start:line_end]).strip()
    if len(line) > 160:
        line = line[:157].rstrip() + "..."
    return "%s+0x%X:%s: %s" % (base, offset, type_name or "unknown", line)


def _offset_deref_review_samples(
    items: list[dict[str, Any]],
    limit: int = 8,
) -> list[str]:
    samples: list[str] = []
    for item in items:
        sample = str(item.get("sample", "") or "")
        if sample and sample not in samples:
            samples.append(sample)
        if len(samples) >= limit:
            break
    return samples


def _normalized_offset_deref_type(type_name: str) -> str:
    value = re.sub(r"\s+", " ", str(type_name or "").replace("struct ", " ")).strip()
    return value or "unknown"


def _offset_deref_base_class(base: str) -> str:
    value = str(base or "")
    if re.fullmatch(r"a\d+", value):
        return "decompiler_argument"
    if re.fullmatch(r"v\d+", value):
        return "decompiler_temp"
    if re.fullmatch(r"argument\d+", value):
        return "renamed_argument"
    lowered = value.lower()
    if lowered in {"context", "ctx"} or lowered.endswith("context"):
        return "context_like"
    if lowered in {"object", "referencedobject", "objectheader", "token"}:
        return "object_or_token_like"
    if lowered in {"hive", "keycontrolblock", "transactionlogentry"}:
        return "registry_like"
    if lowered in {"currentprocess", "currentthread"}:
        return "thread_process_like"
    if value:
        return "named_base"
    return "unknown"


def _offset_deref_shape_class(
    max_base: str,
    max_access: int,
    max_offsets: int,
    dense_bases: list[str],
    low_pressure: bool,
) -> str:
    if dense_bases:
        return "dense_offset_shape_missing_identity"
    if low_pressure:
        return "low_pressure_offset_residue"
    base_class = _offset_deref_base_class(max_base)
    if base_class in {"decompiler_argument", "renamed_argument"}:
        return "parameter_offset_shape_review"
    if base_class == "context_like":
        return "context_offset_shape_review"
    if base_class == "decompiler_temp":
        return "temp_offset_shape_review"
    if max_access >= 6 and max_offsets >= 3:
        return "context_offset_shape_review"
    return "unclassified_offset_residue"


def _offset_deref_top_base_offsets(
    base_offsets: dict[str, set[int]],
    base_accesses: Counter[str],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for base, _count in base_accesses.most_common(5):
        offsets = sorted(base_offsets.get(base, set()))
        result[base] = ["0x%X" % offset for offset in offsets[:12]]
    return result


def _offset_deref_top_base_offset_samples(
    items: list[dict[str, Any]],
    base_accesses: Counter[str],
    base_limit: int = 5,
    sample_limit: int = 3,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    ordered_bases = [str(base) for base, _count in base_accesses.most_common(base_limit)]
    for base in ordered_bases:
        samples: list[str] = []
        for item in items:
            if str(item.get("base", "") or "") != base:
                continue
            sample = str(item.get("sample", "") or "")
            if sample and sample not in samples:
                samples.append(sample)
            if len(samples) >= sample_limit:
                break
        if samples:
            result[base] = samples
    return result


def _body_offset_source_counter(
    items: list[dict[str, Any]],
    key: str,
) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        value = str(item.get(key, "") or "").strip()
        if value:
            counter[value] += 1
    return _counter_to_dict(counter)


def _body_offset_source_detail_counter(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        base = str(item.get("base", "") or "").strip()
        source = str(item.get("source", "") or "").strip()
        anchor = str(item.get("source_anchor", "") or "").strip()
        source_type = str(item.get("source_type", "") or "").strip()
        source_provenance = str(item.get("source_provenance", "") or "").strip()
        rhs_kind = str(item.get("source_rhs_kind", "") or "").strip()
        if not base:
            continue
        suffixes = []
        if anchor:
            parts = [base, "<-", anchor]
        elif source:
            parts = [base, "<-", source]
            if source_provenance and source_provenance not in {"none", "unknown"}:
                suffixes.append(source_provenance)
        else:
            continue
        if source and anchor and not anchor.startswith(source):
            parts.extend([" via ", source])
        detail = "".join(parts)
        if source_type:
            suffixes.append(source_type)
        if rhs_kind and rhs_kind not in {"none", "unknown"}:
            suffixes.append(rhs_kind)
        if suffixes:
            detail = "%s:%s" % (detail, ":".join(suffixes))
        counter[detail] += 1
    return _counter_to_dict(counter)


def _body_offset_parameter_indexed_counter(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        value = str(item.get(key, "") or "").strip()
        if value:
            counter[value] += 1
    return _counter_to_dict(counter)


def _body_offset_parameter_indexed_stride_counter(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        stride = _int_value(item.get("stride"), 0)
        if stride > 0:
            counter[str(stride)] += 1
    return _counter_to_dict(counter)


def _body_offset_parameter_indexed_offsets(items: list[dict[str, Any]]) -> list[str]:
    offsets: list[str] = []
    for item in items:
        for offset in item.get("offsets", []) or []:
            parsed = _int_value(offset, 0)
            text = "+0x%X" % parsed if parsed >= 0 else "-0x%X" % abs(parsed)
            if text not in offsets:
                offsets.append(text)
    return offsets[:8]


def _body_offset_stable_source_summary_parts(item: dict[str, Any], limit: int = 2) -> list[str]:
    sources = [
        str(source)
        for source in _coerce_dict(item.get("top_stable_sources", {})).keys()
        if str(source)
    ][:limit]
    provenance = [
        str(kind)
        for kind in _coerce_dict(item.get("stable_source_provenance", {})).keys()
        if str(kind)
    ][:limit]
    source_kinds = [
        str(kind)
        for kind in _coerce_dict(item.get("stable_source_kinds", {})).keys()
        if str(kind)
    ][:limit]
    parts: list[str] = []
    if sources:
        parts.append("source=%s" % ",".join(sources))
    if provenance:
        parts.append("via=%s" % ",".join(provenance))
    if source_kinds:
        parts.append("kind=%s" % ",".join(source_kinds))
    return parts


def _body_offset_blocker_family_counter(reasons: Counter[str]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for reason, count in reasons.items():
        lowered = str(reason or "").lower()
        weight = _int_value(count, 0)
        if weight <= 0:
            continue
        for family in _body_offset_blocker_reason_families(lowered):
            counter[family] += weight
    return _counter_to_dict(counter)


def _body_offset_blocker_reason_families(lowered_reason: str) -> list[str]:
    reason = str(lowered_reason or "")
    families: list[str] = []
    if "source domain identity profile is report-only" in reason:
        families.append("report_only_source_identity")
    elif "domain identity profile is report-only" in reason:
        families.append("report_only_profile")
    if "trusted rewrite source is required" in reason:
        families.append("trusted_source_required")
    if "base is reassigned" in reason or "reassigned after layout access" in reason:
        families.append("source_reassigned")
    if "base uses compound assignment" in reason:
        families.append("source_compound_assignment")
    if "base address is taken" in reason:
        families.append("source_address_taken")
    if "multiple initializers" in reason:
        families.append("source_multiple_initializers")
    if "base is a decompiler temporary" in reason:
        families.append("temp_base")
    if "base name is generic" in reason:
        families.append("generic_base")
    if "mix wide" in reason:
        families.append("type_wide_overlay")
    if "mix narrow" in reason:
        families.append("type_narrow_subfield")
    if "irregular field" in reason:
        families.append("type_irregular_width")
    if "not naturally aligned" in reason:
        families.append("type_unaligned")
    if "volatile-looking" in reason:
        families.append("type_volatile_like")
    if "mmio/register" in reason:
        families.append("type_mmio_register")
    if "rewrite offset threshold" in reason:
        families.append("threshold_offset")
    if "rewrite access threshold" in reason:
        families.append("threshold_access")
    if not families and reason:
        families.append("other_blocker")
    return families


def _body_offset_blocker_family_summary_parts(item: dict[str, Any], limit: int = 3) -> list[str]:
    return [
        "%s=%s" % (str(key), _int_value(value, 0))
        for key, value in _coerce_dict(item.get("blocker_families", {})).items()
        if str(key) and _int_value(value, 0) > 0
    ][:limit]


def _body_offset_residue_promotion_lane(item: dict[str, Any]) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    review_class = str(item.get("review_class", "") or "")
    next_action = str(item.get("next_action", "") or "")
    details = {
        str(detail)
        for detail in item.get("next_action_details", []) or []
        if str(detail)
    }
    hints = {
        str(hint)
        for hint in item.get("promotion_hints", []) or []
        if str(hint)
    }
    families = _coerce_dict(item.get("blocker_families", {}))
    provenance = _coerce_dict(item.get("stable_source_provenance", {}))

    if _int_value(item.get("parameter_indexed_element_count"), 0) > 0:
        return "model_parameter_indexed_layout"
    if _int_value(item.get("nested_field_pointer_residue_count"), 0) > 0:
        return "model_nested_field_pointer_layout"
    if _int_value(provenance.get("named_call_result_alias"), 0) > 0:
        return "verify_call_result_layout_identity"
    if gate == "validated_rewrite_residue_review":
        return "reread_validated_secondary_residue"
    if _int_value(provenance.get("parameter_field_pointer_alias"), 0) > 0:
        return "collect_exact_source_for_parameter_field_pointer_alias"
    if (
        _int_value(provenance.get("parameter_direct_alias"), 0) > 0
        or _int_value(provenance.get("direct_argument_alias"), 0) > 0
    ):
        return "collect_exact_source_for_direct_parameter_alias"
    if gate == "source_build_mismatch":
        return "collect_function_build_source_identity"
    if gate == "exact_source_identity_required":
        return "collect_function_build_source_identity"
    if (
        gate == "pointer_indexed_separate_model"
        or "model_pointer_indexed_entry_or_callback_table" in hints
        or "pointer_indexed_metrics_present" in details
    ):
        return "model_indexed_layout"
    if (
        gate == "report_only_source_identity"
        or _int_value(families.get("report_only_source_identity"), 0) > 0
        or "promote_source_identity_before_alias_rewrite" in details
    ):
        return "collect_exact_source_identity_for_report_only_alias"
    if gate == "report_only_private_layout" or _int_value(families.get("report_only_profile"), 0) > 0:
        return "collect_exact_private_layout_source"
    if (
        gate == "source_stability_required"
        or _int_value(families.get("source_reassigned"), 0) > 0
        or _int_value(families.get("source_address_taken"), 0) > 0
        or _int_value(families.get("source_compound_assignment"), 0) > 0
        or _int_value(families.get("source_multiple_initializers"), 0) > 0
    ):
        return "prove_source_stability"
    if (
        gate == "type_conflict_required"
        or _int_value(families.get("type_wide_overlay"), 0) > 0
        or _int_value(families.get("type_narrow_subfield"), 0) > 0
        or _int_value(families.get("type_irregular_width"), 0) > 0
        or _int_value(families.get("type_unaligned"), 0) > 0
        or _int_value(families.get("type_volatile_like"), 0) > 0
        or _int_value(families.get("type_mmio_register"), 0) > 0
    ):
        return "resolve_type_overlay_or_alignment"
    if gate == "temp_source_identity_required" or "trace_temp_initializer_before_promotion" in details:
        return "trace_temp_initializer_identity"
    if (
        review_class == "parameter_offset_shape_review"
        or next_action == "add_parameter_profile_or_keep_review_only"
    ):
        return "add_parameter_profile_or_type_evidence"
    if (
        review_class == "context_offset_shape_review"
        or next_action == "add_context_profile_or_keep_review_only"
    ):
        return "add_exact_context_profile"
    if gate == "low_pressure_deferred" or "defer_low_pressure_residue" in details:
        return "defer_low_pressure"
    return "manual_review"


def _body_offset_top_bases(
    layout_hints: list[dict[str, Any]],
    hot_field_clusters: list[dict[str, Any]],
    indexed_callback_tables: list[dict[str, Any]],
    rewrite_blockers: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    offset_shape_profile: dict[str, Any],
) -> list[str]:
    bases = Counter()
    for item in [*layout_hints, *hot_field_clusters, *indexed_callback_tables, *rewrite_blockers, *domain_identities]:
        base = str(item.get("base", "") or "")
        if base:
            bases[base] += 1
    for base, count in _coerce_dict(offset_shape_profile.get("top_bases", {})).items():
        if str(base):
            bases[str(base)] += _int_value(count, 0)
    return [base for base, _count in bases.most_common(8)]


def _body_offset_residue_review_queues(
    items: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    queue_names = [
        "named_goal_targets",
        "report_only_exact_promotion_candidates",
        "report_only_field_alias_review",
        "source_identity_required",
        "source_provenance_review",
        "parameter_field_pointer_alias_candidates",
        "validated_rewrite_residue",
        "nested_field_pointer_residue_candidates",
        "direct_call_result_layout_candidates",
        "direct_base_zero_deref_candidates",
        "source_bound_live_in_parameter_gap_candidates",
        "live_in_parameter_gap_candidates",
        "callee_arity_residue_candidates",
        "source_stability_required",
        "type_conflict_required",
        "pointer_indexed_layout_candidates",
        "dense_shape_identity_candidates",
        "parameter_profile_candidates",
        "context_profile_candidates",
        "temp_source_identity_candidates",
        "low_pressure_deferred",
        "manual_review_required",
    ]
    return {
        queue_name: _body_offset_residue_review_queue_summary(
            queue_name,
            [
                item
                for item in items
                if isinstance(item, dict)
                and _body_offset_residue_item_matches_queue(queue_name, item)
            ],
            limit,
        )
        for queue_name in queue_names
    }


def _body_offset_named_goal_target_status(
    items: list[dict[str, Any]],
    limit: int,
    analyzed_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    items_by_name = {str(item.get("name", "") or ""): item for item in items}
    analyzed_by_name = {
        str(item.get("name", "") or ""): item
        for item in analyzed_items or []
        if str(item.get("name", "") or "")
    }
    present_targets: list[dict[str, Any]] = []
    no_body_offset_residue_targets: list[dict[str, Any]] = []
    missing_targets: list[dict[str, Any]] = []
    groups: Counter[str] = Counter()
    corpus_groups: Counter[str] = Counter()
    fail_closed_gates: Counter[str] = Counter()
    promotion_lanes: Counter[str] = Counter()
    pressure_classes: Counter[str] = Counter()
    for name, group in _BODY_OFFSET_NAMED_GOAL_TARGETS.items():
        item = items_by_name.get(name)
        if item is None:
            analyzed_item = analyzed_by_name.get(name)
            if analyzed_item is not None:
                corpus_groups[group] += 1
                no_body_offset_residue_targets.append(
                    {
                        "name": name,
                        "ea": str(analyzed_item.get("ea", "") or ""),
                        "target_group": group,
                        "present": True,
                        "body_offset_residue_present": False,
                        "recommended_next": _body_offset_named_goal_target_no_residue_next(
                            group,
                        ),
                        "summary_path": str(analyzed_item.get("summary_path", "") or ""),
                        "cleaned_path": str(analyzed_item.get("cleaned_path", "") or ""),
                    }
                )
                continue
            missing_targets.append(
                {
                    "name": name,
                    "target_group": group,
                    "present": False,
                    "recommended_next": "Rerun or widen the corpus slice before judging this named target.",
                }
            )
            continue
        gate = str(item.get("fail_closed_gate", "") or "")
        lane = str(item.get("promotion_lane", "") or "")
        pressure = str(item.get("residue_pressure_class", "") or "")
        groups[group] += 1
        corpus_groups[group] += 1
        if gate:
            fail_closed_gates[gate] += 1
        if lane:
            promotion_lanes[lane] += 1
        if pressure:
            pressure_classes[pressure] += 1
        present_targets.append(
            {
                "name": name,
                "ea": str(item.get("ea", "") or ""),
                "target_group": group,
                "present": True,
                "body_offset_residue_present": True,
                "subsystem": str(item.get("subsystem", "") or ""),
                "priority_score": _int_value(item.get("priority_score"), 0),
                "fail_closed_gate": gate,
                "fail_closed_family": str(item.get("fail_closed_family", "") or ""),
                "promotion_lane": lane,
                "next_action": str(item.get("next_action", "") or ""),
                "residue_pressure_class": pressure,
                "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
                "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
                "direct_base_deref_bases": _coerce_dict(item.get("direct_base_deref_bases", {})),
                "direct_base_deref_types": _coerce_dict(item.get("direct_base_deref_types", {})),
                "direct_base_deref_base_classes": _coerce_dict(
                    item.get("direct_base_deref_base_classes", {})
                ),
                "direct_base_deref_class_bases": _coerce_dict(
                    item.get("direct_base_deref_class_bases", {})
                ),
                "direct_call_result_callees": _coerce_dict(item.get("direct_call_result_callees", {})),
                "direct_call_result_arg_roots": _coerce_dict(
                    item.get("direct_call_result_arg_roots", {})
                ),
                "direct_call_result_member_paths": _coerce_dict(
                    item.get("direct_call_result_member_paths", {})
                ),
                "direct_call_result_deref_types": _coerce_dict(
                    item.get("direct_call_result_deref_types", {})
                ),
                "direct_call_result_layout_hints": _coerce_dict(
                    item.get("direct_call_result_layout_hints", {})
                ),
                "direct_call_result_hint_modes": _coerce_dict(
                    item.get("direct_call_result_hint_modes", {})
                ),
                "direct_call_result_samples": [
                    str(sample)
                    for sample in item.get("direct_call_result_samples", []) or []
                    if str(sample)
                ],
                "direct_call_result_layout_samples": [
                    str(sample)
                    for sample in item.get("direct_call_result_layout_samples", []) or []
                    if str(sample)
                ],
                "offset_deref_samples": [
                    str(sample)
                    for sample in item.get("offset_deref_samples", []) or []
                    if str(sample)
                ],
                "top_base_offset_samples": {
                    str(base): [
                        str(sample)
                        for sample in samples or []
                        if str(sample)
                    ]
                    for base, samples in _coerce_dict(
                        item.get("top_base_offset_samples", {})
                    ).items()
                    if str(base)
                },
                "generic_parameter_survivors": _int_value(item.get("generic_parameter_survivors"), 0),
                "top_bases": [
                    str(base)
                    for base in item.get("top_bases", []) or []
                    if str(base)
                ][:8],
                "blocker_families": _coerce_dict(item.get("blocker_families", {})),
                "residue_cause_tags": [
                    str(tag)
                    for tag in item.get("residue_cause_tags", []) or []
                    if str(tag)
                ],
                "stable_source_provenance": _coerce_dict(item.get("stable_source_provenance", {})),
                "top_stable_sources": _coerce_dict(item.get("top_stable_sources", {})),
                "top_stable_source_details": _coerce_dict(item.get("top_stable_source_details", {})),
                "parameter_indexed_element_count": _int_value(item.get("parameter_indexed_element_count"), 0),
                "parameter_indexed_parents": _coerce_dict(item.get("parameter_indexed_parents", {})),
                "parameter_indexed_parent_types": _coerce_dict(item.get("parameter_indexed_parent_types", {})),
                "parameter_indexed_strides": _coerce_dict(item.get("parameter_indexed_strides", {})),
                "parameter_indexed_alias_rewrite_risks": _coerce_dict(
                    item.get("parameter_indexed_alias_rewrite_risks", {})
                ),
                "nested_field_pointer_residue_count": _int_value(
                    item.get("nested_field_pointer_residue_count"),
                    0,
                ),
                "nested_field_pointer_parent_fields": _coerce_dict(
                    item.get("nested_field_pointer_parent_fields", {})
                ),
                "nested_field_pointer_offsets": _coerce_dict(
                    item.get("nested_field_pointer_offsets", {})
                ),
                "recommended_next": _body_offset_named_goal_target_recommended_next(item),
                "summary_path": str(item.get("summary_path", "") or ""),
                "cleaned_path": str(item.get("cleaned_path", "") or ""),
            }
        )
    present_targets.sort(
        key=lambda item: (
            -_int_value(item.get("priority_score"), 0),
            str(item.get("target_group", "")),
            str(item.get("name", "")),
        )
    )
    no_body_offset_residue_targets.sort(
        key=lambda item: (
            str(item.get("target_group", "")),
            str(item.get("name", "")),
        )
    )
    return {
        "present_count": len(present_targets),
        "corpus_present_count": len(present_targets) + len(no_body_offset_residue_targets),
        "body_offset_residue_present_count": len(present_targets),
        "no_body_offset_residue_count": len(no_body_offset_residue_targets),
        "missing_count": len(missing_targets),
        "groups": _counter_to_dict(groups),
        "corpus_groups": _counter_to_dict(corpus_groups),
        "fail_closed_gates": _counter_to_dict(fail_closed_gates),
        "promotion_lanes": _counter_to_dict(promotion_lanes),
        "pressure_classes": _counter_to_dict(pressure_classes),
        "present_targets": present_targets[:limit],
        "no_body_offset_residue_targets": no_body_offset_residue_targets[:limit],
        "missing_targets": missing_targets,
    }


def _body_offset_named_goal_target_no_residue_next(group: str) -> str:
    if group == "object_callback_token":
        return (
            "Function is present but has no body-offset residue; review callback/list-entry "
            "semantics separately from canonical body-offset rewrite gates."
        )
    return (
        "Function is present but has no body-offset residue in this corpus; keep it out of "
        "body-offset rewrite queues unless new residue evidence appears."
    )


def _body_offset_named_goal_target_recommended_next(item: dict[str, Any]) -> str:
    lane = str(item.get("promotion_lane", "") or "")
    gate = str(item.get("fail_closed_gate", "") or "")
    direct_root_next = _body_offset_named_goal_target_direct_root_next_step(item)
    if gate == "report_only_private_layout":
        if direct_root_next:
            return direct_root_next
        if lane == "collect_exact_source_for_direct_parameter_alias":
            return "Keep report-only closed; collect exact function/build/source evidence for the direct parameter alias before any canonical body rewrite."
        if lane == "collect_exact_source_for_parameter_field_pointer_alias":
            return "Keep report-only closed; prove the parameter-field pointer source layout before promoting aliases."
        return "Keep report-only closed; collect exact private layout source evidence or leave aliases review-only."
    if lane == "model_parameter_indexed_layout":
        if _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})):
            return "Model the parameter-indexed element shape separately; typed pointer byte-stride evidence makes naive parameter alias rewrite unsafe."
        return "Model the parameter-indexed element shape separately; do not lower rewrite thresholds or rewrite array fields without exact layout identity."
    if lane == "model_nested_field_pointer_layout":
        return "Model the nested object reached through the rewritten parent field before any further body rewrite."
    if lane == "model_indexed_layout":
        return "Model indexed table or array access separately from canonical structure rewrite."
    if lane == "verify_call_result_layout_identity":
        return "Verify the call-result layout identity and returned object source before widening rewrite."
    if lane == "reread_validated_secondary_residue":
        return "Reread the validated canonical output and only chase same-object secondary residue."
    if lane == "prove_source_stability":
        return "Prove initializer dominance and no post-access reassignment before any rewrite."
    if lane == "resolve_type_overlay_or_alignment":
        return "Resolve mixed-width, overlay, or alignment conflicts before any rewrite."
    if lane == "collect_function_build_source_identity":
        return "Collect exact function/build/source identity before enabling correction or rewrite."
    if direct_root_next:
        return direct_root_next
    return "Review manually and keep fail-closed gates until exact evidence exists."


def _body_offset_named_goal_target_direct_root_next_step(item: dict[str, Any]) -> str:
    class_bases = _coerce_dict(item.get("direct_base_deref_class_bases", {}))
    if not class_bases:
        return ""

    def _root_names(root_class: str) -> str:
        roots = [
            str(root)
            for root in _coerce_dict(class_bases.get(root_class, {})).keys()
            if str(root)
        ][:3]
        return ", ".join(roots)

    direct_call_roots = _root_names("direct_call_result")
    if direct_call_roots:
        direct_call_anchors = _body_offset_direct_call_result_anchor_summary(item)
        roots = direct_call_anchors or direct_call_roots
        return (
            "Keep report-only closed; verify direct call-result root(s) %s "
            "returned layout/type identity before any field-zero or body rewrite."
            % roots
        )
    thread_process_roots = _root_names("thread_process_like")
    if thread_process_roots:
        return (
            "Keep report-only closed; prove private thread/process structure and build identity "
            "for %s before any field-zero or body rewrite."
            % thread_process_roots
        )
    object_token_roots = _root_names("object_or_token_like")
    if object_token_roots:
        return (
            "Keep report-only closed; prove object-header or token layout identity for %s "
            "before any field-zero or body rewrite."
            % object_token_roots
        )
    context_roots = _root_names("context_like")
    if context_roots:
        return (
            "Keep report-only closed; add an exact function-scoped context profile for %s "
            "before any field-zero or body rewrite."
            % context_roots
        )
    named_roots = _root_names("named_base")
    if named_roots:
        return (
            "Keep report-only closed; classify named direct-base root(s) %s and prove exact "
            "layout identity before any field-zero or body rewrite."
            % named_roots
        )
    parameter_roots = [
        root
        for root in [
            _root_names("renamed_argument"),
            _root_names("decompiler_argument"),
        ]
        if root
    ]
    if parameter_roots:
        return (
            "Keep report-only closed; validate parameter direct-base root(s) %s with exact "
            "function/build/source identity before any field-zero or body rewrite."
            % ", ".join(parameter_roots)
        )
    temp_roots = _root_names("decompiler_temp")
    if temp_roots:
        return (
            "Keep report-only closed; trace temp direct-base root(s) %s to a trusted source "
            "before any field-zero or body rewrite."
            % temp_roots
        )
    return ""


def _body_offset_direct_call_result_anchor_summary(
    item: dict[str, Any],
    limit: int = 3,
) -> str:
    samples = [
        str(sample)
        for sample in item.get("direct_call_result_samples", []) or []
        if str(sample)
    ][:limit]
    if samples:
        return ", ".join(samples)
    callees = _coerce_dict(item.get("direct_call_result_callees", {}))
    roots = [
        str(callee)
        for callee in callees.keys()
        if str(callee)
    ][:limit]
    return ", ".join(roots)


def _body_offset_direct_call_result_hint_summary(
    item: dict[str, Any],
    limit: int = 3,
) -> str:
    samples = [
        str(sample)
        for sample in item.get("direct_call_result_layout_samples", []) or []
        if str(sample)
    ][:limit]
    if samples:
        return ", ".join(samples)
    hints = _coerce_dict(item.get("direct_call_result_layout_hints", {}))
    return ", ".join(
        "%s=%s" % (key, value)
        for key, value in hints.items()
        if str(key)
    )


def _body_offset_direct_call_result_count(item: dict[str, Any]) -> int:
    class_count = _int_value(
        _coerce_dict(item.get("direct_base_deref_base_classes", {})).get("direct_call_result"),
        0,
    )
    if class_count > 0:
        return class_count
    return sum(
        _int_value(value, 0)
        for value in _coerce_dict(item.get("direct_call_result_callees", {})).values()
    )


def _body_offset_parameter_field_pointer_anchor_summary(
    item: dict[str, Any],
    limit: int = 3,
) -> str:
    samples = [
        str(sample)
        for sample in item.get("parameter_field_pointer_samples", []) or []
        if str(sample)
    ][:limit]
    if samples:
        return ", ".join(samples)
    sources = [
        str(source)
        for source in _coerce_dict(item.get("parameter_field_pointer_sources", {})).keys()
        if str(source)
    ][:limit]
    offsets = [
        str(offset)
        for offset in _coerce_dict(item.get("parameter_field_pointer_offsets", {})).keys()
        if str(offset)
    ][:limit]
    if sources and offsets:
        return "%s via %s" % (", ".join(sources), ",".join(offsets))
    if sources:
        return ", ".join(sources)
    return ""


def _body_offset_offset_deref_sample_summary(
    item: dict[str, Any],
    limit: int = 3,
) -> str:
    function_summary = _body_offset_offset_deref_sample_function_summary(item, limit)
    if function_summary:
        return function_summary
    samples = [
        str(sample)
        for sample in item.get("offset_deref_samples", []) or []
        if str(sample)
    ][:limit]
    if samples:
        return " | ".join(samples)
    base_samples = _coerce_dict(item.get("top_base_offset_samples", {}))
    result: list[str] = []
    for base, values in base_samples.items():
        value_samples = [
            str(sample)
            for sample in values or []
            if str(sample)
        ]
        if not value_samples:
            continue
        result.append("%s: %s" % (str(base), " | ".join(value_samples[:2])))
        if len(result) >= limit:
            break
    return " | ".join(result)


def _body_offset_offset_deref_sample_function_summary(
    item: dict[str, Any],
    limit: int,
) -> str:
    function_items = [
        function_item
        for function_item in item.get("offset_deref_sample_functions", []) or []
        if isinstance(function_item, dict)
    ]
    result: list[str] = []
    for function_item in function_items[:limit]:
        name = str(function_item.get("name", "") or "")
        samples = [
            str(sample)
            for sample in function_item.get("samples", []) or []
            if str(sample)
        ][:2]
        if not name or not samples:
            continue
        result.append("%s: %s" % (name, " | ".join(samples)))
    return " ; ".join(result)


def _body_offset_residue_next_goal_candidates(
    items: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    candidates = [
        _body_offset_residue_next_goal_candidate_item(item)
        for item in items
        if isinstance(item, dict) and _body_offset_residue_next_goal_candidate_kind(item)
    ]
    candidates.sort(
        key=lambda item: (
            -_int_value(item.get("actionability_score"), 0),
            -_int_value(item.get("priority_score"), 0),
            -_int_value(item.get("offset_deref_survivors"), 0),
            str(item.get("subsystem", "")),
            str(item.get("name", "")),
        )
    )
    selected = candidates[:limit]
    candidate_kinds = Counter(str(item.get("candidate_kind", "") or "") for item in selected)
    subsystems = Counter(str(item.get("subsystem", "") or "other") for item in selected)
    fail_closed_gates = Counter(str(item.get("fail_closed_gate", "") or "review_only") for item in selected)
    promotion_lanes = Counter(str(item.get("promotion_lane", "") or "") for item in selected)
    actionability_classes = Counter(
        str(item.get("actionability_class", "") or "manual_review")
        for item in selected
    )
    review_focuses = Counter(str(item.get("review_focus", "") or "") for item in selected)
    safety_policies = Counter(str(item.get("rewrite_safety_policy", "") or "") for item in selected)
    named_target_groups = Counter(
        str(item.get("named_goal_target_group", "") or "non_goal_target")
        for item in selected
        if bool(item.get("named_goal_target"))
    )
    residue_cause_tags: Counter[str] = Counter()
    for item in selected:
        for tag in item.get("residue_cause_tags", []) or []:
            if str(tag):
                residue_cause_tags[str(tag)] += 1
    review_batches = _body_offset_residue_next_goal_review_batches(selected, limit)
    return {
        "schema": "body_offset_next_goal_candidates_v1",
        "description": (
            "Highest-value body offset residue candidates grouped by subsystem, "
            "function identity, source stability, type conflict, and indexed-layout gates."
        ),
        "recommended_workflow": (
            "Attempt exact profile/source/type evidence first; keep report-only, "
            "ambiguous, unstable, and type-conflicted bodies fail-closed."
        ),
        "candidate_count": len(selected),
        "candidate_kinds": _counter_to_dict(Counter(dict(candidate_kinds.most_common(limit)))),
        "subsystems": _counter_to_dict(Counter(dict(subsystems.most_common(limit)))),
        "fail_closed_gates": _counter_to_dict(Counter(dict(fail_closed_gates.most_common(limit)))),
        "promotion_lanes": _counter_to_dict(Counter(dict(promotion_lanes.most_common(limit)))),
        "actionability_classes": _counter_to_dict(
            Counter(dict(actionability_classes.most_common(limit)))
        ),
        "named_goal_targets": sum(1 for item in selected if bool(item.get("named_goal_target"))),
        "named_target_groups": _counter_to_dict(
            Counter(dict(named_target_groups.most_common(limit)))
        ),
        "review_focuses": _counter_to_dict(Counter(dict(review_focuses.most_common(limit)))),
        "rewrite_safety_policies": _counter_to_dict(
            Counter(dict(safety_policies.most_common(limit)))
        ),
        "residue_cause_tags": _counter_to_dict(
            Counter(dict(residue_cause_tags.most_common(limit)))
        ),
        "review_batches": review_batches,
        "items": selected,
    }


def _body_offset_direct_base_root_review_batches(
    items: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        for root_class, count in _coerce_dict(item.get("direct_base_deref_base_classes", {})).items():
            if str(root_class) and _int_value(count, 0) > 0:
                grouped.setdefault(str(root_class), []).append(item)

    batches: list[dict[str, Any]] = []
    for root_class, group_items in grouped.items():
        group_items.sort(
            key=lambda item: (
                -_int_value(item.get("priority_score"), 0),
                -_int_value(item.get("direct_base_deref_survivors"), 0),
                str(item.get("name", "")),
            )
        )
        root_direct_count = sum(
            _int_value(
                _coerce_dict(item.get("direct_base_deref_base_classes", {})).get(root_class),
                0,
            )
            for item in group_items
        )
        root_bases: Counter[str] = Counter()
        subsystems: Counter[str] = Counter()
        fail_closed_gates: Counter[str] = Counter()
        promotion_lanes: Counter[str] = Counter()
        cause_tags: Counter[str] = Counter()
        call_result_callees: Counter[str] = Counter()
        call_result_arg_roots: Counter[str] = Counter()
        call_result_member_paths: Counter[str] = Counter()
        call_result_deref_types: Counter[str] = Counter()
        call_result_layout_hints: Counter[str] = Counter()
        call_result_hint_modes: Counter[str] = Counter()
        call_result_samples: list[str] = []
        call_result_layout_samples: list[str] = []
        for item in group_items:
            subsystems[str(item.get("subsystem", "") or "other")] += 1
            gate = str(item.get("fail_closed_gate", "") or "")
            if gate:
                fail_closed_gates[gate] += 1
            lane = str(item.get("promotion_lane", "") or "")
            if lane:
                promotion_lanes[lane] += 1
            for tag in item.get("residue_cause_tags", []) or []:
                if str(tag):
                    cause_tags[str(tag)] += 1
            class_bases = _coerce_dict(item.get("direct_base_deref_class_bases", {}))
            for base, count in _coerce_dict(class_bases.get(root_class, {})).items():
                root_bases[str(base)] += _int_value(count, 0)
            if root_class == "direct_call_result":
                for callee, count in _coerce_dict(item.get("direct_call_result_callees", {})).items():
                    call_result_callees[str(callee)] += _int_value(count, 0)
                for root, count in _coerce_dict(item.get("direct_call_result_arg_roots", {})).items():
                    call_result_arg_roots[str(root)] += _int_value(count, 0)
                for path, count in _coerce_dict(item.get("direct_call_result_member_paths", {})).items():
                    call_result_member_paths[str(path)] += _int_value(count, 0)
                for key, count in _coerce_dict(item.get("direct_call_result_deref_types", {})).items():
                    call_result_deref_types[str(key)] += _int_value(count, 0)
                for key, count in _coerce_dict(item.get("direct_call_result_layout_hints", {})).items():
                    call_result_layout_hints[str(key)] += _int_value(count, 0)
                for key, count in _coerce_dict(item.get("direct_call_result_hint_modes", {})).items():
                    call_result_hint_modes[str(key)] += _int_value(count, 0)
                for sample in item.get("direct_call_result_samples", []) or []:
                    sample_text = str(sample)
                    if sample_text and sample_text not in call_result_samples:
                        call_result_samples.append(sample_text)
                for sample in item.get("direct_call_result_layout_samples", []) or []:
                    sample_text = str(sample)
                    if sample_text and sample_text not in call_result_layout_samples:
                        call_result_layout_samples.append(sample_text)
        batches.append(
            {
                "root_class": root_class,
                "description": _body_offset_direct_base_root_description(root_class),
                "recommended_next_step": _body_offset_direct_base_root_next_step(root_class),
                "function_count": len(group_items),
                "direct_base_deref_survivors": root_direct_count,
                "offset_deref_survivors": sum(
                    _int_value(item.get("offset_deref_survivors"), 0)
                    for item in group_items
                ),
                "named_goal_targets": sum(1 for item in group_items if bool(item.get("named_goal_target"))),
                "subsystems": _counter_to_dict(Counter(dict(subsystems.most_common(limit)))),
                "fail_closed_gates": _counter_to_dict(Counter(dict(fail_closed_gates.most_common(limit)))),
                "promotion_lanes": _counter_to_dict(Counter(dict(promotion_lanes.most_common(limit)))),
                "direct_base_bases": _counter_to_dict(Counter(dict(root_bases.most_common(limit)))),
                "direct_call_result_callees": _counter_to_dict(
                    Counter(dict(call_result_callees.most_common(limit)))
                ),
                "direct_call_result_arg_roots": _counter_to_dict(
                    Counter(dict(call_result_arg_roots.most_common(limit)))
                ),
                "direct_call_result_member_paths": _counter_to_dict(
                    Counter(dict(call_result_member_paths.most_common(limit)))
                ),
                "direct_call_result_deref_types": _counter_to_dict(
                    Counter(dict(call_result_deref_types.most_common(limit)))
                ),
                "direct_call_result_layout_hints": _counter_to_dict(
                    Counter(dict(call_result_layout_hints.most_common(limit)))
                ),
                "direct_call_result_hint_modes": _counter_to_dict(
                    Counter(dict(call_result_hint_modes.most_common(limit)))
                ),
                "direct_call_result_samples": call_result_samples[:limit],
                "direct_call_result_layout_samples": call_result_layout_samples[:limit],
                "residue_cause_tags": _counter_to_dict(Counter(dict(cause_tags.most_common(limit)))),
                "top_functions": [
                    {
                        "name": str(item.get("name", "") or ""),
                        "ea": str(item.get("ea", "") or ""),
                        "priority_score": _int_value(item.get("priority_score"), 0),
                        "root_class_direct_base_derefs": _int_value(
                            _coerce_dict(item.get("direct_base_deref_base_classes", {})).get(root_class),
                            0,
                        ),
                        "direct_base_bases": _coerce_dict(
                            _coerce_dict(item.get("direct_base_deref_class_bases", {})).get(root_class, {})
                        ),
                        "direct_call_result_callees": _coerce_dict(item.get("direct_call_result_callees", {}))
                        if root_class == "direct_call_result"
                        else {},
                        "direct_call_result_arg_roots": _coerce_dict(
                            item.get("direct_call_result_arg_roots", {})
                        )
                        if root_class == "direct_call_result"
                        else {},
                        "direct_call_result_member_paths": _coerce_dict(
                            item.get("direct_call_result_member_paths", {})
                        )
                        if root_class == "direct_call_result"
                        else {},
                        "direct_call_result_deref_types": _coerce_dict(
                            item.get("direct_call_result_deref_types", {})
                        )
                        if root_class == "direct_call_result"
                        else {},
                        "direct_call_result_layout_hints": _coerce_dict(
                            item.get("direct_call_result_layout_hints", {})
                        )
                        if root_class == "direct_call_result"
                        else {},
                        "direct_call_result_samples": [
                            str(sample)
                            for sample in item.get("direct_call_result_samples", []) or []
                            if str(sample)
                        ]
                        if root_class == "direct_call_result"
                        else [],
                        "direct_call_result_layout_samples": [
                            str(sample)
                            for sample in item.get("direct_call_result_layout_samples", []) or []
                            if str(sample)
                        ]
                        if root_class == "direct_call_result"
                        else [],
                        "fail_closed_gate": str(item.get("fail_closed_gate", "") or ""),
                        "promotion_lane": str(item.get("promotion_lane", "") or ""),
                        "residue_cause_tags": [
                            str(tag)
                            for tag in item.get("residue_cause_tags", []) or []
                            if str(tag)
                        ],
                        "summary_path": str(item.get("summary_path", "") or ""),
                        "cleaned_path": str(item.get("cleaned_path", "") or ""),
                    }
                    for item in group_items[: min(5, limit)]
                ],
            }
        )
    batches.sort(
        key=lambda item: (
            -_int_value(item.get("direct_base_deref_survivors"), 0),
            -_int_value(item.get("function_count"), 0),
            str(item.get("root_class", "")),
        )
    )
    return {
        "schema": "body_offset_direct_base_root_review_batches_v1",
        "description": (
            "Direct base +0 residue grouped by root class so temp, parameter, "
            "call-result, context, and named roots can be reviewed separately."
        ),
        "batch_count": len(batches),
        "batches": batches[:limit],
    }


def _body_offset_direct_base_root_description(root_class: str) -> str:
    value = str(root_class or "")
    descriptions = {
        "decompiler_temp": "Decompiler temporary base; source identity and dominance are unproven.",
        "renamed_argument": "Renamed parameter base; parameter semantics must be exact before field-zero rendering.",
        "decompiler_argument": "Decompiler argument base; parameter semantics must be exact before field-zero rendering.",
        "direct_call_result": "Direct call-result base; returned object layout identity must be proven.",
        "named_base": "Named local/base; source identity still needs review.",
        "context_like": "Context-like base; function-scoped context profile is required.",
        "thread_process_like": "Thread/process-like base; private structure/build identity is required.",
        "object_or_token_like": "Object/token-like base; object header or token layout identity is required.",
    }
    return descriptions.get(value, "Direct-base root class needs exact source identity review.")


def _body_offset_direct_base_root_next_step(root_class: str) -> str:
    value = str(root_class or "")
    if value == "direct_call_result":
        return "Verify the callee return type and exact returned object layout before any field-zero rewrite."
    if value == "decompiler_temp":
        return "Trace the temp initializer and prove a single trusted source before any field-zero rewrite."
    if value in {"renamed_argument", "decompiler_argument"}:
        return "Validate parameter semantics and exact function/build/source identity before field-zero rewrite."
    if value == "context_like":
        return "Add an exact function-scoped context profile or keep +0 dereferences review-only."
    if value == "thread_process_like":
        return "Prove the thread/process private structure and build identity before field-zero rewrite."
    if value == "object_or_token_like":
        return "Prove object-header or token layout identity before field-zero rewrite."
    if value == "named_base":
        return "Classify the named base source and require exact layout identity before field-zero rewrite."
    return "Keep direct +0 dereference fail-closed until exact field-zero source identity is available."


def _body_offset_direct_base_root_summary(
    item: dict[str, Any],
    root_limit: int = 3,
    base_limit: int = 3,
) -> str:
    class_counts = _coerce_dict(item.get("direct_base_deref_base_classes", {}))
    class_bases = _coerce_dict(item.get("direct_base_deref_class_bases", {}))
    parts: list[str] = []
    ordered_classes = sorted(
        [str(root_class) for root_class in class_counts.keys() if str(root_class)],
        key=lambda root_class: (
            -_int_value(class_counts.get(root_class), 0),
            root_class,
        ),
    )
    for root_class in ordered_classes[:root_limit]:
        bases = _coerce_dict(class_bases.get(root_class, {}))
        if not bases:
            count = _int_value(class_counts.get(root_class), 0)
            if count > 0:
                parts.append("%s=%d" % (root_class, count))
            continue
        base_text = ",".join(
            "%s=%d" % (str(base), _int_value(count, 0))
            for base, count in list(bases.items())[:base_limit]
            if str(base) and _int_value(count, 0) > 0
        )
        if base_text:
            if root_class == "direct_call_result":
                anchor_text = _body_offset_direct_call_result_anchor_summary(
                    item,
                    limit=base_limit,
                )
                if anchor_text:
                    base_text = "%s calls=%s" % (base_text, anchor_text)
            parts.append("%s: %s" % (root_class, base_text))
    return "; ".join(parts)


def _body_offset_residue_next_goal_review_batches(
    items: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        subsystem = str(item.get("subsystem", "") or "other")
        kind = str(item.get("candidate_kind", "") or "manual_review")
        grouped.setdefault((subsystem, kind), []).append(item)

    batches: list[dict[str, Any]] = []
    for (subsystem, kind), group_items in grouped.items():
        group_items.sort(
            key=lambda item: (
                -_int_value(item.get("actionability_score"), 0),
                -_int_value(item.get("offset_deref_survivors"), 0),
                str(item.get("name", "")),
            )
        )
        top_item = group_items[0] if group_items else {}
        actionability_classes = Counter(
            str(item.get("actionability_class", "") or "manual_review")
            for item in group_items
        )
        source_identity_requirements = Counter(
            str(item.get("source_identity_requirement", "") or "")
            for item in group_items
            if str(item.get("source_identity_requirement", "") or "")
        )
        source_stability_requirements = Counter(
            str(item.get("source_stability_requirement", "") or "")
            for item in group_items
            if str(item.get("source_stability_requirement", "") or "")
        )
        type_conflict_requirements = Counter(
            str(item.get("type_conflict_requirement", "") or "")
            for item in group_items
            if str(item.get("type_conflict_requirement", "") or "")
        )
        stable_source_provenance: Counter[str] = Counter()
        function_identity_source_contexts: Counter[str] = Counter()
        source_bound_identity_sources: dict[str, str] = {}
        domain_profiles: Counter[str] = Counter()
        named_target_groups: Counter[str] = Counter()
        residue_cause_tags: Counter[str] = Counter()
        direct_base_deref_base_classes: Counter[str] = Counter()
        direct_base_deref_class_bases: dict[str, Counter[str]] = {}
        call_result_callees: Counter[str] = Counter()
        call_result_arg_roots: Counter[str] = Counter()
        call_result_member_paths: Counter[str] = Counter()
        call_result_deref_types: Counter[str] = Counter()
        call_result_layout_hints: Counter[str] = Counter()
        call_result_hint_modes: Counter[str] = Counter()
        call_result_samples: list[str] = []
        call_result_layout_samples: list[str] = []
        parameter_field_pointer_sources: Counter[str] = Counter()
        parameter_field_pointer_offsets: Counter[str] = Counter()
        parameter_field_pointer_samples: list[str] = []
        parameter_indexed_parents: Counter[str] = Counter()
        parameter_indexed_parent_types: Counter[str] = Counter()
        parameter_indexed_strides: Counter[str] = Counter()
        parameter_indexed_alias_rewrite_risks: Counter[str] = Counter()
        parameter_indexed_offsets: list[str] = []
        callee_arity_residue_callees: Counter[str] = Counter()
        callee_arity_residue_samples: list[str] = []
        offset_deref_samples: list[str] = []
        top_base_offset_samples: dict[str, list[str]] = {}
        for item in group_items:
            if bool(item.get("named_goal_target")):
                target_group = str(item.get("named_goal_target_group", "") or "non_goal_target")
                named_target_groups[target_group] += 1
            for key, value in _coerce_dict(item.get("stable_source_provenance", {})).items():
                stable_source_provenance[str(key)] += _int_value(value, 0)
            item_identity_sources = _coerce_dict(item.get("source_bound_identity_sources", {}))
            if item_identity_sources:
                source_context = _coerce_dict(item.get("function_identity_source_context", {}))
                source_key = str(source_context.get("source_key", "") or "").strip()
                if source_key:
                    function_identity_source_contexts[source_key] += 1
            for key, value in item_identity_sources.items():
                profile_id = str(key)
                profile_source = str(value)
                if profile_id and profile_source and profile_id not in source_bound_identity_sources:
                    source_bound_identity_sources[profile_id] = profile_source
            for key, value in _coerce_dict(item.get("domain_profiles", {})).items():
                domain_profiles[str(key)] += _int_value(value, 0)
            for tag in item.get("residue_cause_tags", []) or []:
                if str(tag):
                    residue_cause_tags[str(tag)] += 1
            for root_class, count in _coerce_dict(item.get("direct_base_deref_base_classes", {})).items():
                direct_base_deref_base_classes[str(root_class)] += _int_value(count, 0)
            for root_class, bases in _coerce_dict(item.get("direct_base_deref_class_bases", {})).items():
                if not isinstance(bases, dict):
                    continue
                class_counter = direct_base_deref_class_bases.setdefault(str(root_class), Counter())
                for base, count in _coerce_dict(bases).items():
                    class_counter[str(base)] += _int_value(count, 0)
            for callee, count in _coerce_dict(item.get("direct_call_result_callees", {})).items():
                call_result_callees[str(callee)] += _int_value(count, 0)
            for root, count in _coerce_dict(item.get("direct_call_result_arg_roots", {})).items():
                call_result_arg_roots[str(root)] += _int_value(count, 0)
            for key, count in _coerce_dict(item.get("direct_call_result_member_paths", {})).items():
                call_result_member_paths[str(key)] += _int_value(count, 0)
            for key, count in _coerce_dict(item.get("direct_call_result_deref_types", {})).items():
                call_result_deref_types[str(key)] += _int_value(count, 0)
            for key, count in _coerce_dict(item.get("direct_call_result_layout_hints", {})).items():
                call_result_layout_hints[str(key)] += _int_value(count, 0)
            for key, count in _coerce_dict(item.get("direct_call_result_hint_modes", {})).items():
                call_result_hint_modes[str(key)] += _int_value(count, 0)
            for sample in item.get("direct_call_result_samples", []) or []:
                sample_text = str(sample)
                if sample_text and sample_text not in call_result_samples:
                    call_result_samples.append(sample_text)
            for sample in item.get("direct_call_result_layout_samples", []) or []:
                sample_text = str(sample)
                if sample_text and sample_text not in call_result_layout_samples:
                    call_result_layout_samples.append(sample_text)
            for source, count in _coerce_dict(item.get("parameter_field_pointer_sources", {})).items():
                parameter_field_pointer_sources[str(source)] += _int_value(count, 0)
            for offset, count in _coerce_dict(item.get("parameter_field_pointer_offsets", {})).items():
                parameter_field_pointer_offsets[str(offset)] += _int_value(count, 0)
            for sample in item.get("parameter_field_pointer_samples", []) or []:
                sample_text = str(sample)
                if sample_text and sample_text not in parameter_field_pointer_samples:
                    parameter_field_pointer_samples.append(sample_text)
            for key, value in _coerce_dict(item.get("parameter_indexed_parents", {})).items():
                parameter_indexed_parents[str(key)] += _int_value(value, 0)
            for key, value in _coerce_dict(item.get("parameter_indexed_parent_types", {})).items():
                parameter_indexed_parent_types[str(key)] += _int_value(value, 0)
            for key, value in _coerce_dict(item.get("parameter_indexed_strides", {})).items():
                parameter_indexed_strides[str(key)] += _int_value(value, 0)
            for key, value in _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})).items():
                parameter_indexed_alias_rewrite_risks[str(key)] += _int_value(value, 0)
            for offset in item.get("parameter_indexed_offsets", []) or []:
                offset_text = str(offset)
                if offset_text and offset_text not in parameter_indexed_offsets:
                    parameter_indexed_offsets.append(offset_text)
            for callee, count in _coerce_dict(item.get("callee_arity_residue_callees", {})).items():
                callee_arity_residue_callees[str(callee)] += _int_value(count, 0)
            for sample in item.get("callee_arity_residue_samples", []) or []:
                sample_text = str(sample)
                if sample_text and sample_text not in callee_arity_residue_samples:
                    callee_arity_residue_samples.append(sample_text)
            for sample in item.get("offset_deref_samples", []) or []:
                sample_text = str(sample)
                if sample_text and sample_text not in offset_deref_samples:
                    offset_deref_samples.append(sample_text)
            for base, samples in _coerce_dict(item.get("top_base_offset_samples", {})).items():
                base_text = str(base)
                if not base_text:
                    continue
                bucket = top_base_offset_samples.setdefault(base_text, [])
                for sample in samples or []:
                    sample_text = str(sample)
                    if sample_text and sample_text not in bucket:
                        bucket.append(sample_text)
        batches.append(
            {
                "batch": "%s:%s" % (subsystem, kind),
                "subsystem": subsystem,
                "candidate_kind": kind,
                "actionability_classes": _counter_to_dict(
                    Counter(dict(actionability_classes.most_common(limit)))
                ),
                "function_count": len(group_items),
                "offset_deref_survivors": sum(
                    _int_value(item.get("offset_deref_survivors"), 0)
                    for item in group_items
                ),
                "direct_base_deref_survivors": sum(
                    _int_value(item.get("direct_base_deref_survivors"), 0)
                    for item in group_items
                ),
                "generic_parameter_survivors": sum(
                    _int_value(item.get("generic_parameter_survivors"), 0)
                    for item in group_items
                ),
                "nested_field_pointer_residue": sum(
                    _int_value(item.get("nested_field_pointer_residue_count"), 0)
                    for item in group_items
                ),
                "named_goal_targets": sum(1 for item in group_items if bool(item.get("named_goal_target"))),
                "named_target_groups": _counter_to_dict(
                    Counter(dict(named_target_groups.most_common(limit)))
                ),
                "max_actionability_score": max(
                    [_int_value(item.get("actionability_score"), 0) for item in group_items]
                    or [0]
                ),
                "fail_closed_gates": _counter_to_dict(
                    Counter(
                        dict(
                            Counter(
                                str(item.get("fail_closed_gate", "") or "review_only")
                                for item in group_items
                            ).most_common(limit)
                        )
                    )
                ),
                "promotion_lanes": _counter_to_dict(
                    Counter(
                        dict(
                            Counter(
                                str(item.get("promotion_lane", "") or "")
                                for item in group_items
                                if str(item.get("promotion_lane", "") or "")
                            ).most_common(limit)
                        )
                    )
                ),
                "rewrite_safety_policies": _counter_to_dict(
                    Counter(
                        dict(
                            Counter(
                                str(item.get("rewrite_safety_policy", "") or "review_only")
                                for item in group_items
                            ).most_common(limit)
                        )
                    )
                ),
                "source_identity_requirements": _counter_to_dict(
                    Counter(dict(source_identity_requirements.most_common(limit)))
                ),
                "source_stability_requirements": _counter_to_dict(
                    Counter(dict(source_stability_requirements.most_common(limit)))
                ),
                "type_conflict_requirements": _counter_to_dict(
                    Counter(dict(type_conflict_requirements.most_common(limit)))
                ),
                "stable_source_provenance": _counter_to_dict(
                    Counter(dict(stable_source_provenance.most_common(limit)))
                ),
                "function_identity_source_contexts": _counter_to_dict(
                    Counter(dict(function_identity_source_contexts.most_common(limit)))
                ),
                "source_bound_identity_sources": dict(
                    list(source_bound_identity_sources.items())[:limit]
                ),
                "domain_profiles": _counter_to_dict(Counter(dict(domain_profiles.most_common(limit)))),
                "direct_base_deref_base_classes": _counter_to_dict(
                    Counter(dict(direct_base_deref_base_classes.most_common(limit)))
                ),
                "direct_base_deref_class_bases": {
                    root_class: _counter_to_dict(Counter(dict(counter.most_common(limit))))
                    for root_class, counter in direct_base_deref_class_bases.items()
                },
                "direct_call_result_callees": _counter_to_dict(
                    Counter(dict(call_result_callees.most_common(limit)))
                ),
                "direct_call_result_arg_roots": _counter_to_dict(
                    Counter(dict(call_result_arg_roots.most_common(limit)))
                ),
                "direct_call_result_member_paths": _counter_to_dict(
                    Counter(dict(call_result_member_paths.most_common(limit)))
                ),
                "direct_call_result_deref_types": _counter_to_dict(
                    Counter(dict(call_result_deref_types.most_common(limit)))
                ),
                "direct_call_result_layout_hints": _counter_to_dict(
                    Counter(dict(call_result_layout_hints.most_common(limit)))
                ),
                "direct_call_result_hint_modes": _counter_to_dict(
                    Counter(dict(call_result_hint_modes.most_common(limit)))
                ),
                "direct_call_result_samples": call_result_samples[:limit],
                "direct_call_result_layout_samples": call_result_layout_samples[:limit],
                "parameter_field_pointer_sources": _counter_to_dict(
                    Counter(dict(parameter_field_pointer_sources.most_common(limit)))
                ),
                "parameter_field_pointer_offsets": _counter_to_dict(
                    Counter(dict(parameter_field_pointer_offsets.most_common(limit)))
                ),
                "parameter_field_pointer_samples": parameter_field_pointer_samples[:limit],
                "parameter_indexed_elements": sum(
                    _int_value(item.get("parameter_indexed_element_count"), 0)
                    for item in group_items
                ),
                "parameter_indexed_parents": _counter_to_dict(
                    Counter(dict(parameter_indexed_parents.most_common(limit)))
                ),
                "parameter_indexed_parent_types": _counter_to_dict(
                    Counter(dict(parameter_indexed_parent_types.most_common(limit)))
                ),
                "parameter_indexed_strides": _counter_to_dict(
                    Counter(dict(parameter_indexed_strides.most_common(limit)))
                ),
                "parameter_indexed_alias_rewrite_risks": _counter_to_dict(
                    Counter(dict(parameter_indexed_alias_rewrite_risks.most_common(limit)))
                ),
                "parameter_indexed_offsets": parameter_indexed_offsets[:limit],
                "callee_arity_residue_callees": _counter_to_dict(
                    Counter(dict(callee_arity_residue_callees.most_common(limit)))
                ),
                "callee_arity_residue_samples": callee_arity_residue_samples[:limit],
                "offset_deref_samples": offset_deref_samples[:limit],
                "offset_deref_sample_functions": _body_offset_sample_function_items(
                    group_items,
                    limit,
                ),
                "top_base_offset_samples": {
                    str(base): samples[:3]
                    for base, samples in list(top_base_offset_samples.items())[:limit]
                },
                "residue_cause_tags": _counter_to_dict(
                    Counter(dict(residue_cause_tags.most_common(limit)))
                ),
                "recommended_next_step": str(top_item.get("next_step", "") or ""),
                "top_functions": [
                    {
                        "name": str(item.get("name", "") or ""),
                        "ea": str(item.get("ea", "") or ""),
                        "actionability_score": _int_value(item.get("actionability_score"), 0),
                        "named_goal_target": bool(item.get("named_goal_target")),
                        "named_goal_target_group": str(
                            item.get("named_goal_target_group", "") or ""
                        ),
                        "fail_closed_gate": str(item.get("fail_closed_gate", "") or ""),
                        "promotion_lane": str(item.get("promotion_lane", "") or ""),
                        "source_identity_requirement": str(
                            item.get("source_identity_requirement", "") or ""
                        ),
                        "source_stability_requirement": str(
                            item.get("source_stability_requirement", "") or ""
                        ),
                        "type_conflict_requirement": str(
                            item.get("type_conflict_requirement", "") or ""
                        ),
                        "direct_call_result_samples": [
                            str(sample)
                            for sample in item.get("direct_call_result_samples", []) or []
                            if str(sample)
                        ],
                        "direct_call_result_layout_samples": [
                            str(sample)
                            for sample in item.get("direct_call_result_layout_samples", []) or []
                            if str(sample)
                        ],
                        "direct_base_root_summary": _body_offset_direct_base_root_summary(item),
                        "parameter_field_pointer_samples": [
                            str(sample)
                            for sample in item.get("parameter_field_pointer_samples", []) or []
                            if str(sample)
                        ],
                        "parameter_indexed_element_count": _int_value(
                            item.get("parameter_indexed_element_count"),
                            0,
                        ),
                        "parameter_indexed_parents": _coerce_dict(
                            item.get("parameter_indexed_parents", {})
                        ),
                        "parameter_indexed_parent_types": _coerce_dict(
                            item.get("parameter_indexed_parent_types", {})
                        ),
                        "parameter_indexed_strides": _coerce_dict(
                            item.get("parameter_indexed_strides", {})
                        ),
                        "parameter_indexed_alias_rewrite_risks": _coerce_dict(
                            item.get("parameter_indexed_alias_rewrite_risks", {})
                        ),
                        "parameter_indexed_offsets": [
                            str(offset)
                            for offset in item.get("parameter_indexed_offsets", []) or []
                            if str(offset)
                        ],
                        "callee_arity_residue_samples": [
                            str(sample)
                            for sample in item.get("callee_arity_residue_samples", []) or []
                            if str(sample)
                        ],
                        "offset_deref_samples": [
                            str(sample)
                            for sample in item.get("offset_deref_samples", []) or []
                            if str(sample)
                        ],
                        "top_base_offset_samples": {
                            str(base): [
                                str(sample)
                                for sample in samples or []
                                if str(sample)
                            ]
                            for base, samples in _coerce_dict(
                                item.get("top_base_offset_samples", {})
                            ).items()
                            if str(base)
                        },
                        "residue_cause_tags": [
                            str(tag)
                            for tag in item.get("residue_cause_tags", []) or []
                            if str(tag)
                        ],
                        "top_stable_source_details": _coerce_dict(
                            item.get("top_stable_source_details", {})
                        ),
                        "function_identity_source_context": _coerce_dict(
                            item.get("function_identity_source_context", {})
                        ),
                        "source_bound_identity_sources": _coerce_dict(
                            item.get("source_bound_identity_sources", {})
                        ),
                        "nested_field_pointer_residue_count": _int_value(
                            item.get("nested_field_pointer_residue_count"),
                            0,
                        ),
                    }
                    for item in group_items[: min(5, limit)]
                ],
            }
        )
    batches.sort(
        key=lambda item: (
            -_int_value(item.get("max_actionability_score"), 0),
            -_int_value(item.get("function_count"), 0),
            -_int_value(item.get("offset_deref_survivors"), 0),
            str(item.get("subsystem", "")),
            str(item.get("candidate_kind", "")),
        )
    )
    return batches[:limit]


def _body_offset_residue_next_goal_candidate_item(item: dict[str, Any]) -> dict[str, Any]:
    kind = _body_offset_residue_next_goal_candidate_kind(item)
    actionability = _body_offset_residue_next_goal_actionability_class(item, kind)
    next_step = _body_offset_residue_next_goal_candidate_next_step(item, kind)
    return {
        "name": str(item.get("name", "") or ""),
        "ea": str(item.get("ea", "") or ""),
        "subsystem": str(item.get("subsystem", "") or "other"),
        "candidate_kind": kind,
        "actionability_class": actionability,
        "actionability_score": _body_offset_residue_next_goal_actionability_score(item, kind),
        "priority_score": _int_value(item.get("priority_score"), 0),
        "fail_closed_gate": str(item.get("fail_closed_gate", "") or ""),
        "fail_closed_family": str(item.get("fail_closed_family", "") or ""),
        "promotion_lane": str(item.get("promotion_lane", "") or ""),
        "rewrite_safety_policy": str(item.get("rewrite_safety_policy", "") or ""),
        "evidence_maturity": str(item.get("evidence_maturity", "") or ""),
        "residue_pressure_class": str(item.get("residue_pressure_class", "") or ""),
        "named_goal_target": bool(item.get("named_goal_target")),
        "named_goal_target_group": str(item.get("named_goal_target_group", "") or ""),
        "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
        "direct_base_deref_bases": _coerce_dict(item.get("direct_base_deref_bases", {})),
        "direct_base_deref_types": _coerce_dict(item.get("direct_base_deref_types", {})),
        "direct_base_deref_base_classes": _coerce_dict(
            item.get("direct_base_deref_base_classes", {})
        ),
        "direct_base_deref_class_bases": _coerce_dict(item.get("direct_base_deref_class_bases", {})),
        "direct_base_root_summary": _body_offset_direct_base_root_summary(item),
        "direct_call_result_callees": _coerce_dict(item.get("direct_call_result_callees", {})),
        "direct_call_result_arg_roots": _coerce_dict(item.get("direct_call_result_arg_roots", {})),
        "direct_call_result_member_paths": _coerce_dict(item.get("direct_call_result_member_paths", {})),
        "direct_call_result_deref_types": _coerce_dict(item.get("direct_call_result_deref_types", {})),
        "direct_call_result_layout_hints": _coerce_dict(item.get("direct_call_result_layout_hints", {})),
        "direct_call_result_hint_modes": _coerce_dict(item.get("direct_call_result_hint_modes", {})),
        "direct_call_result_samples": [
            str(sample)
            for sample in item.get("direct_call_result_samples", []) or []
            if str(sample)
        ],
        "direct_call_result_layout_samples": [
            str(sample)
            for sample in item.get("direct_call_result_layout_samples", []) or []
            if str(sample)
        ],
        "existing_parameter_alias_count": _int_value(item.get("existing_parameter_alias_count"), 0),
        "existing_parameter_alias_actions": _coerce_dict(
            item.get("existing_parameter_alias_actions", {})
        ),
        "existing_parameter_alias_registers": _coerce_dict(
            item.get("existing_parameter_alias_registers", {})
        ),
        "existing_parameter_alias_callees": _coerce_dict(
            item.get("existing_parameter_alias_callees", {})
        ),
        "existing_parameter_alias_samples": [
            str(sample)
            for sample in item.get("existing_parameter_alias_samples", []) or []
            if str(sample)
        ],
        "live_in_parameter_gap_count": _int_value(item.get("live_in_parameter_gap_count"), 0),
        "source_bound_live_in_parameter_gap_count": _int_value(
            item.get("source_bound_live_in_parameter_gap_count"),
            0,
        ),
        "live_in_parameter_gap_actions": _coerce_dict(item.get("live_in_parameter_gap_actions", {})),
        "live_in_parameter_gap_registers": _coerce_dict(item.get("live_in_parameter_gap_registers", {})),
        "live_in_parameter_gap_callees": _coerce_dict(item.get("live_in_parameter_gap_callees", {})),
        "live_in_parameter_gap_abi_slots": _coerce_dict(item.get("live_in_parameter_gap_abi_slots", {})),
        "live_in_parameter_gap_missing_signature_slots": _coerce_dict(
            item.get("live_in_parameter_gap_missing_signature_slots", {})
        ),
        "live_in_parameter_gap_samples": [
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        ],
        "callee_arity_residue_count": _int_value(item.get("callee_arity_residue_count"), 0),
        "callee_arity_residue_actions": _coerce_dict(item.get("callee_arity_residue_actions", {})),
        "callee_arity_residue_registers": _coerce_dict(item.get("callee_arity_residue_registers", {})),
        "callee_arity_residue_callees": _coerce_dict(item.get("callee_arity_residue_callees", {})),
        "callee_arity_residue_evidence": _coerce_dict(item.get("callee_arity_residue_evidence", {})),
        "callee_arity_residue_samples": [
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        ],
        "parameter_field_pointer_source_anchor_count": _int_value(
            item.get("parameter_field_pointer_source_anchor_count"),
            0,
        ),
        "parameter_field_pointer_sources": _coerce_dict(item.get("parameter_field_pointer_sources", {})),
        "parameter_field_pointer_targets": _coerce_dict(item.get("parameter_field_pointer_targets", {})),
        "parameter_field_pointer_offsets": _coerce_dict(item.get("parameter_field_pointer_offsets", {})),
        "parameter_field_pointer_samples": [
            str(sample)
            for sample in item.get("parameter_field_pointer_samples", []) or []
            if str(sample)
        ],
        "parameter_indexed_element_count": _int_value(item.get("parameter_indexed_element_count"), 0),
        "parameter_indexed_parents": _coerce_dict(item.get("parameter_indexed_parents", {})),
        "parameter_indexed_parent_types": _coerce_dict(item.get("parameter_indexed_parent_types", {})),
        "parameter_indexed_strides": _coerce_dict(item.get("parameter_indexed_strides", {})),
        "parameter_indexed_alias_rewrite_risks": _coerce_dict(
            item.get("parameter_indexed_alias_rewrite_risks", {})
        ),
        "parameter_indexed_offsets": [
            str(offset)
            for offset in item.get("parameter_indexed_offsets", []) or []
            if str(offset)
        ],
        "offset_deref_samples": [
            str(sample)
            for sample in item.get("offset_deref_samples", []) or []
            if str(sample)
        ],
        "top_base_offset_samples": {
            str(base): [
                str(sample)
                for sample in samples or []
                if str(sample)
            ]
            for base, samples in _coerce_dict(item.get("top_base_offset_samples", {})).items()
            if str(base)
        },
        "generic_parameter_survivors": _int_value(item.get("generic_parameter_survivors"), 0),
        "nested_field_pointer_residue_count": _int_value(
            item.get("nested_field_pointer_residue_count"),
            0,
        ),
        "review_focus": str(item.get("review_focus", "") or ""),
        "review_summary": _body_offset_residue_review_summary(item),
        "next_step": next_step,
        "safety_note": _body_offset_residue_next_goal_safety_note(item, kind),
        "function_identity_source_context": _coerce_dict(
            item.get("function_identity_source_context", {})
        ),
        "source_bound_identity_sources": _coerce_dict(
            item.get("source_bound_identity_sources", {})
        ),
        "source_identity_requirement": _body_offset_residue_next_goal_source_identity_requirement(
            item,
            kind,
        ),
        "source_stability_requirement": _body_offset_residue_next_goal_source_stability_requirement(item),
        "type_conflict_requirement": _body_offset_residue_next_goal_type_conflict_requirement(item),
        "primary_review_reasons": [
            str(reason)
            for reason in item.get("primary_review_reasons", []) or []
            if str(reason)
        ],
        "residue_review_notes": [
            str(note)
            for note in item.get("residue_review_notes", []) or []
            if str(note)
        ],
        "residue_cause_tags": [
            str(tag)
            for tag in item.get("residue_cause_tags", []) or []
            if str(tag)
        ],
        "next_action_details": [
            str(detail)
            for detail in item.get("next_action_details", []) or []
            if str(detail)
        ],
        "top_bases": [
            str(base)
            for base in item.get("top_bases", []) or []
            if str(base)
        ][:8],
        "blocker_families": _coerce_dict(item.get("blocker_families", {})),
        "stable_source_provenance": _coerce_dict(item.get("stable_source_provenance", {})),
        "stable_source_kinds": _coerce_dict(item.get("stable_source_kinds", {})),
        "top_stable_sources": _coerce_dict(item.get("top_stable_sources", {})),
        "top_stable_source_details": _coerce_dict(item.get("top_stable_source_details", {})),
        "domain_profiles": _coerce_dict(item.get("domain_profiles", {})),
        "nested_field_pointer_parent_fields": _coerce_dict(
            item.get("nested_field_pointer_parent_fields", {})
        ),
        "nested_field_pointer_offsets": _coerce_dict(item.get("nested_field_pointer_offsets", {})),
        "summary_path": str(item.get("summary_path", "") or ""),
        "cleaned_path": str(item.get("cleaned_path", "") or ""),
    }


def _body_offset_residue_next_goal_candidate_kind(item: dict[str, Any]) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    lane = str(item.get("promotion_lane", "") or "")
    details = {str(value) for value in item.get("next_action_details", []) or [] if str(value)}
    factors = {str(value) for value in item.get("priority_factors", []) or [] if str(value)}
    if _body_offset_direct_call_result_count(item) > 0:
        return "direct_call_result_layout_identity"
    if _int_value(item.get("source_bound_live_in_parameter_gap_count"), 0) > 0:
        return "source_bound_live_in_parameter_gap_type_correction"
    if _int_value(item.get("live_in_parameter_gap_count"), 0) > 0:
        return "live_in_parameter_gap_type_correction"
    if _int_value(item.get("callee_arity_residue_count"), 0) > 0:
        return "callee_arity_contract_review"
    if gate in {"source_build_mismatch", "exact_source_identity_required", "report_only_source_identity"}:
        return "exact_function_build_source_identity"
    if gate == "report_only_private_layout":
        if "parameter_field_pointer_alias_requires_source_profile" in details:
            return "parameter_field_pointer_source_identity"
        if "direct_parameter_source_alias_available" in details:
            return "direct_parameter_source_identity"
        return "exact_private_layout_source"
    if gate == "source_stability_required":
        return "source_stability_proof"
    if gate == "type_conflict_required":
        return "type_conflict_resolution"
    if gate in {"pointer_indexed_separate_model", "parameter_indexed_separate_model"}:
        return "indexed_layout_model"
    if lane == "model_nested_field_pointer_layout":
        return "nested_field_pointer_layout_model"
    if gate == "validated_rewrite_residue_review":
        return "validated_secondary_residue_reread"
    if lane == "add_parameter_profile_or_type_evidence" or "parameter_type_followup" in factors:
        return "parameter_profile_or_type_correction"
    if lane == "add_exact_context_profile":
        return "exact_context_profile"
    if gate == "temp_source_identity_required":
        return "temp_source_identity_trace"
    if _int_value(item.get("direct_base_deref_survivors"), 0) > 0:
        return "direct_base_zero_deref_review"
    if gate in {"manual_review_required", "threshold_evidence_gap"}:
        return "manual_or_threshold_gap"
    if gate == "low_pressure_deferred" and bool(item.get("named_goal_target")):
        return "named_target_low_pressure_followup"
    return ""


def _body_offset_residue_next_goal_actionability_class(item: dict[str, Any], kind: str) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    if kind in {
        "direct_parameter_source_identity",
        "parameter_field_pointer_source_identity",
        "exact_function_build_source_identity",
        "parameter_profile_or_type_correction",
        "direct_call_result_layout_identity",
        "source_bound_live_in_parameter_gap_type_correction",
        "live_in_parameter_gap_type_correction",
    }:
        return "exact_evidence_attempt"
    if kind == "callee_arity_contract_review":
        return "callee_contract_review"
    if kind in {
        "source_stability_proof",
        "type_conflict_resolution",
        "indexed_layout_model",
        "nested_field_pointer_layout_model",
        "validated_secondary_residue_reread",
        "direct_base_zero_deref_review",
    }:
        return "model_or_reread_before_rewrite"
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        return "report_only_fail_closed"
    if gate == "temp_source_identity_required":
        return "source_trace_required"
    if gate == "low_pressure_deferred":
        return "deferred"
    return "manual_review"


def _body_offset_residue_next_goal_actionability_score(item: dict[str, Any], kind: str) -> int:
    score = _int_value(item.get("priority_score"), 0)
    score += 30 if bool(item.get("named_goal_target")) else 0
    score += 20 if kind in {
        "direct_parameter_source_identity",
        "parameter_field_pointer_source_identity",
        "exact_function_build_source_identity",
    } else 0
    score += 60 if kind in {
        "direct_parameter_source_identity",
        "parameter_field_pointer_source_identity",
    } else 0
    score += 40 if kind == "exact_function_build_source_identity" else 0
    score += 55 if kind == "direct_call_result_layout_identity" else 0
    score += 52 if kind == "source_bound_live_in_parameter_gap_type_correction" else 0
    score += 24 if kind == "callee_arity_contract_review" else 0
    score += 36 if kind == "live_in_parameter_gap_type_correction" else 0
    score += 14 if kind in {"type_conflict_resolution", "source_stability_proof"} else 0
    score += 10 if kind == "indexed_layout_model" else 0
    score += 18 if kind == "nested_field_pointer_layout_model" else 0
    score += 12 if kind == "direct_base_zero_deref_review" else 0
    score += 8 if kind == "parameter_profile_or_type_correction" else 0
    if str(item.get("fail_closed_gate", "") or "") == "low_pressure_deferred":
        score -= 25
    return score


def _body_offset_residue_next_goal_candidate_next_step(item: dict[str, Any], kind: str) -> str:
    if kind == "direct_parameter_source_identity":
        return (
            "Reread the direct parameter alias and add exact function/build/source "
            "identity only if the profile proves the private layout source."
        )
    if kind == "parameter_field_pointer_source_identity":
        anchors = _body_offset_parameter_field_pointer_anchor_summary(item)
        if anchors:
            return (
                "Trace parameter-field pointer anchor(s) %s, prove the containing object layout, "
                "and keep the temp/generic base closed without exact evidence."
                % anchors
            )
        return (
            "Trace the parameter-field pointer source, prove the containing object "
            "layout, and keep the temp/generic base closed without exact evidence."
        )
    if kind == "exact_function_build_source_identity":
        return "Resolve function/profile/build/source identity before any body rewrite or stronger type correction."
    if kind == "direct_call_result_layout_identity":
        anchors = _body_offset_direct_call_result_anchor_summary(item)
        hints = _body_offset_direct_call_result_hint_summary(item)
        if anchors and hints:
            return (
                "Verify report-only return/member layout hint(s) %s for %s, including call arguments and build/source provenance, before any field-zero rewrite."
                % (hints, anchors)
            )
        if anchors:
            return (
                "Verify returned layout/type identity for %s, including call arguments and build/source provenance, before any field-zero rewrite."
                % anchors
            )
        return "Verify returned layout/type identity for the direct call-result before any field-zero rewrite."
    if kind == "callee_arity_contract_review":
        samples = ", ".join(
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        )
        if samples:
            return (
                "Validate callee arity/helper residue %s against the callee contract before adding caller parameters or widening this function signature."
                % samples
            )
        return "Validate callee arity/helper residue against the callee contract before adding caller parameters or widening this function signature."
    if kind == "live_in_parameter_gap_type_correction":
        samples = ", ".join(
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        )
        if samples:
            return (
                "Validate live-in ABI parameter gap(s) %s against caller/callee argument use before adding an exact parameter type correction."
                % samples
            )
        return "Validate live-in ABI parameter gaps against caller/callee argument use before adding an exact parameter type correction."
    if kind == "source_bound_live_in_parameter_gap_type_correction":
        samples = ", ".join(
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        )
        if samples:
            return (
                "Validate source-bound live-in ABI parameter gap(s) %s against exact caller/callee identity before adding preview-only missing-parameter support."
                % samples
            )
        return "Validate source-bound live-in ABI parameter gaps against exact caller/callee identity before adding preview-only missing-parameter support."
    if kind == "exact_private_layout_source":
        return "Keep aliases report-only while collecting exact private field layout source evidence."
    if kind == "source_stability_proof":
        return "Prove single initializer dominance and no post-access reassignment before rewrite."
    if kind == "type_conflict_resolution":
        return "Resolve overlay, width, and alignment conflicts before promoting fields."
    if kind == "indexed_layout_model":
        anchors = _body_offset_parameter_indexed_anchor_summary(item)
        if anchors:
            return (
                "Model indexed element shape(s) %s separately from canonical structure rewrite."
                % anchors
            )
        return "Model the array/table element shape separately from canonical structure rewrite."
    if kind == "nested_field_pointer_layout_model":
        return "Model the nested field-pointer object separately and prove exact nested layout identity before rewrite."
    if kind == "validated_secondary_residue_reread":
        return "Reread validated output and chase only same-object secondary residue."
    if kind == "direct_base_zero_deref_review":
        return "Classify direct base +0 dereferences and require exact field-zero source identity before rewrite."
    if kind == "parameter_profile_or_type_correction":
        return "Add exact parameter semantic profile or type correction, not a generic field rewrite."
    if kind == "exact_context_profile":
        return "Add an exact function-scoped context profile or leave the context base review-only."
    if kind == "temp_source_identity_trace":
        return "Trace the temp initializer to a trusted source before any promotion."
    if kind == "manual_or_threshold_gap":
        return "Review manually and collect threshold evidence without lowering rewrite thresholds."
    return "Keep fail-closed until exact evidence is available."


def _body_offset_residue_next_goal_safety_note(item: dict[str, Any], kind: str) -> str:
    policy = str(item.get("rewrite_safety_policy", "") or "")
    gate = str(item.get("fail_closed_gate", "") or "")
    if kind == "source_bound_live_in_parameter_gap_type_correction":
        return "Source-bound live-in evidence is a missing-parameter lead only; keep body rewrite and IDB mutation closed until preview-safe signature support exists."
    if gate in {"report_only_private_layout", "report_only_source_identity"}:
        return "Report-only profile remains closed; canonical rewrite is forbidden without exact identity."
    if gate == "type_conflict_required":
        return "Type/overlay conflict blocks body rewrite."
    if gate == "source_stability_required":
        return "Unstable source blocks body rewrite."
    if gate in {"pointer_indexed_separate_model", "parameter_indexed_separate_model"}:
        anchors = _body_offset_parameter_indexed_anchor_summary(item)
        if anchors:
            return "Indexed layouts are not canonical field rewrites; %s stays a separate element model." % anchors
        return "Indexed layouts are not canonical field rewrites."
    if kind == "nested_field_pointer_layout_model":
        return "Nested field-pointer residue needs its own exact layout identity; parent rewrite evidence is not enough."
    if kind == "direct_base_zero_deref_review":
        return "Direct +0 dereference is not enough to render field_0; exact source identity is still required."
    if kind == "direct_call_result_layout_identity":
        return "Direct call-result +0 residue remains fail-closed until callee return type, source object, and build identity are exact."
    if kind == "callee_arity_contract_review":
        return "Callee arity residue is not caller-parameter proof; keep caller signature and body rewrite closed until the callee ABI is exact."
    if kind == "live_in_parameter_gap_type_correction":
        return "Live-in register evidence is a type-correction lead only; do not rewrite the body or mutate IDB without exact ABI proof."
    if kind == "parameter_profile_or_type_correction":
        return "Use canonical_type/display_type for output; accepted_types are input guards only."
    if policy:
        return "Policy: %s." % policy
    return "No canonical body rewrite without exact function/profile/source/build identity."


def _body_offset_residue_next_goal_source_identity_requirement(
    item: dict[str, Any],
    kind: str,
) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    provenance = _coerce_dict(item.get("stable_source_provenance", {}))
    source_details = _body_offset_stable_source_detail_summary(item)
    if kind == "direct_parameter_source_identity":
        if source_details:
            return "direct parameter alias source %s must match exact function/build/profile identity" % source_details
        return "direct parameter alias source must match exact function/build/profile identity"
    if kind == "parameter_field_pointer_source_identity":
        anchors = _body_offset_parameter_field_pointer_anchor_summary(item)
        if anchors:
            return "parameter-field pointer source anchors %s must match exact containing-object layout identity" % anchors
        if source_details:
            return "parameter-field pointer source %s must match exact containing-object layout identity" % source_details
        return "parameter-field pointer source must match exact containing-object layout identity"
    if kind == "direct_call_result_layout_identity":
        anchors = _body_offset_direct_call_result_anchor_summary(item)
        hints = _body_offset_direct_call_result_hint_summary(item)
        if anchors and hints:
            return "callee return/member layout identity required for %s; report-only hint(s) %s" % (anchors, hints)
        if anchors:
            return "callee return layout identity required for %s" % anchors
        return "callee return layout identity required for direct call-result residue"
    if kind == "callee_arity_contract_review":
        samples = ", ".join(
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        )
        if samples:
            return "callee arity residue evidence %s must match exact callee prototype and helper contract identity" % samples
        return "callee arity residue evidence must match exact callee prototype and helper contract identity"
    if kind == "live_in_parameter_gap_type_correction":
        samples = ", ".join(
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        )
        if samples:
            return "live-in ABI parameter gap evidence %s must match exact caller/callee ABI identity" % samples
        return "live-in ABI parameter gap evidence must match exact caller/callee ABI identity"
    if kind == "source_bound_live_in_parameter_gap_type_correction":
        samples = ", ".join(
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        )
        if samples:
            return "source-bound live-in ABI gap evidence %s must match exact source, caller, callee, and build identity" % samples
        return "source-bound live-in ABI gap evidence must match exact source, caller, callee, and build identity"
    if gate in {"source_build_mismatch", "exact_source_identity_required", "report_only_source_identity"}:
        return "exact function, build, profile, and source object identity required"
    if gate == "report_only_private_layout":
        if source_details:
            return "exact private layout source required for %s before canonical rewrite" % source_details
        return "exact private layout source required before canonical rewrite"
    if kind == "indexed_layout_model":
        anchors = _body_offset_parameter_indexed_anchor_summary(item)
        if anchors:
            return "indexed element identity required for %s; do not rewrite the parent parameter as a canonical field" % anchors
        return "indexed element identity required; do not rewrite the parent parameter as a canonical field"
    if kind == "nested_field_pointer_layout_model":
        return "exact nested object layout identity required before nested field rewrite"
    if kind == "direct_base_zero_deref_review":
        return "exact field-zero source identity required before direct-base rewrite"
    if provenance:
        if source_details:
            return "stable source provenance %s available; verify exact profile identity before promotion" % source_details
        return "stable source provenance available; verify exact profile identity before promotion"
    return ""


def _body_offset_stable_source_detail_summary(item: dict[str, Any], limit: int = 3) -> str:
    details = [
        str(detail)
        for detail in _coerce_dict(item.get("top_stable_source_details", {})).keys()
        if str(detail)
    ][:limit]
    return ", ".join(details)


def _body_offset_identity_context_summary(item: dict[str, Any], limit: int = 3) -> str:
    contexts = _coerce_dict(item.get("function_identity_source_contexts", {}))
    if contexts:
        return ", ".join(
            "%s=%s" % (key, value)
            for key, value in list(contexts.items())[:limit]
            if str(key)
        )
    if not _coerce_dict(item.get("source_bound_identity_sources", {})):
        return ""
    context = _coerce_dict(item.get("function_identity_source_context", {}))
    source_key = str(context.get("source_key", "") or "").strip()
    if source_key:
        return source_key
    image = str(context.get("profile_image", "") or "").strip()
    build = str(context.get("profile_build", "") or "").strip()
    arch = str(context.get("profile_arch", "") or "").strip()
    parts = [part for part in [image, build, arch] if part]
    if parts:
        return ":".join(parts)
    return str(context.get("source_file", "") or "").strip()


def _body_offset_identity_source_summary(item: dict[str, Any], limit: int = 2) -> str:
    sources = _coerce_dict(item.get("source_bound_identity_sources", {}))
    parts = []
    for profile_id, profile_source in list(sources.items())[:limit]:
        if str(profile_id) and str(profile_source):
            parts.append("%s: %s" % (profile_id, profile_source))
    return "; ".join(parts)


def _body_offset_named_target_summary(item: dict[str, Any], limit: int = 3) -> str:
    groups = _coerce_dict(item.get("named_target_groups", {}))
    if groups:
        group_text = ", ".join(
            "%s=%s" % (key, value)
            for key, value in list(groups.items())[:limit]
            if str(key)
        )
        count = _int_value(item.get("named_goal_targets"), 0)
        if count > 0 and group_text:
            return "%d: %s" % (count, group_text)
        return group_text
    if bool(item.get("named_goal_target")):
        group = str(item.get("named_goal_target_group", "") or "goal_target")
        return group
    return ""


def _body_offset_parameter_indexed_anchor_summary(
    item: dict[str, Any],
    limit: int = 3,
) -> str:
    indexed_count = max(
        _int_value(item.get("parameter_indexed_element_count"), 0),
        _int_value(item.get("parameter_indexed_elements"), 0),
    )
    if indexed_count <= 0:
        return ""
    parents = [
        str(parent)
        for parent in _coerce_dict(item.get("parameter_indexed_parents", {})).keys()
        if str(parent)
    ][:limit]
    parent_types = [
        str(parent_type)
        for parent_type in _coerce_dict(item.get("parameter_indexed_parent_types", {})).keys()
        if str(parent_type)
    ][:limit]
    strides = [
        str(stride)
        for stride in _coerce_dict(item.get("parameter_indexed_strides", {})).keys()
        if str(stride)
    ][:limit]
    offsets = [
        str(offset)
        for offset in item.get("parameter_indexed_offsets", []) or []
        if str(offset)
    ][:limit]
    risks = [
        str(risk)
        for risk in _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})).keys()
        if str(risk)
    ][:limit]
    parts: list[str] = []
    if parents and parent_types:
        paired = []
        for index, parent in enumerate(parents):
            parent_type = parent_types[index] if index < len(parent_types) else parent_types[0]
            paired.append("%s:%s" % (parent, parent_type))
        parts.append(",".join(paired))
    elif parents:
        parts.append(",".join(parents))
    elif parent_types:
        parts.append(",".join(parent_types))
    if strides:
        parts.append("stride=%s" % ",".join(strides))
    if offsets:
        parts.append("offsets=%s" % ",".join(offsets))
    if risks:
        parts.append("risk=%s" % ",".join(risks))
    return " ".join(parts)


def _body_offset_residue_next_goal_source_stability_requirement(item: dict[str, Any]) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    families = _coerce_dict(item.get("blocker_families", {}))
    if gate == "source_stability_required":
        return "prove initializer dominance and no post-access reassignment"
    if _int_value(families.get("source_reassigned"), 0) > 0:
        return "base reassignment must be proven harmless before rewrite"
    if _int_value(families.get("source_address_taken"), 0) > 0:
        return "address-taken source needs alias-stability proof"
    if _int_value(families.get("source_compound_assignment"), 0) > 0:
        return "compound assignment source needs stability proof"
    return ""


def _body_offset_residue_next_goal_type_conflict_requirement(item: dict[str, Any]) -> str:
    gate = str(item.get("fail_closed_gate", "") or "")
    families = _coerce_dict(item.get("blocker_families", {}))
    conflict_parts: list[str] = []
    for key, text in [
        ("type_wide_overlay", "wide overlay"),
        ("type_narrow_subfield", "narrow subfield"),
        ("type_unaligned", "unaligned typed offset"),
        ("type_irregular_width", "irregular width"),
    ]:
        if _int_value(families.get(key), 0) > 0:
            conflict_parts.append(text)
    if not conflict_parts and gate != "type_conflict_required":
        return ""
    if conflict_parts:
        return "resolve %s conflict before rewrite" % ", ".join(conflict_parts)
    return "resolve type width, overlay, or alignment conflict before rewrite"


def _body_offset_residue_item_matches_queue(queue_name: str, item: dict[str, Any]) -> bool:
    review_class = str(item.get("review_class", "") or "")
    next_action = str(item.get("next_action", "") or "")
    evidence = {str(value) for value in item.get("review_evidence", []) or [] if str(value)}
    details = {str(value) for value in item.get("next_action_details", []) or [] if str(value)}
    priority_factors = {str(value) for value in item.get("priority_factors", []) or [] if str(value)}
    fail_closed_gate = str(item.get("fail_closed_gate", "") or "")
    if queue_name == "named_goal_targets":
        return bool(item.get("named_goal_target"))
    if queue_name == "report_only_exact_promotion_candidates":
        return bool(
            evidence.intersection(
                {
                    "report_only_profile_kept_closed",
                    "report_only_source_identity",
                }
            )
        )
    if queue_name == "report_only_field_alias_review":
        return "report_only_field_alias_available" in priority_factors
    if queue_name == "source_identity_required":
        return (
            next_action == "add_exact_source_identity_or_keep_review_only"
            or "trusted_source_required" in evidence
            or "report_only_source_identity" in evidence
            or "trusted_source_gate_is_blocking" in details
            or "promote_source_identity_before_alias_rewrite" in details
        )
    if queue_name == "source_provenance_review":
        return (
            _int_value(item.get("stable_base_source_count"), 0) > 0
            or "stable_source_provenance_available_for_review" in details
        )
    if queue_name == "parameter_field_pointer_alias_candidates":
        return (
            _int_value(item.get("parameter_field_pointer_source_anchor_count"), 0) > 0
            or _int_value(
                _coerce_dict(item.get("stable_source_provenance", {})).get("parameter_field_pointer_alias"),
                0,
            )
            > 0
        )
    if queue_name == "validated_rewrite_residue":
        return (
            fail_closed_gate == "validated_rewrite_residue_review"
            or review_class == "rewrite_ready_residue"
        )
    if queue_name == "nested_field_pointer_residue_candidates":
        return _int_value(item.get("nested_field_pointer_residue_count"), 0) > 0
    if queue_name == "direct_call_result_layout_candidates":
        return _body_offset_direct_call_result_count(item) > 0
    if queue_name == "direct_base_zero_deref_candidates":
        return _int_value(item.get("direct_base_deref_survivors"), 0) > 0
    if queue_name == "source_bound_live_in_parameter_gap_candidates":
        return _int_value(item.get("source_bound_live_in_parameter_gap_count"), 0) > 0
    if queue_name == "live_in_parameter_gap_candidates":
        return _int_value(item.get("live_in_parameter_gap_count"), 0) > 0
    if queue_name == "callee_arity_residue_candidates":
        return _int_value(item.get("callee_arity_residue_count"), 0) > 0
    if queue_name == "source_stability_required":
        return (
            review_class == "source_stability_blocked_residue"
            or "source_stability_risk" in evidence
            or "source_stability_gate_is_blocking" in details
        )
    if queue_name == "type_conflict_required":
        return (
            review_class == "type_conflict_blocked_residue"
            or "type_width_or_alignment_conflict" in evidence
            or "type_evidence_gate_is_blocking" in details
        )
    if queue_name == "pointer_indexed_layout_candidates":
        return (
            next_action == "model_pointer_indexed_layout_or_callback_table"
            or "pointer_indexed_array_or_table_shape" in evidence
            or "pointer_indexed_metrics_present" in details
            or fail_closed_gate == "parameter_indexed_separate_model"
            or "parameter_indexed_element_shape" in evidence
            or "parameter_indexed_parent_stride_available" in details
        )
    if queue_name == "dense_shape_identity_candidates":
        return (
            review_class == "dense_offset_shape_missing_identity"
            or "add_dense_shape_identity_or_keep_review_only" in details
        )
    if queue_name == "parameter_profile_candidates":
        return (
            review_class == "parameter_offset_shape_review"
            or "validate_parameter_semantics_before_type_correction" in details
        )
    if queue_name == "context_profile_candidates":
        return (
            review_class == "context_offset_shape_review"
            or "add_exact_context_profile_or_keep_review_only" in details
        )
    if queue_name == "temp_source_identity_candidates":
        return (
            review_class == "temp_offset_shape_review"
            or "trace_temp_initializer_before_promotion" in details
        )
    if queue_name == "low_pressure_deferred":
        return (
            fail_closed_gate == "low_pressure_deferred"
            or (
                review_class == "low_pressure_offset_residue"
                and "parameter_indexed_element_shape" not in evidence
                and "pointer_indexed_array_or_table_shape" not in evidence
            )
        )
    if queue_name == "manual_review_required":
        return (
            fail_closed_gate in {"manual_review_required", "threshold_evidence_gap"}
            or review_class in {"unclassified_offset_residue", "identity_or_threshold_blocked_residue"}
        )
    return False


def _body_offset_residue_review_queue_summary(
    queue_name: str,
    items: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    subsystems = Counter(str(item.get("subsystem", "") or "other") for item in items)
    review_classes = Counter(str(item.get("review_class", "") or "manual_review") for item in items)
    next_actions = Counter(str(item.get("next_action", "") or "manual_review") for item in items)
    next_action_details: Counter[str] = Counter()
    priority_factors: Counter[str] = Counter()
    fail_closed_gates = Counter(str(item.get("fail_closed_gate", "") or "review_only") for item in items)
    fail_closed_families = Counter(str(item.get("fail_closed_family", "") or "review_only") for item in items)
    review_focuses = Counter(str(item.get("review_focus", "") or "review_only") for item in items)
    target_groups = Counter(
        str(item.get("named_goal_target_group", "") or "non_goal_target")
        for item in items
    )
    safety_policies = Counter(str(item.get("rewrite_safety_policy", "") or "review_only") for item in items)
    evidence_maturity = Counter(str(item.get("evidence_maturity", "") or "review_only") for item in items)
    pressure_classes = Counter(str(item.get("residue_pressure_class", "") or "unknown") for item in items)
    primary_review_reasons: Counter[str] = Counter()
    residue_review_notes: Counter[str] = Counter()
    residue_cause_tags: Counter[str] = Counter()
    blocker_reasons: Counter[str] = Counter()
    blocker_families: Counter[str] = Counter()
    promotion_lanes: Counter[str] = Counter()
    stable_source_provenance: Counter[str] = Counter()
    stable_source_kinds: Counter[str] = Counter()
    top_stable_sources: Counter[str] = Counter()
    top_stable_source_details: Counter[str] = Counter()
    function_identity_source_contexts: Counter[str] = Counter()
    source_bound_identity_sources: dict[str, str] = {}
    domain_profiles: Counter[str] = Counter()
    parameter_indexed_parents: Counter[str] = Counter()
    parameter_indexed_parent_types: Counter[str] = Counter()
    parameter_indexed_strides: Counter[str] = Counter()
    parameter_indexed_alias_rewrite_risks: Counter[str] = Counter()
    direct_base_deref_bases: Counter[str] = Counter()
    direct_base_deref_types: Counter[str] = Counter()
    direct_base_deref_base_classes: Counter[str] = Counter()
    direct_call_result_callees: Counter[str] = Counter()
    direct_call_result_arg_roots: Counter[str] = Counter()
    direct_call_result_member_paths: Counter[str] = Counter()
    direct_call_result_deref_types: Counter[str] = Counter()
    direct_call_result_layout_hints: Counter[str] = Counter()
    direct_call_result_hint_modes: Counter[str] = Counter()
    direct_call_result_samples: list[str] = []
    direct_call_result_layout_samples: list[str] = []
    offset_deref_samples: list[str] = []
    top_base_offset_samples: dict[str, list[str]] = {}
    existing_parameter_alias_actions: Counter[str] = Counter()
    existing_parameter_alias_registers: Counter[str] = Counter()
    existing_parameter_alias_callees: Counter[str] = Counter()
    existing_parameter_alias_samples: list[str] = []
    live_in_parameter_gap_actions: Counter[str] = Counter()
    live_in_parameter_gap_registers: Counter[str] = Counter()
    live_in_parameter_gap_callees: Counter[str] = Counter()
    live_in_parameter_gap_abi_slots: Counter[str] = Counter()
    live_in_parameter_gap_missing_signature_slots: Counter[str] = Counter()
    live_in_parameter_gap_samples: list[str] = []
    callee_arity_residue_actions: Counter[str] = Counter()
    callee_arity_residue_registers: Counter[str] = Counter()
    callee_arity_residue_callees: Counter[str] = Counter()
    callee_arity_residue_evidence: Counter[str] = Counter()
    callee_arity_residue_samples: list[str] = []
    parameter_field_pointer_sources: Counter[str] = Counter()
    parameter_field_pointer_targets: Counter[str] = Counter()
    parameter_field_pointer_offsets: Counter[str] = Counter()
    parameter_field_pointer_samples: list[str] = []
    for item in items:
        for detail in item.get("next_action_details", []) or []:
            if str(detail):
                next_action_details[str(detail)] += 1
        for factor in item.get("priority_factors", []) or []:
            if str(factor):
                priority_factors[str(factor)] += 1
        for reason in item.get("primary_review_reasons", []) or []:
            if str(reason):
                primary_review_reasons[str(reason)] += 1
        for note in item.get("residue_review_notes", []) or []:
            if str(note):
                residue_review_notes[str(note)] += 1
        for tag in item.get("residue_cause_tags", []) or []:
            if str(tag):
                residue_cause_tags[str(tag)] += 1
        for key, value in _coerce_dict(item.get("blocker_reasons", {})).items():
            blocker_reasons[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("blocker_families", {})).items():
            blocker_families[str(key)] += _int_value(value, 0)
        promotion_lane = str(item.get("promotion_lane", "") or "")
        if promotion_lane:
            promotion_lanes[promotion_lane] += 1
        for key, value in _coerce_dict(item.get("stable_source_provenance", {})).items():
            stable_source_provenance[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("stable_source_kinds", {})).items():
            stable_source_kinds[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("top_stable_sources", {})).items():
            top_stable_sources[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("top_stable_source_details", {})).items():
            top_stable_source_details[str(key)] += _int_value(value, 0)
        item_identity_sources = _coerce_dict(item.get("source_bound_identity_sources", {}))
        if item_identity_sources:
            source_context = _coerce_dict(item.get("function_identity_source_context", {}))
            source_key = str(source_context.get("source_key", "") or "").strip()
            if source_key:
                function_identity_source_contexts[source_key] += 1
        for key, value in item_identity_sources.items():
            profile_id = str(key)
            profile_source = str(value)
            if profile_id and profile_source and profile_id not in source_bound_identity_sources:
                source_bound_identity_sources[profile_id] = profile_source
        for key, value in _coerce_dict(item.get("domain_profiles", {})).items():
            domain_profiles[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_parents", {})).items():
            parameter_indexed_parents[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_parent_types", {})).items():
            parameter_indexed_parent_types[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_strides", {})).items():
            parameter_indexed_strides[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})).items():
            parameter_indexed_alias_rewrite_risks[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_base_deref_bases", {})).items():
            direct_base_deref_bases[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_base_deref_types", {})).items():
            direct_base_deref_types[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_base_deref_base_classes", {})).items():
            direct_base_deref_base_classes[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_callees", {})).items():
            direct_call_result_callees[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_arg_roots", {})).items():
            direct_call_result_arg_roots[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_member_paths", {})).items():
            direct_call_result_member_paths[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_deref_types", {})).items():
            direct_call_result_deref_types[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_layout_hints", {})).items():
            direct_call_result_layout_hints[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("direct_call_result_hint_modes", {})).items():
            direct_call_result_hint_modes[str(key)] += _int_value(value, 0)
        for sample in item.get("direct_call_result_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in direct_call_result_samples:
                direct_call_result_samples.append(sample_text)
        for sample in item.get("direct_call_result_layout_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in direct_call_result_layout_samples:
                direct_call_result_layout_samples.append(sample_text)
        for sample in item.get("offset_deref_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in offset_deref_samples:
                offset_deref_samples.append(sample_text)
        for base, samples in _coerce_dict(item.get("top_base_offset_samples", {})).items():
            base_text = str(base)
            if not base_text:
                continue
            bucket = top_base_offset_samples.setdefault(base_text, [])
            for sample in samples or []:
                sample_text = str(sample)
                if sample_text and sample_text not in bucket:
                    bucket.append(sample_text)
        for key, value in _coerce_dict(item.get("existing_parameter_alias_actions", {})).items():
            existing_parameter_alias_actions[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("existing_parameter_alias_registers", {})).items():
            existing_parameter_alias_registers[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("existing_parameter_alias_callees", {})).items():
            existing_parameter_alias_callees[str(key)] += _int_value(value, 0)
        for sample in item.get("existing_parameter_alias_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in existing_parameter_alias_samples:
                existing_parameter_alias_samples.append(sample_text)
        for key, value in _coerce_dict(item.get("live_in_parameter_gap_actions", {})).items():
            live_in_parameter_gap_actions[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("live_in_parameter_gap_registers", {})).items():
            live_in_parameter_gap_registers[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("live_in_parameter_gap_callees", {})).items():
            live_in_parameter_gap_callees[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("live_in_parameter_gap_abi_slots", {})).items():
            live_in_parameter_gap_abi_slots[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("live_in_parameter_gap_missing_signature_slots", {})).items():
            live_in_parameter_gap_missing_signature_slots[str(key)] += _int_value(value, 0)
        for sample in item.get("live_in_parameter_gap_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in live_in_parameter_gap_samples:
                live_in_parameter_gap_samples.append(sample_text)
        for key, value in _coerce_dict(item.get("callee_arity_residue_actions", {})).items():
            callee_arity_residue_actions[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("callee_arity_residue_registers", {})).items():
            callee_arity_residue_registers[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("callee_arity_residue_callees", {})).items():
            callee_arity_residue_callees[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("callee_arity_residue_evidence", {})).items():
            callee_arity_residue_evidence[str(key)] += _int_value(value, 0)
        for sample in item.get("callee_arity_residue_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in callee_arity_residue_samples:
                callee_arity_residue_samples.append(sample_text)
        for key, value in _coerce_dict(item.get("parameter_field_pointer_sources", {})).items():
            parameter_field_pointer_sources[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_field_pointer_targets", {})).items():
            parameter_field_pointer_targets[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_field_pointer_offsets", {})).items():
            parameter_field_pointer_offsets[str(key)] += _int_value(value, 0)
        for sample in item.get("parameter_field_pointer_samples", []) or []:
            sample_text = str(sample)
            if sample_text and sample_text not in parameter_field_pointer_samples:
                parameter_field_pointer_samples.append(sample_text)
    nested_field_pointer_parents: Counter[str] = Counter()
    nested_field_pointer_fields: Counter[str] = Counter()
    nested_field_pointer_parent_fields: Counter[str] = Counter()
    nested_field_pointer_offsets: Counter[str] = Counter()
    for item in items:
        for key, value in _coerce_dict(item.get("nested_field_pointer_parents", {})).items():
            nested_field_pointer_parents[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("nested_field_pointer_fields", {})).items():
            nested_field_pointer_fields[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("nested_field_pointer_parent_fields", {})).items():
            nested_field_pointer_parent_fields[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("nested_field_pointer_offsets", {})).items():
            nested_field_pointer_offsets[str(key)] += _int_value(value, 0)
    return {
        "queue": queue_name,
        "description": _BODY_OFFSET_QUEUE_DESCRIPTIONS.get(queue_name, "Manual body offset residue review queue."),
        "recommended_next_step": _BODY_OFFSET_QUEUE_RECOMMENDED_NEXT_STEPS.get(
            queue_name,
            "Read the cleaned body and preserve fail-closed gates until evidence is exact.",
        ),
        "functions": len(items),
        "offset_deref_survivors": sum(
            _int_value(item.get("offset_deref_survivors"), 0)
            for item in items
        ),
        "direct_base_deref_survivors": sum(
            _int_value(item.get("direct_base_deref_survivors"), 0)
            for item in items
        ),
        "direct_base_deref_bases": _counter_to_dict(
            Counter(dict(direct_base_deref_bases.most_common(limit)))
        ),
        "direct_base_deref_types": _counter_to_dict(
            Counter(dict(direct_base_deref_types.most_common(limit)))
        ),
        "direct_base_deref_base_classes": _counter_to_dict(
            Counter(dict(direct_base_deref_base_classes.most_common(limit)))
        ),
        "direct_call_result_callees": _counter_to_dict(
            Counter(dict(direct_call_result_callees.most_common(limit)))
        ),
        "direct_call_result_arg_roots": _counter_to_dict(
            Counter(dict(direct_call_result_arg_roots.most_common(limit)))
        ),
        "direct_call_result_member_paths": _counter_to_dict(
            Counter(dict(direct_call_result_member_paths.most_common(limit)))
        ),
        "direct_call_result_deref_types": _counter_to_dict(
            Counter(dict(direct_call_result_deref_types.most_common(limit)))
        ),
        "direct_call_result_layout_hints": _counter_to_dict(
            Counter(dict(direct_call_result_layout_hints.most_common(limit)))
        ),
        "direct_call_result_hint_modes": _counter_to_dict(
            Counter(dict(direct_call_result_hint_modes.most_common(limit)))
        ),
        "direct_call_result_samples": direct_call_result_samples[:limit],
        "direct_call_result_layout_samples": direct_call_result_layout_samples[:limit],
        "offset_deref_samples": offset_deref_samples[:limit],
        "offset_deref_sample_functions": _body_offset_sample_function_items(
            items,
            limit,
        ),
        "top_base_offset_samples": {
            str(base): samples[:3]
            for base, samples in list(top_base_offset_samples.items())[:limit]
        },
        "existing_parameter_alias_count": sum(
            _int_value(item.get("existing_parameter_alias_count"), 0)
            for item in items
        ),
        "existing_parameter_alias_actions": _counter_to_dict(
            Counter(dict(existing_parameter_alias_actions.most_common(limit)))
        ),
        "existing_parameter_alias_registers": _counter_to_dict(
            Counter(dict(existing_parameter_alias_registers.most_common(limit)))
        ),
        "existing_parameter_alias_callees": _counter_to_dict(
            Counter(dict(existing_parameter_alias_callees.most_common(limit)))
        ),
        "existing_parameter_alias_samples": existing_parameter_alias_samples[:limit],
        "live_in_parameter_gap_count": sum(
            _int_value(item.get("live_in_parameter_gap_count"), 0)
            for item in items
        ),
        "source_bound_live_in_parameter_gap_count": sum(
            _int_value(item.get("source_bound_live_in_parameter_gap_count"), 0)
            for item in items
        ),
        "live_in_parameter_gap_actions": _counter_to_dict(
            Counter(dict(live_in_parameter_gap_actions.most_common(limit)))
        ),
        "live_in_parameter_gap_registers": _counter_to_dict(
            Counter(dict(live_in_parameter_gap_registers.most_common(limit)))
        ),
        "live_in_parameter_gap_callees": _counter_to_dict(
            Counter(dict(live_in_parameter_gap_callees.most_common(limit)))
        ),
        "live_in_parameter_gap_abi_slots": _counter_to_dict(
            Counter(dict(live_in_parameter_gap_abi_slots.most_common(limit)))
        ),
        "live_in_parameter_gap_missing_signature_slots": _counter_to_dict(
            Counter(dict(live_in_parameter_gap_missing_signature_slots.most_common(limit)))
        ),
        "live_in_parameter_gap_samples": live_in_parameter_gap_samples[:limit],
        "callee_arity_residue_count": sum(
            _int_value(item.get("callee_arity_residue_count"), 0)
            for item in items
        ),
        "callee_arity_residue_actions": _counter_to_dict(
            Counter(dict(callee_arity_residue_actions.most_common(limit)))
        ),
        "callee_arity_residue_registers": _counter_to_dict(
            Counter(dict(callee_arity_residue_registers.most_common(limit)))
        ),
        "callee_arity_residue_callees": _counter_to_dict(
            Counter(dict(callee_arity_residue_callees.most_common(limit)))
        ),
        "callee_arity_residue_evidence": _counter_to_dict(
            Counter(dict(callee_arity_residue_evidence.most_common(limit)))
        ),
        "callee_arity_residue_samples": callee_arity_residue_samples[:limit],
        "parameter_field_pointer_source_anchors": sum(
            _int_value(item.get("parameter_field_pointer_source_anchor_count"), 0)
            for item in items
        ),
        "parameter_field_pointer_sources": _counter_to_dict(
            Counter(dict(parameter_field_pointer_sources.most_common(limit)))
        ),
        "parameter_field_pointer_targets": _counter_to_dict(
            Counter(dict(parameter_field_pointer_targets.most_common(limit)))
        ),
        "parameter_field_pointer_offsets": _counter_to_dict(
            Counter(dict(parameter_field_pointer_offsets.most_common(limit)))
        ),
        "parameter_field_pointer_samples": parameter_field_pointer_samples[:limit],
        "generic_parameter_survivors": sum(
            _int_value(item.get("generic_parameter_survivors"), 0)
            for item in items
        ),
        "parameter_indexed_elements": sum(
            _int_value(item.get("parameter_indexed_element_count"), 0)
            for item in items
        ),
        "nested_field_pointer_residue": sum(
            _int_value(item.get("nested_field_pointer_residue_count"), 0)
            for item in items
        ),
        "subsystems": _counter_to_dict(Counter(dict(subsystems.most_common(limit)))),
        "review_classes": _counter_to_dict(Counter(dict(review_classes.most_common(limit)))),
        "next_actions": _counter_to_dict(Counter(dict(next_actions.most_common(limit)))),
        "next_action_details": _counter_to_dict(Counter(dict(next_action_details.most_common(limit)))),
        "priority_factors": _counter_to_dict(Counter(dict(priority_factors.most_common(limit)))),
        "fail_closed_gates": _counter_to_dict(Counter(dict(fail_closed_gates.most_common(limit)))),
        "fail_closed_families": _counter_to_dict(Counter(dict(fail_closed_families.most_common(limit)))),
        "review_focuses": _counter_to_dict(Counter(dict(review_focuses.most_common(limit)))),
        "target_groups": _counter_to_dict(Counter(dict(target_groups.most_common(limit)))),
        "rewrite_safety_policies": _counter_to_dict(Counter(dict(safety_policies.most_common(limit)))),
        "evidence_maturity": _counter_to_dict(Counter(dict(evidence_maturity.most_common(limit)))),
        "residue_pressure_classes": _counter_to_dict(Counter(dict(pressure_classes.most_common(limit)))),
        "primary_review_reasons": _counter_to_dict(
            Counter(dict(primary_review_reasons.most_common(limit)))
        ),
        "residue_review_notes": _counter_to_dict(
            Counter(dict(residue_review_notes.most_common(limit)))
        ),
        "residue_cause_tags": _counter_to_dict(
            Counter(dict(residue_cause_tags.most_common(limit)))
        ),
        "blocker_reasons": _counter_to_dict(Counter(dict(blocker_reasons.most_common(limit)))),
        "blocker_families": _counter_to_dict(Counter(dict(blocker_families.most_common(limit)))),
        "promotion_lanes": _counter_to_dict(Counter(dict(promotion_lanes.most_common(limit)))),
        "stable_source_provenance": _counter_to_dict(
            Counter(dict(stable_source_provenance.most_common(limit)))
        ),
        "stable_source_kinds": _counter_to_dict(Counter(dict(stable_source_kinds.most_common(limit)))),
        "top_stable_sources": _counter_to_dict(Counter(dict(top_stable_sources.most_common(limit)))),
        "top_stable_source_details": _counter_to_dict(
            Counter(dict(top_stable_source_details.most_common(limit)))
        ),
        "function_identity_source_contexts": _counter_to_dict(
            Counter(dict(function_identity_source_contexts.most_common(limit)))
        ),
        "source_bound_identity_sources": dict(list(source_bound_identity_sources.items())[:limit]),
        "domain_profiles": _counter_to_dict(Counter(dict(domain_profiles.most_common(limit)))),
        "parameter_indexed_parents": _counter_to_dict(
            Counter(dict(parameter_indexed_parents.most_common(limit)))
        ),
        "parameter_indexed_parent_types": _counter_to_dict(
            Counter(dict(parameter_indexed_parent_types.most_common(limit)))
        ),
        "parameter_indexed_strides": _counter_to_dict(
            Counter(dict(parameter_indexed_strides.most_common(limit)))
        ),
        "parameter_indexed_alias_rewrite_risks": _counter_to_dict(
            Counter(dict(parameter_indexed_alias_rewrite_risks.most_common(limit)))
        ),
        "nested_field_pointer_parents": _counter_to_dict(
            Counter(dict(nested_field_pointer_parents.most_common(limit)))
        ),
        "nested_field_pointer_fields": _counter_to_dict(
            Counter(dict(nested_field_pointer_fields.most_common(limit)))
        ),
        "nested_field_pointer_parent_fields": _counter_to_dict(
            Counter(dict(nested_field_pointer_parent_fields.most_common(limit)))
        ),
        "nested_field_pointer_offsets": _counter_to_dict(
            Counter(dict(nested_field_pointer_offsets.most_common(limit)))
        ),
        "items": [
            _body_offset_residue_review_queue_item(item, queue_name=queue_name)
            for item in items[:limit]
        ],
    }


def _body_offset_residue_review_queue_item(
    item: dict[str, Any],
    queue_name: str = "",
) -> dict[str, Any]:
    return {
        "name": str(item.get("name", "") or ""),
        "ea": str(item.get("ea", "") or ""),
        "subsystem": str(item.get("subsystem", "") or ""),
        "review_class": str(item.get("review_class", "") or ""),
        "next_action": str(item.get("next_action", "") or ""),
        "queue_reason": _body_offset_residue_queue_reason(queue_name, item),
        "review_summary": _body_offset_residue_review_summary(item),
        "promotion_lane": str(item.get("promotion_lane", "") or ""),
        "review_focus": str(item.get("review_focus", "") or ""),
        "fail_closed_gate": str(item.get("fail_closed_gate", "") or ""),
        "fail_closed_family": str(item.get("fail_closed_family", "") or ""),
        "rewrite_safety_policy": str(item.get("rewrite_safety_policy", "") or ""),
        "evidence_maturity": str(item.get("evidence_maturity", "") or ""),
        "residue_pressure_class": str(item.get("residue_pressure_class", "") or ""),
        "named_goal_target": bool(item.get("named_goal_target")),
        "named_goal_target_group": str(item.get("named_goal_target_group", "") or ""),
        "priority_factors": [
            str(factor)
            for factor in item.get("priority_factors", []) or []
            if str(factor)
        ],
        "primary_review_reasons": [
            str(reason)
            for reason in item.get("primary_review_reasons", []) or []
            if str(reason)
        ],
        "residue_review_notes": [
            str(note)
            for note in item.get("residue_review_notes", []) or []
            if str(note)
        ],
        "residue_cause_tags": [
            str(tag)
            for tag in item.get("residue_cause_tags", []) or []
            if str(tag)
        ],
        "next_action_details": [
            str(detail)
            for detail in item.get("next_action_details", []) or []
            if str(detail)
        ],
        "priority_score": _int_value(item.get("priority_score"), 0),
        "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
        "direct_base_deref_bases": _coerce_dict(item.get("direct_base_deref_bases", {})),
        "direct_base_deref_types": _coerce_dict(item.get("direct_base_deref_types", {})),
        "direct_base_deref_base_classes": _coerce_dict(
            item.get("direct_base_deref_base_classes", {})
        ),
        "direct_base_deref_class_bases": _coerce_dict(item.get("direct_base_deref_class_bases", {})),
        "direct_call_result_callees": _coerce_dict(item.get("direct_call_result_callees", {})),
        "direct_call_result_arg_roots": _coerce_dict(item.get("direct_call_result_arg_roots", {})),
        "direct_call_result_member_paths": _coerce_dict(item.get("direct_call_result_member_paths", {})),
        "direct_call_result_deref_types": _coerce_dict(item.get("direct_call_result_deref_types", {})),
        "direct_call_result_layout_hints": _coerce_dict(item.get("direct_call_result_layout_hints", {})),
        "direct_call_result_hint_modes": _coerce_dict(item.get("direct_call_result_hint_modes", {})),
        "direct_call_result_samples": [
            str(sample)
            for sample in item.get("direct_call_result_samples", []) or []
            if str(sample)
        ],
        "direct_call_result_layout_samples": [
            str(sample)
            for sample in item.get("direct_call_result_layout_samples", []) or []
            if str(sample)
        ],
        "offset_deref_samples": [
            str(sample)
            for sample in item.get("offset_deref_samples", []) or []
            if str(sample)
        ],
        "top_base_offset_samples": {
            str(base): [
                str(sample)
                for sample in samples or []
                if str(sample)
            ]
            for base, samples in _coerce_dict(item.get("top_base_offset_samples", {})).items()
            if str(base)
        },
        "live_in_parameter_gap_count": _int_value(item.get("live_in_parameter_gap_count"), 0),
        "source_bound_live_in_parameter_gap_count": _int_value(
            item.get("source_bound_live_in_parameter_gap_count"),
            0,
        ),
        "live_in_parameter_gap_actions": _coerce_dict(item.get("live_in_parameter_gap_actions", {})),
        "live_in_parameter_gap_registers": _coerce_dict(item.get("live_in_parameter_gap_registers", {})),
        "live_in_parameter_gap_callees": _coerce_dict(item.get("live_in_parameter_gap_callees", {})),
        "live_in_parameter_gap_abi_slots": _coerce_dict(item.get("live_in_parameter_gap_abi_slots", {})),
        "live_in_parameter_gap_missing_signature_slots": _coerce_dict(
            item.get("live_in_parameter_gap_missing_signature_slots", {})
        ),
        "live_in_parameter_gap_samples": [
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        ],
        "callee_arity_residue_count": _int_value(item.get("callee_arity_residue_count"), 0),
        "callee_arity_residue_actions": _coerce_dict(item.get("callee_arity_residue_actions", {})),
        "callee_arity_residue_registers": _coerce_dict(item.get("callee_arity_residue_registers", {})),
        "callee_arity_residue_callees": _coerce_dict(item.get("callee_arity_residue_callees", {})),
        "callee_arity_residue_evidence": _coerce_dict(item.get("callee_arity_residue_evidence", {})),
        "callee_arity_residue_samples": [
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        ],
        "parameter_field_pointer_source_anchor_count": _int_value(
            item.get("parameter_field_pointer_source_anchor_count"),
            0,
        ),
        "parameter_field_pointer_sources": _coerce_dict(item.get("parameter_field_pointer_sources", {})),
        "parameter_field_pointer_targets": _coerce_dict(item.get("parameter_field_pointer_targets", {})),
        "parameter_field_pointer_offsets": _coerce_dict(item.get("parameter_field_pointer_offsets", {})),
        "parameter_field_pointer_samples": [
            str(sample)
            for sample in item.get("parameter_field_pointer_samples", []) or []
            if str(sample)
        ],
        "direct_base_deref_samples": [
            str(sample)
            for sample in item.get("direct_base_deref_samples", []) or []
            if str(sample)
        ],
        "generic_parameter_survivors": _int_value(item.get("generic_parameter_survivors"), 0),
        "field_access_pressure": _int_value(item.get("field_access_pressure"), 0),
        "review_evidence": [
            str(evidence)
            for evidence in item.get("review_evidence", []) or []
            if str(evidence)
        ],
        "promotion_hints": [
            str(hint)
            for hint in item.get("promotion_hints", []) or []
            if str(hint)
        ],
        "top_bases": [
            str(base)
            for base in item.get("top_bases", []) or []
            if str(base)
        ],
        "blocker_reasons": _coerce_dict(item.get("blocker_reasons", {})),
        "blocker_families": _coerce_dict(item.get("blocker_families", {})),
        "stable_source_provenance": _coerce_dict(item.get("stable_source_provenance", {})),
        "stable_source_kinds": _coerce_dict(item.get("stable_source_kinds", {})),
        "top_stable_sources": _coerce_dict(item.get("top_stable_sources", {})),
        "top_stable_source_details": _coerce_dict(item.get("top_stable_source_details", {})),
        "function_identity_source_context": _coerce_dict(
            item.get("function_identity_source_context", {})
        ),
        "source_bound_identity_sources": _coerce_dict(
            item.get("source_bound_identity_sources", {})
        ),
        "parameter_indexed_element_count": _int_value(item.get("parameter_indexed_element_count"), 0),
        "parameter_indexed_parents": _coerce_dict(item.get("parameter_indexed_parents", {})),
        "parameter_indexed_parent_types": _coerce_dict(item.get("parameter_indexed_parent_types", {})),
        "parameter_indexed_strides": _coerce_dict(item.get("parameter_indexed_strides", {})),
        "parameter_indexed_alias_rewrite_risks": _coerce_dict(
            item.get("parameter_indexed_alias_rewrite_risks", {})
        ),
        "parameter_indexed_offsets": [
            str(offset)
            for offset in item.get("parameter_indexed_offsets", []) or []
            if str(offset)
        ],
        "nested_field_pointer_residue_count": _int_value(
            item.get("nested_field_pointer_residue_count"),
            0,
        ),
        "nested_field_pointer_parents": _coerce_dict(item.get("nested_field_pointer_parents", {})),
        "nested_field_pointer_fields": _coerce_dict(item.get("nested_field_pointer_fields", {})),
        "nested_field_pointer_parent_fields": _coerce_dict(
            item.get("nested_field_pointer_parent_fields", {})
        ),
        "nested_field_pointer_offsets": _coerce_dict(item.get("nested_field_pointer_offsets", {})),
        "nested_field_pointer_samples": [
            str(sample)
            for sample in item.get("nested_field_pointer_samples", []) or []
            if str(sample)
        ],
        "domain_profiles": _coerce_dict(item.get("domain_profiles", {})),
        "summary_path": str(item.get("summary_path", "") or ""),
        "cleaned_path": str(item.get("cleaned_path", "") or ""),
    }


def _body_offset_sample_function_items(
    items: list[dict[str, Any]],
    limit: int,
    sample_limit: int = 2,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for item in items:
        name = str(item.get("name", "") or "")
        if not name or name in seen_names:
            continue
        samples = _body_offset_item_offset_deref_samples(item, sample_limit)
        if not samples:
            continue
        seen_names.add(name)
        result.append(
            {
                "name": name,
                "ea": str(item.get("ea", "") or ""),
                "subsystem": str(item.get("subsystem", "") or ""),
                "fail_closed_gate": str(item.get("fail_closed_gate", "") or ""),
                "promotion_lane": str(item.get("promotion_lane", "") or ""),
                "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
                "direct_base_deref_survivors": _int_value(
                    item.get("direct_base_deref_survivors"),
                    0,
                ),
                "samples": samples,
            }
        )
        if len(result) >= limit:
            break
    return result


def _body_offset_item_offset_deref_samples(
    item: dict[str, Any],
    limit: int,
) -> list[str]:
    result: list[str] = []
    for sample in item.get("offset_deref_samples", []) or []:
        sample_text = str(sample)
        if sample_text and sample_text not in result:
            result.append(sample_text)
        if len(result) >= limit:
            return result
    for base, samples in _coerce_dict(item.get("top_base_offset_samples", {})).items():
        base_text = str(base)
        for sample in samples or []:
            sample_text = str(sample)
            if not sample_text:
                continue
            if base_text and not sample_text.startswith("%s:" % base_text):
                sample_text = "%s: %s" % (base_text, sample_text)
            if sample_text not in result:
                result.append(sample_text)
            if len(result) >= limit:
                return result
    return result


def _body_offset_residue_queue_reason(queue_name: str, item: dict[str, Any]) -> str:
    queue = str(queue_name or "")
    group = str(item.get("named_goal_target_group", "") or "")
    gate = str(item.get("fail_closed_gate", "") or "review_only")
    policy = str(item.get("rewrite_safety_policy", "") or "review_only")
    if queue == "named_goal_targets":
        if group:
            return "named %s goal target stays visible under gate %s" % (group, gate)
        return "named goal target stays visible under gate %s" % gate
    if queue == "report_only_exact_promotion_candidates":
        return "report-only identity remains closed; promote only with exact private layout source"
    if queue == "report_only_field_alias_review":
        return "report-only field aliases can guide review but must not enable canonical rewrite"
    if queue == "source_identity_required":
        return "canonical rewrite requires exact function/build/source identity"
    if queue == "source_provenance_review":
        provenance = _coerce_dict(item.get("stable_source_provenance", {}))
        if _int_value(provenance.get("parameter_direct_alias"), 0) > 0:
            return "direct parameter source alias exists; verify exact profile/build before rewrite"
        if _int_value(provenance.get("parameter_field_pointer_alias"), 0) > 0:
            return "parameter-field pointer source alias exists; require exact source profile before rewrite"
        if _int_value(provenance.get("named_call_result_alias"), 0) > 0:
            return "named call-result source alias exists; verify returned layout identity before rewrite"
        return "stable source provenance exists; verify it before widening rewrite"
    if queue == "parameter_field_pointer_alias_candidates":
        samples = [
            str(sample)
            for sample in item.get("parameter_field_pointer_samples", []) or []
            if str(sample)
        ][:3]
        if samples:
            return (
                "parameter-field pointer source anchor(s) %s need exact containing-object identity"
                % ", ".join(samples)
            )
        return "parameter-field pointer source alias needs exact containing-object identity"
    if queue == "validated_rewrite_residue":
        return "validated rewrite already ran; reread remaining secondary residue"
    if queue == "nested_field_pointer_residue_candidates":
        parent_fields = [
            str(key)
            for key in _coerce_dict(item.get("nested_field_pointer_parent_fields", {})).keys()
            if str(key)
        ][:2]
        if parent_fields:
            return (
                "nested residue through %s needs a separate object layout model before rewrite"
                % ", ".join(parent_fields)
            )
        return "nested field-pointer residue needs a separate object layout model before rewrite"
    if queue == "direct_call_result_layout_candidates":
        anchors = _body_offset_direct_call_result_anchor_summary(item)
        hints = _body_offset_direct_call_result_hint_summary(item)
        if anchors and hints:
            return (
                "direct call-result %s has report-only layout hint(s) %s; verify returned layout/type identity before field-zero rewrite"
                % (anchors, hints)
            )
        if anchors:
            return (
                "direct call-result %s needs returned layout/type identity before field-zero rewrite"
                % anchors
            )
        return "direct call-result needs returned layout/type identity before field-zero rewrite"
    if queue == "direct_base_zero_deref_candidates":
        bases = [
            str(key)
            for key in _coerce_dict(item.get("direct_base_deref_bases", {})).keys()
            if str(key)
        ][:3]
        if bases:
            return (
                "direct +0 dereference on %s needs exact field-zero source identity before rewrite"
                % ", ".join(bases)
            )
        return "direct +0 dereference needs exact field-zero source identity before rewrite"
    if queue == "live_in_parameter_gap_candidates":
        samples = [
            str(sample)
            for sample in item.get("live_in_parameter_gap_samples", []) or []
            if str(sample)
        ][:3]
        if samples:
            return (
                "live-in ABI parameter gap candidate(s) %s need caller/callee argument validation before type correction"
                % ", ".join(samples)
            )
        return "live-in ABI parameter gap needs caller/callee argument validation before type correction"
    if queue == "callee_arity_residue_candidates":
        samples = [
            str(sample)
            for sample in item.get("callee_arity_residue_samples", []) or []
            if str(sample)
        ][:3]
        if samples:
            return (
                "callee arity/helper residue candidate(s) %s need callee contract validation before adding caller parameters"
                % ", ".join(samples)
            )
        return "callee arity/helper residue needs callee contract validation before adding caller parameters"
    if queue == "source_stability_required":
        families = _coerce_dict(item.get("blocker_families", {}))
        if _int_value(families.get("source_reassigned"), 0) > 0:
            return "base is reassigned after layout access; prove stable source before rewrite"
        if _int_value(families.get("source_address_taken"), 0) > 0:
            return "base address is taken; prove no alias instability before rewrite"
        if _int_value(families.get("source_compound_assignment"), 0) > 0:
            return "compound base assignment blocks stable source proof"
        return "source stability is unproven; keep rewrite fail-closed"
    if queue == "type_conflict_required":
        families = _coerce_dict(item.get("blocker_families", {}))
        if _int_value(families.get("type_wide_overlay"), 0) > 0:
            return "wide overlay access conflict must be resolved before rewrite"
        if _int_value(families.get("type_narrow_subfield"), 0) > 0:
            return "narrow subfield overlay conflict must be resolved before rewrite"
        if _int_value(families.get("type_unaligned"), 0) > 0:
            return "unaligned typed offset conflict must be resolved before rewrite"
        if _int_value(families.get("type_irregular_width"), 0) > 0:
            return "irregular field width conflict must be resolved before rewrite"
        return "type width or alignment conflict must be resolved before rewrite"
    if queue == "pointer_indexed_layout_candidates":
        if _int_value(item.get("parameter_indexed_element_count"), 0) > 0:
            if _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})):
                return (
                    "parameter-indexed element uses a typed parent pointer with byte-stride evidence; "
                    "model indexed layout and avoid naive parameter alias rewrite"
                )
            return "parameter-indexed element shape has parent/stride/offset evidence; model indexed layout before rewrite"
        return "pointer-indexed shape needs a separate indexed layout model"
    if queue == "dense_shape_identity_candidates":
        return "dense offset shape needs exact identity before rewrite"
    if queue == "parameter_profile_candidates":
        return "parameter-shaped residue needs semantic profile or type correction evidence"
    if queue == "context_profile_candidates":
        return "generic context residue needs exact context profile"
    if queue == "temp_source_identity_candidates":
        return "temporary base residue needs initializer/source identity proof"
    if queue == "low_pressure_deferred":
        return "low-pressure residue is deferred behind stronger queues"
    if queue == "manual_review_required":
        return "manual review is required before promotion"
    if policy:
        return "review under policy %s" % policy
    return "manual body offset residue review"


def _body_offset_residue_review_summary(item: dict[str, Any]) -> str:
    subsystem = str(item.get("subsystem", "") or "other")
    gate = str(item.get("fail_closed_gate", "") or "review_only")
    pressure = str(item.get("residue_pressure_class", "") or "unknown")
    parts = ["%s/%s pressure=%s" % (subsystem, gate, pressure)]
    counts = []
    offset_derefs = _int_value(item.get("offset_deref_survivors"), 0)
    direct_base_derefs = _int_value(item.get("direct_base_deref_survivors"), 0)
    generic_parameters = _int_value(item.get("generic_parameter_survivors"), 0)
    if offset_derefs:
        counts.append("%d offset deref(s)" % offset_derefs)
    if direct_base_derefs:
        counts.append("%d direct-base zero deref(s)" % direct_base_derefs)
    if generic_parameters:
        counts.append("%d generic parameter survivor(s)" % generic_parameters)
    if counts:
        parts.append(", ".join(counts))
    policy = str(item.get("rewrite_safety_policy", "") or "")
    if policy:
        parts.append("policy=%s" % policy)
    lane = str(item.get("promotion_lane", "") or "")
    if lane:
        parts.append("lane=%s" % lane)
    primary_reasons = [
        str(reason)
        for reason in item.get("primary_review_reasons", []) or []
        if str(reason)
    ][:3]
    if primary_reasons:
        parts.append("reasons=%s" % ",".join(primary_reasons))
    top_bases = [
        str(base)
        for base in item.get("top_bases", []) or []
        if str(base)
    ][:3]
    if top_bases:
        parts.append("bases=%s" % ",".join(top_bases))
    blocker_family_parts = _body_offset_blocker_family_summary_parts(item)
    if blocker_family_parts:
        parts.append("blockers=%s" % ",".join(blocker_family_parts))
    stable_source_parts = _body_offset_stable_source_summary_parts(item)
    if stable_source_parts:
        parts.append("stable-source=%s" % " ".join(stable_source_parts))
    if direct_base_derefs:
        direct_parts = []
        direct_bases = [
            str(base)
            for base in _coerce_dict(item.get("direct_base_deref_bases", {})).keys()
            if str(base)
        ][:3]
        direct_types = [
            str(type_name)
            for type_name in _coerce_dict(item.get("direct_base_deref_types", {})).keys()
            if str(type_name)
        ][:2]
        direct_classes = [
            str(base_class)
            for base_class in _coerce_dict(item.get("direct_base_deref_base_classes", {})).keys()
            if str(base_class)
        ][:2]
        if direct_bases:
            direct_parts.append("bases=%s" % ",".join(direct_bases))
        if direct_types:
            direct_parts.append("types=%s" % ",".join(direct_types))
        if direct_classes:
            direct_parts.append("classes=%s" % ",".join(direct_classes))
        if direct_parts:
            parts.append("direct-base=%s" % " ".join(direct_parts))
    cause_tags = [
        str(tag)
        for tag in item.get("residue_cause_tags", []) or []
        if str(tag)
    ][:4]
    if cause_tags:
        parts.append("causes=%s" % ",".join(cause_tags))
    nested_count = _int_value(item.get("nested_field_pointer_residue_count"), 0)
    if nested_count > 0:
        nested_parts = []
        parent_fields = [
            str(parent_field)
            for parent_field in _coerce_dict(item.get("nested_field_pointer_parent_fields", {})).keys()
            if str(parent_field)
        ][:2]
        nested_offsets = [
            str(offset)
            for offset in _coerce_dict(item.get("nested_field_pointer_offsets", {})).keys()
            if str(offset)
        ][:4]
        if parent_fields:
            nested_parts.append("parent-field=%s" % ",".join(parent_fields))
        if nested_offsets:
            nested_parts.append("offsets=%s" % ",".join(nested_offsets))
        if nested_parts:
            parts.append("nested-field=%s" % " ".join(nested_parts))
        else:
            parts.append("nested-field=%d residue" % nested_count)
    parameter_indexed_count = _int_value(item.get("parameter_indexed_element_count"), 0)
    if parameter_indexed_count > 0:
        indexed_parts = []
        indexed_parents = [
            str(parent)
            for parent in _coerce_dict(item.get("parameter_indexed_parents", {})).keys()
            if str(parent)
        ][:2]
        indexed_parent_types = [
            str(parent_type)
            for parent_type in _coerce_dict(item.get("parameter_indexed_parent_types", {})).keys()
            if str(parent_type)
        ][:2]
        indexed_strides = [
            str(stride)
            for stride in _coerce_dict(item.get("parameter_indexed_strides", {})).keys()
            if str(stride)
        ][:2]
        indexed_offsets = [
            str(offset)
            for offset in item.get("parameter_indexed_offsets", []) or []
            if str(offset)
        ][:4]
        if indexed_parents:
            indexed_parts.append("parent=%s" % ",".join(indexed_parents))
        if indexed_parent_types:
            indexed_parts.append("type=%s" % ",".join(indexed_parent_types))
        if indexed_strides:
            indexed_parts.append("stride=%s" % ",".join(indexed_strides))
        if indexed_offsets:
            indexed_parts.append("offsets=%s" % ",".join(indexed_offsets))
        indexed_risks = [
            str(risk)
            for risk in _coerce_dict(item.get("parameter_indexed_alias_rewrite_risks", {})).keys()
            if str(risk)
        ][:2]
        if indexed_risks:
            indexed_parts.append("alias-risk=%s" % ",".join(indexed_risks))
        if indexed_parts:
            parts.append("indexed-element=%s" % " ".join(indexed_parts))
        else:
            parts.append("indexed-element=%d evidence" % parameter_indexed_count)
    live_in_samples = [
        str(sample)
        for sample in item.get("live_in_parameter_gap_samples", []) or []
        if str(sample)
    ][:2]
    if live_in_samples:
        parts.append("live-in=%s" % ",".join(live_in_samples))
    existing_parameter_alias_samples = [
        str(sample)
        for sample in item.get("existing_parameter_alias_samples", []) or []
        if str(sample)
    ][:2]
    if existing_parameter_alias_samples:
        parts.append("resolved-alias=%s" % ",".join(existing_parameter_alias_samples))
    callee_arity_samples = [
        str(sample)
        for sample in item.get("callee_arity_residue_samples", []) or []
        if str(sample)
    ][:2]
    if callee_arity_samples:
        parts.append("callee-arity=%s" % ",".join(callee_arity_samples))
    parameter_field_pointer_samples = [
        str(sample)
        for sample in item.get("parameter_field_pointer_samples", []) or []
        if str(sample)
    ][:2]
    if parameter_field_pointer_samples:
        parts.append("field-pointer=%s" % ",".join(parameter_field_pointer_samples))
    return "; ".join(parts)


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _counter_like_dict(value: Any) -> dict[str, int]:
    counter = Counter(
        {
            str(key): _int_value(count, 0)
            for key, count in _coerce_dict(value).items()
            if _int_value(count, 0) > 0
        }
    )
    return _counter_to_dict(counter)


def _profile_counter(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        profile_id = str(item.get("profile_id", "") or "").strip()
        if profile_id == "ambiguous":
            for ambiguous_id in _string_list(item.get("ambiguous_profile_ids")):
                counter[ambiguous_id] += 1
        elif profile_id:
            counter[profile_id] += 1
    return _counter_to_dict(counter)


def _canonical_type_counter(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        type_text = str(item.get("display_type", "") or item.get("canonical_type", "") or "").strip()
        if type_text:
            counter[type_text] += 1
    return _counter_to_dict(counter)


def _generic_parameter_survivor_count(text: str) -> int:
    signature = _first_signature_text(text)
    if not signature:
        return 0
    return sum(
        1
        for parameter in _signature_parameter_chunks(signature)
        if _weak_parameter_type_survives(parameter) or _generic_parameter_name_survives(parameter)
    )


def _first_signature_text(text: str) -> str:
    lines: list[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lines.append(stripped)
        if "{" in stripped:
            break
        if ")" in stripped and "(" in " ".join(lines):
            break
    signature = " ".join(lines)
    return signature.split("{", 1)[0].strip()


def _signature_parameter_chunks(signature: str) -> list[str]:
    match = re.search(r"\((?P<params>.*)\)", signature or "")
    if match is None:
        return []
    params = match.group("params").strip()
    if not params or params == "void":
        return []
    return [item.strip() for item in params.split(",") if item.strip()]


def _weak_parameter_type_survives(parameter: str) -> bool:
    normalized = " ".join(str(parameter or "").replace("*", " * ").split())
    tokens = normalized.split()
    if len(tokens) > 1:
        type_text = " ".join(tokens[:-1])
    else:
        type_text = normalized
    type_text = type_text.replace(" *", " *").strip()
    return type_text in WEAK_PARAMETER_TYPES


def _generic_parameter_name_survives(parameter: str) -> bool:
    tokens = str(parameter or "").replace("*", " ").split()
    if not tokens:
        return False
    return GENERIC_PARAMETER_NAME_RE.fullmatch(tokens[-1]) is not None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [str(item) for item in value]
    else:
        values = []
    return [item.strip() for item in values if item.strip()]


def _update_rename_metrics(
    rename_items: list[dict[str, Any]],
    sources: Counter[str],
    applied_sources: Counter[str],
) -> None:
    for item in rename_items:
        source = str(item.get("source", "") or "unknown")
        sources[source] += 1
        if _rename_applied(item):
            applied_sources[source] += 1


def _rename_applied(item: dict[str, Any]) -> bool:
    if "apply" not in item:
        return True
    return bool(item.get("apply"))


def _update_rule_metrics(rule_report: dict[str, Any], rewrite_kinds: Counter[str], totals: Counter[str]) -> None:
    rewrite_emissions = [item for item in rule_report.get("rewrite_emissions", []) or [] if isinstance(item, dict)]
    totals["rule_rewrite_emissions"] += len(rewrite_emissions)
    totals["rule_rejected_emissions"] += len(rule_report.get("rejected_emissions", []) or [])
    totals["rule_load_errors"] += len(rule_report.get("load_errors", []) or [])
    totals["rule_validation_errors"] += len(rule_report.get("validation_errors", []) or [])
    for item in rewrite_emissions:
        rewrite_kinds[str(item.get("kind", "") or "unknown")] += 1


def _api_semantic_review_queue_function_items(
    name: str,
    ea: str,
    summary_path: Path,
    rule_report: dict[str, Any],
) -> list[dict[str, Any]]:
    diagnostics = [
        item
        for item in rule_report.get("api_semantic_diagnostics", []) or []
        if isinstance(item, dict)
    ]
    result: list[dict[str, Any]] = []
    for item in diagnostics:
        if str(item.get("status", "") or "unknown") != "rejected":
            continue
        profile = _api_semantic_profile(item)
        result.append(
            {
                "category": _api_semantic_review_category(item, profile),
                "reason": str(profile.get("reason", "") or "unknown"),
                "stage": str(profile.get("stage", "") or "unknown"),
                "callee": str(profile.get("callee", "") or ""),
                "parameter": str(profile.get("parameter", "") or ""),
                "parameter_type": str(profile.get("parameter_type", "") or ""),
                "old": str(item.get("old", "") or ""),
                "new": str(profile.get("new", "") or ""),
                "argument_index": str(profile.get("argument_index", "") or ""),
                "argument": str(item.get("argument", "") or ""),
                "candidate_kind": str(item.get("candidate_kind", "") or ""),
                "candidate_targets": _api_semantic_candidate_targets(item),
                "evidence": str(item.get("evidence", "") or ""),
                "function_name": name,
                "ea": ea,
                "summary_path": str(summary_path),
            }
        )
    return result


def _api_semantic_review_queue(items: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    category_counts = Counter(str(item.get("category", "") or "likely_profile_gap") for item in items)
    top_items = _api_semantic_group_queue_items(items)
    repeated_targets = [
        item
        for item in _api_semantic_group_repeated_targets(items)
        if int(item.get("count", 0) or 0) > 1 or int(item.get("function_count", 0) or 0) > 1
    ]
    category_payload: dict[str, Any] = {}
    for category in API_SEMANTIC_REVIEW_CATEGORIES:
        category_payload[category] = {
            "count": int(category_counts.get(category, 0)),
            "top_items": [item for item in top_items if item.get("category") == category][:limit],
            "top_repeated_targets": [
                item for item in repeated_targets if item.get("category") == category
            ][:limit],
        }
    return {
        "schema": "api_semantic_review_queue_v1",
        "item_count": len(items),
        "repeated_target_count": len(repeated_targets),
        "category_counts": _api_semantic_category_counts(category_counts),
        "top_items": top_items[:limit],
        "top_repeated_targets": repeated_targets[:limit],
        "categories": category_payload,
    }


def _api_semantic_group_queue_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("category", "")),
            str(item.get("reason", "")),
            str(item.get("stage", "")),
            str(item.get("callee", "")),
            str(item.get("parameter", "")),
            str(item.get("parameter_type", "")),
            str(item.get("old", "")),
            str(item.get("new", "")),
            str(item.get("argument_index", "")),
            str(item.get("function_name", "")),
            str(item.get("ea", "")),
        )
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "category": item.get("category", ""),
                "reason": item.get("reason", ""),
                "stage": item.get("stage", ""),
                "callee": item.get("callee", ""),
                "parameter": item.get("parameter", ""),
                "parameter_type": item.get("parameter_type", ""),
                "old": item.get("old", ""),
                "new": item.get("new", ""),
                "argument_index": item.get("argument_index", ""),
                "argument": item.get("argument", ""),
                "candidate_kind": item.get("candidate_kind", ""),
                "function_name": item.get("function_name", ""),
                "ea": item.get("ea", ""),
                "summary_path": item.get("summary_path", ""),
                "count": 0,
                "_candidate_targets": Counter(),
                "_evidence_samples": [],
            }
            grouped[key] = entry
        entry["count"] = int(entry["count"]) + 1
        for target in item.get("candidate_targets", []) or []:
            entry["_candidate_targets"][str(target)] += 1
        evidence = str(item.get("evidence", "") or "")
        if evidence and evidence not in entry["_evidence_samples"] and len(entry["_evidence_samples"]) < 3:
            entry["_evidence_samples"].append(evidence)
    result = []
    for entry in grouped.values():
        entry["candidate_targets"] = _counter_to_dict(entry.pop("_candidate_targets"))
        entry["evidence_samples"] = entry.pop("_evidence_samples")
        result.append(entry)
    result.sort(key=_api_semantic_queue_sort_key)
    return result


def _api_semantic_group_repeated_targets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("category", "")),
            str(item.get("reason", "")),
            str(item.get("stage", "")),
            str(item.get("callee", "")),
            str(item.get("parameter", "")),
            str(item.get("parameter_type", "")),
            str(item.get("new", "")),
            str(item.get("argument_index", "")),
        )
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "category": item.get("category", ""),
                "reason": item.get("reason", ""),
                "stage": item.get("stage", ""),
                "callee": item.get("callee", ""),
                "parameter": item.get("parameter", ""),
                "parameter_type": item.get("parameter_type", ""),
                "new": item.get("new", ""),
                "argument_index": item.get("argument_index", ""),
                "count": 0,
                "_old_names": Counter(),
                "_functions": Counter(),
                "_candidate_targets": Counter(),
            }
            grouped[key] = entry
        entry["count"] = int(entry["count"]) + 1
        old_name = str(item.get("old", "") or "")
        if old_name:
            entry["_old_names"][old_name] += 1
        function_key = json.dumps(
            {
                "name": str(item.get("function_name", "") or ""),
                "ea": str(item.get("ea", "") or ""),
                "summary_path": str(item.get("summary_path", "") or ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        entry["_functions"][function_key] += 1
        for target in item.get("candidate_targets", []) or []:
            entry["_candidate_targets"][str(target)] += 1
    result = []
    for entry in grouped.values():
        functions = []
        function_counter = entry.pop("_functions")
        entry["function_count"] = len(function_counter)
        for function_key, count in function_counter.most_common(8):
            try:
                function = json.loads(function_key)
            except json.JSONDecodeError:
                function = {"name": function_key, "ea": "", "summary_path": ""}
            if not isinstance(function, dict):
                function = {"name": str(function), "ea": "", "summary_path": ""}
            function["count"] = int(count)
            functions.append(function)
        entry["functions"] = functions
        entry["old_names"] = _counter_to_dict(Counter(dict(entry.pop("_old_names").most_common(8))))
        entry["candidate_targets"] = _counter_to_dict(entry.pop("_candidate_targets"))
        result.append(entry)
    result.sort(key=_api_semantic_queue_sort_key)
    return result


def _api_semantic_queue_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -int(item.get("count", 0) or 0),
        -int(item.get("function_count", 1) or 1),
        _api_semantic_category_order(str(item.get("category", "") or "")),
        str(item.get("reason", "")),
        str(item.get("callee", "")),
        str(item.get("parameter", "")),
        str(item.get("new", "")),
        str(item.get("function_name", "")),
        str(item.get("ea", "")),
    )


def _api_semantic_category_order(category: str) -> int:
    try:
        return API_SEMANTIC_REVIEW_CATEGORIES.index(category)
    except ValueError:
        return len(API_SEMANTIC_REVIEW_CATEGORIES)


def _api_semantic_category_counts(counter: Counter[str]) -> dict[str, int]:
    result = {category: int(counter.get(category, 0)) for category in API_SEMANTIC_REVIEW_CATEGORIES}
    for category, count in counter.most_common():
        if category not in result:
            result[category] = int(count)
    return result


def _api_semantic_review_category(item: dict[str, Any], profile: dict[str, Any]) -> str:
    reason = str(profile.get("reason", "") or item.get("reason", "") or "unknown")
    if reason == "large_dispatcher":
        return "correctly_blocked_large_dispatcher"
    if reason == "weak_parameter_name":
        return "weak_parameter_name_gap"
    if reason in {"conflict_old", "conflict_target", "shadow"}:
        return "shadow_or_conflict_needs_manual_review"
    if reason == "unsafe_wrapper_role":
        return "unsafe_wrapper_role"
    return "likely_profile_gap"


def _api_semantic_candidate_targets(item: dict[str, Any]) -> list[str]:
    targets = []
    direct_new = str(item.get("new", "") or "")
    if direct_new:
        targets.append(direct_new)
    details = item.get("candidate_details", [])
    if isinstance(details, list):
        for detail in details:
            if not isinstance(detail, dict):
                continue
            value = str(detail.get("new", "") or "")
            if value and value not in targets:
                targets.append(value)
    if not targets:
        for value in _string_list(item.get("candidates")):
            if value not in targets:
                targets.append(value)
    return targets


def _update_api_semantic_metrics(
    rule_report: dict[str, Any],
    reasons: Counter[str],
    stages: Counter[str],
    statuses: Counter[str],
    profiles: Counter[str],
    totals: Counter[str],
) -> int:
    diagnostics = [
        item
        for item in rule_report.get("api_semantic_diagnostics", []) or []
        if isinstance(item, dict)
    ]
    for item in diagnostics:
        totals["api_semantic_diagnostics"] += 1
        status = str(item.get("status", "") or "unknown")
        statuses[status] += 1
        if status != "rejected":
            continue
        totals["api_semantic_rejections"] += 1
        reasons[str(item.get("reason", "") or "unknown")] += 1
        stages[str(item.get("stage", "") or "unknown")] += 1
        profiles[_api_semantic_profile_key(item)] += 1
    return len(diagnostics)


def _api_semantic_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    rule_report: dict[str, Any],
) -> dict[str, Any]:
    diagnostics = [
        item
        for item in rule_report.get("api_semantic_diagnostics", []) or []
        if isinstance(item, dict)
    ]
    rejections = [
        item
        for item in diagnostics
        if str(item.get("status", "") or "unknown") == "rejected"
    ]
    reasons: Counter[str] = Counter()
    stages: Counter[str] = Counter()
    targets: Counter[str] = Counter()
    profiles: Counter[str] = Counter()
    candidate_targets: Counter[str] = Counter()
    for item in rejections:
        reasons[str(item.get("reason", "") or "unknown")] += 1
        stages[str(item.get("stage", "") or "unknown")] += 1
        new_name = str(item.get("new", "") or "")
        if new_name:
            targets[new_name] += 1
        candidate_details = item.get("candidate_details", [])
        if isinstance(candidate_details, list):
            for detail in candidate_details:
                if isinstance(detail, dict):
                    candidate_new = str(detail.get("new", "") or "")
                    if candidate_new:
                        candidate_targets[candidate_new] += 1
        profiles[_api_semantic_profile_key(item)] += 1
    return {
        "name": name,
        "ea": ea,
        "summary_path": str(summary_path),
        "diagnostic_count": len(diagnostics),
        "rejection_count": len(rejections),
        "rejections_by_reason": _counter_to_dict(reasons),
        "rejections_by_stage": _counter_to_dict(stages),
        "rejections_by_target": _counter_to_dict(Counter(dict(targets.most_common(8)))),
        "candidate_targets": _counter_to_dict(Counter(dict(candidate_targets.most_common(8)))),
        "top_rejection_profiles": _api_semantic_profile_summaries(profiles, 8),
    }


def _api_semantic_profile_key(item: dict[str, Any]) -> str:
    profile = _api_semantic_profile(item)
    return json.dumps(profile, sort_keys=True, separators=(",", ":"))


def _api_semantic_profile_summaries(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    result = []
    for key, count in counter.most_common(max(0, limit)):
        try:
            profile = json.loads(key)
        except json.JSONDecodeError:
            profile = {"reason": key}
        if not isinstance(profile, dict):
            profile = {"reason": str(profile)}
        profile["count"] = int(count)
        result.append(profile)
    return result


def _api_semantic_profile(item: dict[str, Any]) -> dict[str, Any]:
    evidence_profile = _api_semantic_profile_from_evidence(str(item.get("evidence", "") or ""))
    callee = str(item.get("callee", "") or evidence_profile.get("callee", "") or "")
    parameter = str(item.get("parameter", "") or evidence_profile.get("parameter", "") or "")
    parameter_type = str(item.get("parameter_type", "") or "")
    argument_index = item.get("argument_index", "")
    if argument_index in (None, ""):
        argument_index = evidence_profile.get("argument_index", "")
    return {
        "reason": str(item.get("reason", "") or "unknown"),
        "stage": str(item.get("stage", "") or "unknown"),
        "new": str(item.get("new", "") or evidence_profile.get("new", "") or ""),
        "callee": callee,
        "parameter": parameter,
        "parameter_type": parameter_type,
        "argument_index": str(argument_index if argument_index not in (None, "") else ""),
    }


def _api_semantic_profile_from_evidence(evidence: str) -> dict[str, str]:
    if not evidence:
        return {}
    match = re.search(
        r"\blocal is passed to (?P<callee>[A-Za-z_][A-Za-z0-9_]*) profile parameter (?P<parameter>[A-Za-z_][A-Za-z0-9_]*)",
        evidence,
    )
    if match:
        return {
            "callee": match.group("callee"),
            "parameter": match.group("parameter"),
        }
    match = re.search(
        r"\b(?P<callee>[A-Za-z_][A-Za-z0-9_]*) argument (?P<argument_index>\d+) is an address-taken local for profile parameter (?P<parameter>[A-Za-z_][A-Za-z0-9_]*)",
        evidence,
    )
    if match:
        return {
            "callee": match.group("callee"),
            "argument_index": match.group("argument_index"),
            "parameter": match.group("parameter"),
        }
    match = re.search(
        r"\blarge dispatcher local has a strong single-use API role (?P<new>[A-Za-z_][A-Za-z0-9_]*) from (?P<callee>[A-Za-z_][A-Za-z0-9_]*)(?: profile parameter (?P<parameter>[A-Za-z_][A-Za-z0-9_]*))?",
        evidence,
    )
    if match:
        return {
            "new": match.group("new"),
            "callee": match.group("callee"),
            "parameter": match.group("parameter") or "",
        }
    return {}


def _update_text_metrics(
    text_totals: Counter[str],
    body_text_totals: Counter[str],
    path: Path,
) -> tuple[Any, ...]:
    text = _read_text(path)
    if not text:
        return [], [], [], [], [], [], [], [], [], [], [], {}, [], [], [], [], [], [], [], []
    _update_residue_metrics(text_totals, text)
    body_text = _strip_pseudoforge_header(text)
    _update_visible_review_only_field_alias_metrics(text_totals, text)
    _update_visible_review_only_field_alias_metrics(body_text_totals, body_text)
    _update_synthetic_aggregate_metrics(text_totals, text)
    _update_synthetic_aggregate_metrics(body_text_totals, body_text)
    full_synthetic_candidates = len(SYNTHETIC_AGGREGATE_COMMENT_RE.findall(text))
    full_pool_candidates = len(SYNTHETIC_POOL_AGGREGATE_COMMENT_RE.findall(text))
    full_blocked_candidates = len(SYNTHETIC_BLOCKED_AGGREGATE_COMMENT_RE.findall(text))
    body_synthetic_candidates = len(SYNTHETIC_AGGREGATE_COMMENT_RE.findall(body_text))
    body_synthetic_aliases = len(INLINE_REVIEW_ONLY_AGGREGATE_ALIAS_RE.findall(body_text))
    body_synthetic_projections = len(PROJECTED_AGGREGATE_ACCESS_RE.findall(body_text))
    body_blocked_candidates = len(SYNTHETIC_BLOCKED_AGGREGATE_COMMENT_RE.findall(body_text))
    if full_synthetic_candidates and (body_synthetic_aliases or body_synthetic_projections) and not body_synthetic_candidates:
        body_text_totals["synthetic_local_aggregate_candidates"] += full_synthetic_candidates
        body_text_totals["synthetic_pool_aggregate_candidates"] += full_pool_candidates
    if full_blocked_candidates and not body_blocked_candidates:
        body_text_totals["blocked_aggregate_candidates"] += full_blocked_candidates
    body_metric_text = _strip_visible_review_only_field_alias_comments(body_text)
    _update_residue_metrics(body_text_totals, body_metric_text)
    decimal_status_body_literals = _decimal_status_like_literals(body_text)
    ntstatus_body_literals = _ntstatus_family_literals(body_text)
    layout_hints = _extract_layout_hints(text)
    subfield_overlays = _extract_layout_subfield_overlays(text)
    narrow_subfields = _extract_layout_narrow_subfields(text)
    bitfield_aliases = _extract_layout_bitfield_aliases(text)
    hot_field_clusters = _extract_layout_hot_field_clusters(text)
    indexed_callback_tables = _extract_layout_indexed_callback_tables(text)
    parameter_indexed_elements = _extract_layout_parameter_indexed_elements(text)
    stable_base_sources = _extract_layout_stable_base_sources(text)
    base_stability = _extract_layout_base_stability(text)
    generic_base_evidence = _extract_layout_generic_base_evidence(text)
    generic_base_trust_candidates = _extract_layout_generic_base_trust_candidates(text)
    temp_provenance = _extract_layout_temp_provenance(text)
    rewrite_ready = _extract_layout_rewrite_ready(text)
    rewrite_previews = _extract_layout_rewrite_previews(text)
    rewrite_near_ready = _extract_layout_rewrite_near_ready(text)
    rewrite_partial_opportunities = _extract_layout_rewrite_partial_opportunities(text)
    rewrite_blockers = _extract_layout_rewrite_blockers(text)
    domain_identities = _extract_domain_structure_identities(text)
    text_totals["inferred_offset_layout_hints"] += len(layout_hints)
    if layout_hints:
        text_totals["functions_with_inferred_offset_layout_hints"] += 1
    _count_pattern(
        text_totals,
        text,
        FIELD_PREVIEW_RE,
        "inferred_offset_field_previews",
        "functions_with_inferred_offset_field_previews",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_ALIAS_RE,
        "inferred_offset_field_aliases",
        "functions_with_inferred_offset_field_aliases",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_SUBFIELD_OVERLAY_RE,
        "inferred_offset_subfield_overlays",
        "functions_with_inferred_offset_subfield_overlays",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_NARROW_SUBFIELD_RE,
        "inferred_offset_narrow_subfields",
        "functions_with_inferred_offset_narrow_subfields",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BITFIELD_ALIAS_RE,
        "inferred_offset_bitfield_aliases",
        "functions_with_inferred_offset_bitfield_aliases",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_HOT_CLUSTER_RE,
        "inferred_offset_field_hot_clusters",
        "functions_with_inferred_offset_field_hot_clusters",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_INDEXED_CALLBACK_TABLE_RE,
        "inferred_offset_indexed_callback_table_evidence",
        "functions_with_inferred_offset_indexed_callback_table_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_PARAMETER_INDEXED_ELEMENT_RE,
        "inferred_offset_parameter_indexed_element_evidence",
        "functions_with_inferred_offset_parameter_indexed_element_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_STABLE_BASE_SOURCE_RE,
        "inferred_offset_stable_base_sources",
        "functions_with_inferred_offset_stable_base_sources",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BASE_STABILITY_RE,
        "inferred_offset_base_stability",
        "functions_with_inferred_offset_base_stability",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BASE_RELOCATION_EVIDENCE_RE,
        "inferred_offset_base_relocation_evidence",
        "functions_with_inferred_offset_base_relocation_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BASE_MERGE_EVIDENCE_RE,
        "inferred_offset_base_merge_evidence",
        "functions_with_inferred_offset_base_merge_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_BUGCHECK_PARAMETER_MERGE_IDENTITY_RE,
        "inferred_offset_bugcheck_parameter_merge_identity",
        "functions_with_inferred_offset_bugcheck_parameter_merge_identity",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_CALL_RESULT_MERGE_EQUIVALENCE_RE,
        "inferred_offset_call_result_merge_equivalence",
        "functions_with_inferred_offset_call_result_merge_equivalence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_ALLOCATION_NULL_MERGE_DOMINANCE_RE,
        "inferred_offset_allocation_null_merge_dominance",
        "functions_with_inferred_offset_allocation_null_merge_dominance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_CALL_RESULT_PARAMETER_MERGE_PROVENANCE_RE,
        "inferred_offset_call_result_parameter_merge_provenance",
        "functions_with_inferred_offset_call_result_parameter_merge_provenance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_CALL_RESULT_TEMPORARY_MERGE_PROVENANCE_RE,
        "inferred_offset_call_result_temporary_merge_provenance",
        "functions_with_inferred_offset_call_result_temporary_merge_provenance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_SAME_SOURCE_FAMILY_MERGE_DOMINANCE_RE,
        "inferred_offset_same_source_family_merge_dominance",
        "functions_with_inferred_offset_same_source_family_merge_dominance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_TRUSTED_TEMP_SOURCE_RE,
        "inferred_offset_trusted_temp_source",
        "functions_with_inferred_offset_trusted_temp_source",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_TEMP_PROVENANCE_TRACE_RE,
        "inferred_offset_temp_provenance_trace",
        "functions_with_inferred_offset_temp_provenance_trace",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_TEMP_PROMOTION_BLOCKED_RE,
        "inferred_offset_temp_promotion_blocked",
        "functions_with_inferred_offset_temp_promotion_blocked",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_SAME_FAMILY_MERGE_PROVENANCE_RE,
        "inferred_offset_same_family_merge_provenance",
        "functions_with_inferred_offset_same_family_merge_provenance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_CALL_RESULT_PARAMETER_DOMINANCE_RE,
        "inferred_offset_call_result_parameter_dominance",
        "functions_with_inferred_offset_call_result_parameter_dominance",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_POST_ACCESS_MUTATION_BLOCKER_RE,
        "inferred_offset_post_access_mutation_blocker",
        "functions_with_inferred_offset_post_access_mutation_blocker",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_GENERIC_BASE_EVIDENCE_RE,
        "inferred_offset_generic_base_evidence",
        "functions_with_inferred_offset_generic_base_evidence",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_GENERIC_BASE_TRUST_CANDIDATE_RE,
        "inferred_offset_generic_base_trust_candidates",
        "functions_with_inferred_offset_generic_base_trust_candidates",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_READY_RE,
        "inferred_offset_rewrite_ready",
        "functions_with_inferred_offset_rewrite_ready",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_PREVIEW_RE,
        "inferred_offset_rewrite_previews",
        "functions_with_inferred_offset_rewrite_previews",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_NEAR_READY_RE,
        "inferred_offset_rewrite_near_ready",
        "functions_with_inferred_offset_rewrite_near_ready",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_PARTIAL_OPPORTUNITY_RE,
        "inferred_offset_rewrite_partial_opportunities",
        "functions_with_inferred_offset_rewrite_partial_opportunities",
    )
    _count_pattern(
        text_totals,
        text,
        FIELD_REWRITE_BLOCKER_RE,
        "inferred_offset_rewrite_blockers",
        "functions_with_inferred_offset_rewrite_blockers",
    )
    return (
        layout_hints,
        subfield_overlays,
        narrow_subfields,
        bitfield_aliases,
        hot_field_clusters,
        indexed_callback_tables,
        parameter_indexed_elements,
        stable_base_sources,
        base_stability,
        generic_base_evidence,
        generic_base_trust_candidates,
        temp_provenance,
        rewrite_ready,
        rewrite_previews,
        rewrite_near_ready,
        rewrite_partial_opportunities,
        rewrite_blockers,
        domain_identities,
        decimal_status_body_literals,
        ntstatus_body_literals,
    )


def _update_residue_metrics(text_totals: Counter[str], text: str) -> None:
    _count_pattern(text_totals, text, GENERIC_IDENTIFIER_RE, "generic_identifier_tokens", "functions_with_generic_identifiers")
    _count_pattern(text_totals, text, OFFSET_DEREF_RE, "offset_deref_patterns", "functions_with_offset_derefs")
    _count_pattern(
        text_totals,
        text,
        DIRECT_BASE_DEREF_RE,
        "direct_base_deref_patterns",
        "functions_with_direct_base_derefs",
    )
    _count_pattern(
        text_totals,
        text,
        POINTER_INDEXED_OFFSET_DEREF_RE,
        "pointer_indexed_offset_deref_patterns",
        "functions_with_pointer_indexed_offset_derefs",
    )
    _count_pattern(text_totals, text, LABEL_RE, "label_tokens", "functions_with_labels")
    _count_pattern(
        text_totals,
        text,
        DECIMAL_STATUS_RE,
        "decimal_status_like_literals",
        "functions_with_decimal_status_like_literals",
    )
    _count_pattern(text_totals, text, HEX_STATUS_RE, "hex_status_like_literals", "functions_with_hex_status_like_literals")
    _count_profiled_status_argument_literals(text_totals, text)
    _count_ntstatus_family_literals(text_totals, text)


def _update_visible_review_only_field_alias_metrics(text_totals: Counter[str], text: str) -> None:
    comments = list(VISIBLE_REVIEW_ONLY_FIELD_ALIAS_RE.finditer(text or ""))
    if not comments:
        return
    text_totals["visible_review_only_field_alias_annotations"] += len(comments)
    text_totals["functions_with_visible_review_only_field_aliases"] += 1
    alias_tokens = 0
    for comment in comments:
        alias_tokens += len(VISIBLE_REVIEW_ONLY_FIELD_ALIAS_TOKEN_RE.findall(comment.group(0)))
    text_totals["visible_review_only_field_alias_tokens"] += alias_tokens


def _strip_visible_review_only_field_alias_comments(text: str) -> str:
    return VISIBLE_REVIEW_ONLY_FIELD_ALIAS_RE.sub("", text or "")


def _update_synthetic_aggregate_metrics(text_totals: Counter[str], text: str) -> None:
    raw_text = text or ""
    for key in (
        "synthetic_local_aggregate_candidates",
        "synthetic_pool_aggregate_candidates",
        "functions_with_synthetic_local_aggregate_view",
        "inline_review_only_aggregate_aliases",
        "inline_review_only_aggregate_alias_tokens",
        "projected_aggregate_accesses",
        "projected_aggregate_access_tokens",
        "blocked_aggregate_candidates",
        "aggregate_projection_policy_balanced",
        "aggregate_projection_policy_projection_heavy",
        "aggregate_projection_policy_review_only",
        "aggregate_projection_policy_audit_strict",
        "aggregate_canonical_rewrite_attempts",
        "aggregate_misleading_rewrites",
    ):
        text_totals[key] += 0
    candidates = len(SYNTHETIC_AGGREGATE_COMMENT_RE.findall(raw_text))
    pool_candidates = len(SYNTHETIC_POOL_AGGREGATE_COMMENT_RE.findall(raw_text))
    blocked_candidates = len(SYNTHETIC_BLOCKED_AGGREGATE_COMMENT_RE.findall(raw_text))
    inline_aliases = list(INLINE_REVIEW_ONLY_AGGREGATE_ALIAS_RE.finditer(raw_text))
    projected_accesses = list(PROJECTED_AGGREGATE_ACCESS_RE.finditer(raw_text))
    misleading = len(AGGREGATE_MISLEADING_REWRITE_RE.findall(raw_text))
    canonical_attempts = len(re.findall(r"\bcanonical aggregate rewrite (?:applied|attempted)\b", raw_text))
    if candidates:
        text_totals["synthetic_local_aggregate_candidates"] += candidates
    if pool_candidates:
        text_totals["synthetic_pool_aggregate_candidates"] += pool_candidates
    if blocked_candidates:
        text_totals["blocked_aggregate_candidates"] += blocked_candidates
    if inline_aliases:
        text_totals["inline_review_only_aggregate_aliases"] += len(inline_aliases)
        tokens = 0
        for alias in inline_aliases:
            tokens += len(INLINE_REVIEW_ONLY_AGGREGATE_ALIAS_TOKEN_RE.findall(alias.group(0)))
        text_totals["inline_review_only_aggregate_alias_tokens"] += tokens
    if projected_accesses:
        text_totals["projected_aggregate_accesses"] += len(projected_accesses)
        projected_tokens = 0
        for projected in projected_accesses:
            for token in PROJECTED_AGGREGATE_ACCESS_TOKEN_RE.finditer(projected.group(0)):
                projected_tokens += 1
                policy = str(token.group("policy") or "").lower()
                key = "aggregate_projection_policy_%s" % policy
                if key in text_totals:
                    text_totals[key] += 1
        text_totals["projected_aggregate_access_tokens"] += projected_tokens
    if candidates or inline_aliases or projected_accesses:
        text_totals["functions_with_synthetic_local_aggregate_view"] += 1
    if canonical_attempts:
        text_totals["aggregate_canonical_rewrite_attempts"] += canonical_attempts
    if misleading:
        text_totals["aggregate_misleading_rewrites"] += misleading


def _strip_pseudoforge_header(text: str) -> str:
    raw_text = text or ""
    stripped = raw_text.lstrip()
    leading_whitespace = len(raw_text) - len(stripped)
    if stripped.startswith("/*"):
        consumed = leading_whitespace
        candidate_lines = stripped.splitlines(keepends=True)
        header_lines: list[str] = []
        for line in candidate_lines:
            header_lines.append(line)
            consumed += len(line)
            if line.strip() == "*/":
                header = "".join(header_lines)
                if any(marker in header for marker in ("Generated by PseudoForge", "Kernel insights:", "Rename candidates:")):
                    return raw_text[consumed:]
                return raw_text

    match = re.match(r"\s*/\*(?P<header>.*?)\*/\s*", raw_text, flags=re.DOTALL)
    if match is None:
        return raw_text
    header = match.group("header")
    if not any(marker in header for marker in ("Generated by PseudoForge", "Kernel insights:", "Rename candidates:")):
        return raw_text
    return raw_text[match.end() :]


def _decimal_status_like_literals(text: str) -> list[dict[str, Any]]:
    result = []
    declaration_types = _local_declaration_types(text)
    for match in NUMERIC_LITERAL_RE.finditer(text or ""):
        literal = match.group("literal")
        if literal.lower().startswith("0x") or not _is_decimal_status_like_literal(literal):
            continue
        context_kind = _decimal_status_like_context_kind(text, match)
        if not context_kind:
            continue
        parsed = _parse_numeric_literal(literal)
        if parsed is None:
            continue
        unsigned_value = parsed & 0xFFFFFFFF
        profile_name = _ntstatus_profile_name(parsed, literal)
        line_text = _line_for_match(text, match.start(), match.end()).strip()
        severity = _ntstatus_severity_name(unsigned_value)
        target_name = _decimal_status_target_name(line_text, literal, context_kind)
        target_type = declaration_types.get(target_name, "")
        target_evidence = _decimal_status_target_evidence(text, target_name, target_type, context_kind)
        review_class = _decimal_status_review_class(
            unsigned_value,
            profile_name,
            severity,
            context_kind,
            line_text,
            literal,
            text,
            target_name,
            target_evidence,
        )
        target_review_hint = _decimal_status_target_review_hint(
            text,
            target_name,
            target_type,
            target_evidence,
            context_kind,
            review_class,
        )
        result.append(
            {
                "literal": literal,
                "unsigned_value": unsigned_value,
                "signed_value": _signed_32bit_value(unsigned_value),
                "hex_value": "0x%08X" % unsigned_value,
                "profile_name": profile_name,
                "profiled": profile_name != "",
                "context_kind": context_kind,
                "severity": severity,
                "target_name": target_name,
                "target_type": target_type,
                "target_evidence": target_evidence,
                "review_class": review_class,
                "target_review_hint": target_review_hint,
                "line": _line_number_for_offset(text, match.start()),
                "line_text": line_text,
            }
        )
    return result


def _is_decimal_status_like_literal(literal: str) -> bool:
    digits = str(literal or "")
    if digits.startswith("-"):
        digits = digits[1:]
    return digits.startswith("107374") or digits.startswith("322122") or len(digits) >= 8


def _decimal_status_like_context_kind(text: str, match: re.Match[str]) -> str:
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    if line_end < 0:
        line_end = len(text)
    prefix = text[line_start : match.start()]
    suffix = text[match.end() : line_end]
    if re.search(r"\breturn\s*$", prefix):
        return "return"
    if re.search(r"(?:==|!=)\s*$", prefix) or re.match(r"\s*(?:==|!=)", suffix):
        return "comparison"
    if re.search(r"(?<![=!<>])=\s*$", prefix):
        return "assignment"
    return ""


def _decimal_status_target_name(line_text: str, literal: str, context_kind: str) -> str:
    if context_kind == "assignment":
        match = re.match(
            r"\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?:\([^)]+\)\s*)?%s(?:u?LL|ULL|LL|u|U|L)?\b" % re.escape(literal),
            line_text or "",
        )
        if match is not None:
            return match.group("target")
        return ""
    if context_kind == "comparison":
        suffix = r"(?:u?LL|ULL|LL|u|U|L)?"
        identifier_first = re.search(
            r"(?<![A-Za-z0-9_*>.\]])(?:\([^)]+\)\s*)?"
            r"(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=)\s*"
            r"%s%s\b" % (re.escape(literal), suffix),
            line_text or "",
        )
        if identifier_first is not None:
            return identifier_first.group("target")
        literal_first = re.search(
            r"(?<![A-Za-z0-9_])%s%s\s*(?:==|!=)\s*"
            r"(?:\([^)]+\)\s*)?(?P<target>[A-Za-z_][A-Za-z0-9_]*)\b"
            % (re.escape(literal), suffix),
            line_text or "",
        )
        if literal_first is not None:
            return literal_first.group("target")
    return ""


def _decimal_status_target_evidence(text: str, target_name: str, target_type: str, context_kind: str) -> str:
    if not target_name:
        return "complex_or_memory_target"
    if _is_status_identifier_name(target_name):
        return "status_identifier_target"
    if _is_ntstatus_type(target_type):
        return "ntstatus_declared_target"
    if context_kind == "comparison":
        if _has_status_assignment_alias_use(text, target_name):
            return "status_assignment_alias_target"
        if _has_call_result_assignment_use(text, target_name) and _has_status_carrier_use(text, target_name):
            return "call_result_status_carrier_target"
        if _has_status_carrier_use(text, target_name):
            return "status_carrier_comparison_target"
    if _is_four_byte_status_candidate_type(target_type):
        if _has_status_carrier_use(text, target_name):
            return "four_byte_status_carrier_target"
        return "four_byte_scalar_target"
    if target_type:
        return "wide_or_nonstatus_target"
    return "unknown_target"


def _decimal_status_target_review_hint(
    text: str,
    target_name: str,
    target_type: str,
    target_evidence: str,
    context_kind: str,
    review_class: str,
) -> str:
    if target_evidence == "four_byte_scalar_target":
        if review_class == "ascii_magic_candidate":
            return "four_byte_scalar_ascii_magic_review"
        if review_class == "nonstatus_magic_candidate":
            return "four_byte_scalar_nonstatus_magic_review"
        if review_class == "bitmask_comparison_candidate":
            return "four_byte_scalar_bitmask_review"
        if review_class == "small_enum_comparison_candidate":
            return "four_byte_scalar_small_enum_comparison_review"
        if review_class == "debug_exception_assignment_candidate":
            return "four_byte_scalar_debug_exception_assignment_review"
        if target_name and _has_call_result_assignment_use(text, target_name):
            return "four_byte_scalar_call_result_review"
        if target_name and _has_mixed_debug_exception_assignment_use(text, target_name):
            return "four_byte_scalar_debug_exception_assignment_review"
        if target_name and _has_profiled_status_literal_assignment_use(text, target_name):
            return "four_byte_scalar_status_literal_assignment_review"
        if context_kind == "assignment":
            return "four_byte_scalar_assignment_review"
        if context_kind == "comparison":
            return "four_byte_scalar_comparison_review"
        return "four_byte_scalar_review"
    if target_evidence == "complex_or_memory_target":
        return "complex_or_memory_review"
    if target_evidence == "wide_or_nonstatus_target":
        return "wide_or_nonstatus_review"
    if target_evidence == "unknown_target":
        return "unknown_target_review"
    if target_evidence in {"status_identifier_target", "ntstatus_declared_target"}:
        return "strong_status_target"
    return "status_flow_target"


def _decimal_status_review_class(
    unsigned_value: int,
    profile_name: str,
    severity: str,
    context_kind: str,
    line_text: str,
    literal: str,
    text: str,
    target_name: str,
    target_evidence: str,
) -> str:
    if (
        context_kind == "assignment"
        and target_evidence == "four_byte_scalar_target"
        and _is_debug_exception_status_profile(profile_name)
        and _has_nonstatus_literal_assignment_use(text, target_name)
    ):
        return "debug_exception_assignment_candidate"
    if (
        context_kind == "comparison"
        and target_evidence == "four_byte_scalar_target"
        and _line_has_mixed_small_enum_comparison_context(line_text, target_name, literal)
    ):
        return "small_enum_comparison_candidate"
    if profile_name:
        if context_kind == "assignment" and target_evidence not in {
            "status_identifier_target",
            "ntstatus_declared_target",
            "four_byte_status_carrier_target",
        }:
            return "profiled_status_literal_weak_target"
        return "profiled_status_literal_candidate"
    if context_kind == "comparison" and _line_has_bitwise_comparison_context(line_text, re.escape(literal)):
        return "bitmask_comparison_candidate"
    if _is_ascii_magic_value(unsigned_value):
        return "ascii_magic_candidate"
    if _is_known_nonstatus_magic_value(unsigned_value):
        return "nonstatus_magic_candidate"
    if severity == "error":
        return "unprofiled_ntstatus_error_candidate"
    return "manual_review"


def _line_has_mixed_small_enum_comparison_context(line_text: str, target_name: str, literal: str) -> bool:
    if not line_text or not target_name:
        return False

    escaped_target = re.escape(target_name)
    value_pattern = r"-?(?:0x[0-9A-Fa-f]+|\d+)(?:u?LL|ULL|LL|u|U|L)?"
    values: list[str] = []
    identifier_first = re.compile(
        r"(?<![A-Za-z0-9_*>.\]])(?:\([^)]+\)\s*)?"
        r"%s\s*(?:==|!=)\s*(?P<value>%s)\b" % (escaped_target, value_pattern)
    )
    literal_first = re.compile(
        r"(?<![A-Za-z0-9_])(?P<value>%s)\s*(?:==|!=)\s*"
        r"(?:\([^)]+\)\s*)?%s\b" % (value_pattern, escaped_target)
    )
    for pattern in (identifier_first, literal_first):
        values.extend(match.group("value") for match in pattern.finditer(line_text))

    escaped_literal = re.escape(literal)
    if any(
        _is_small_nonzero_enum_literal(value)
        for value in values
        if not re.fullmatch(escaped_literal + r"(?:u?LL|ULL|LL|u|U|L)?", value)
    ):
        return True

    compact_range_pattern = re.compile(
        r"\(\s*(?:unsigned\s+int|int|_DWORD|unsigned\s+__int32)?\s*\)?\s*"
        r"\(\s*%s\s*-\s*(?P<base>0x[0-9A-Fa-f]+|\d+)\s*\)\s*"
        r"(?:<=|<)\s*(?P<width>0x[0-9A-Fa-f]+|\d+)" % escaped_target
    )
    return any(
        _is_small_nonzero_enum_literal(match.group("base"))
        and _is_small_nonzero_enum_literal(match.group("width"))
        for match in compact_range_pattern.finditer(line_text)
    )


def _is_small_nonzero_enum_literal(value: str) -> bool:
    cleaned = re.sub(r"(?:u?LL|ULL|LL|u|U|L)$", "", str(value or ""))
    parsed = _parse_numeric_literal(cleaned)
    if parsed is None:
        return False
    return 0 < parsed <= 0xFF


def _has_mixed_debug_exception_assignment_use(text: str, name: str) -> bool:
    return (
        _has_debug_exception_status_literal_assignment_use(text, name)
        and _has_nonstatus_literal_assignment_use(text, name)
    )


def _has_debug_exception_status_literal_assignment_use(text: str, name: str) -> bool:
    escaped = re.escape(name or "")
    if not escaped:
        return False
    assignment_pattern = re.compile(
        r"(?m)^[ \t]*%s\s*=\s*(?:\([^)]+\)\s*)?"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\s*;" % escaped
    )
    for match in assignment_pattern.finditer(text or ""):
        literal = match.group("literal")
        parsed = _parse_numeric_literal(literal)
        if parsed is not None and _is_debug_exception_status_profile(_ntstatus_profile_name(parsed, literal)):
            return True
    return False


def _has_nonstatus_literal_assignment_use(text: str, name: str) -> bool:
    escaped = re.escape(name or "")
    if not escaped:
        return False
    assignment_pattern = re.compile(
        r"(?m)^[ \t]*%s\s*=\s*(?:\([^)]+\)\s*)?"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\s*;" % escaped
    )
    for match in assignment_pattern.finditer(text or ""):
        literal = match.group("literal")
        parsed = _parse_numeric_literal(literal)
        if parsed is None or parsed == 0:
            continue
        if not _ntstatus_profile_name(parsed, literal):
            return True
    return False


def _is_debug_exception_status_profile(profile_name: str) -> bool:
    return str(profile_name or "") in _DEBUG_EXCEPTION_STATUS_NAMES


def _is_ascii_magic_value(unsigned_value: int) -> bool:
    value = int(unsigned_value) & 0xFFFFFFFF
    for byte_order in ("little", "big"):
        raw = value.to_bytes(4, byte_order)
        if all(32 <= byte <= 126 for byte in raw) and any(chr(byte).isalnum() for byte in raw):
            return True
    return False


def _is_known_nonstatus_magic_value(unsigned_value: int) -> bool:
    value = int(unsigned_value) & 0xFFFFFFFF
    return value in _KNOWN_CRYPTO_INITIAL_VALUES or value in _KNOWN_DEBUG_FILL_VALUES


def _local_declaration_types(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    declaration_pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|\[)"
    )
    for match in declaration_pattern.finditer(text or ""):
        name = match.group("name")
        result.setdefault(name, re.sub(r"\s+", " ", match.group("type")).strip())
    return result


def _is_status_identifier_name(name: str) -> bool:
    lowered = str(name or "").lower()
    if lowered in {"status", "updated", "result", "returnstatus", "ntstatus"}:
        return True
    return "status" in lowered


def _normalize_scalar_type(type_text: str) -> str:
    normalized = re.sub(r"\b(?:const|volatile|signed)\b", " ", type_text or "", flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", normalized).strip().upper()


def _is_ntstatus_type(type_text: str) -> bool:
    return _normalize_scalar_type(type_text) == "NTSTATUS"


def _is_four_byte_status_candidate_type(type_text: str) -> bool:
    if not type_text or "*" in type_text or "&" in type_text:
        return False
    normalized = _normalize_scalar_type(type_text)
    return normalized in {
        "_DWORD",
        "INT",
        "UNSIGNED INT",
        "LONG",
        "ULONG",
        "DWORD",
        "NTSTATUS",
        "__INT32",
        "UNSIGNED __INT32",
        "INT32_T",
        "UINT32_T",
    }


def _has_status_carrier_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    return any(
        re.search(pattern % escaped, text or "")
        for pattern in (
            r"\b%s\s*(?:<|>=)\s*0\b",
            r"\b0\s*(?:>|<=)\s*%s\b",
            r"\breturn\s+(?:\(unsigned int\)\s*)?%s\s*;",
        )
    )


def _has_status_assignment_alias_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    assignment_pattern = re.compile(
        r"(?m)^[ \t]*(?P<status>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:\([^)]+\)\s*)?%s\s*;" % escaped,
        flags=re.IGNORECASE,
    )
    return any(
        _is_status_identifier_name(match.group("status"))
        for match in assignment_pattern.finditer(text or "")
    )


def _has_call_result_assignment_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    if re.search(
        r"(?m)^[ \t]*%s\s*=\s*(?:\([^)]+\)\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(" % escaped,
        text or "",
    ):
        return True
    if re.search(
        r"(?m)^[ \t]*%s\s*=\s*[^;\n]*\([^;\n]*\)[^;\n]*\s*;" % escaped,
        text or "",
    ):
        return True
    return re.search(
        r"(?m)^[ \t]*%s\s*=\s*\(\*.*\)\s*\(" % escaped,
        text or "",
    ) is not None


def _has_profiled_status_literal_assignment_use(text: str, name: str) -> bool:
    escaped = re.escape(name)
    assignment_pattern = re.compile(
        r"(?m)^[ \t]*%s\s*=\s*(?:\([^)]+\)\s*)?"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))"
        r"(?P<suffix>u?LL|ULL|LL|u|U|L)?\s*;" % escaped
    )
    for match in assignment_pattern.finditer(text or ""):
        literal = match.group("literal")
        parsed = _parse_numeric_literal(literal)
        if parsed is not None and _ntstatus_profile_name(parsed, literal):
            return True
    return False


def _update_decimal_status_residue_metrics(
    literals: list[dict[str, Any]],
    values: Counter[str],
    profile_names: Counter[str],
    context_kinds: Counter[str],
    review_classes: Counter[str],
    target_evidence: Counter[str],
    target_review_hints: Counter[str],
) -> None:
    for item in literals:
        values[str(item.get("hex_value", "") or "unknown")] += 1
        profile_name = str(item.get("profile_name", "") or "unprofiled")
        profile_names[profile_name] += 1
        context_kinds[str(item.get("context_kind", "") or "unknown")] += 1
        review_classes[str(item.get("review_class", "") or "manual_review")] += 1
        target_evidence[str(item.get("target_evidence", "") or "none")] += 1
        target_review_hints[str(item.get("target_review_hint", "") or "manual_review")] += 1


def _decimal_status_residue_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    literals: list[dict[str, Any]],
) -> dict[str, Any]:
    context_kinds = Counter(str(item.get("context_kind", "") or "unknown") for item in literals)
    values = Counter(str(item.get("hex_value", "") or "unknown") for item in literals)
    profile_names = Counter(str(item.get("profile_name", "") or "unprofiled") for item in literals)
    review_classes = Counter(str(item.get("review_class", "") or "manual_review") for item in literals)
    target_evidence = Counter(str(item.get("target_evidence", "") or "none") for item in literals)
    target_review_hints = Counter(str(item.get("target_review_hint", "") or "manual_review") for item in literals)
    target_review_classes: dict[str, Counter[str]] = {}
    target_review_hints_by_evidence: dict[str, Counter[str]] = {}
    for item in literals:
        target = str(item.get("target_evidence", "") or "none")
        review_class = str(item.get("review_class", "") or "manual_review")
        review_hint = str(item.get("target_review_hint", "") or "manual_review")
        if target not in target_review_classes:
            target_review_classes[target] = Counter()
        if target not in target_review_hints_by_evidence:
            target_review_hints_by_evidence[target] = Counter()
        target_review_classes[target][review_class] += 1
        target_review_hints_by_evidence[target][review_hint] += 1
    contexts = []
    for item in literals[:5]:
        contexts.append(
            {
                "line": int(item.get("line", 0) or 0),
                "kind": str(item.get("context_kind", "") or "unknown"),
                "literal": str(item.get("literal", "") or ""),
                "hex_value": str(item.get("hex_value", "") or ""),
                "profile_name": str(item.get("profile_name", "") or ""),
                "review_class": str(item.get("review_class", "") or "manual_review"),
                "target_name": str(item.get("target_name", "") or ""),
                "target_type": str(item.get("target_type", "") or ""),
                "target_evidence": str(item.get("target_evidence", "") or "none"),
                "target_review_hint": str(item.get("target_review_hint", "") or "manual_review"),
                "source": str(item.get("line_text", "") or ""),
            }
        )
    profiled_count = sum(1 for item in literals if bool(item.get("profiled")))
    return {
        "name": name,
        "ea": ea,
        "literal_count": len(literals),
        "profiled_count": profiled_count,
        "unprofiled_count": len(literals) - profiled_count,
        "context_kinds": dict(context_kinds.most_common()),
        "values": dict(values.most_common()),
        "profile_names": dict(profile_names.most_common()),
        "review_classes": dict(review_classes.most_common()),
        "target_evidence": dict(target_evidence.most_common()),
        "target_review_hints": dict(target_review_hints.most_common()),
        "target_review_classes": {
            key: dict(value.most_common())
            for key, value in sorted(target_review_classes.items())
        },
        "target_review_hints_by_evidence": {
            key: dict(value.most_common())
            for key, value in sorted(target_review_hints_by_evidence.items())
        },
        "contexts": contexts,
        "summary_path": str(summary_path),
    }


def _decimal_status_review_queues(
    functions: list[dict[str, Any]],
    top: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for queue_name in _DECIMAL_STATUS_REVIEW_QUEUE_ORDER:
        queue_classes = _decimal_status_review_queue_classes(queue_name)
        items: list[dict[str, Any]] = []
        class_counts: Counter[str] = Counter()
        target_counts: Counter[str] = Counter()
        literal_total = 0
        function_names: set[str] = set()
        for function in functions:
            review_classes = _coerce_dict(function.get("review_classes", {}))
            matching_literal_count = sum(int(review_classes.get(name, 0) or 0) for name in queue_classes)
            if matching_literal_count <= 0:
                continue
            function_names.add(str(function.get("name", "") or ""))
            literal_total += matching_literal_count
            class_counts.update(
                {
                    name: int(review_classes.get(name, 0) or 0)
                    for name in queue_classes
                    if int(review_classes.get(name, 0) or 0) > 0
                }
            )
            item = _decimal_status_review_queue_item(function, queue_classes, matching_literal_count)
            matching_targets = Counter(
                str(context.get("target_evidence", "") or "none")
                for context in item.get("contexts", []) or []
                if isinstance(context, dict)
            )
            if matching_targets:
                target_counts.update(matching_targets)
            else:
                target_counts.update(_coerce_dict(function.get("target_evidence", {})))
            items.append(item)
        items.sort(key=lambda item: (-int(item.get("literals", 0) or 0), str(item.get("name", ""))))
        result[queue_name] = {
            "literals": literal_total,
            "functions": len(function_names),
            "review_classes": _counter_to_dict(Counter(dict(class_counts.most_common(top)))),
            "target_evidence": _counter_to_dict(Counter(dict(target_counts.most_common(top)))),
            "items": items[:top],
        }
    return result


def _decimal_status_review_queue_classes(queue_name: str) -> set[str]:
    mapping = {
        "strong_profiled_status_literals": {"profiled_status_literal_candidate"},
        "weak_target_profiled_status_literals": {"profiled_status_literal_weak_target"},
        "unprofiled_ntstatus_error_literals": {"unprofiled_ntstatus_error_candidate"},
        "nonstatus_magic_literals": {"nonstatus_magic_candidate"},
        "nonstatus_ascii_magic_literals": {"ascii_magic_candidate"},
        "nonstatus_bitmask_comparisons": {"bitmask_comparison_candidate"},
        "nonstatus_small_enum_comparisons": {"small_enum_comparison_candidate"},
        "nonstatus_debug_exception_assignments": {"debug_exception_assignment_candidate"},
        "manual_review": {"manual_review"},
    }
    return set(mapping.get(queue_name, {"manual_review"}))


def _decimal_status_target_review_queues(
    functions: list[dict[str, Any]],
    top: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for queue_name in _DECIMAL_STATUS_TARGET_REVIEW_QUEUE_ORDER:
        target_evidence = _decimal_status_target_review_queue_evidence(queue_name)
        items: list[dict[str, Any]] = []
        class_counts: Counter[str] = Counter()
        target_counts: Counter[str] = Counter()
        hint_counts: Counter[str] = Counter()
        literal_total = 0
        function_names: set[str] = set()
        for function in functions:
            function_target_counts = _coerce_dict(function.get("target_evidence", {}))
            matching_literal_count = sum(
                int(function_target_counts.get(target, 0) or 0)
                for target in target_evidence
            )
            if matching_literal_count <= 0:
                continue
            contexts = [
                context
                for context in function.get("contexts", []) or []
                if isinstance(context, dict)
                and str(context.get("target_evidence", "") or "none") in target_evidence
            ]
            function_names.add(str(function.get("name", "") or ""))
            literal_total += matching_literal_count
            function_target_review_classes = _coerce_dict(
                function.get("target_review_classes", {})
            )
            function_target_review_hints = _coerce_dict(
                function.get("target_review_hints_by_evidence", {})
            )
            for target in target_evidence:
                class_counts.update(
                    _coerce_dict(function_target_review_classes.get(target, {}))
                )
                hint_counts.update(
                    _coerce_dict(function_target_review_hints.get(target, {}))
                )
            target_counts.update(
                {
                    target: int(function_target_counts.get(target, 0) or 0)
                    for target in target_evidence
                    if int(function_target_counts.get(target, 0) or 0) > 0
                }
            )
            items.append(
                _decimal_status_target_review_queue_item(
                    function,
                    contexts,
                    target_evidence,
                    matching_literal_count,
                )
            )
        items.sort(key=lambda item: (-int(item.get("literals", 0) or 0), str(item.get("name", ""))))
        result[queue_name] = {
            "literals": literal_total,
            "functions": len(function_names),
            "review_classes": _counter_to_dict(Counter(dict(class_counts.most_common(top)))),
            "target_evidence": _counter_to_dict(Counter(dict(target_counts.most_common(top)))),
            "target_review_hints": _counter_to_dict(Counter(dict(hint_counts.most_common(top)))),
            "items": items[:top],
        }
    return result


def _decimal_status_target_review_queue_evidence(queue_name: str) -> set[str]:
    mapping = {
        "complex_or_memory_targets": {"complex_or_memory_target"},
        "four_byte_scalar_targets": {"four_byte_scalar_target"},
        "wide_or_nonstatus_targets": {"wide_or_nonstatus_target"},
        "unknown_targets": {"unknown_target"},
    }
    return set(mapping.get(queue_name, {"unknown_target"}))


def _decimal_status_target_review_queue_item(
    function: dict[str, Any],
    contexts: list[dict[str, Any]],
    target_evidence: set[str],
    literal_count: int,
) -> dict[str, Any]:
    function_target_counts = _coerce_dict(function.get("target_evidence", {}))
    function_target_review_classes = _coerce_dict(function.get("target_review_classes", {}))
    function_target_review_hints = _coerce_dict(function.get("target_review_hints_by_evidence", {}))
    review_classes: Counter[str] = Counter()
    review_hints: Counter[str] = Counter()
    for target in target_evidence:
        review_classes.update(_coerce_dict(function_target_review_classes.get(target, {})))
        review_hints.update(_coerce_dict(function_target_review_hints.get(target, {})))
    return {
        "name": str(function.get("name", "") or ""),
        "ea": str(function.get("ea", "") or ""),
        "literals": int(literal_count),
        "review_classes": _counter_to_dict(review_classes),
        "target_review_hints": _counter_to_dict(review_hints),
        "target_evidence": _counter_to_dict(
            Counter(
                {
                    target: int(function_target_counts.get(target, 0) or 0)
                    for target in target_evidence
                    if int(function_target_counts.get(target, 0) or 0) > 0
                }
            )
        ),
        "contexts": contexts[:3],
        "summary_path": str(function.get("summary_path", "") or ""),
    }


def _decimal_status_review_queue_item(
    function: dict[str, Any],
    queue_classes: set[str],
    literal_count: int,
) -> dict[str, Any]:
    contexts = [
        context
        for context in function.get("contexts", []) or []
        if isinstance(context, dict) and str(context.get("review_class", "")) in queue_classes
    ]
    return {
        "name": str(function.get("name", "") or ""),
        "ea": str(function.get("ea", "") or ""),
        "literals": int(literal_count),
        "review_classes": {
            key: value
            for key, value in _coerce_dict(function.get("review_classes", {})).items()
            if key in queue_classes
        },
        "target_evidence": _coerce_dict(function.get("target_evidence", {})),
        "contexts": contexts[:3],
        "summary_path": str(function.get("summary_path", "") or ""),
    }


def _nested_status_pointer_store_literals(text: str) -> list[dict[str, Any]]:
    result = []
    pattern = re.compile(
        r"(?m)^(?P<indent>[ \t]*)"
        r"(?P<target>\*\*\s*\((?P<store_type>[^)\n;]*\*\*)\)\s*(?P<address>[^=\n;]+?))\s*=\s*"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?\s*;"
    )
    for match in pattern.finditer(text or ""):
        literal = match.group("literal")
        parsed = _parse_numeric_literal(literal)
        if parsed is None:
            continue
        unsigned_value = parsed & 0xFFFFFFFF
        severity = _ntstatus_severity_name(unsigned_value)
        if severity != "error":
            continue
        profile_name = _ntstatus_profile_name(parsed, literal)
        store_type = re.sub(r"\s+", " ", match.group("store_type")).strip()
        width = _nested_pointer_store_width(store_type)
        line_text = _line_for_match(text, match.start(), match.end()).strip()
        result.append(
            {
                "literal": literal,
                "unsigned_value": unsigned_value,
                "signed_value": _signed_32bit_value(unsigned_value),
                "hex_value": "0x%08X" % unsigned_value,
                "profile_name": profile_name,
                "profiled": profile_name != "",
                "severity": severity,
                "store_type": store_type,
                "store_width": width,
                "target": match.group("target").strip(),
                "address": match.group("address").strip(),
                "review_class": _nested_status_store_review_class(profile_name, width),
                "line": _line_number_for_offset(text, match.start()),
                "line_text": line_text,
            }
        )
    return result


def _nested_pointer_store_width(store_type: str) -> str:
    normalized = _normalize_scalar_type((store_type or "").replace("*", " "))
    if any(token in normalized for token in ("_DWORD", "DWORD", "ULONG", "LONG", "INT", "NTSTATUS")):
        return "dword"
    if any(token in normalized for token in ("_QWORD", "QWORD", "__INT64", "ULONG_PTR", "UINT64")):
        return "wide"
    return "unknown"


def _nested_status_store_review_class(profile_name: str, store_width: str) -> str:
    if store_width == "dword":
        return "dword_nested_pointer_status_store_candidate"
    if store_width == "wide":
        return "wide_nested_pointer_status_store_review"
    if profile_name:
        return "manual_review"
    return "manual_review"


def _update_nested_status_store_metrics(
    stores: list[dict[str, Any]],
    values: Counter[str],
    profile_names: Counter[str],
    widths: Counter[str],
    review_classes: Counter[str],
) -> None:
    for item in stores:
        values[str(item.get("hex_value", "") or "unknown")] += 1
        profile_name = str(item.get("profile_name", "") or "unprofiled")
        profile_names[profile_name] += 1
        widths[str(item.get("store_width", "") or "unknown")] += 1
        review_classes[str(item.get("review_class", "") or "manual_review")] += 1


def _nested_status_store_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    stores: list[dict[str, Any]],
) -> dict[str, Any]:
    values = Counter(str(item.get("hex_value", "") or "unknown") for item in stores)
    profile_names = Counter(str(item.get("profile_name", "") or "unprofiled") for item in stores)
    widths = Counter(str(item.get("store_width", "") or "unknown") for item in stores)
    review_classes = Counter(str(item.get("review_class", "") or "manual_review") for item in stores)
    review_class_store_widths: dict[str, Counter[str]] = {}
    for item in stores:
        review_class = str(item.get("review_class", "") or "manual_review")
        width = str(item.get("store_width", "") or "unknown")
        review_class_store_widths.setdefault(review_class, Counter())[width] += 1
    contexts = []
    for item in stores[:5]:
        contexts.append(
            {
                "line": int(item.get("line", 0) or 0),
                "literal": str(item.get("literal", "") or ""),
                "hex_value": str(item.get("hex_value", "") or ""),
                "profile_name": str(item.get("profile_name", "") or ""),
                "store_width": str(item.get("store_width", "") or "unknown"),
                "store_type": str(item.get("store_type", "") or ""),
                "review_class": str(item.get("review_class", "") or "manual_review"),
                "target": str(item.get("target", "") or ""),
                "address": str(item.get("address", "") or ""),
                "source": str(item.get("line_text", "") or ""),
            }
        )
    dword_store_count = sum(1 for item in stores if str(item.get("store_width", "")) == "dword")
    profiled_count = sum(1 for item in stores if bool(item.get("profiled")))
    return {
        "name": name,
        "ea": ea,
        "store_count": len(stores),
        "dword_store_count": dword_store_count,
        "wide_store_count": sum(1 for item in stores if str(item.get("store_width", "")) == "wide"),
        "profiled_count": profiled_count,
        "unprofiled_count": len(stores) - profiled_count,
        "values": dict(values.most_common()),
        "profile_names": dict(profile_names.most_common()),
        "store_widths": dict(widths.most_common()),
        "review_classes": dict(review_classes.most_common()),
        "review_class_store_widths": {
            key: dict(value.most_common())
            for key, value in sorted(review_class_store_widths.items())
        },
        "contexts": contexts,
        "summary_path": str(summary_path),
    }


def _nested_status_store_review_queues(
    functions: list[dict[str, Any]],
    top: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for queue_name in _STATUS_STORE_REVIEW_QUEUE_ORDER:
        queue_classes = _nested_status_store_review_queue_classes(queue_name)
        items: list[dict[str, Any]] = []
        class_counts: Counter[str] = Counter()
        width_counts: Counter[str] = Counter()
        store_total = 0
        function_names: set[str] = set()
        for function in functions:
            review_classes = _coerce_dict(function.get("review_classes", {}))
            matching_store_count = sum(int(review_classes.get(name, 0) or 0) for name in queue_classes)
            if matching_store_count <= 0:
                continue
            function_names.add(str(function.get("name", "") or ""))
            store_total += matching_store_count
            class_counts.update(
                {
                    name: int(review_classes.get(name, 0) or 0)
                    for name in queue_classes
                    if int(review_classes.get(name, 0) or 0) > 0
                }
            )
            item = _nested_status_store_review_queue_item(function, queue_classes, matching_store_count)
            width_counts.update(_coerce_dict(item.get("store_widths", {})))
            items.append(item)
        items.sort(key=lambda item: (-int(item.get("stores", 0) or 0), str(item.get("name", ""))))
        result[queue_name] = {
            "stores": store_total,
            "functions": len(function_names),
            "review_classes": _counter_to_dict(Counter(dict(class_counts.most_common(top)))),
            "store_widths": _counter_to_dict(Counter(dict(width_counts.most_common(top)))),
            "items": items[:top],
        }
    return result


def _nested_status_store_review_queue_classes(queue_name: str) -> set[str]:
    mapping = {
        "dword_nested_pointer_status_stores": {"dword_nested_pointer_status_store_candidate"},
        "wide_nested_pointer_status_stores": {"wide_nested_pointer_status_store_review"},
        "manual_review": {"manual_review"},
    }
    return set(mapping.get(queue_name, {"manual_review"}))


def _nested_status_store_review_queue_item(
    function: dict[str, Any],
    queue_classes: set[str],
    store_count: int,
) -> dict[str, Any]:
    contexts = [
        context
        for context in function.get("contexts", []) or []
        if isinstance(context, dict) and str(context.get("review_class", "")) in queue_classes
    ]
    store_widths: Counter[str] = Counter()
    review_class_store_widths = _coerce_dict(function.get("review_class_store_widths", {}))
    for queue_class in queue_classes:
        store_widths.update(_coerce_dict(review_class_store_widths.get(queue_class, {})))
    if not store_widths:
        store_widths.update(str(context.get("store_width", "") or "unknown") for context in contexts)
    return {
        "name": str(function.get("name", "") or ""),
        "ea": str(function.get("ea", "") or ""),
        "stores": int(store_count),
        "review_classes": {
            key: value
            for key, value in _coerce_dict(function.get("review_classes", {})).items()
            if key in queue_classes
        },
        "store_widths": _counter_to_dict(store_widths),
        "contexts": contexts[:3],
        "summary_path": str(function.get("summary_path", "") or ""),
    }


def _count_profiled_status_argument_literals(counter: Counter[str], text: str) -> None:
    count = _profiled_status_argument_literal_count(text)
    counter["profiled_status_argument_literals"] += count
    if count:
        counter["functions_with_profiled_status_argument_literals"] += 1


def _count_ntstatus_family_literals(counter: Counter[str], text: str) -> None:
    literals = _ntstatus_family_literals(text)
    if not literals:
        return
    counter["ntstatus_family_literals"] += len(literals)
    counter["functions_with_ntstatus_family_literals"] += 1
    known_count = sum(1 for item in literals if item["profiled"])
    unknown_count = len(literals) - known_count
    counter["ntstatus_profiled_family_literals"] += known_count
    counter["ntstatus_unprofiled_family_literals"] += unknown_count
    if unknown_count:
        counter["functions_with_ntstatus_unprofiled_family_literals"] += 1
    for item in literals:
        severity = str(item["severity"])
        counter["ntstatus_%s_family_literals" % severity] += 1
        if not item["profiled"]:
            counter["ntstatus_unprofiled_%s_family_literals" % severity] += 1


def _ntstatus_family_literals(text: str) -> list[dict[str, Any]]:
    result = []
    for match in NUMERIC_LITERAL_RE.finditer(text or ""):
        context_kind = _ntstatus_literal_context_kind(text, match)
        if not context_kind:
            continue
        parsed = _parse_numeric_literal(match.group("literal"))
        if parsed is None:
            continue
        if parsed >= 0 and parsed > 0xFFFFFFFF:
            continue
        unsigned_value = parsed & 0xFFFFFFFF
        severity = _ntstatus_severity_name(unsigned_value)
        if not severity:
            continue
        profile_name = _ntstatus_profile_name(parsed, match.group("literal"))
        if not profile_name and (
            _is_ascii_magic_value(unsigned_value) or _is_known_nonstatus_magic_value(unsigned_value)
        ):
            continue
        if not profile_name and severity != "error":
            continue
        result.append(
            {
                "literal": match.group("literal"),
                "unsigned_value": unsigned_value,
                "signed_value": _signed_32bit_value(unsigned_value),
                "hex_value": "0x%08X" % unsigned_value,
                "facility": _ntstatus_facility_value(unsigned_value),
                "facility_hex": "0x%03X" % _ntstatus_facility_value(unsigned_value),
                "code": unsigned_value & 0xFFFF,
                "code_hex": "0x%04X" % (unsigned_value & 0xFFFF),
                "customer": bool((unsigned_value >> 29) & 1),
                "line": _line_number_for_offset(text, match.start()),
                "line_text": _line_for_match(text, match.start(), match.end()).strip(),
                "context_kind": context_kind,
                "severity": severity,
                "profile_name": profile_name,
                "profiled": profile_name != "",
            }
        )
    return result


def _update_ntstatus_body_unprofiled_value_metrics(
    literals: list[dict[str, Any]],
    values: Counter[str],
    value_functions: dict[str, set[str]],
    value_contexts: dict[str, Counter[str]],
    context_kinds: Counter[str],
    function_name: str,
) -> None:
    for item in literals:
        hex_value = str(item.get("hex_value", "") or "")
        if not hex_value:
            continue
        context_kind = str(item.get("context_kind", "") or "unknown")
        values[hex_value] += 1
        value_functions.setdefault(hex_value, set()).add(str(function_name or ""))
        value_contexts.setdefault(hex_value, Counter())[context_kind] += 1
        context_kinds[context_kind] += 1


def _ntstatus_unprofiled_value_summaries(
    values: Counter[str],
    value_functions: dict[str, set[str]],
    value_contexts: dict[str, Counter[str]],
    top: int,
) -> list[dict[str, Any]]:
    result = []
    for hex_value, count in values.most_common(top):
        unsigned_value = _parse_numeric_literal(hex_value)
        if unsigned_value is None:
            continue
        result.append(
            {
                "hex_value": hex_value,
                "signed_value": _signed_32bit_value(unsigned_value & 0xFFFFFFFF),
                "facility": _ntstatus_facility_value(unsigned_value),
                "facility_hex": "0x%03X" % _ntstatus_facility_value(unsigned_value),
                "code": unsigned_value & 0xFFFF,
                "code_hex": "0x%04X" % (unsigned_value & 0xFFFF),
                "customer": bool((unsigned_value >> 29) & 1),
                "context_kinds": _counter_to_dict(value_contexts.get(hex_value, Counter())),
                "review_hint": _ntstatus_review_hint(value_contexts.get(hex_value, Counter())),
                "count": int(count),
                "function_count": len(value_functions.get(hex_value, set())),
            }
        )
    return result


def _ntstatus_body_unprofiled_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    literals: list[dict[str, Any]],
) -> dict[str, Any]:
    values = Counter(str(item.get("hex_value", "") or "") for item in literals)
    raw_literals = Counter(str(item.get("literal", "") or "") for item in literals)
    context_kinds = Counter(str(item.get("context_kind", "") or "unknown") for item in literals)
    return {
        "ea": ea,
        "name": name,
        "literal_count": len(literals),
        "review_hint": _ntstatus_review_hint(context_kinds),
        "context_kinds": _counter_to_dict(context_kinds),
        "values": _counter_to_dict(values),
        "raw_literals": _counter_to_dict(raw_literals),
        "contexts": [
            {
                "line": int(item.get("line", 0) or 0),
                "literal": str(item.get("literal", "") or ""),
                "hex_value": str(item.get("hex_value", "") or ""),
                "kind": str(item.get("context_kind", "") or "unknown"),
                "source": str(item.get("line_text", "") or ""),
            }
            for item in literals
        ],
        "summary_path": str(summary_path),
    }


def _ntstatus_facility_value(unsigned_value: int) -> int:
    return (int(unsigned_value) >> 16) & 0xFFF


def _ntstatus_review_hint(context_kinds: Counter[str]) -> str:
    kinds = {str(kind) for kind in context_kinds if str(kind)}
    if not kinds:
        return "manual_review"
    if kinds <= {"comparison"}:
        return "comparison_sentinel_candidate"
    if kinds & {"return", "assignment", "status_argument", "guard_dispatch_fallback"}:
        return "status_profile_candidate"
    return "manual_review"


def _ntstatus_review_hint_counts(value_contexts: dict[str, Counter[str]]) -> Counter[str]:
    result: Counter[str] = Counter()
    for context_kinds in value_contexts.values():
        result[_ntstatus_review_hint(context_kinds)] += 1
    return result


def _ntstatus_review_queues(
    value_summaries: list[dict[str, Any]],
    function_summaries: list[dict[str, Any]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    queue_by_hint = {
        "comparison_sentinel_candidate": "comparison_sentinel_candidates",
        "manual_review": "manual_review",
        "status_profile_candidate": "status_profile_candidates",
    }
    result = {
        "comparison_sentinel_candidates": {"values": [], "functions": []},
        "manual_review": {"values": [], "functions": []},
        "status_profile_candidates": {"values": [], "functions": []},
    }
    for item in value_summaries:
        queue_name = queue_by_hint.get(str(item.get("review_hint", "")), "manual_review")
        result[queue_name]["values"].append(item)
    for item in function_summaries:
        queue_name = queue_by_hint.get(str(item.get("review_hint", "")), "manual_review")
        result[queue_name]["functions"].append(item)
    return result


def _signed_32bit_value(unsigned_value: int) -> int:
    value = int(unsigned_value) & 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _is_ntstatus_literal_context(text: str, match: re.Match[str]) -> bool:
    return _ntstatus_literal_context_kind(text, match) != ""


def _ntstatus_literal_context_kind(text: str, match: re.Match[str]) -> str:
    line = _line_for_match(text, match.start(), match.end())
    token = re.escape(match.group(0))
    if _line_has_bitwise_literal_context(line, token):
        return ""
    for kind, pattern in (
        ("return", r"\breturn\s+(?:\([^)]+\)\s*)?%s\s*;"),
        ("comparison", r"(?:==|!=)\s*%s\b"),
        ("comparison", r"(?<![A-Za-z0-9_])%s\s*(?:==|!=)"),
        ("assignment", r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:\([^)]+\)\s*)?%s\s*;"),
        ("status_argument", r"\bSetFailureLocation\s*\([^;\n]*%s"),
        ("guard_dispatch_fallback", r"\bguard_dispatch_icall_no_overrides\s*\([^;\n]*[?:][^;\n]*%s"),
        ("guard_dispatch_fallback", r"\b%s[^;\n]*[?:][^;\n]*guard_dispatch_icall_no_overrides\s*\("),
    ):
        if re.search(pattern % token, line):
            return kind
    return ""


def _line_for_match(text: str, start: int, end: int) -> str:
    line_start = str(text or "").rfind("\n", 0, max(0, start)) + 1
    line_end = str(text or "").find("\n", max(0, end))
    if line_end < 0:
        line_end = len(str(text or ""))
    return str(text or "")[line_start:line_end]


def _line_number_for_offset(text: str, offset: int) -> int:
    return str(text or "").count("\n", 0, max(0, offset)) + 1


def _line_has_bitwise_literal_context(line: str, token: str) -> bool:
    bitwise_operator = r"(?:(?<!\|)\|(?!\|)|\^|<<|>>|(?<!&)&(?!&))"
    return (
        re.search(r"%s\s*%s" % (bitwise_operator, token), line or "") is not None
        or re.search(r"%s\s*%s" % (token, bitwise_operator), line or "") is not None
    )


def _line_has_bitwise_comparison_context(line: str, token: str) -> bool:
    text = line or ""
    bitwise_operator = r"(?:(?<!\|)\|(?!\|)|\^|<<|>>|(?<!&)&(?!&))"
    if _line_has_bitwise_literal_context(text, token):
        return True
    if re.search(bitwise_operator, text) is None:
        return False
    return (
        re.search(r"(?:==|!=)\s*%s\b" % token, text) is not None
        or re.search(r"\b%s\s*(?:==|!=)" % token, text) is not None
    )


def _ntstatus_severity_name(unsigned_value: int) -> str:
    severity = (int(unsigned_value) >> 30) & 0x3
    if severity == 1:
        return "informational"
    if severity == 2:
        return "warning"
    if severity == 3 and ((int(unsigned_value) >> 28) & 0xF) == 0xC:
        return "error"
    return ""


def _ntstatus_profile_name(value: int, literal: str) -> str:
    candidates = [str(value), str(literal)]
    unsigned_value = value & 0xFFFFFFFF
    candidates.append(str(unsigned_value))
    if unsigned_value & 0x80000000:
        candidates.append(str(unsigned_value - 0x100000000))
    candidates.append("0x%08X" % unsigned_value)
    candidates.append("0x%X" % unsigned_value)
    for candidate in candidates:
        name = NTSTATUS_RETURN_MAP.get(candidate)
        if name:
            return name
    return ""


def _parse_numeric_literal(literal: str) -> int | None:
    try:
        text = str(literal or "")
        if text.lower().startswith("-0x"):
            return -int(text[3:], 16)
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _profiled_status_argument_literal_count(text: str) -> int:
    if not STATUS_ARGUMENT_INDEXES:
        return 0
    function_names = sorted(STATUS_ARGUMENT_INDEXES, key=len, reverse=True)
    pattern = re.compile(
        r"\b(?P<function>%s)\((?P<args>[^;\n]*)\)"
        % "|".join(re.escape(name) for name in function_names)
    )
    count = 0
    for match in pattern.finditer(text):
        indexes = STATUS_ARGUMENT_INDEXES.get(match.group("function"), set())
        spans = _top_level_argument_spans(match.group("args"))
        for index in indexes:
            if index >= len(spans):
                continue
            start, end = spans[index]
            if _is_status_like_numeric_argument(match.group("args")[start:end]):
                count += 1
    return count


def _is_status_like_numeric_argument(argument: str) -> bool:
    return re.fullmatch(
        r"\s*-?(?:0xC[0-9A-Fa-f]{7}|107374\d+|\d{8,}|322122\d+)"
        r"(?:u?LL|ULL|LL|u|U|L)?\s*",
        argument,
    ) is not None


def _top_level_argument_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(text)))
    return spans


def _count_pattern(
    counter: Counter[str],
    text: str,
    pattern: re.Pattern[str],
    token_key: str,
    function_key: str,
) -> None:
    count = len(pattern.findall(text))
    counter[token_key] += count
    if count:
        counter[function_key] += 1


def _extract_layout_hints(text: str) -> list[dict[str, Any]]:
    hints = []
    for match in LAYOUT_HINT_RE.finditer(text or ""):
        hint = {
            "base": match.group("base"),
            "access_count": _int_value(match.group("access_count"), 0),
            "offset_count": _int_value(match.group("offset_count"), 0),
            "confidence": _float_value(match.group("confidence"), 0.0),
            "review": match.group("review"),
            "types": _parse_layout_hint_types(match.group("types")),
        }
        hints.append(hint)
    return hints


def _extract_layout_subfield_overlays(text: str) -> list[dict[str, Any]]:
    overlays = []
    for match in FIELD_SUBFIELD_OVERLAY_DETAIL_RE.finditer(text or ""):
        fields = _parse_subfield_overlay_fields(match.group("fields"))
        overlays.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return overlays


def _extract_layout_narrow_subfields(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_NARROW_SUBFIELD_DETAIL_RE.finditer(text or ""):
        fields = _parse_subfield_overlay_fields(match.group("fields"))
        candidates.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_bitfield_aliases(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_BITFIELD_ALIAS_DETAIL_RE.finditer(text or ""):
        fields = _parse_bitfield_alias_fields(match.group("fields"))
        candidates.append(
            {
                "base": match.group("base"),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_hot_field_clusters(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_HOT_CLUSTER_DETAIL_RE.finditer(text or ""):
        fields = _parse_hot_cluster_fields(match.group("fields"))
        candidates.append(
            {
                "base": match.group("base"),
                "base_kind": match.group("base_kind").replace(" ", "_"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "field_count": len(fields),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_indexed_callback_tables(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_INDEXED_CALLBACK_TABLE_DETAIL_RE.finditer(text or ""):
        scalar_indexes = _parse_indexed_callback_slots(match.group("scalar_indexes"), "index")
        callback_slots = _parse_indexed_callback_slots(match.group("callback_slots"), "slot")
        alias_bases = _parse_indexed_callback_alias_bases(
            match.groupdict().get("alias_bases") or ""
        )
        candidates.append(
            {
                "base": match.group("base"),
                "base_kind": match.group("base_kind").replace(" ", "_"),
                "access_count": _int_value(match.group("access_count"), 0),
                "slot_count": _int_value(match.group("slot_count"), 0),
                "scalar_indexes": scalar_indexes,
                "callback_slots": callback_slots,
                "alias_bases": alias_bases,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_parameter_indexed_elements(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_PARAMETER_INDEXED_ELEMENT_DETAIL_RE.finditer(text or ""):
        offsets = _parse_hex_offsets(match.group("offsets"))
        parent_type = str(match.groupdict().get("parent_type") or "")
        alias_risk = _parameter_indexed_alias_risk(parent_type, _int_value(match.group("stride"), 0))
        candidates.append(
            {
                "base": match.group("base"),
                "parent": match.group("parent"),
                "parent_alias": match.groupdict().get("parent_alias") or "",
                "index": match.group("index"),
                "stride": _int_value(match.group("stride"), 0),
                "access_count": _int_value(match.group("access_count"), 0),
                "offsets": offsets,
                "offset_count": len(offsets),
                "types": _parse_comma_tokens(match.group("types")),
                "parent_type": parent_type,
                "alias_rewrite_risk": alias_risk,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _parameter_indexed_alias_risk(parent_type: str, stride: int) -> str:
    normalized = re.sub(r"\s+", "", str(parent_type or ""))
    if stride <= 0 or not normalized:
        return ""
    if "*" in normalized:
        return "typed_parent_pointer_byte_stride"
    if _parameter_indexed_parent_type_is_value_like(normalized):
        return ""
    if re.fullmatch(r"P[A-Z0-9_]+", normalized):
        return "typed_parent_pointer_byte_stride"
    return ""


def _parameter_indexed_parent_type_is_value_like(normalized_type: str) -> bool:
    if normalized_type in {
        "PFN_NUMBER",
        "PHYSICAL_ADDRESS",
        "POOL_TYPE",
        "PORT_MESSAGE",
        "POWER_ACTION",
        "POWER_STATE",
        "PROCESSOR_NUMBER",
    }:
        return True
    return normalized_type.startswith(
        (
            "PAGE_",
            "PCI_",
            "PFN_",
            "PHYSICAL_",
            "POOL_",
            "PORT_",
            "POWER_",
            "PROCESSOR_",
        )
    )


def _parse_hex_offsets(value: str) -> list[int]:
    offsets = []
    for match in re.finditer(r"[+-]0x[0-9A-Fa-f]+|[+-]?\d+", str(value or "")):
        token = match.group(0)
        sign = -1 if token.startswith("-") else 1
        normalized = token[1:] if token[:1] in {"+", "-"} else token
        try:
            if normalized.lower().startswith("0x"):
                offsets.append(sign * int(normalized, 16))
            else:
                offsets.append(sign * int(normalized, 10))
        except ValueError:
            continue
    return offsets


def _parse_comma_tokens(value: str) -> list[str]:
    return [
        item.strip()
        for item in str(value or "").split(",")
        if item.strip() and item.strip().lower() not in {"none", "unknown"}
    ]


def _parse_indexed_callback_slots(value: str, prefix: str) -> list[int]:
    slots = []
    pattern = re.compile(r"\b%s_(?P<slot>\d+)\b" % re.escape(prefix))
    for match in pattern.finditer(str(value or "")):
        slots.append(_int_value(match.group("slot"), 0))
    return slots


def _parse_indexed_callback_alias_bases(value: str) -> list[str]:
    return [
        item.strip()
        for item in str(value or "").split(",")
        if item.strip() and item.strip().lower() != "none"
    ]


def _extract_layout_stable_base_sources(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_STABLE_BASE_SOURCE_DETAIL_RE.finditer(text or ""):
        provenance = _layout_source_provenance(
            text,
            match.group("base"),
            match.group("source"),
            match.group("source_kind"),
        )
        source_provenance = match.groupdict().get("source_provenance") or provenance["source_provenance"]
        detail = _parse_stable_source_detail(match.groupdict().get("source_detail") or "")
        candidate = {
            "base": match.group("base"),
            "source": match.group("source"),
            "source_kind": match.group("source_kind"),
            "source_provenance": source_provenance,
            "source_rhs_kind": provenance["source_rhs_kind"],
            "base_alias_assignments": provenance["base_alias_assignments"],
            "source_assignments": provenance["source_assignments"],
            "access_count": _int_value(match.group("access_count"), 0),
            "offset_count": _int_value(match.group("offset_count"), 0),
            "confidence": _float_value(match.group("confidence"), 0.0),
        }
        candidate.update(detail)
        if str(detail.get("source_rhs_kind", "") or ""):
            candidate["source_rhs_kind"] = str(detail["source_rhs_kind"])
        candidates.append(candidate)
    return candidates


def _parse_stable_source_detail(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_part in str(value or "").split(","):
        part = raw_part.strip()
        if not part:
            continue
        if part.startswith("anchor "):
            result["source_anchor"] = part[len("anchor "):].strip()
            continue
        if part.startswith("container_offset "):
            result["source_container_offset"] = part[len("container_offset "):].strip()
            continue
        if part.startswith("index "):
            result["source_index"] = part[len("index "):].strip()
            continue
        if part.startswith("type "):
            result["source_type"] = part[len("type "):].strip()
            continue
        if part.startswith("call "):
            result["source_call"] = part[len("call "):].strip()
            continue
        if part.startswith("alias "):
            result["source_alias"] = part[len("alias "):].strip()
            continue
        if part.startswith("rhs "):
            result["source_rhs_kind"] = part[len("rhs "):].strip()
            continue
    if value:
        result["source_detail"] = str(value)
    return result


def _extract_layout_base_stability(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_BASE_STABILITY_DETAIL_RE.finditer(text or ""):
        rhs_samples = [
            item.strip()
            for item in match.group("rhs").split(";")
            if item.strip() and item.strip() != "none" and item.strip() != "..."
        ]
        candidates.append(
            {
                "base": match.group("base"),
                "pre_access_assignment_count": _int_value(
                    match.group("pre_access_assignment_count"),
                    0,
                ),
                "distinct_pre_access_rhs_count": _int_value(
                    match.group("distinct_pre_access_rhs_count"),
                    0,
                ),
                "distinct_pre_access_rhs": rhs_samples,
                "post_access_assignment_count": _int_value(
                    match.group("post_access_assignment_count"),
                    0,
                ),
                "risky_post_access_assignment_count": _int_value(
                    match.group("risky_post_access_assignment_count"),
                    0,
                ),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _layout_source_provenance(
    text: str,
    base: str,
    source: str,
    source_kind: str,
) -> dict[str, Any]:
    normalized_source = str(source or "").strip()
    base_alias_assignments = [
        item
        for item in _layout_direct_assignments(text, base)
        if _normalize_layout_rhs(item["rhs"]) == normalized_source
    ]
    source_assignments = _layout_direct_assignments(text, normalized_source)
    source_rhs_kinds = Counter(
        _layout_rhs_kind(_normalize_layout_rhs(item["rhs"]))
        for item in source_assignments
    )
    source_rhs_kind = next(iter(source_rhs_kinds), "none")
    if len(source_rhs_kinds) > 1:
        source_rhs_kind = "mixed"
    source_provenance = _layout_source_provenance_class(
        str(source_kind or ""),
        base_alias_assignments,
        source_assignments,
        source_rhs_kind,
    )
    return {
        "source_provenance": source_provenance,
        "source_rhs_kind": source_rhs_kind,
        "base_alias_assignments": len(base_alias_assignments),
        "source_assignments": len(source_assignments),
    }


def _layout_source_provenance_class(
    source_kind: str,
    base_alias_assignments: list[dict[str, str]],
    source_assignments: list[dict[str, str]],
    source_rhs_kind: str,
) -> str:
    if not base_alias_assignments:
        return "missing_alias_assignment"
    if source_kind == "argument":
        return "direct_argument_alias"
    if source_kind == "named":
        if len(source_assignments) == 1 and source_rhs_kind == "call_result":
            return "named_call_result_alias"
        if len(source_assignments) == 1 and source_rhs_kind == "direct_identifier":
            return "named_direct_alias"
        if len(source_assignments) == 1 and source_rhs_kind in {"address", "deref", "pointer_arithmetic"}:
            return "named_derived_pointer_alias"
        if len(source_assignments) > 1:
            return "named_multi_assignment_alias"
        return "named_existing_alias"
    if source_kind == "generic":
        return "generic_source_alias"
    if source_kind == "temporary":
        return "temporary_source_alias"
    return "unknown_source_alias"


def _layout_direct_assignments(text: str, name: str) -> list[dict[str, str]]:
    if not name:
        return []
    pattern = re.compile(
        r"(?m)^\s*%s\s*=\s*(?P<rhs>[^;\n]*);\s*(?://[^\n]*)?$"
        % re.escape(name)
    )
    return [
        {
            "rhs": match.group("rhs"),
        }
        for match in pattern.finditer(text or "")
    ]


def _normalize_layout_rhs(rhs: str) -> str:
    result = str(rhs or "").strip()
    while True:
        updated = re.sub(r"^\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*", "", result).strip()
        if updated == result:
            return result
        result = updated


def _layout_rhs_kind(rhs: str) -> str:
    value = _normalize_layout_rhs(rhs)
    if not value:
        return "empty"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        return "direct_identifier"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*\)", value):
        return "call_result"
    if value.startswith("&"):
        return "address"
    if value.startswith("*"):
        return "deref"
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b\s*(?:\+|-)", value):
        return "pointer_arithmetic"
    return "expression"


def _extract_layout_generic_base_evidence(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_GENERIC_BASE_EVIDENCE_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "blocker_profile": match.group("blocker_profile"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_generic_base_trust_candidates(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_GENERIC_BASE_TRUST_CANDIDATE_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "source_kind": match.group("source_kind"),
                "blocker_profile": match.group("blocker_profile").replace("-", "_"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_temp_provenance(text: str) -> dict[str, list[dict[str, Any]]]:
    traces = []
    for match in FIELD_TEMP_PROVENANCE_TRACE_DETAIL_RE.finditer(text or ""):
        traces.append(
            {
                "base": match.group("base"),
                "trust_class": match.group("trust_class"),
                "source": match.group("source"),
                "source_kind": match.group("source_kind"),
                "source_provenance": match.group("source_provenance"),
                "source_origin": match.group("source_origin"),
                "first_layout_access_line": _int_value(match.group("first_layout_access_line"), -1),
                "pre_access_assignment_count": _int_value(match.group("pre_access_assignment_count"), 0),
                "distinct_pre_access_rhs_count": _int_value(match.group("distinct_pre_access_rhs_count"), 0),
                "post_access_assignment_count": _int_value(match.group("post_access_assignment_count"), 0),
                "risky_post_access_assignment_count": _int_value(
                    match.group("risky_post_access_assignment_count"),
                    0,
                ),
                "pointer_mutation": match.group("pointer_mutation") == "yes",
                "address_taken": match.group("address_taken") == "yes",
                "array_indexed": match.group("array_indexed") == "yes",
                "call_mutation_risk": match.group("call_mutation_risk") == "yes",
                "branch_merge_shape": match.group("branch_merge_shape"),
                "guard_dominance": match.group("guard_dominance"),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    trusted = []
    for match in FIELD_TRUSTED_TEMP_SOURCE_DETAIL_RE.finditer(text or ""):
        trusted.append(
            {
                "base": match.group("base"),
                "source": match.group("source"),
                "source_kind": match.group("source_kind"),
                "source_provenance": match.group("source_provenance"),
                "source_origin": match.group("source_origin"),
                "promotion_ready": match.group("promotion_ready") == "yes",
                "first_layout_access_line": _int_value(match.group("first_layout_access_line"), -1),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    blocked = []
    for match in FIELD_TEMP_PROMOTION_BLOCKED_DETAIL_RE.finditer(text or ""):
        blocked.append(
            {
                "base": match.group("base"),
                "trust_class": match.group("trust_class"),
                "block_reasons": _split_reason_list(match.group("block_reasons")),
                "rewrite_blockers": _split_semicolon_list(match.group("rewrite_blockers")),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return {
        "traces": traces,
        "trusted": trusted,
        "blocked": blocked,
    }


def _extract_layout_rewrite_ready(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_READY_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "source": match.groupdict().get("source") or "",
                "source_provenance": match.groupdict().get("source_provenance") or "none",
                "threshold_policy": match.groupdict().get("threshold_policy") or "standard",
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_previews(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_PREVIEW_DETAIL_RE.finditer(text or ""):
        fields = [
            item.strip()
            for item in match.group("fields").split(",")
            if item.strip() and item.strip() != "..."
        ]
        candidates.append(
            {
                "base": match.group("base"),
                "source": match.groupdict().get("source") or "",
                "source_provenance": match.groupdict().get("source_provenance") or "none",
                "access_count": _int_value(match.group("access_count"), 0),
                "field_count": _int_value(match.group("field_count"), 0),
                "fields": fields,
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_near_ready(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_NEAR_READY_DETAIL_RE.finditer(text or ""):
        candidates.append(
            {
                "base": match.group("base"),
                "access_count": _int_value(match.group("access_count"), 0),
                "offset_count": _int_value(match.group("offset_count"), 0),
                "missing_threshold": match.group("missing"),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


def _extract_layout_rewrite_partial_opportunities(text: str) -> list[dict[str, Any]]:
    candidates = []
    for match in FIELD_REWRITE_PARTIAL_OPPORTUNITY_DETAIL_RE.finditer(text or ""):
        safe_fields = [
            item.strip()
            for item in match.group("safe_fields").split(",")
            if item.strip() and item.strip() != "..."
        ]
        reasons = [
            item.strip()
            for item in match.group("reasons").split(";")
            if item.strip()
        ]
        safe_offsets = _parse_layout_offset_list(match.groupdict().get("safe_offsets") or "")
        excluded_offsets = _parse_layout_offset_list(match.groupdict().get("excluded_offsets") or "")
        application_status = _partial_opportunity_application_status(match.group("disposition"))
        candidate = {
            "base": match.group("base"),
            "source": match.groupdict().get("source") or "",
            "source_provenance": match.groupdict().get("source_provenance") or "none",
            "safe_access_count": _int_value(match.group("safe_access_count"), 0),
            "safe_offset_count": _int_value(match.group("safe_offset_count"), 0),
            "excluded_access_count": _int_value(match.group("excluded_access_count"), 0),
            "excluded_offset_count": _int_value(match.group("excluded_offset_count"), 0),
            "safe_fields": safe_fields,
            "safe_offsets": safe_offsets,
            "excluded_offsets": excluded_offsets,
            "reasons": reasons,
            "application_status": application_status,
            "confidence": _float_value(match.group("confidence"), 0.0),
        }
        candidate["review_class"] = _partial_opportunity_review_class(candidate)
        candidates.append(
            candidate
        )
    return candidates


def _partial_opportunity_application_status(disposition: str) -> str:
    if "Validated partial layout rewrite applied" in str(disposition or ""):
        return "validated_partial_applied"
    return "review_only"


def _partial_opportunity_review_class(candidate: dict[str, Any]) -> str:
    if str(candidate.get("application_status", "") or "") == "validated_partial_applied":
        return "validated_partial_rewrite"
    source_provenance = str(candidate.get("source_provenance", "") or "none")
    if source_provenance in {
        "direct_argument_alias",
        "direct_call_result_alias",
        "generic_parameter_trust",
        "parameter_field_pointer_alias",
        "stable_argument_source",
    }:
        if (
            _int_value(candidate.get("safe_offset_count"), 0) >= 8
            and _int_value(candidate.get("safe_access_count"), 0) >= 12
            and _int_value(candidate.get("excluded_offset_count"), 0) <= 3
        ):
            return "partial_validation_candidate"
    if source_provenance != "none":
        return "partial_source_review"
    return "partial_review_only"


def _parse_layout_offset_list(value: str) -> list[int]:
    offsets = []
    for item in str(value or "").split(","):
        text = item.strip()
        if not text:
            continue
        if text.startswith("+"):
            text = text[1:].strip()
        try:
            offset = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            continue
        offsets.append(offset)
    return offsets


def _split_reason_list(value: str) -> list[str]:
    return [
        item.strip()
        for item in str(value or "").split(",")
        if item.strip() and item.strip().lower() != "none"
    ]


def _split_semicolon_list(value: str) -> list[str]:
    return [
        item.strip()
        for item in str(value or "").split(";")
        if item.strip() and item.strip().lower() != "none"
    ]


def _extract_layout_rewrite_blockers(text: str) -> list[dict[str, Any]]:
    blockers = []
    for match in FIELD_REWRITE_BLOCKER_DETAIL_RE.finditer(text or ""):
        reasons = [
            item.strip()
            for item in match.group("reasons").split(";")
            if item.strip()
        ]
        item = {
            "base": match.group("base"),
            "reasons": reasons,
            "confidence": _float_value(match.group("confidence"), 0.0),
        }
        source = str(match.groupdict().get("source") or "").strip()
        if source:
            item["source_identity_source"] = source
            item["source_identity_source_provenance"] = str(
                match.groupdict().get("source_provenance") or ""
            )
            item["source_identity_profile_id"] = str(
                match.groupdict().get("source_profile_id") or ""
            )
            item["source_identity_role"] = str(match.groupdict().get("source_role") or "")
            item["source_identity_structure"] = str(
                match.groupdict().get("source_structure") or ""
            )
        domain_blocker_profile_id = str(
            match.groupdict().get("domain_blocker_profile_id") or ""
        )
        if domain_blocker_profile_id:
            item["domain_identity_blocker_profile_id"] = domain_blocker_profile_id
            item["domain_identity_blocker_role"] = str(
                match.groupdict().get("domain_blocker_role") or ""
            )
            item["domain_identity_blocker_structure"] = str(
                match.groupdict().get("domain_blocker_structure") or ""
            )
        blockers.append(item)
    return blockers


def _extract_domain_structure_identities(text: str) -> list[dict[str, Any]]:
    identities = []
    for match in DOMAIN_STRUCTURE_IDENTITY_DETAIL_RE.finditer(text or ""):
        field_text = str(match.group("fields") or "").strip()
        fields = _domain_identity_field_names(field_text)
        identities.append(
            {
                "base": match.group("base"),
                "role": match.group("role"),
                "structure": match.group("structure"),
                "mode": match.group("mode"),
                "profile_id": match.group("profile_id"),
                "parameter": str(match.group("parameter") or "").strip(),
                "field_text": field_text,
                "field_count": len(fields),
                "fields": fields,
                "has_observed_fields": bool(fields),
            }
        )
    return identities


def _domain_identity_field_names(field_text: str) -> list[str]:
    if not field_text or field_text.lower().startswith("none observed"):
        return []
    aliases = list(dict.fromkeys(FIELD_ALIAS_NAME_RE.findall(field_text)))
    offsets = list(dict.fromkeys(DOMAIN_FIELD_OFFSET_RE.findall(field_text)))
    if len(aliases) >= len(offsets):
        return aliases
    return offsets


def _parse_layout_hint_types(value: str) -> list[str]:
    result = []
    for item in str(value or "").split(","):
        type_name = item.strip().strip(".")
        if not type_name or type_name == "...":
            continue
        result.append(type_name)
    return result


def _parse_subfield_overlay_fields(value: str) -> list[dict[str, Any]]:
    fields = []
    for match in SUBFIELD_OVERLAY_FIELD_RE.finditer(value or ""):
        sizes = [
            _int_value(item, 0)
            for item in match.group("sizes").split("/")
            if item
        ]
        size_class = _subfield_overlay_size_class(sizes)
        annotation = _parse_subfield_overlay_annotation(match.group("annotation"))
        fields.append(
            {
                "offset": int(match.group("offset"), 16),
                "sizes": [item for item in sizes if item > 0],
                "size_class": size_class,
                "policy_class": _subfield_overlay_policy_class(size_class),
                "interpretation": annotation["interpretation"],
                "bit_masks": annotation["bit_masks"],
                "bit_operations": annotation["bit_operations"],
                "mask_families": annotation["mask_families"],
                "types": [
                    item.strip()
                    for item in match.group("types").split("/")
                    if item.strip()
                ],
            }
        )
    return fields


def _parse_bitfield_alias_fields(value: str) -> list[dict[str, Any]]:
    fields = []
    for match in BITFIELD_ALIAS_FIELD_RE.finditer(value or ""):
        masks = [
            item
            for item in match.group("masks").split(",")
            if item and item != "unknown"
        ]
        aliases = [
            item
            for item in match.group("aliases").split("/")
            if item
        ]
        offset = int(match.group("offset"), 16)
        fields.append(
            {
                "offset": offset,
                "name": "field_%X" % offset,
                "aliases": aliases,
                "masks": masks,
            }
        )
    return fields


def _parse_hot_cluster_fields(value: str) -> list[dict[str, Any]]:
    fields = []
    for item in str(value or "").split(";"):
        match = HOT_CLUSTER_FIELD_RE.fullmatch(item.strip())
        if not match:
            continue
        offset = int(match.group("offset"), 16)
        fields.append(
            {
                "offset": offset,
                "name": match.group("name"),
                "type": match.group("type").strip(),
                "access_count": _int_value(match.group("access_count"), 0),
            }
        )
    return fields


def _parse_subfield_overlay_annotation(value: str | None) -> dict[str, Any]:
    parts = [item for item in str(value or "").split() if item]
    annotation = {
        "interpretation": "unknown",
        "bit_masks": [],
        "bit_operations": [],
        "mask_families": [],
    }
    for index, part in enumerate(parts):
        if index == 0 and "=" not in part:
            annotation["interpretation"] = part
            continue
        key, separator, raw_value = part.partition("=")
        if not separator:
            continue
        values = [item for item in raw_value.split(",") if item]
        if key == "masks":
            annotation["bit_masks"] = values
        elif key == "ops":
            annotation["bit_operations"] = values
        elif key == "families":
            annotation["mask_families"] = values
    return annotation


def _subfield_overlay_size_class(sizes: list[int]) -> str:
    normalized = sorted({int(size) for size in sizes if int(size) > 0})
    if normalized == [1, 2]:
        return "byte_word"
    if normalized == [1, 4]:
        return "byte_dword"
    if normalized == [2, 4]:
        return "word_dword"
    if normalized == [4, 8]:
        return "dword_qword"
    if normalized == [8, 16]:
        return "qword_oword"
    return "mixed_width"


def _subfield_overlay_policy_class(size_class: str) -> str:
    if size_class in {"byte_word", "byte_dword", "word_dword"}:
        return "narrow_subfield"
    if size_class in {"dword_qword", "qword_oword"}:
        return "wide_overlay"
    return "irregular_overlay"


def _update_layout_hint_metrics(
    hints: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    types: Counter[str],
) -> None:
    if not hints:
        return
    totals["functions_with_hints"] += 1
    for hint in hints:
        totals["hints"] += 1
        totals["access_observations"] += _int_value(hint.get("access_count"), 0)
        totals["offset_observations"] += _int_value(hint.get("offset_count"), 0)
        base = str(hint.get("base", "") or "unknown")
        bases[base] += 1
        if _is_decompiler_temp_base(base):
            totals["temp_base_hints"] += 1
        else:
            totals["named_base_hints"] += 1
        if _int_value(hint.get("offset_count"), 0) >= 8:
            totals["large_offset_hints"] += 1
        for type_name in hint.get("types", []) or []:
            types[str(type_name)] += 1


def _update_layout_subfield_overlay_metrics(
    overlays: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    size_classes: Counter[str],
    policy_classes: Counter[str],
    interpretations: Counter[str],
    bit_masks: Counter[str],
    bit_operations: Counter[str],
    mask_families: Counter[str],
) -> None:
    if not overlays:
        return
    totals["functions_with_overlay_comments"] += 1
    for overlay in overlays:
        totals["overlay_comments"] += 1
        totals["field_observations"] += _int_value(overlay.get("field_count"), 0)
        bases[str(overlay.get("base", "") or "unknown")] += 1
        for field in overlay.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            size_classes[str(field.get("size_class", "") or "unknown")] += 1
            policy_classes[str(field.get("policy_class", "") or "unknown")] += 1
            interpretations[str(field.get("interpretation", "") or "unknown")] += 1
            for mask in field.get("bit_masks", []) or []:
                bit_masks[str(mask)] += 1
            for operation in field.get("bit_operations", []) or []:
                bit_operations[str(operation)] += 1
            for family in field.get("mask_families", []) or []:
                mask_families[str(family)] += 1


def _update_layout_narrow_subfield_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    size_classes: Counter[str],
    interpretations: Counter[str],
    bit_masks: Counter[str],
    bit_operations: Counter[str],
    mask_families: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_candidate_comments"] += 1
    for candidate in candidates:
        totals["candidate_comments"] += 1
        totals["field_observations"] += _int_value(candidate.get("field_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        for field in candidate.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            size_classes[str(field.get("size_class", "") or "unknown")] += 1
            interpretations[str(field.get("interpretation", "") or "unknown")] += 1
            for mask in field.get("bit_masks", []) or []:
                bit_masks[str(mask)] += 1
            for operation in field.get("bit_operations", []) or []:
                bit_operations[str(operation)] += 1
            for family in field.get("mask_families", []) or []:
                mask_families[str(family)] += 1


def _update_layout_bitfield_alias_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    aliases: Counter[str],
    masks: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_alias_comments"] += 1
    for candidate in candidates:
        totals["alias_comments"] += 1
        totals["field_observations"] += _int_value(candidate.get("field_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        for field in candidate.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            for alias in field.get("aliases", []) or []:
                aliases[str(alias)] += 1
            for mask in field.get("masks", []) or []:
                masks[str(mask)] += 1


def _update_layout_hot_field_cluster_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    base_kinds: Counter[str],
    field_types: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_cluster_comments"] += 1
    for candidate in candidates:
        totals["cluster_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        fields = [item for item in candidate.get("fields", []) or [] if isinstance(item, dict)]
        totals["field_observations"] += len(fields)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        base_kinds[str(candidate.get("base_kind", "") or "unknown")] += 1
        for field in fields:
            field_types[str(field.get("type", "") or "unknown")] += 1


def _update_layout_indexed_callback_table_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    base_kinds: Counter[str],
    alias_bases: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_evidence_comments"] += 1
    for candidate in candidates:
        totals["evidence_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["slot_observations"] += _int_value(candidate.get("slot_count"), 0)
        totals["scalar_index_observations"] += len(candidate.get("scalar_indexes", []) or [])
        totals["callback_slot_observations"] += len(candidate.get("callback_slots", []) or [])
        bases[str(candidate.get("base", "") or "unknown")] += 1
        base_kinds[str(candidate.get("base_kind", "") or "unknown")] += 1
        for alias_base in candidate.get("alias_bases", []) or []:
            alias_bases[str(alias_base)] += 1


def _update_layout_parameter_indexed_element_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    parents: Counter[str],
    parent_types: Counter[str],
    strides: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_evidence_comments"] += 1
    for candidate in candidates:
        totals["evidence_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["element_offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        if str(candidate.get("alias_rewrite_risk", "") or ""):
            totals["alias_rewrite_risks"] += 1
        bases[str(candidate.get("base", "") or "unknown")] += 1
        parents[str(candidate.get("parent", "") or "unknown")] += 1
        parent_type = str(candidate.get("parent_type", "") or "")
        if parent_type:
            parent_types[parent_type] += 1
        stride = _int_value(candidate.get("stride"), 0)
        if stride > 0:
            strides[str(stride)] += 1


def _update_layout_stable_base_source_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    sources: Counter[str],
    source_kinds: Counter[str],
    source_provenance: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_source_comments"] += 1
    for candidate in candidates:
        totals["source_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        sources[str(candidate.get("source", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1
        source_provenance[str(candidate.get("source_provenance", "") or "unknown")] += 1


def _update_layout_base_stability_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    rhs_samples: Counter[str],
    profiles: Counter[str],
    review_queues: dict[str, list[dict[str, Any]]],
    function_name: str,
    ea: str,
    summary_path: Path,
) -> None:
    if not candidates:
        return
    totals["functions_with_stability_comments"] += 1
    for candidate in candidates:
        totals["stability_comments"] += 1
        totals["pre_access_assignments"] += _int_value(candidate.get("pre_access_assignment_count"), 0)
        totals["distinct_pre_access_rhs_observations"] += _int_value(
            candidate.get("distinct_pre_access_rhs_count"),
            0,
        )
        totals["post_access_assignments"] += _int_value(candidate.get("post_access_assignment_count"), 0)
        totals["risky_post_access_assignments"] += _int_value(
            candidate.get("risky_post_access_assignment_count"),
            0,
        )
        bases[str(candidate.get("base", "") or "unknown")] += 1
        profile = _base_stability_review_profile(candidate)
        profiles[profile] += 1
        review_queues.setdefault(profile, []).append(
            {
                "ea": ea,
                "name": function_name,
                "base": str(candidate.get("base", "") or "unknown"),
                "profile": profile,
                "pre_access_assignment_count": _int_value(
                    candidate.get("pre_access_assignment_count"),
                    0,
                ),
                "distinct_pre_access_rhs_count": _int_value(
                    candidate.get("distinct_pre_access_rhs_count"),
                    0,
                ),
                "distinct_pre_access_rhs": [
                    str(rhs)
                    for rhs in candidate.get("distinct_pre_access_rhs", []) or []
                    if str(rhs)
                ],
                "post_access_assignment_count": _int_value(
                    candidate.get("post_access_assignment_count"),
                    0,
                ),
                "risky_post_access_assignment_count": _int_value(
                    candidate.get("risky_post_access_assignment_count"),
                    0,
                ),
                "confidence": _float_value(candidate.get("confidence"), 0.0),
                "summary_path": str(summary_path),
            }
        )
        for rhs in candidate.get("distinct_pre_access_rhs", []) or []:
            rhs_samples[str(rhs)] += 1


def _base_stability_review_profile(candidate: dict[str, Any]) -> str:
    distinct_rhs = _int_value(candidate.get("distinct_pre_access_rhs_count"), 0)
    risky_post_access = _int_value(candidate.get("risky_post_access_assignment_count"), 0)
    if distinct_rhs > 1:
        if risky_post_access > 0:
            return "initializer_and_reassignment_risk"
        return "initializer_dominance_review"
    if risky_post_access > 0:
        return "post_access_reassignment_risk"
    if distinct_rhs == 1:
        return "single_initializer_trace"
    return "missing_initializer_trace"


def _layout_base_stability_review_queues(
    queue_items: dict[str, list[dict[str, Any]]],
    top: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for profile in _BASE_STABILITY_REVIEW_PROFILE_ORDER:
        items = list(queue_items.get(profile, []))
        items.sort(
            key=lambda item: (
                -_int_value(item.get("distinct_pre_access_rhs_count"), 0),
                -_int_value(item.get("risky_post_access_assignment_count"), 0),
                -_float_value(item.get("confidence"), 0.0),
                str(item.get("name", "")),
                str(item.get("base", "")),
            )
        )
        bases = Counter(str(item.get("base", "") or "unknown") for item in items)
        rhs_samples = Counter(
            str(rhs)
            for item in items
            for rhs in item.get("distinct_pre_access_rhs", []) or []
            if str(rhs)
        )
        function_names = {str(item.get("name", "") or "") for item in items}
        result[profile] = {
            "items": items[:top],
            "comments": len(items),
            "functions": len(function_names),
            "max_distinct_pre_access_rhs": max(
                (_int_value(item.get("distinct_pre_access_rhs_count"), 0) for item in items),
                default=0,
            ),
            "max_risky_post_access_assignments": max(
                (_int_value(item.get("risky_post_access_assignment_count"), 0) for item in items),
                default=0,
            ),
            "top_bases": _counter_to_dict(Counter(dict(bases.most_common(top)))),
            "rhs_samples": _counter_to_dict(Counter(dict(rhs_samples.most_common(top)))),
        }
    return result


def _update_layout_generic_base_evidence_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    blocker_profiles: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_evidence_comments"] += 1
    for candidate in candidates:
        totals["evidence_comments"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        blocker_profiles[str(candidate.get("blocker_profile", "") or "unknown")] += 1


def _update_layout_generic_base_trust_candidate_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    source_kinds: Counter[str],
    blocker_profiles: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_trust_candidates"] += 1
    for candidate in candidates:
        totals["trust_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1
        blocker_profiles[str(candidate.get("blocker_profile", "") or "unknown")] += 1


def _update_layout_temp_provenance_metrics(
    provenance: dict[str, list[dict[str, Any]]],
    totals: Counter[str],
    bases: Counter[str],
    trust_classes: Counter[str],
    source_origins: Counter[str],
    source_kinds: Counter[str],
    source_provenance: Counter[str],
    branch_shapes: Counter[str],
    guard_dominance: Counter[str],
    block_reasons: Counter[str],
) -> None:
    traces = [item for item in provenance.get("traces", []) or [] if isinstance(item, dict)]
    trusted = [item for item in provenance.get("trusted", []) or [] if isinstance(item, dict)]
    blocked = [item for item in provenance.get("blocked", []) or [] if isinstance(item, dict)]
    if not traces and not trusted and not blocked:
        return
    totals["functions_with_temp_provenance"] += 1
    totals["trace_comments"] += len(traces)
    totals["trusted_temp_sources"] += len(trusted)
    totals["blocked_candidates"] += len(blocked)
    totals["review_only_candidates"] += sum(
        1
        for item in traces
        if str(item.get("trust_class", "") or "").endswith("_review")
        or str(item.get("trust_class", "") or "") == "stable_review_only"
    )
    totals["rewrite_ready_unlocked"] += sum(
        1
        for item in trusted
        if bool(item.get("promotion_ready"))
    )
    for item in traces:
        base = str(item.get("base", "") or "unknown")
        bases[base] += 1
        trust_classes[str(item.get("trust_class", "") or "unknown")] += 1
        source_origins[str(item.get("source_origin", "") or "unknown")] += 1
        source_kinds[str(item.get("source_kind", "") or "unknown")] += 1
        source_provenance[str(item.get("source_provenance", "") or "unknown")] += 1
        branch_shapes[str(item.get("branch_merge_shape", "") or "none")] += 1
        guard_dominance[str(item.get("guard_dominance", "") or "unknown")] += 1
    for item in trusted:
        bases[str(item.get("base", "") or "unknown")] += 1
        source_origins[str(item.get("source_origin", "") or "unknown")] += 1
        source_kinds[str(item.get("source_kind", "") or "unknown")] += 1
        source_provenance[str(item.get("source_provenance", "") or "unknown")] += 1
    for item in blocked:
        bases[str(item.get("base", "") or "unknown")] += 1
        trust_classes[str(item.get("trust_class", "") or "unknown")] += 1
        for reason in item.get("block_reasons", []) or []:
            block_reasons[str(reason)] += 1


def _update_layout_rewrite_ready_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    source_provenance: Counter[str],
    threshold_policies: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_ready_candidates"] += 1
    for candidate in candidates:
        totals["ready_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        source_provenance[str(candidate.get("source_provenance", "") or "none")] += 1
        threshold_policies[str(candidate.get("threshold_policy", "") or "standard")] += 1


def _update_layout_rewrite_preview_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    source_provenance: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_preview_plans"] += 1
    for candidate in candidates:
        totals["preview_plans"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["field_observations"] += _int_value(candidate.get("field_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        source_provenance[str(candidate.get("source_provenance", "") or "none")] += 1


def _update_layout_rewrite_preview_artifact_metrics(
    metadata: dict[str, Any],
    totals: Counter[str],
    statuses: Counter[str],
    canonical_statuses: Counter[str],
    plan_kinds: Counter[str],
    failed_checks: Counter[str],
) -> None:
    if not metadata:
        return
    totals["preview_artifacts"] += 1
    totals["functions_with_preview_artifacts"] += 1
    totals["rewritten_accesses"] += _int_value(metadata.get("rewritten_accesses"), 0)
    totals["rewritten_fields"] += _int_value(metadata.get("rewritten_fields"), 0)
    direct_zero_rewritten_accesses = _rewrite_preview_artifact_direct_zero_rewrite_accesses(metadata)
    totals["direct_zero_rewritten_accesses"] += direct_zero_rewritten_accesses
    if direct_zero_rewritten_accesses > 0:
        totals["functions_with_direct_zero_rewrites"] += 1
    validation = _coerce_dict(metadata.get("validation", {}))
    status = str(validation.get("status", "") or "unknown")
    statuses[status] += 1
    errors = [str(error) for error in validation.get("errors", []) or [] if str(error)]
    totals["validation_errors"] += len(errors)
    normalizations = [
        item
        for item in metadata.get("advertisement_normalizations", []) or []
        if isinstance(item, dict)
    ]
    totals["advertisement_normalizations"] += len(normalizations)
    for item in normalizations:
        original_accesses = _int_value(item.get("original_accesses"), 0)
        normalized_accesses = _int_value(item.get("normalized_accesses"), 0)
        original_fields = _int_value(item.get("original_fields"), 0)
        normalized_fields = _int_value(item.get("normalized_fields"), 0)
        totals["normalized_access_delta"] += max(0, original_accesses - normalized_accesses)
        totals["normalized_field_delta"] += max(0, original_fields - normalized_fields)
    source_alias_extensions = [
        item
        for item in metadata.get("source_alias_residual_extensions", []) or []
        if isinstance(item, dict)
    ]
    totals["source_alias_residual_extensions"] += len(source_alias_extensions)
    if source_alias_extensions:
        totals["functions_with_source_alias_residual_extensions"] += 1
    for item in source_alias_extensions:
        totals["source_alias_residual_extended_offsets"] += len(
            [
                offset
                for offset in item.get("extended_offsets", []) or []
                if _rewrite_preview_artifact_offset_key(offset) is not None
            ]
        )
    canonical_status = str(metadata.get("canonical_rewrite_status", "") or "unknown")
    canonical_statuses[canonical_status] += 1
    preview_plans = [
        item
        for item in metadata.get("preview_plans", []) or []
        if isinstance(item, dict)
    ]
    for plan in preview_plans:
        plan_kind = str(plan.get("plan_kind", "") or "full")
        plan_kinds[plan_kind] += 1
        totals[f"{plan_kind}_preview_plans"] += 1
    if bool(metadata.get("canonical_rewrite_requested", False)):
        totals["canonical_rewrite_requested"] += 1
    if bool(metadata.get("canonical_cleaned_output_modified", False)):
        totals["canonical_rewrite_applied"] += 1
        totals["canonical_direct_zero_rewritten_accesses"] += direct_zero_rewritten_accesses
        if direct_zero_rewritten_accesses > 0:
            totals["functions_with_canonical_direct_zero_rewrites"] += 1
        if canonical_status == "applied":
            totals["canonical_rewrite_applied_full"] += 1
        elif canonical_status == "applied_partial":
            totals["canonical_rewrite_applied_partial"] += 1
        else:
            totals["canonical_rewrite_applied_other"] += 1
    if canonical_status == "blocked_by_validation":
        totals["canonical_rewrite_blocked"] += 1
    canonical_errors = [
        str(error)
        for error in metadata.get("canonical_rewrite_errors", []) or []
        if str(error)
    ]
    totals["canonical_rewrite_errors"] += len(canonical_errors)
    checks = _coerce_dict(validation.get("checks", {}))
    for check, passed in checks.items():
        if bool(passed):
            continue
        failed_checks[str(check)] += 1


def _rewrite_preview_artifact_direct_zero_rewrite_accesses(metadata: dict[str, Any]) -> int:
    total = 0
    rewrite_results = _coerce_dict(metadata.get("rewrite_results", {}))
    for result in rewrite_results.values():
        if not isinstance(result, dict):
            continue
        offset_accesses = _coerce_dict(result.get("offset_accesses", {}))
        for offset_key, count in offset_accesses.items():
            if _rewrite_preview_artifact_offset_key(offset_key) != 0:
                continue
            total += _int_value(count, 0)
    return total


def _rewrite_preview_artifact_offset_key(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        result = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None
    return result if result >= 0 else None


def _update_layout_rewrite_near_ready_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    missing_thresholds: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_near_ready_candidates"] += 1
    for candidate in candidates:
        totals["near_ready_candidates"] += 1
        totals["access_observations"] += _int_value(candidate.get("access_count"), 0)
        totals["offset_observations"] += _int_value(candidate.get("offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        missing_thresholds[str(candidate.get("missing_threshold", "") or "unknown")] += 1


def _update_layout_rewrite_partial_opportunity_metrics(
    candidates: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    source_provenance: Counter[str],
    reasons: Counter[str],
    application_statuses: Counter[str],
    review_classes: Counter[str],
) -> None:
    if not candidates:
        return
    totals["functions_with_partial_opportunities"] += 1
    for candidate in candidates:
        totals["partial_opportunities"] += 1
        totals["safe_access_observations"] += _int_value(candidate.get("safe_access_count"), 0)
        totals["safe_offset_observations"] += _int_value(candidate.get("safe_offset_count"), 0)
        totals["excluded_access_observations"] += _int_value(candidate.get("excluded_access_count"), 0)
        totals["excluded_offset_observations"] += _int_value(candidate.get("excluded_offset_count"), 0)
        bases[str(candidate.get("base", "") or "unknown")] += 1
        source_provenance[str(candidate.get("source_provenance", "") or "none")] += 1
        application_statuses[str(candidate.get("application_status", "") or "unknown")] += 1
        review_classes[str(candidate.get("review_class", "") or "manual_review")] += 1
        for reason in candidate.get("reasons", []) or []:
            reasons[str(reason)] += 1


def _update_layout_rewrite_blocker_metrics(
    blockers: list[dict[str, Any]],
    layout_hints: list[dict[str, Any]],
    stable_base_sources: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
    totals: Counter[str],
    bases: Counter[str],
    reasons: Counter[str],
    review_profiles: Counter[str],
    review_queues: dict[str, list[dict[str, Any]]],
    function_name: str,
    ea: str,
    summary_path: Path,
) -> None:
    if not blockers:
        return
    layout_evidence = _layout_evidence_by_base(layout_hints)
    identity_evidence = _layout_identity_evidence_by_base(
        stable_base_sources,
        generic_base_evidence,
        generic_base_trust_candidates,
    )
    domain_identity_by_base = _domain_identity_by_base(domain_identities)
    totals["functions_with_blockers"] += 1
    for blocker in blockers:
        totals["blockers"] += 1
        base = str(blocker.get("base", "") or "unknown")
        evidence = layout_evidence.get(base, {})
        identity = identity_evidence.get(base, {"identity_evidence": "none"})
        if (
            str(identity.get("identity_evidence", "") or "none") == "none"
            and str(blocker.get("source_identity_source", "") or "")
        ):
            identity = {
                "identity_evidence": "report_only_source_identity",
                "source": str(blocker.get("source_identity_source", "") or ""),
                "source_kind": "source_identity",
                "source_provenance": str(blocker.get("source_identity_source_provenance", "") or ""),
                "source_rhs_kind": "report_only_profile",
                "blocker_profile": "report_only_source_identity",
                "confidence": _float_value(blocker.get("confidence"), 0.0),
            }
        domain_identity = domain_identity_by_base.get(base, {})
        bases[base] += 1
        reason_items = [str(item) for item in blocker.get("reasons", []) or []]
        promotion_review_class = _layout_promotion_review_class(identity, reason_items)
        promotion_risk_factors = _layout_promotion_risk_factors(identity, reason_items)
        promotion_next_action = _layout_promotion_next_action(
            identity,
            reason_items,
            promotion_review_class,
            domain_identity,
        )
        promotion_next_action_details = _layout_promotion_next_action_details(
            identity,
            reason_items,
            promotion_next_action,
            domain_identity,
        )
        totals["reason_observations"] += len(reason_items)
        for reason in reason_items:
            reasons[reason] += 1
        profiles = _layout_rewrite_blocker_review_profiles(reason_items)
        for profile in profiles:
            review_profiles[profile] += 1
            review_queues.setdefault(profile, []).append(
                {
                    "ea": ea,
                    "name": function_name,
                    "base": base,
                    "offset_count": _int_value(evidence.get("offset_count"), 0),
                    "access_count": _int_value(evidence.get("access_count"), 0),
                    "layout_confidence": _float_value(evidence.get("confidence"), 0.0),
                    "blocker_confidence": _float_value(blocker.get("confidence"), 0.0),
                    "identity_evidence": str(identity.get("identity_evidence", "") or "none"),
                    "identity_source": str(identity.get("source", "") or ""),
                    "identity_source_kind": str(identity.get("source_kind", "") or ""),
                    "identity_blocker_profile": str(identity.get("blocker_profile", "") or ""),
                    "identity_source_provenance": str(identity.get("source_provenance", "") or ""),
                    "identity_source_rhs_kind": str(identity.get("source_rhs_kind", "") or ""),
                    "identity_source_anchor": str(identity.get("source_anchor", "") or ""),
                    "identity_source_type": str(identity.get("source_type", "") or ""),
                    "identity_source_detail": str(identity.get("source_detail", "") or ""),
                    "identity_confidence": _float_value(identity.get("confidence"), 0.0),
                    "domain_profile_id": str(domain_identity.get("profile_id", "") or ""),
                    "domain_role": str(domain_identity.get("role", "") or ""),
                    "domain_mode": str(domain_identity.get("mode", "") or ""),
                    "domain_field_count": _int_value(domain_identity.get("field_count"), 0),
                    "domain_fields": list(domain_identity.get("fields", []) or []),
                    "source_identity_source": str(blocker.get("source_identity_source", "") or ""),
                    "source_identity_source_provenance": str(
                        blocker.get("source_identity_source_provenance", "") or ""
                    ),
                    "source_identity_profile_id": str(
                        blocker.get("source_identity_profile_id", "") or ""
                    ),
                    "source_identity_role": str(blocker.get("source_identity_role", "") or ""),
                    "source_identity_structure": str(
                        blocker.get("source_identity_structure", "") or ""
                    ),
                    "promotion_review_class": promotion_review_class,
                    "promotion_risk_factors": promotion_risk_factors,
                    "promotion_next_action": promotion_next_action,
                    "promotion_next_action_details": promotion_next_action_details,
                    "reasons": reason_items,
                    "summary_path": str(summary_path),
                }
            )


def _layout_evidence_by_base(hints: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for hint in hints:
        base = str(hint.get("base", "") or "unknown")
        current = result.get(base)
        candidate = {
            "offset_count": _int_value(hint.get("offset_count"), 0),
            "access_count": _int_value(hint.get("access_count"), 0),
            "confidence": _float_value(hint.get("confidence"), 0.0),
        }
        if current is None:
            result[base] = candidate
            continue
        current_score = (
            _int_value(current.get("access_count"), 0),
            _int_value(current.get("offset_count"), 0),
            _float_value(current.get("confidence"), 0.0),
        )
        candidate_score = (
            _int_value(candidate.get("access_count"), 0),
            _int_value(candidate.get("offset_count"), 0),
            _float_value(candidate.get("confidence"), 0.0),
        )
        if candidate_score > current_score:
            result[base] = candidate
    return result


def _layout_identity_evidence_by_base(
    stable_base_sources: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in stable_base_sources:
        source_kind = str(item.get("source_kind", "") or "unknown")
        evidence_class = "stable_%s_source" % source_kind
        _set_layout_identity_evidence(
            result,
            str(item.get("base", "") or "unknown"),
            {
                "identity_evidence": evidence_class,
                "source": str(item.get("source", "") or ""),
                "source_kind": source_kind,
                "blocker_profile": "",
                "source_provenance": str(item.get("source_provenance", "") or "unknown"),
                "source_rhs_kind": str(item.get("source_rhs_kind", "") or "unknown"),
                "source_anchor": str(item.get("source_anchor", "") or ""),
                "source_type": str(item.get("source_type", "") or ""),
                "source_detail": str(item.get("source_detail", "") or ""),
                "confidence": _float_value(item.get("confidence"), 0.0),
                "offset_count": _int_value(item.get("offset_count"), 0),
                "access_count": _int_value(item.get("access_count"), 0),
            },
        )
    for item in generic_base_evidence:
        blocker_profile = str(item.get("blocker_profile", "") or "unknown")
        evidence_class = "generic_base_evidence"
        if blocker_profile != "generic_only":
            evidence_class = blocker_profile
        _set_layout_identity_evidence(
            result,
            str(item.get("base", "") or "unknown"),
            {
                "identity_evidence": evidence_class,
                "source": "",
                "source_kind": "",
                "blocker_profile": blocker_profile,
                "confidence": _float_value(item.get("confidence"), 0.0),
                "offset_count": _int_value(item.get("offset_count"), 0),
                "access_count": _int_value(item.get("access_count"), 0),
            },
        )
    for item in generic_base_trust_candidates:
        blocker_profile = str(item.get("blocker_profile", "") or "unknown")
        source_kind = str(item.get("source_kind", "") or "unknown")
        _set_layout_identity_evidence(
            result,
            str(item.get("base", "") or "unknown"),
            {
                "identity_evidence": "generic_%s_trust" % source_kind,
                "source": "",
                "source_kind": source_kind,
                "blocker_profile": blocker_profile,
                "confidence": _float_value(item.get("confidence"), 0.0),
                "offset_count": _int_value(item.get("offset_count"), 0),
                "access_count": _int_value(item.get("access_count"), 0),
            },
        )
    return result


def _domain_identity_by_base(domain_identities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in domain_identities:
        base = str(item.get("base", "") or "unknown")
        current = result.get(base)
        if current is None:
            result[base] = item
            continue
        current_score = (
            _int_value(current.get("field_count"), 0),
            1 if str(current.get("mode", "") or "") == "canonical-rewrite-eligible" else 0,
            str(current.get("profile_id", "")),
        )
        candidate_score = (
            _int_value(item.get("field_count"), 0),
            1 if str(item.get("mode", "") or "") == "canonical-rewrite-eligible" else 0,
            str(item.get("profile_id", "")),
        )
        if candidate_score > current_score:
            result[base] = item
    return result


def _set_layout_identity_evidence(
    result: dict[str, dict[str, Any]],
    base: str,
    candidate: dict[str, Any],
) -> None:
    current = result.get(base)
    if current is None:
        result[base] = candidate
        return
    current_score = _layout_identity_evidence_score(current)
    candidate_score = _layout_identity_evidence_score(candidate)
    if candidate_score > current_score:
        result[base] = candidate


def _layout_identity_evidence_score(item: dict[str, Any]) -> tuple[int, int, int, float]:
    priority = {
        "generic_parameter_trust": 40,
        "stable_argument_source": 35,
        "stable_named_source": 30,
        "generic_base_evidence": 20,
        "generic_with_other_blockers": 15,
    }.get(str(item.get("identity_evidence", "") or ""), 10)
    return (
        priority,
        _int_value(item.get("access_count"), 0),
        _int_value(item.get("offset_count"), 0),
        _float_value(item.get("confidence"), 0.0),
    )


def _layout_promotion_review_class(identity: dict[str, Any], reasons: list[str]) -> str:
    identity_evidence = str(identity.get("identity_evidence", "") or "none")
    if _has_layout_trusted_source_gap(reasons):
        return "trusted_source_missing"
    if identity_evidence == "none":
        return "missing_identity_evidence"
    if _has_layout_source_stability_risk(reasons):
        return "source_stability_blocked"
    if _has_layout_source_provenance_risk(identity):
        return "source_provenance_blocked"
    if _has_layout_type_evidence_risk(reasons):
        return "type_evidence_blocked"
    if _has_layout_threshold_gap(reasons):
        return "threshold_blocked"
    if identity_evidence == "generic_parameter_trust":
        return "generic_parameter_promotion_review"
    if identity_evidence in {"stable_argument_source", "stable_named_source"}:
        return "stable_source_promotion_review"
    if identity_evidence == "generic_with_other_blockers":
        return "generic_other_blocker_review"
    if identity_evidence == "generic_base_evidence":
        return "generic_base_evidence_review"
    return "manual_review"


def _layout_promotion_risk_factors(identity: dict[str, Any], reasons: list[str]) -> list[str]:
    identity_evidence = str(identity.get("identity_evidence", "") or "none")
    factors = []
    if _has_layout_trusted_source_gap(reasons):
        factors.append("trusted_source_gap")
    if identity_evidence == "none":
        factors.append("missing_identity_evidence")
    if _has_layout_source_stability_risk(reasons):
        factors.append("source_stability_risk")
    if _has_layout_source_provenance_risk(identity):
        factors.append("source_provenance_risk")
    if _has_layout_type_evidence_risk(reasons):
        factors.append("type_evidence_risk")
    if _has_layout_threshold_gap(reasons):
        factors.append("threshold_gap")
    if not factors:
        factors.append("identity_only")
    return factors


def _layout_promotion_next_action(
    identity: dict[str, Any],
    reasons: list[str],
    review_class: str | None = None,
    domain_identity: dict[str, Any] | None = None,
) -> str:
    reasons_lower = [str(reason or "").lower() for reason in reasons]
    identity_evidence = str(identity.get("identity_evidence", "") or "none")
    review = review_class or _layout_promotion_review_class(identity, reasons)
    domain = domain_identity or {}
    if _has_layout_trusted_source_gap(reasons):
        return "add_exact_source_identity_or_keep_review_only"
    if _has_layout_source_stability_risk(reasons):
        return "prove_source_stability_before_rewrite"
    if _has_layout_source_provenance_risk(identity):
        return "prove_source_provenance_before_rewrite"
    if _has_layout_type_evidence_risk(reasons):
        return "resolve_type_width_or_subfield_conflict"
    if (
        any("domain identity profile is report-only" in reason for reason in reasons_lower)
        and _has_layout_threshold_gap(reasons)
    ):
        if _int_value(domain.get("field_count"), 0) > 0:
            return "review_report_only_field_aliases"
        return "collect_more_exact_field_evidence"
    if review == "missing_identity_evidence" or identity_evidence == "none":
        return "add_exact_identity_or_keep_review_only"
    if _has_layout_threshold_gap(reasons):
        return "collect_more_offset_access_evidence"
    if review in {"generic_parameter_promotion_review", "stable_source_promotion_review"}:
        return "consider_validated_profile_promotion"
    if review == "type_evidence_blocked":
        return "resolve_type_width_or_subfield_conflict"
    return "manual_review"


def _layout_promotion_next_action_details(
    identity: dict[str, Any],
    reasons: list[str],
    next_action: str | None = None,
    domain_identity: dict[str, Any] | None = None,
) -> list[str]:
    details: list[str] = []
    reasons_lower = [str(reason or "").lower() for reason in reasons]
    identity_evidence = str(identity.get("identity_evidence", "") or "none")
    provenance = str(identity.get("source_provenance", "") or "")
    blocker_profile = str(identity.get("blocker_profile", "") or "")
    domain = domain_identity or {}
    action = next_action or _layout_promotion_next_action(identity, reasons, domain_identity=domain)

    if action in {"collect_more_exact_field_evidence", "review_report_only_field_aliases"}:
        details.append("report_only_profile")
        if any("rewrite offset threshold" in reason for reason in reasons_lower):
            details.append("offset_threshold_gap")
        if any("rewrite access threshold" in reason for reason in reasons_lower):
            details.append("access_threshold_gap")
        if action == "review_report_only_field_aliases":
            details.append("observed_field_aliases")
    if action == "prove_source_stability_before_rewrite":
        if any("domain identity profile is report-only" in reason for reason in reasons_lower):
            details.append("report_only_profile")
        if _int_value(domain.get("field_count"), 0) > 0:
            details.append("observed_field_aliases")
        if any("multiple initializers" in reason for reason in reasons_lower):
            details.append("multiple_initializers")
        if any("reassigned" in reason for reason in reasons_lower):
            details.append("post_access_reassignment")
        if any("address is taken" in reason for reason in reasons_lower):
            details.append("address_taken")
        if any("indexed like an array" in reason for reason in reasons_lower):
            details.append("indexed_array_base")
        if any("rewrite offset threshold" in reason for reason in reasons_lower):
            details.append("offset_threshold_gap")
        if any("rewrite access threshold" in reason for reason in reasons_lower):
            details.append("access_threshold_gap")
        if any("mix narrow" in reason for reason in reasons_lower):
            details.append("narrow_subfield_conflict")
        if any("mix wide" in reason for reason in reasons_lower):
            details.append("wide_overlay_conflict")
        if any("irregular field" in reason for reason in reasons_lower):
            details.append("irregular_overlay_conflict")
        if any("not naturally aligned" in reason for reason in reasons_lower):
            details.append("alignment_conflict")
    if action == "prove_source_provenance_before_rewrite":
        details.append("source_provenance_%s" % (provenance or "unknown"))
    if action == "resolve_type_width_or_subfield_conflict":
        if any("mix narrow" in reason for reason in reasons_lower):
            details.append("narrow_subfield_conflict")
        if any("mix wide" in reason for reason in reasons_lower):
            details.append("wide_overlay_conflict")
        if any("irregular field" in reason for reason in reasons_lower):
            details.append("irregular_overlay_conflict")
        if any("not naturally aligned" in reason for reason in reasons_lower):
            details.append("alignment_conflict")
        if any("volatile-looking" in reason or "mmio/register" in reason for reason in reasons_lower):
            details.append("volatile_or_mmio_conflict")
    if action == "add_exact_identity_or_keep_review_only":
        details.append("missing_identity_evidence")
    if action == "add_exact_source_identity_or_keep_review_only":
        details.append("trusted_source_required")
        if identity_evidence == "none":
            details.append("missing_identity_evidence")
    if action == "collect_more_offset_access_evidence":
        if any("rewrite offset threshold" in reason for reason in reasons_lower):
            details.append("offset_threshold_gap")
        if any("rewrite access threshold" in reason for reason in reasons_lower):
            details.append("access_threshold_gap")
    if action == "consider_validated_profile_promotion":
        details.append(identity_evidence)
        if blocker_profile:
            details.append(blocker_profile)
    if not details:
        details.append("manual_review")
    return details


def _has_layout_source_provenance_risk(identity: dict[str, Any]) -> bool:
    provenance = str(identity.get("source_provenance", "") or "")
    if not provenance:
        return False
    return provenance in {
        "missing_alias_assignment",
        "named_derived_pointer_alias",
        "named_multi_assignment_alias",
        "temporary_source_alias",
        "generic_source_alias",
        "unknown_source_alias",
    }


def _has_layout_source_stability_risk(reasons: list[str]) -> bool:
    return any(
        any(token in str(reason or "").lower() for token in ("multiple initializers", "reassigned", "address is taken", "indexed like an array"))
        for reason in reasons
    )


def _has_layout_trusted_source_gap(reasons: list[str]) -> bool:
    return any(
        "trusted rewrite source is required" in str(reason or "").lower()
        for reason in reasons
    )


def _has_layout_type_evidence_risk(reasons: list[str]) -> bool:
    return any(
        any(
            token in str(reason or "").lower()
            for token in (
                "mix narrow",
                "mix wide",
                "irregular field",
                "not naturally aligned",
                "volatile-looking",
                "mmio/register",
            )
        )
        for reason in reasons
    )


def _has_layout_threshold_gap(reasons: list[str]) -> bool:
    return any("rewrite offset threshold" in str(reason or "").lower() or "rewrite access threshold" in str(reason or "").lower() for reason in reasons)


def _layout_rewrite_blocker_review_profiles(reasons: list[str]) -> list[str]:
    profiles: set[str] = set()
    for reason in reasons:
        lowered = str(reason or "").lower()
        if "decompiler temporary" in lowered:
            profiles.add("base_identity_candidates")
            profiles.add("temp_base_identity_candidates")
        if "base name is generic" in lowered:
            profiles.add("base_identity_candidates")
            profiles.add("generic_base_identity_candidates")
        if "trusted rewrite source is required" in lowered:
            profiles.add("base_identity_candidates")
            profiles.add("source_identity_gap_candidates")
        if "source domain identity profile is report-only" in lowered:
            profiles.add("base_identity_candidates")
            profiles.add("source_identity_gap_candidates")
        if "multiple initializers" in lowered:
            profiles.add("base_stability_blockers")
            profiles.add("multiple_initializer_base_blockers")
        if "reassigned" in lowered:
            profiles.add("base_stability_blockers")
            profiles.add("reassigned_base_blockers")
        if "address is taken" in lowered:
            profiles.add("base_stability_blockers")
            profiles.add("address_taken_base_blockers")
        if "mix narrow" in lowered:
            profiles.add("type_evidence_blockers")
            profiles.add("narrow_subfield_type_blockers")
        if "mix wide" in lowered:
            profiles.add("type_evidence_blockers")
            profiles.add("wide_overlay_type_blockers")
        if "irregular field" in lowered:
            profiles.add("type_evidence_blockers")
            profiles.add("irregular_overlay_type_blockers")
        if "not naturally aligned" in lowered:
            profiles.add("type_evidence_blockers")
            profiles.add("alignment_type_blockers")
        if "rewrite offset threshold" in lowered:
            profiles.add("threshold_gap_candidates")
            profiles.add("offset_threshold_gap_candidates")
        if "rewrite access threshold" in lowered:
            profiles.add("threshold_gap_candidates")
            profiles.add("access_threshold_gap_candidates")
    if not profiles:
        profiles.add("manual_review")
    return [profile for profile in _LAYOUT_REWRITE_BLOCKER_QUEUE_ORDER if profile in profiles]


def _layout_rewrite_blocker_review_queues(
    queue_items: dict[str, list[dict[str, Any]]],
    top: int,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for queue_name in _LAYOUT_REWRITE_BLOCKER_QUEUE_ORDER:
        items = list(queue_items.get(queue_name, []))
        items.sort(
            key=lambda item: (
                -_int_value(item.get("access_count"), 0),
                -_int_value(item.get("offset_count"), 0),
                str(item.get("name", "")),
                str(item.get("base", "")),
            )
        )
        function_names = {str(item.get("name", "") or "") for item in items}
        bases = Counter(str(item.get("base", "") or "unknown") for item in items)
        identity_evidence = Counter(str(item.get("identity_evidence", "") or "none") for item in items)
        identity_source_provenance = Counter(
            str(item.get("identity_source_provenance", "") or "none")
            for item in items
        )
        promotion_review_classes = Counter(
            str(item.get("promotion_review_class", "") or "manual_review")
            for item in items
        )
        promotion_risk_factors = Counter(
            str(factor)
            for item in items
            for factor in item.get("promotion_risk_factors", []) or []
        )
        promotion_next_actions = Counter(
            str(item.get("promotion_next_action", "") or "manual_review")
            for item in items
        )
        promotion_next_action_details = Counter(
            str(detail)
            for item in items
            for detail in item.get("promotion_next_action_details", []) or []
        )
        result[queue_name] = {
            "blockers": len(items),
            "functions": len(function_names),
            "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in items), default=0),
            "max_access_count": max((_int_value(item.get("access_count"), 0) for item in items), default=0),
            "max_layout_confidence": max(
                (_float_value(item.get("layout_confidence"), 0.0) for item in items),
                default=0.0,
            ),
            "max_blocker_confidence": max(
                (_float_value(item.get("blocker_confidence"), 0.0) for item in items),
                default=0.0,
            ),
            "top_bases": _counter_to_dict(Counter(dict(bases.most_common(top)))),
            "identity_evidence": _counter_to_dict(Counter(dict(identity_evidence.most_common(top)))),
            "identity_source_provenance": _counter_to_dict(
                Counter(dict(identity_source_provenance.most_common(top)))
            ),
            "promotion_review_classes": _counter_to_dict(
                Counter(dict(promotion_review_classes.most_common(top)))
            ),
            "promotion_risk_factors": _counter_to_dict(Counter(dict(promotion_risk_factors.most_common(top)))),
            "promotion_next_actions": _counter_to_dict(
                Counter(dict(promotion_next_actions.most_common(top)))
            ),
            "promotion_next_action_details": _counter_to_dict(
                Counter(dict(promotion_next_action_details.most_common(top)))
            ),
            "items": items[:top],
        }
    return result


def _layout_hint_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    hints: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "hint_count": len(hints),
        "bases": [str(item.get("base", "") or "unknown") for item in hints[:8]],
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in hints), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in hints), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in hints), default=0.0),
        "summary_path": str(summary_path),
    }


def _subfield_overlay_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    overlays: list[dict[str, Any]],
) -> dict[str, Any]:
    size_classes = Counter()
    policy_classes = Counter()
    interpretations = Counter()
    bit_masks = Counter()
    bit_operations = Counter()
    mask_families = Counter()
    for overlay in overlays:
        for field in overlay.get("fields", []) or []:
            if isinstance(field, dict):
                size_classes[str(field.get("size_class", "") or "unknown")] += 1
                policy_classes[str(field.get("policy_class", "") or "unknown")] += 1
                interpretations[str(field.get("interpretation", "") or "unknown")] += 1
                for mask in field.get("bit_masks", []) or []:
                    bit_masks[str(mask)] += 1
                for operation in field.get("bit_operations", []) or []:
                    bit_operations[str(operation)] += 1
                for family in field.get("mask_families", []) or []:
                    mask_families[str(family)] += 1
    return {
        "ea": ea,
        "name": name,
        "overlay_count": len(overlays),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in overlays),
        "bases": [str(item.get("base", "") or "unknown") for item in overlays[:8]],
        "top_size_classes": _counter_to_dict(Counter(dict(size_classes.most_common(5)))),
        "top_policy_classes": _counter_to_dict(Counter(dict(policy_classes.most_common(5)))),
        "top_interpretations": _counter_to_dict(Counter(dict(interpretations.most_common(5)))),
        "top_bit_masks": _counter_to_dict(Counter(dict(bit_masks.most_common(5)))),
        "top_bit_operations": _counter_to_dict(Counter(dict(bit_operations.most_common(5)))),
        "top_mask_families": _counter_to_dict(Counter(dict(mask_families.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in overlays), default=0.0),
        "summary_path": str(summary_path),
    }


def _narrow_subfield_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    size_classes = Counter()
    interpretations = Counter()
    bit_masks = Counter()
    bit_operations = Counter()
    mask_families = Counter()
    for candidate in candidates:
        for field in candidate.get("fields", []) or []:
            if isinstance(field, dict):
                size_classes[str(field.get("size_class", "") or "unknown")] += 1
                interpretations[str(field.get("interpretation", "") or "unknown")] += 1
                for mask in field.get("bit_masks", []) or []:
                    bit_masks[str(mask)] += 1
                for operation in field.get("bit_operations", []) or []:
                    bit_operations[str(operation)] += 1
                for family in field.get("mask_families", []) or []:
                    mask_families[str(family)] += 1
    return {
        "ea": ea,
        "name": name,
        "candidate_count": len(candidates),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_size_classes": _counter_to_dict(Counter(dict(size_classes.most_common(5)))),
        "top_interpretations": _counter_to_dict(Counter(dict(interpretations.most_common(5)))),
        "top_bit_masks": _counter_to_dict(Counter(dict(bit_masks.most_common(5)))),
        "top_bit_operations": _counter_to_dict(Counter(dict(bit_operations.most_common(5)))),
        "top_mask_families": _counter_to_dict(Counter(dict(mask_families.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _bitfield_alias_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    aliases = Counter()
    masks = Counter()
    for candidate in candidates:
        for field in candidate.get("fields", []) or []:
            if isinstance(field, dict):
                for alias in field.get("aliases", []) or []:
                    aliases[str(alias)] += 1
                for mask in field.get("masks", []) or []:
                    masks[str(mask)] += 1
    return {
        "ea": ea,
        "name": name,
        "alias_comment_count": len(candidates),
        "field_count": sum(_int_value(item.get("field_count"), 0) for item in candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_aliases": _counter_to_dict(Counter(dict(aliases.most_common(5)))),
        "top_masks": _counter_to_dict(Counter(dict(masks.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _hot_field_cluster_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    base_kinds = Counter(
        str(item.get("base_kind", "") or "unknown")
        for item in candidates
    )
    field_types = Counter()
    top_field_access_count = 0
    for candidate in candidates:
        for field in candidate.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            field_types[str(field.get("type", "") or "unknown")] += 1
            top_field_access_count = max(
                top_field_access_count,
                _int_value(field.get("access_count"), 0),
            )
    return {
        "ea": ea,
        "name": name,
        "cluster_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "base_kinds": _counter_to_dict(Counter(dict(base_kinds.most_common(5)))),
        "top_field_types": _counter_to_dict(Counter(dict(field_types.most_common(5)))),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_top_field_access_count": top_field_access_count,
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _indexed_callback_table_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    base_kinds = Counter(
        str(item.get("base_kind", "") or "unknown")
        for item in candidates
    )
    alias_bases = Counter()
    for candidate in candidates:
        for alias_base in candidate.get("alias_bases", []) or []:
            alias_bases[str(alias_base)] += 1
    return {
        "ea": ea,
        "name": name,
        "evidence_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "base_kinds": _counter_to_dict(Counter(dict(base_kinds.most_common(5)))),
        "alias_bases": _counter_to_dict(Counter(dict(alias_bases.most_common(5)))),
        "max_slot_count": max((_int_value(item.get("slot_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _parameter_indexed_element_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    parents = Counter(
        str(item.get("parent", "") or "unknown")
        for item in candidates
    )
    parent_types = Counter(
        str(item.get("parent_type", "") or "unknown")
        for item in candidates
        if str(item.get("parent_type", "") or "")
    )
    strides = Counter(
        str(_int_value(item.get("stride"), 0))
        for item in candidates
        if _int_value(item.get("stride"), 0) > 0
    )
    alias_rewrite_risks = Counter(
        str(item.get("alias_rewrite_risk", "") or "")
        for item in candidates
        if str(item.get("alias_rewrite_risk", "") or "")
    )
    return {
        "ea": ea,
        "name": name,
        "evidence_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "parents": _counter_to_dict(Counter(dict(parents.most_common(5)))),
        "parent_types": _counter_to_dict(Counter(dict(parent_types.most_common(5)))),
        "strides": _counter_to_dict(Counter(dict(strides.most_common(5)))),
        "alias_rewrite_risks": _counter_to_dict(Counter(dict(alias_rewrite_risks.most_common(5)))),
        "max_offset_count": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _stable_base_source_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    sources = Counter()
    source_kinds = Counter()
    source_provenance = Counter()
    for candidate in candidates:
        sources[str(candidate.get("source", "") or "unknown")] += 1
        source_kinds[str(candidate.get("source_kind", "") or "unknown")] += 1
        source_provenance[str(candidate.get("source_provenance", "") or "unknown")] += 1
    return {
        "ea": ea,
        "name": name,
        "source_comment_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "top_sources": _counter_to_dict(Counter(dict(sources.most_common(5)))),
        "top_source_kinds": _counter_to_dict(Counter(dict(source_kinds.most_common(5)))),
        "top_source_provenance": _counter_to_dict(Counter(dict(source_provenance.most_common(5)))),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _base_stability_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    rhs_samples = Counter(
        str(rhs)
        for candidate in candidates
        for rhs in candidate.get("distinct_pre_access_rhs", []) or []
        if str(rhs)
    )
    profiles = Counter(_base_stability_review_profile(candidate) for candidate in candidates)
    return {
        "ea": ea,
        "name": name,
        "stability_comment_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "rhs_samples": _counter_to_dict(Counter(dict(rhs_samples.most_common(5)))),
        "profiles": _counter_to_dict(Counter(dict(profiles.most_common(5)))),
        "max_distinct_pre_access_rhs": max(
            (_int_value(item.get("distinct_pre_access_rhs_count"), 0) for item in candidates),
            default=0,
        ),
        "max_risky_post_access_assignments": max(
            (_int_value(item.get("risky_post_access_assignment_count"), 0) for item in candidates),
            default=0,
        ),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _generic_base_evidence_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    blocker_profiles = Counter(
        str(item.get("blocker_profile", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "evidence_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "blocker_profiles": _counter_to_dict(blocker_profiles),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _generic_base_trust_candidate_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    source_kinds = Counter(
        str(item.get("source_kind", "") or "unknown")
        for item in candidates
    )
    blocker_profiles = Counter(
        str(item.get("blocker_profile", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "candidate_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "source_kinds": _counter_to_dict(source_kinds),
        "blocker_profiles": _counter_to_dict(blocker_profiles),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _temp_provenance_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    provenance: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    traces = [item for item in provenance.get("traces", []) or [] if isinstance(item, dict)]
    trusted = [item for item in provenance.get("trusted", []) or [] if isinstance(item, dict)]
    blocked = [item for item in provenance.get("blocked", []) or [] if isinstance(item, dict)]
    all_items = traces + trusted + blocked
    trust_classes = Counter(
        str(item.get("trust_class", "") or "trusted_stable_temp")
        for item in all_items
    )
    source_origins = Counter(
        str(item.get("source_origin", "") or "unknown")
        for item in traces + trusted
    )
    bases = [str(item.get("base", "") or "unknown") for item in all_items[:8]]
    return {
        "ea": ea,
        "name": name,
        "trace_count": len(traces),
        "trusted_count": len(trusted),
        "blocked_count": len(blocked),
        "bases": bases,
        "trust_classes": _counter_to_dict(Counter(dict(trust_classes.most_common(5)))),
        "source_origins": _counter_to_dict(Counter(dict(source_origins.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in all_items), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_ready_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    source_provenance = Counter(
        str(item.get("source_provenance", "") or "none")
        for item in candidates
    )
    threshold_policies = Counter(
        str(item.get("threshold_policy", "") or "standard")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "ready_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "source_provenance": _counter_to_dict(Counter(dict(source_provenance.most_common(5)))),
        "threshold_policies": _counter_to_dict(Counter(dict(threshold_policies.most_common(5)))),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_preview_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    source_provenance = Counter(
        str(item.get("source_provenance", "") or "none")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "preview_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "source_provenance": _counter_to_dict(Counter(dict(source_provenance.most_common(5)))),
        "max_fields": max((_int_value(item.get("field_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_preview_artifact_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    validation = _coerce_dict(metadata.get("validation", {}))
    direct_zero_rewritten_accesses = _rewrite_preview_artifact_direct_zero_rewrite_accesses(metadata)
    canonical_modified = bool(metadata.get("canonical_cleaned_output_modified", False))
    source_alias_extensions = [
        dict(item)
        for item in metadata.get("source_alias_residual_extensions", []) or []
        if isinstance(item, dict)
    ]
    return {
        "ea": ea,
        "name": name,
        "validation_status": str(validation.get("status", "") or "unknown"),
        "validation_errors": [
            str(error)
            for error in validation.get("errors", []) or []
            if str(error)
        ],
        "canonical_rewrite_status": str(metadata.get("canonical_rewrite_status", "") or "unknown"),
        "canonical_cleaned_output_modified": canonical_modified,
        "preview_plan_kinds": dict(
            Counter(
                str(plan.get("plan_kind", "") or "full")
                for plan in metadata.get("preview_plans", []) or []
                if isinstance(plan, dict)
            )
        ),
        "advertisement_normalizations": [
            dict(item)
            for item in metadata.get("advertisement_normalizations", []) or []
            if isinstance(item, dict)
        ],
        "source_alias_residual_extensions": source_alias_extensions,
        "source_alias_residual_extension_count": len(source_alias_extensions),
        "source_alias_residual_extended_offsets": sum(
            len(
                [
                    offset
                    for offset in item.get("extended_offsets", []) or []
                    if _rewrite_preview_artifact_offset_key(offset) is not None
                ]
            )
            for item in source_alias_extensions
        ),
        "rewritten_accesses": _int_value(metadata.get("rewritten_accesses"), 0),
        "rewritten_fields": _int_value(metadata.get("rewritten_fields"), 0),
        "direct_zero_rewritten_accesses": direct_zero_rewritten_accesses,
        "canonical_direct_zero_rewritten_accesses": (
            direct_zero_rewritten_accesses if canonical_modified else 0
        ),
        "rewritten_bases": [
            str(base)
            for base in metadata.get("rewritten_bases", []) or []
            if str(base)
        ],
        "summary_path": str(summary_path),
    }


def _rewrite_near_ready_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    missing_thresholds = Counter(
        str(item.get("missing_threshold", "") or "unknown")
        for item in candidates
    )
    return {
        "ea": ea,
        "name": name,
        "near_ready_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "missing_thresholds": _counter_to_dict(missing_thresholds),
        "max_offsets": max((_int_value(item.get("offset_count"), 0) for item in candidates), default=0),
        "max_access_count": max((_int_value(item.get("access_count"), 0) for item in candidates), default=0),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_partial_opportunity_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons = Counter()
    application_statuses = Counter(
        str(item.get("application_status", "") or "unknown")
        for item in candidates
    )
    review_classes = Counter(
        str(item.get("review_class", "") or "manual_review")
        for item in candidates
    )
    source_provenance = Counter(
        str(item.get("source_provenance", "") or "none")
        for item in candidates
    )
    for candidate in candidates:
        for reason in candidate.get("reasons", []) or []:
            reasons[str(reason)] += 1
    return {
        "ea": ea,
        "name": name,
        "partial_opportunity_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "source_provenance": _counter_to_dict(Counter(dict(source_provenance.most_common(5)))),
        "application_statuses": _counter_to_dict(Counter(dict(application_statuses.most_common(5)))),
        "review_classes": _counter_to_dict(Counter(dict(review_classes.most_common(5)))),
        "max_safe_offsets": max((_int_value(item.get("safe_offset_count"), 0) for item in candidates), default=0),
        "max_safe_access_count": max(
            (_int_value(item.get("safe_access_count"), 0) for item in candidates),
            default=0,
        ),
        "max_excluded_offsets": max(
            (_int_value(item.get("excluded_offset_count"), 0) for item in candidates),
            default=0,
        ),
        "max_excluded_access_count": max(
            (_int_value(item.get("excluded_access_count"), 0) for item in candidates),
            default=0,
        ),
        "top_reasons": _counter_to_dict(Counter(dict(reasons.most_common(5)))),
        "max_confidence": max((_float_value(item.get("confidence"), 0.0) for item in candidates), default=0.0),
        "summary_path": str(summary_path),
    }


def _rewrite_blocker_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    blockers: list[dict[str, Any]],
    layout_hints: list[dict[str, Any]],
    stable_base_sources: list[dict[str, Any]],
    generic_base_evidence: list[dict[str, Any]],
    generic_base_trust_candidates: list[dict[str, Any]],
    domain_identities: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons = Counter()
    review_profiles = Counter()
    identity_evidence = Counter()
    identity_source_provenance = Counter()
    promotion_review_classes = Counter()
    promotion_next_actions = Counter()
    promotion_next_action_details = Counter()
    bases = []
    layout_evidence = _layout_evidence_by_base(layout_hints)
    identity_by_base = _layout_identity_evidence_by_base(
        stable_base_sources,
        generic_base_evidence,
        generic_base_trust_candidates,
    )
    domain_identity_by_base = _domain_identity_by_base(domain_identities)
    max_offsets = 0
    max_access_count = 0
    max_layout_confidence = 0.0
    max_blocker_confidence = 0.0
    for blocker in blockers:
        base = str(blocker.get("base", "") or "unknown")
        bases.append(base)
        evidence = layout_evidence.get(base, {})
        max_offsets = max(max_offsets, _int_value(evidence.get("offset_count"), 0))
        max_access_count = max(max_access_count, _int_value(evidence.get("access_count"), 0))
        max_layout_confidence = max(max_layout_confidence, _float_value(evidence.get("confidence"), 0.0))
        max_blocker_confidence = max(max_blocker_confidence, _float_value(blocker.get("confidence"), 0.0))
        identity = identity_by_base.get(base, {"identity_evidence": "none"})
        domain_identity = domain_identity_by_base.get(base, {})
        reason_items = [str(reason) for reason in blocker.get("reasons", []) or []]
        identity_evidence[str(identity.get("identity_evidence", "") or "none")] += 1
        identity_source_provenance[str(identity.get("source_provenance", "") or "none")] += 1
        promotion_review_class = _layout_promotion_review_class(identity, reason_items)
        promotion_review_classes[promotion_review_class] += 1
        promotion_next_action = _layout_promotion_next_action(
            identity,
            reason_items,
            promotion_review_class,
            domain_identity,
        )
        promotion_next_actions[promotion_next_action] += 1
        for detail in _layout_promotion_next_action_details(
            identity,
            reason_items,
            promotion_next_action,
            domain_identity,
        ):
            promotion_next_action_details[detail] += 1
        for reason in reason_items:
            reasons[str(reason)] += 1
        for profile in _layout_rewrite_blocker_review_profiles(reason_items):
            review_profiles[profile] += 1
    return {
        "ea": ea,
        "name": name,
        "blocker_count": len(blockers),
        "reason_count": sum(reasons.values()),
        "bases": bases[:8],
        "max_offsets": max_offsets,
        "max_access_count": max_access_count,
        "max_layout_confidence": max_layout_confidence,
        "max_blocker_confidence": max_blocker_confidence,
        "review_profiles": _counter_to_dict(Counter(dict(review_profiles.most_common(5)))),
        "identity_evidence": _counter_to_dict(Counter(dict(identity_evidence.most_common(5)))),
        "identity_source_provenance": _counter_to_dict(Counter(dict(identity_source_provenance.most_common(5)))),
        "promotion_review_classes": _counter_to_dict(Counter(dict(promotion_review_classes.most_common(5)))),
        "promotion_next_actions": _counter_to_dict(Counter(dict(promotion_next_actions.most_common(5)))),
        "promotion_next_action_details": _counter_to_dict(
            Counter(dict(promotion_next_action_details.most_common(5)))
        ),
        "top_reasons": _counter_to_dict(Counter(dict(reasons.most_common(5)))),
        "summary_path": str(summary_path),
    }


def _is_decompiler_temp_base(name: str) -> bool:
    return re.fullmatch(r"[av]\d+", str(name or "")) is not None


def _existing_parameter_register_alias_diagnostics(
    warning_diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        item
        for item in warning_diagnostics
        if isinstance(item, dict)
        and str(item.get("candidate_action", "") or "") == "existing_parameter_register_alias"
    ]


def _existing_parameter_alias_profile(
    warning_diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    actions: Counter[str] = Counter()
    registers: Counter[str] = Counter()
    callees: Counter[str] = Counter()
    symbols: Counter[str] = Counter()
    samples: list[str] = []
    diagnostics = _existing_parameter_register_alias_diagnostics(warning_diagnostics)
    for item in diagnostics:
        action = str(item.get("candidate_action", "") or "").strip()
        symbol = str(item.get("symbol", "") or "").strip()
        register = str(item.get("register", "") or "").strip()
        callee = str(item.get("callee_name", "") or "").strip()
        if action:
            actions[action] += 1
        if register:
            registers[register] += 1
        if callee:
            callees[callee] += 1
        if symbol:
            symbols[symbol] += 1
        sample = _existing_parameter_alias_sample(item)
        if sample and sample not in samples:
            samples.append(sample)
    if not diagnostics:
        return {}
    return {
        "count": len(diagnostics),
        "actions": _counter_to_dict(Counter(dict(actions.most_common(8)))),
        "registers": _counter_to_dict(Counter(dict(registers.most_common(8)))),
        "callees": _counter_to_dict(Counter(dict(callees.most_common(8)))),
        "symbols": _counter_to_dict(Counter(dict(symbols.most_common(8)))),
        "samples": samples[:5],
    }


def _existing_parameter_alias_sample(item: dict[str, Any]) -> str:
    symbol = str(item.get("symbol", "") or "live_in").strip()
    register = str(item.get("register", "") or "").strip()
    rendered_name = str(item.get("existing_parameter_rendered_name", "") or "").strip()
    callee = str(item.get("callee_name", "") or "").strip()
    argument_index = _int_value(item.get("argument_index"), -1)
    left = symbol
    if register:
        left = "%s(%s)" % (left, register)
    if rendered_name:
        result = "%s->%s" % (left, rendered_name)
    else:
        result = "%s->existing_parameter" % left
    if argument_index >= 0:
        result = "%s arg%d" % (result, argument_index)
    if callee:
        result = "%s %s" % (result, callee)
    return result


def _existing_parameter_alias_function_summary(
    name: str,
    ea: str,
    summary_path: Path,
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    aliases = []
    for item in diagnostics[:8]:
        aliases.append(
            {
                "symbol": str(item.get("symbol", "") or ""),
                "register": str(item.get("register", "") or ""),
                "existing_parameter_index": _int_value(item.get("existing_parameter_index"), -1),
                "existing_parameter_raw_name": str(item.get("existing_parameter_raw_name", "") or ""),
                "existing_parameter_rendered_name": str(
                    item.get("existing_parameter_rendered_name", "") or ""
                ),
                "callee_name": str(item.get("callee_name", "") or ""),
                "argument_index": _int_value(item.get("argument_index"), -1),
            }
        )
    return {
        "ea": ea,
        "name": name,
        "alias_count": len(diagnostics),
        "aliases": aliases,
        "summary_path": str(summary_path),
    }


_LIVE_IN_PARAMETER_GAP_ACTIONS = {
    "caller_parameter_gap_candidate",
    "parameter_gap_candidate",
}


def _live_in_parameter_gap_profile(
    warning_diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    actions: Counter[str] = Counter()
    registers: Counter[str] = Counter()
    callees: Counter[str] = Counter()
    symbols: Counter[str] = Counter()
    abi_slots: Counter[str] = Counter()
    missing_signature_slots: Counter[str] = Counter()
    samples: list[str] = []
    count = 0
    for item in warning_diagnostics:
        if not isinstance(item, dict):
            continue
        if str(item.get("kind", "") or "") != "unassigned_local_live_in_register":
            continue
        if str(item.get("register_class", "") or "") != "abi_argument":
            continue
        action = str(item.get("candidate_action", "") or "").strip()
        if action not in _LIVE_IN_PARAMETER_GAP_ACTIONS:
            continue
        symbol = str(item.get("symbol", "") or "").strip()
        register = str(item.get("register", "") or "").strip()
        callee = str(item.get("callee_name", "") or "").strip()
        argument_index = _int_value(item.get("argument_index"), -1)
        abi_parameter_index = _int_value(item.get("abi_parameter_index"), -1)
        missing_slot_label = str(item.get("missing_signature_parameter_slot_label", "") or "").strip()
        count += 1
        if action:
            actions[action] += 1
        if register:
            registers[register] += 1
        if callee:
            callees[callee] += 1
        if symbol:
            symbols[symbol] += 1
        if abi_parameter_index >= 0:
            abi_slots["abi_slot%d" % abi_parameter_index] += 1
        if bool(item.get("missing_signature_parameter_slot")) and missing_slot_label:
            missing_signature_slots[missing_slot_label] += 1
        sample = _live_in_parameter_gap_sample(symbol, register, callee, argument_index, action, item)
        if sample and sample not in samples:
            samples.append(sample)
    if count <= 0:
        return {}
    return {
        "count": count,
        "actions": _counter_to_dict(Counter(dict(actions.most_common(8)))),
        "registers": _counter_to_dict(Counter(dict(registers.most_common(8)))),
        "callees": _counter_to_dict(Counter(dict(callees.most_common(8)))),
        "symbols": _counter_to_dict(Counter(dict(symbols.most_common(8)))),
        "abi_slots": _counter_to_dict(Counter(dict(abi_slots.most_common(8)))),
        "missing_signature_slots": _counter_to_dict(
            Counter(dict(missing_signature_slots.most_common(8)))
        ),
        "samples": samples[:5],
    }


def _live_in_parameter_gap_sample(
    symbol: str,
    register: str,
    callee: str,
    argument_index: int,
    action: str,
    item: dict[str, Any],
) -> str:
    left = symbol or "live_in"
    if register:
        left = "%s(%s)" % (left, register)
    target = callee
    if argument_index >= 0:
        target = "%s[arg%d]" % (target or "call", argument_index)
    if action == "existing_parameter_register_alias":
        existing_name = str(item.get("existing_parameter_rendered_name", "") or "").strip()
        if existing_name:
            target = "%s=>%s" % (target or "existing_parameter", existing_name)
    missing_slot_label = str(item.get("missing_signature_parameter_slot_label", "") or "").strip()
    if missing_slot_label:
        target = "%s %s" % (target or "call", missing_slot_label)
    if target:
        return "%s->%s %s" % (left, target, action)
    return "%s %s" % (left, action)


def _callee_arity_residue_profile(
    warning_diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    actions: Counter[str] = Counter()
    registers: Counter[str] = Counter()
    callees: Counter[str] = Counter()
    evidence: Counter[str] = Counter()
    samples: list[str] = []
    count = 0
    for item in warning_diagnostics:
        if not isinstance(item, dict):
            continue
        if str(item.get("kind", "") or "") != "unassigned_local_live_in_register":
            continue
        if str(item.get("register_class", "") or "") != "abi_argument":
            continue
        action = str(item.get("candidate_action", "") or "").strip()
        if action != "callee_arity_residue_candidate":
            continue
        symbol = str(item.get("symbol", "") or "").strip()
        register = str(item.get("register", "") or "").strip()
        callee = str(item.get("callee_name", "") or "").strip()
        argument_index = _int_value(item.get("argument_index"), -1)
        contract_evidence = str(item.get("callee_contract_evidence", "") or "").strip()
        count += 1
        actions[action] += 1
        if register:
            registers[register] += 1
        if callee:
            callees[callee] += 1
        if contract_evidence:
            evidence[contract_evidence] += 1
        sample = _live_in_parameter_gap_sample(symbol, register, callee, argument_index, action, item)
        if sample and sample not in samples:
            samples.append(sample)
    if count <= 0:
        return {}
    return {
        "count": count,
        "actions": _counter_to_dict(Counter(dict(actions.most_common(8)))),
        "registers": _counter_to_dict(Counter(dict(registers.most_common(8)))),
        "callees": _counter_to_dict(Counter(dict(callees.most_common(8)))),
        "evidence": _counter_to_dict(Counter(dict(evidence.most_common(8)))),
        "samples": samples[:5],
    }


def _effective_warning_count(
    summary: dict[str, Any],
    warnings: list[str],
    warning_diagnostics: list[dict[str, Any]],
) -> int:
    summary_count = _int_value(summary.get("warnings"), len(warnings))
    return max(summary_count, len(warnings), len(warning_diagnostics))


def _classify_warning(warning: Any) -> str:
    if isinstance(warning, dict):
        candidate_action = str(warning.get("candidate_action", "") or "").strip()
        if candidate_action:
            return candidate_action
        kind = str(warning.get("kind", "") or "").strip()
        if kind:
            return kind
        warning = warning.get("message", "")
    text = str(warning)
    lowered = text.lower()
    if "skipped pascalcase llm rename" in lowered:
        return "llm_pascal_case"
    if "low confidence" in lowered:
        return "llm_low_confidence"
    if "skipped generic argument rename" in lowered:
        return "llm_generic_argument"
    if "skipped weak argument rename" in lowered:
        return "llm_weak_argument"
    if "unsupported saved-argument" in lowered:
        return "llm_saved_argument_copy"
    if "value-invariant" in lowered:
        return "llm_value_invariant"
    if "pointer-bound" in lowered:
        return "llm_pointer_bound"
    if "dispatcher" in lowered and "rename" in lowered:
        return "llm_dispatcher_context"
    if "skipped duplicate target" in lowered:
        return "rename_duplicate_target"
    if "skipped colliding rename" in lowered:
        return "rename_collision"
    if "skipped invalid identifier" in lowered:
        return "rename_invalid_identifier"
    if "skipped missing identifier" in lowered:
        return "rename_missing_identifier"
    if "skipped noop rename" in lowered:
        return "rename_noop"
    if "potential bad call target" in lowered:
        return "call_target_review"
    if "deterministic rule pack rejected" in lowered:
        return "rule_pack_rejected"
    if "deterministic rule emission rejected" in lowered:
        return "rule_emission_rejected"
    return "other"


def _markdown_counter_table(counter: dict[str, Any], label: str) -> list[str]:
    if not counter:
        return ["No data."]
    lines = [
        "| %s | Count |" % label,
        "| --- | ---: |",
    ]
    for key, value in counter.items():
        lines.append("| `%s` | %s |" % (key, value))
    return lines


def _markdown_table_cell(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _int_value(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _float_value(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) * 100.0 / float(denominator), 2)


def _counter_to_dict(counter: Counter[str]) -> dict[str, int]:
    return {str(key): int(value) for key, value in counter.most_common()}


if __name__ == "__main__":
    raise SystemExit(main())
