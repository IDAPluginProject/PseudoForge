from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.core.api_semantics import NTSTATUS_RETURN_MAP, STATUS_ARGUMENT_INDEXES
from ida_pseudoforge.version import VERSION, plugin_title


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
OFFSET_DEREF_RE = re.compile(
    r"\*\s*\([^)]*\*\s*\)\s*\([^;\n]*\+\s*(?:0x[0-9A-Fa-f]+|\d+)(?:LL|i64|L)?\s*\)"
)
OFFSET_DEREF_ITEM_RE = re.compile(
    r"\*\s*\(\s*(?P<type>[^()]*?)\s*\*\s*\)\s*"
    r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?:i64|LL|ULL|uLL|UL|U|L)?\s*\)"
)
DIRECT_BASE_DEREF_RE = re.compile(
    r"\*\s*\(\s*[^()]*?\*\s*\)\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b"
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
    "validated_rewrite_residue": (
        "Validated canonical rewrite outputs that still have residual raw offset dereferences to reread."
    ),
    "source_stability_required": (
        "Candidates whose base object may move, reload, or be reassigned after layout access."
    ),
    "type_conflict_required": (
        "Candidates blocked by mixed width, overlay, or alignment evidence that must be resolved before rewrite."
    ),
    "pointer_indexed_layout_candidates": (
        "Pointer-indexed table or callback-like shapes; model separately from canonical field rewrite."
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
    "validated_rewrite_residue": (
        "Compare the canonical cleaned output with the preview artifact and rewrite only advertised same-object residue."
    ),
    "source_stability_required": (
        "Prove a single stable initializer and no risky post-access reassignment for the candidate base."
    ),
    "type_conflict_required": (
        "Resolve subfield width, overlay, and alignment conflicts or keep aliases report-only."
    ),
    "pointer_indexed_layout_candidates": (
        "Treat table slots and callback arrays as indexed layouts instead of field rewrites."
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
    report = analyze_corpus(
        args.corpus_root,
        sample_limit=max(0, args.sample_limit),
        text_scan=not args.no_text_scan,
        top=max(1, args.top),
        ea_filter=_load_ea_filter(args.ea, args.ea_file),
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
    return parser


def analyze_corpus(
    corpus_root: str | Path,
    *,
    sample_limit: int = 0,
    text_scan: bool = True,
    top: int = 20,
    ea_filter: set[int] | None = None,
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
    body_offset_residue_named_target_groups: Counter[str] = Counter()
    body_offset_residue_safety_policies: Counter[str] = Counter()
    body_offset_residue_evidence_maturity: Counter[str] = Counter()
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
    totals = Counter()
    text_totals = Counter()
    body_text_totals = Counter()
    top_warning_functions = []
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
    top_decimal_status_residue_functions = []
    top_nested_status_store_functions = []
    top_ntstatus_body_unprofiled_functions = []
    top_prototype_correction_functions = []
    prototype_negative_control_functions = []

    for summary_path in summary_paths:
        summary = _coerce_dict(_read_json(summary_path))
        artifacts = _coerce_dict(summary.get("artifacts", {}))
        name = str(summary.get("function", "") or summary_path.parent.name)
        ea = str(summary.get("function_ea", ""))
        warnings = _read_warnings(_artifact_path(summary_path, artifacts, "warnings"))
        warning_diagnostics = _read_warning_diagnostics(_artifact_path(summary_path, artifacts, "warning_diagnostics"))
        warning_class_items: list[Any] = warning_diagnostics if warning_diagnostics else warnings
        warning_count = _effective_warning_count(summary, warnings, warning_diagnostics)
        rename_items = _read_rename_items(_artifact_path(summary_path, artifacts, "rename_map"))
        rule_report = _coerce_dict(_read_json(_artifact_path(summary_path, artifacts, "rule_report")))
        buffer_contracts = _read_list(_artifact_path(summary_path, artifacts, "buffer_contracts"))
        cleaned_path = _artifact_path(summary_path, artifacts, "cleaned_pseudocode")
        raw_path = _artifact_path(summary_path, artifacts, "raw_pseudocode")
        rewrite_preview_metadata = _coerce_dict(
            _read_json(_artifact_path(summary_path, artifacts, "layout_rewrite_preview_metadata"))
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
                        body_offset_residue_named_target_groups,
                        body_offset_residue_safety_policies,
                        body_offset_residue_evidence_maturity,
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
            "named_target_groups": _counter_to_dict(
                Counter(dict(body_offset_residue_named_target_groups.most_common(top)))
            ),
            "rewrite_safety_policies": _counter_to_dict(
                Counter(dict(body_offset_residue_safety_policies.most_common(top)))
            ),
            "evidence_maturity": _counter_to_dict(
                Counter(dict(body_offset_residue_evidence_maturity.most_common(top)))
            ),
            "review_queues": _body_offset_residue_review_queues(
                top_body_offset_residue_functions,
                top,
            ),
            "top_functions": top_body_offset_residue_functions[:top],
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
    return result


def render_quality_markdown(report: dict[str, Any]) -> str:
    totals = _coerce_dict(report.get("totals", {}))
    rename_stats = _coerce_dict(report.get("rename_stats", {}))
    warning_stats = _coerce_dict(report.get("warning_stats", {}))
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
    body_offset_residue_stats = _coerce_dict(report.get("body_offset_residue_review_stats", {}))
    prototype_correction_totals = _coerce_dict(prototype_correction_stats.get("totals", {}))
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
        "## Warning Classes",
        "",
    ]
    lines.extend(_markdown_counter_table(_coerce_dict(warning_stats.get("top_classes", {})), "Class"))
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
                "| Queue | Functions | Blocked | Generic survivors | Offset derefs | Profiles | Blockers | Next step |",
                "| --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
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
                "| `%s` | %s | %s | %s | %s | %s | %s | %s |"
                % (
                    queue_name,
                    int(queue.get("function_count", 0) or 0),
                    int(queue.get("blocked_parameter_type_corrections", 0) or 0),
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
                "| Queue | Function | EA | Blocked | Generic survivors | Offset derefs | Profiles | Blockers |",
                "| --- | --- | --- | ---: | ---: | ---: | --- | --- |",
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
                    "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s |"
                    % (
                        queue_name,
                        str(item.get("name", "")),
                        str(item.get("ea", "")),
                        int(item.get("blocked_parameter_type_corrections", 0) or 0),
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
            "| Function | EA | Identities | Corrections | Applied | Blocked | Map | Body ready | Generic survivors | Offset derefs | Profiles | Types | Blockers |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |",
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
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("function_identity_candidates", 0) or 0),
                int(item.get("parameter_type_corrections", 0) or 0),
                int(item.get("applied_parameter_type_corrections", 0) or 0),
                int(item.get("blocked_parameter_type_corrections", 0) or 0),
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
            "### Residue Review Queues",
            "",
            "| Queue | Description | Functions | Offset derefs | Direct-base derefs | Generic params | Target groups | Subsystems | Gates | Families | Policies | Maturity | Pressure | Primary reasons | Notes | Blocker families | Promotion lanes | Factors | Classes | Details | Source provenance | Source kinds | Stable sources | Profiles | Next step |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
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
        domain_profiles = ", ".join(
            "%s=%s" % (key, value)
            for key, value in _coerce_dict(queue.get("domain_profiles", {})).items()
        )
        lines.append(
            "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(queue_name),
                _markdown_table_cell(str(queue.get("description", "") or "")),
                int(queue.get("functions", 0) or 0),
                int(queue.get("offset_deref_survivors", 0) or 0),
                int(queue.get("direct_base_deref_survivors", 0) or 0),
                int(queue.get("generic_parameter_survivors", 0) or 0),
                _markdown_table_cell(target_groups),
                _markdown_table_cell(subsystems),
                _markdown_table_cell(gates),
                _markdown_table_cell(families),
                _markdown_table_cell(policies),
                _markdown_table_cell(maturity),
                _markdown_table_cell(pressure),
                _markdown_table_cell(primary_reasons),
                _markdown_table_cell(review_notes),
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
    lines.extend(
        [
            "",
            "### Highest Body Offset Residue Functions",
            "",
            "| Function | Summary | Lane | EA | Goal | Subsystem | Focus | Gate | Family | Safety | Maturity | Pressure | Primary reasons | Notes | Factors | Class | Next action | Details | Score | Offset derefs | Direct-base derefs | Field pressure | Ready | Blockers | Evidence | Promotion hints | Bases | Reasons |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- |",
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
        goal_group = str(item.get("named_goal_target_group", "") or "")
        goal_text = goal_group if bool(item.get("named_goal_target")) else ""
        promotion_lane = str(item.get("promotion_lane", "") or "")
        lines.append(
            "| `%s` | %s | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
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
                _markdown_table_cell(priority_factors),
                str(item.get("review_class", "")),
                str(item.get("next_action", "")),
                _markdown_table_cell(next_action_details),
                int(item.get("priority_score", 0) or 0),
                int(item.get("offset_deref_survivors", 0) or 0),
                int(item.get("direct_base_deref_survivors", 0) or 0),
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
            "| Function | EA | Evidence | Max offsets | Max accesses | Parents | Parent types | Strides | Bases |",
            "| --- | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
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
        lines.append(
            "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |"
            % (
                str(item.get("name", "")),
                str(item.get("ea", "")),
                int(item.get("evidence_count", 0) or 0),
                int(item.get("max_offset_count", 0) or 0),
                int(item.get("max_access_count", 0) or 0),
                _markdown_table_cell(parents),
                _markdown_table_cell(parent_types),
                _markdown_table_cell(strides),
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
        "correction_blockers": _counter_to_dict(correction_blockers),
        "corrected_parameter_map_entries": len(corrected_parameter_map),
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
    totals["corrected_parameter_map_entries"] += _int_value(metrics.get("corrected_parameter_map_entries"), 0)
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
    for counter_name in ("function_identity_blockers", "correction_blockers", "body_rewrite_blocker_counts"):
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
        "corrected_parameter_map_entries": _int_value(metrics.get("corrected_parameter_map_entries"), 0),
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
    raw_queues: dict[str, list[dict[str, Any]]] = {name: [] for name in queue_blockers}
    for item in functions:
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
        "generic_parameter_survivors": _int_value(item.get("generic_parameter_survivors"), 0),
        "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
        "profiles": _coerce_dict(item.get("profiles", {})),
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
    canonical_types = Counter()
    blockers = Counter()
    for item in items:
        for key, value in _coerce_dict(item.get("profiles", {})).items():
            profiles[str(key)] += _int_value(value, 0)
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
        "corrected_parameter_map_entries",
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
) -> dict[str, Any]:
    offset_deref_survivors = _int_value(prototype_metrics.get("offset_deref_survivors"), 0)
    if offset_deref_survivors <= 0:
        return {}
    direct_base_deref_survivors = _int_value(
        prototype_metrics.get("direct_base_deref_survivors"),
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
        "generic_parameter_survivors": _int_value(prototype_metrics.get("generic_parameter_survivors"), 0),
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
        "parameter_indexed_offsets": _body_offset_parameter_indexed_offsets(
            parameter_indexed_elements,
        ),
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
    }
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
    named_target_groups: Counter[str],
    safety_policies: Counter[str],
    evidence_maturity: Counter[str],
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
    shape_profile = _coerce_dict(item.get("offset_shape_profile", {}))
    shape_class = str(shape_profile.get("shape_class", "") or "")
    if shape_class:
        shape_classes[shape_class] += 1
    for base_class, count in _coerce_dict(shape_profile.get("base_classes", {})).items():
        base_classes[str(base_class)] += _int_value(count, 0)


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
    if gate == "pointer_indexed_separate_model":
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
    if gate == "pointer_indexed_separate_model":
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
    if gate == "pointer_indexed_separate_model":
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
        items.append(
            {
                "base": base,
                "offset": offset,
                "type": _normalized_offset_deref_type(match.group("type")),
            }
        )
    return items


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
        "validated_rewrite_residue",
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
    if queue_name == "validated_rewrite_residue":
        return (
            fail_closed_gate == "validated_rewrite_residue_review"
            or review_class == "rewrite_ready_residue"
        )
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
            or review_class == "low_pressure_offset_residue"
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
    blocker_reasons: Counter[str] = Counter()
    blocker_families: Counter[str] = Counter()
    promotion_lanes: Counter[str] = Counter()
    stable_source_provenance: Counter[str] = Counter()
    stable_source_kinds: Counter[str] = Counter()
    top_stable_sources: Counter[str] = Counter()
    domain_profiles: Counter[str] = Counter()
    parameter_indexed_parents: Counter[str] = Counter()
    parameter_indexed_parent_types: Counter[str] = Counter()
    parameter_indexed_strides: Counter[str] = Counter()
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
        for key, value in _coerce_dict(item.get("domain_profiles", {})).items():
            domain_profiles[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_parents", {})).items():
            parameter_indexed_parents[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_parent_types", {})).items():
            parameter_indexed_parent_types[str(key)] += _int_value(value, 0)
        for key, value in _coerce_dict(item.get("parameter_indexed_strides", {})).items():
            parameter_indexed_strides[str(key)] += _int_value(value, 0)
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
        "generic_parameter_survivors": sum(
            _int_value(item.get("generic_parameter_survivors"), 0)
            for item in items
        ),
        "parameter_indexed_elements": sum(
            _int_value(item.get("parameter_indexed_element_count"), 0)
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
        "blocker_reasons": _counter_to_dict(Counter(dict(blocker_reasons.most_common(limit)))),
        "blocker_families": _counter_to_dict(Counter(dict(blocker_families.most_common(limit)))),
        "promotion_lanes": _counter_to_dict(Counter(dict(promotion_lanes.most_common(limit)))),
        "stable_source_provenance": _counter_to_dict(
            Counter(dict(stable_source_provenance.most_common(limit)))
        ),
        "stable_source_kinds": _counter_to_dict(Counter(dict(stable_source_kinds.most_common(limit)))),
        "top_stable_sources": _counter_to_dict(Counter(dict(top_stable_sources.most_common(limit)))),
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
        "next_action_details": [
            str(detail)
            for detail in item.get("next_action_details", []) or []
            if str(detail)
        ],
        "priority_score": _int_value(item.get("priority_score"), 0),
        "offset_deref_survivors": _int_value(item.get("offset_deref_survivors"), 0),
        "direct_base_deref_survivors": _int_value(item.get("direct_base_deref_survivors"), 0),
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
        "parameter_indexed_element_count": _int_value(item.get("parameter_indexed_element_count"), 0),
        "parameter_indexed_parents": _coerce_dict(item.get("parameter_indexed_parents", {})),
        "parameter_indexed_parent_types": _coerce_dict(item.get("parameter_indexed_parent_types", {})),
        "parameter_indexed_strides": _coerce_dict(item.get("parameter_indexed_strides", {})),
        "parameter_indexed_offsets": [
            str(offset)
            for offset in item.get("parameter_indexed_offsets", []) or []
            if str(offset)
        ],
        "domain_profiles": _coerce_dict(item.get("domain_profiles", {})),
        "summary_path": str(item.get("summary_path", "") or ""),
    }


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
    if queue == "validated_rewrite_residue":
        return "validated rewrite already ran; reread remaining secondary residue"
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
        if indexed_parts:
            parts.append("indexed-element=%s" % " ".join(indexed_parts))
        else:
            parts.append("indexed-element=%d evidence" % parameter_indexed_count)
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
    _update_residue_metrics(body_text_totals, body_text)
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
                "parent_type": str(match.groupdict().get("parent_type") or ""),
                "confidence": _float_value(match.group("confidence"), 0.0),
            }
        )
    return candidates


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
        candidates.append(
            {
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
        )
    return candidates


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
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


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
    return {
        "ea": ea,
        "name": name,
        "evidence_count": len(candidates),
        "bases": [str(item.get("base", "") or "unknown") for item in candidates[:8]],
        "parents": _counter_to_dict(Counter(dict(parents.most_common(5)))),
        "parent_types": _counter_to_dict(Counter(dict(parent_types.most_common(5)))),
        "strides": _counter_to_dict(Counter(dict(strides.most_common(5)))),
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
