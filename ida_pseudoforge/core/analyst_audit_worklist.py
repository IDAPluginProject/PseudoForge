from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.evidence_pack import ANALYST_AUDIT_LEDGER_SCHEMA


DEFAULT_AUDIT_STATUS = "blocked"


def analyst_audit_ledger_from_corpus_manifest(
    manifest: dict[str, Any],
    reviewer: str = "pending-review",
    reference_prefix: str = "pending-review://",
) -> dict[str, Any]:
    corpora = [item for item in manifest.get("corpora", []) or [] if isinstance(item, dict)]
    audits = [
        _audit_entry(corpus, reviewer=reviewer, reference_prefix=reference_prefix)
        for corpus in corpora
        if bool(corpus.get("claim_eligible", False))
    ]
    return {
        "schema": ANALYST_AUDIT_LEDGER_SCHEMA,
        "audits": audits,
    }


def load_corpus_manifest_for_audit(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("corpus manifest file not found: %s" % target) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            "invalid corpus manifest JSON at line %d column %d: %s"
            % (exc.lineno, exc.colno, exc.msg)
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("corpus manifest root must be an object")
    corpora = payload.get("corpora", [])
    if not isinstance(corpora, list):
        raise ValueError("corpus manifest corpora must be a list")
    return payload


def _audit_entry(corpus: dict[str, Any], reviewer: str, reference_prefix: str) -> dict[str, str]:
    corpus_name = str(corpus.get("name", "") or "").strip()
    target_family = str(corpus.get("target_family", "") or "").strip()
    audit_id = "audit-%s-001" % _slug(corpus_name)
    reference = "%s%s/review-001" % (str(reference_prefix or "pending-review://"), _slug(corpus_name))
    return {
        "id": audit_id,
        "corpus_name": corpus_name,
        "target_family": target_family,
        "reviewer": str(reviewer or "pending-review"),
        "reference": reference,
        "status": DEFAULT_AUDIT_STATUS,
    }


def _slug(value: object) -> str:
    text = str(value or "").strip().lower()
    chars = [char if char.isalnum() else "-" for char in text]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "unknown"
