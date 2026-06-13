from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError
from tools.kernel_corpus.schema import MANIFEST_FILENAME, SQLITE_FILENAME


SCHEMA = "kernel_corpus_pack_relocation_v1"
RELOCATABLE_TEXT_SUFFIXES = {".json", ".md", ".txt"}
EVIDENCE_PACK_DIR = Path("evidence-packs")
ATLAS_DIR = Path("reports") / "atlas"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = relocate_kernel_pack(
            args.pack_root,
            target_pack_root=args.target_pack_root or None,
            from_pack_roots=args.from_pack_root,
            dry_run=args.dry_run,
        )
        if args.validate:
            from tools.kernel_corpus.validate_pack import validate_pack

            validation = validate_pack(
                result["target_pack_root"],
                include_derived=args.include_derived,
            )
            result["validation"] = validation
    except (OSError, KernelCorpusError, ValueError) as exc:
        print("Kernel corpus pack relocation failed: %s" % exc, file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    else:
        print(format_text_report(result))
        validation_payload = result.get("validation")
        if isinstance(validation_payload, dict):
            from tools.kernel_corpus.validate_pack import format_text_report as format_validation_report

            print("")
            print(format_validation_report(validation_payload))

    validation_result = result.get("validation")
    if isinstance(validation_result, dict) and not validation_result.get("ok", False):
        return 2
    return 0 if result.get("ok", False) else 1


def relocate_kernel_pack(
    pack_root: str | Path,
    *,
    target_pack_root: str | Path | None = None,
    from_pack_roots: list[str] | tuple[str, ...] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    root = Path(pack_root).resolve(strict=False)
    target = Path(target_pack_root).resolve(strict=False) if target_pack_root is not None else root
    _require_pack(root)

    explicit_roots = [Path(value).resolve(strict=False) for value in from_pack_roots or [] if str(value or "")]
    inferred_roots = _infer_pack_roots(root)
    source_roots = _ordered_unique_paths(explicit_roots + inferred_roots, skip=target)
    replacements = _path_replacements(source_roots, target)

    text_result = _rewrite_text_paths(root, replacements, dry_run=dry_run)
    sqlite_result = _rewrite_sqlite_manifest(root / SQLITE_FILENAME, replacements, target, dry_run=dry_run)

    return {
        "schema": SCHEMA,
        "ok": True,
        "dry_run": bool(dry_run),
        "relocated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "pack_root": str(root),
        "target_pack_root": str(target),
        "source_pack_roots": [str(path) for path in source_roots],
        "replacement_count": len(replacements),
        "text_files_scanned": text_result["files_scanned"],
        "text_files_rewritten": text_result["files_rewritten"],
        "text_replacements": text_result["replacements"],
        "sqlite_rows_rewritten": sqlite_result["rows_rewritten"],
        "sqlite_replacements": sqlite_result["replacements"],
    }


def format_text_report(result: dict[str, Any]) -> str:
    status = "PASS" if result.get("ok") else "FAIL"
    lines = [
        "Kernel Corpus pack relocation: %s" % status,
        "Pack root: %s" % result.get("pack_root", ""),
        "Target pack root: %s" % result.get("target_pack_root", ""),
        "Dry run: %s" % str(bool(result.get("dry_run", False))).lower(),
        "Source pack roots: %s" % len(result.get("source_pack_roots", []) or []),
        "Text files rewritten: %s" % result.get("text_files_rewritten", 0),
        "SQLite rows rewritten: %s" % result.get("sqlite_rows_rewritten", 0),
    ]
    for source_root in result.get("source_pack_roots", []) or []:
        lines.append("- %s" % source_root)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rewrite Kernel Corpus pack-root metadata after extracting a release package."
    )
    parser.add_argument("--pack-root", required=True, help="Installed Kernel Corpus pack root.")
    parser.add_argument(
        "--target-pack-root",
        default="",
        help="Target pack root to write into metadata. Default: --pack-root.",
    )
    parser.add_argument(
        "--from-pack-root",
        action="append",
        default=[],
        help="Previous pack root to rewrite. Can be repeated. Auto-detected when omitted.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing files.")
    parser.add_argument("--validate", action="store_true", help="Run validate_pack.py after relocation.")
    parser.add_argument(
        "--include-derived",
        action="store_true",
        help="When used with --validate, also validate evidence packs and atlas pages.",
    )
    parser.add_argument("--format", choices=("json", "text"), default="json", help="Output format.")
    return parser


def _require_pack(pack_root: Path) -> None:
    if not pack_root.exists():
        raise KernelCorpusError("Pack root does not exist: %s" % pack_root)
    if not pack_root.is_dir():
        raise KernelCorpusError("Pack root is not a directory: %s" % pack_root)
    if not (pack_root / MANIFEST_FILENAME).is_file():
        raise KernelCorpusError("Pack manifest is missing: %s" % (pack_root / MANIFEST_FILENAME))
    if not (pack_root / SQLITE_FILENAME).is_file():
        raise KernelCorpusError("Pack SQLite database is missing: %s" % (pack_root / SQLITE_FILENAME))


def _infer_pack_roots(pack_root: Path) -> list[Path]:
    roots: list[Path] = []
    roots.extend(_infer_roots_from_manifest(pack_root / MANIFEST_FILENAME))
    roots.extend(_infer_roots_from_sqlite(pack_root / SQLITE_FILENAME))
    roots.extend(_infer_roots_from_evidence_packs(pack_root))
    roots.extend(_infer_roots_from_atlas_pages(pack_root))
    return roots


def _infer_roots_from_manifest(path: Path) -> list[Path]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    return _roots_from_payload_values(payload)


def _infer_roots_from_sqlite(path: Path) -> list[Path]:
    roots: list[Path] = []
    try:
        connection = sqlite3.connect(path)
    except sqlite3.Error:
        return []
    try:
        rows = connection.execute("select key, value from corpus_manifest").fetchall()
    except sqlite3.Error:
        return []
    finally:
        connection.close()
    for key, value in rows:
        if str(key) == "sqlite_path":
            root = _root_from_sqlite_path(str(value))
            if root is not None:
                roots.append(root)
    return roots


def _infer_roots_from_evidence_packs(pack_root: Path) -> list[Path]:
    roots: list[Path] = []
    evidence_dir = pack_root / EVIDENCE_PACK_DIR
    if not evidence_dir.is_dir():
        return roots
    for path in sorted(evidence_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            root = _path_or_none(payload.get("pack_root"))
            if root is not None:
                roots.append(root)
    return roots


def _infer_roots_from_atlas_pages(pack_root: Path) -> list[Path]:
    roots: list[Path] = []
    atlas_dir = pack_root / ATLAS_DIR
    if not atlas_dir.is_dir():
        return roots
    for path in sorted(atlas_dir.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r"^\s*-\s*Pack root:\s*`([^`]+)`", text, flags=re.MULTILINE)
        if match:
            root = _path_or_none(match.group(1))
            if root is not None:
                roots.append(root)
    return roots


def _roots_from_payload_values(payload: dict[str, Any]) -> list[Path]:
    roots: list[Path] = []
    sqlite_path = _root_from_sqlite_path(str(payload.get("sqlite_path", "") or ""))
    if sqlite_path is not None:
        roots.append(sqlite_path)
    pack_root = _path_or_none(payload.get("pack_root"))
    if pack_root is not None:
        roots.append(pack_root)
    return roots


def _root_from_sqlite_path(value: str) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        return None
    if path.name.lower() != SQLITE_FILENAME.lower():
        return None
    return path.parent.resolve(strict=False)


def _path_or_none(value: Any) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute():
        return None
    return path.resolve(strict=False)


def _ordered_unique_paths(paths: list[Path], *, skip: Path) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    skip_key = _path_key(skip)
    for path in paths:
        key = _path_key(path)
        if not key or key == skip_key or key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _path_key(path: Path) -> str:
    return str(path.resolve(strict=False)).replace("/", "\\").casefold()


def _path_replacements(source_roots: list[Path], target_root: Path) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    target_variants = _path_variants(target_root)
    for source_root in source_roots:
        source_variants = _path_variants(source_root)
        for index, source in enumerate(source_variants):
            target = target_variants[min(index, len(target_variants) - 1)]
            key = (source, target)
            if source and source != target and key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def _path_variants(path: Path) -> list[str]:
    raw = str(path)
    slash = raw.replace("\\", "/")
    escaped = raw.replace("\\", "\\\\")
    variants = [raw]
    if slash != raw:
        variants.append(slash)
    if escaped != raw:
        variants.append(escaped)
    return variants


def _rewrite_text_paths(pack_root: Path, replacements: list[tuple[str, str]], *, dry_run: bool) -> dict[str, int]:
    files_scanned = 0
    files_rewritten = 0
    replacement_count = 0
    for path in pack_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in RELOCATABLE_TEXT_SUFFIXES:
            continue
        files_scanned += 1
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = original
        for old, new in replacements:
            count = updated.count(old)
            if count:
                replacement_count += count
                updated = updated.replace(old, new)
        if updated != original:
            files_rewritten += 1
            if not dry_run:
                path.write_text(updated, encoding="utf-8", newline="\n")
    return {
        "files_scanned": files_scanned,
        "files_rewritten": files_rewritten,
        "replacements": replacement_count,
    }


def _rewrite_sqlite_manifest(
    sqlite_path: Path,
    replacements: list[tuple[str, str]],
    target_pack_root: Path,
    *,
    dry_run: bool,
) -> dict[str, int]:
    rows_rewritten = 0
    replacement_count = 0
    connection = sqlite3.connect(sqlite_path)
    try:
        rows = connection.execute("select key, value from corpus_manifest").fetchall()
        for key, value in rows:
            updated = str(value)
            for old, new in replacements:
                count = updated.count(old)
                if count:
                    replacement_count += count
                    updated = updated.replace(old, new)
            if key == "sqlite_path":
                updated = str(target_pack_root / SQLITE_FILENAME)
            if updated != value:
                rows_rewritten += 1
                if not dry_run:
                    connection.execute(
                        "update corpus_manifest set value = ? where key = ?",
                        (updated, key),
                    )
        if not dry_run:
            connection.commit()
    finally:
        connection.close()
    return {
        "rows_rewritten": rows_rewritten,
        "replacements": replacement_count,
    }


if __name__ == "__main__":
    raise SystemExit(main())
