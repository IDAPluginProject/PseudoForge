# PseudoForge Release Validation Workflow

This workflow defines the release-quality validation path for PseudoForge code
changes that affect decompiler cleanup, IDA batch export, corpus quality, or
release packaging. It is intentionally separate from Kernel Corpus package
release validation. PseudoForge releases ship code and documentation; large
kernel corpus artifacts are released from the dedicated artifact repository.

## Goals

Use this workflow to answer four release questions:

1. Does the normal unit and packaging suite pass?
2. Does a deterministic IDA replay produce the same or better cleanup metrics?
3. If an LLM rename filter changed, does candidate replay prove the change
   against the same recorded model output?
4. Does the large corpus quality report show no release-blocking regression?

The default posture is evidence-first. Do not judge cleanup changes from a few
hand-picked diffs only. Record the commands, output roots, quality reports, and
metric deltas used for the release decision.

## Artifact Policy

Generated validation outputs belong under `pseudoforge_out\` or another ignored
workspace. Do not commit:

- IDA batch output directories
- `pseudoforge_corpus_quality.py` reports
- LLM candidate cache or replay directories
- large source corpora
- release-package staging directories

Commit only code, tests, and durable documentation.

## Tier 0: Repository Gate

Run this tier for every release and for every cleanup-quality change before
commit.

```powershell
python -B -m pytest -q
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B .\tools\release_pseudoforge.py --dry-run
git diff --check -- .
```

Hard failures:

- any failing test
- compile failure
- invalid builtin rule pack
- release dry-run failure
- whitespace errors from `git diff --check`
- unexpected version mismatch between `ida_pseudoforge/version.py` and
  `ida-plugin.json`

## Tier 1: Deterministic IDA Replay

Use this tier for renderer, rename, profile, rule, corpus-quality, and export
changes. It disables LLM rename assist even when the saved plugin configuration
has LLM enabled.

Recommended input:

- a fixed EA list committed or stored as an ignored local validation input
- a symbol path that matches the target build
- a small replay size for normal changes, usually 12 to 30 functions
- a larger replay size for risky cleanup changes, usually 100 functions

Example:

```powershell
$Ida = "C:\Program Files\IDA Professional 9.0\ida.exe"
$Idb = "D:\bin\os\26200.8457\ntoskrnl.exe.i64"
$Target = "D:\bin\os\26200.8457\ntoskrnl.exe"
$PdbPath = "C:\symbols"
$EaFile = "F:\kernullist\PseudoForge\pseudoforge_out\pascalcase-rerun-top100-eas.txt"
$Out = "F:\kernullist\PseudoForge\pseudoforge_out\release-validation-top30-nollm"
$QualityOut = "F:\kernullist\PseudoForge\pseudoforge_out\release-validation-top30-nollm-quality"

python -B .\tools\pseudoforge_ida_cli.py `
  $Ida `
  $Idb `
  $Out `
  --target-path $Target `
  --pdb-path $PdbPath `
  --ea-file $EaFile `
  --no-llm-renames `
  --max-functions 30 `
  --no-index

python -B .\tools\pseudoforge_corpus_quality.py `
  --corpus-root $Out `
  --out $QualityOut `
  --format both `
  --top 10
```

Required checks:

- `pseudoforge-ida-summary.json` reports `failed=0`
- JSONL progress has one `status=ok` function record per selected EA
- `llm_statuses` are all `disabled`
- `pseudoforge_corpus_quality.py` writes both JSON and Markdown reports
- no new rule load or validation errors appear

Hard failures:

- any failed function in a fixed replay set
- `llm_status` is anything other than `disabled`
- missing cleaned pseudocode, rename map, rule report, warnings, or summary
  artifacts for successful functions
- corpus quality analyzer cannot parse the output

## Tier 2: LLM Candidate Replay

Use this tier when the change affects LLM candidate normalization, candidate
filtering, rename validation, LLM diagnostics, or anything where live provider
variance would hide the real delta.

First record a baseline candidate cache from the old code or a known-good
baseline:

```powershell
$BaselineOut = "F:\kernullist\PseudoForge\pseudoforge_out\llm-validation-baseline"
$CandidateCache = "F:\kernullist\PseudoForge\pseudoforge_out\llm-validation-candidates"

python -B .\tools\pseudoforge_ida_cli.py `
  $Ida `
  $Idb `
  $BaselineOut `
  --target-path $Target `
  --pdb-path $PdbPath `
  --ea-file $EaFile `
  --llm-candidate-cache-dir $CandidateCache `
  --max-functions 30 `
  --no-index
```

Then replay the same raw candidate responses after the code change:

```powershell
$ReplayOut = "F:\kernullist\PseudoForge\pseudoforge_out\llm-validation-replay"

python -B .\tools\pseudoforge_ida_cli.py `
  $Ida `
  $Idb `
  $ReplayOut `
  --target-path $Target `
  --pdb-path $PdbPath `
  --ea-file $EaFile `
  --llm-candidate-replay-dir $CandidateCache `
  --max-functions 30 `
  --no-index
```

Generate quality reports for both outputs and compare the JSON metrics. Replay
mode must fail if a function has no matching recorded candidate file; silent
fallback to live LLM is not acceptable for release validation.

Hard failures:

- candidate replay calls a live provider
- a missing replay candidate falls back to deterministic analysis
- artifact counts differ for reasons unrelated to the intended change
- warning counts, rename apply rates, or key residue metrics regress without an
  explicit reviewed reason

## Tier 3: Full Or Large Corpus Quality Scan

Use this tier after a large batch run has completed or before a release that
claims corpus-wide cleanup quality. A full IDA rerun can take days, so this
tier usually scans an existing generated corpus unless the release specifically
requires regenerating it.

```powershell
$CorpusRoot = "F:\kernullist\analysis-ouput\ntoskrnl"
$QualityOut = "F:\kernullist\PseudoForge\pseudoforge_out\corpus-quality-ntoskrnl-release"

python -B .\tools\pseudoforge_corpus_quality.py `
  --corpus-root $CorpusRoot `
  --out $QualityOut `
  --format both `
  --top 25
```

For a fast smoke before the full scan:

```powershell
python -B .\tools\pseudoforge_corpus_quality.py `
  --corpus-root $CorpusRoot `
  --sample-limit 100 `
  --out "F:\kernullist\PseudoForge\pseudoforge_out\corpus-quality-smoke" `
  --format both
```

Record these release-note inputs:

- corpus root
- target binary and IDB build identity
- function count
- failed/skipped function count
- warning count and top warning classes
- rename apply rate and LLM apply rate
- status-like literal residue
- profiled status-argument literal residue
- offset dereference residue
- code-body residue from `body_text_stats`
- inferred layout hint, field-preview, and field-alias counts
- API semantic diagnostic reasons

## Compare Quality Reports

Use this helper snippet when comparing two `corpus-quality.json` files. It keeps
the comparison focused on release-relevant metrics and avoids hand-copy drift.
Use `text_stats` to track full rendered output, including PseudoForge review
comments. Use `body_text_stats` for release gates that should measure only the
cleaned pseudocode body.

```powershell
$OldQuality = "F:\kernullist\PseudoForge\pseudoforge_out\old-quality\corpus-quality.json"
$NewQuality = "F:\kernullist\PseudoForge\pseudoforge_out\new-quality\corpus-quality.json"

@'
import json
import sys
from pathlib import Path

old = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
new = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

items = [
    ("warnings", ("totals", "warnings")),
    ("functions_with_warnings", ("totals", "functions_with_warnings")),
    ("applied_renames", ("totals", "applied_renames")),
    ("rename_apply_rate", ("rename_stats", "apply_rate")),
    ("llm_apply_rate", ("rename_stats", "llm_apply_rate")),
    ("generic_identifier_tokens", ("text_stats", "generic_identifier_tokens")),
    ("body_generic_identifier_tokens", ("body_text_stats", "generic_identifier_tokens")),
    ("decimal_status_like_literals", ("text_stats", "decimal_status_like_literals")),
    ("body_decimal_status_like_literals", ("body_text_stats", "decimal_status_like_literals")),
    ("hex_status_like_literals", ("text_stats", "hex_status_like_literals")),
    ("body_hex_status_like_literals", ("body_text_stats", "hex_status_like_literals")),
    ("profiled_status_argument_literals", ("text_stats", "profiled_status_argument_literals")),
    ("body_profiled_status_argument_literals", ("body_text_stats", "profiled_status_argument_literals")),
    ("offset_deref_patterns", ("text_stats", "offset_deref_patterns")),
    ("body_offset_deref_patterns", ("body_text_stats", "offset_deref_patterns")),
    ("label_tokens", ("text_stats", "label_tokens")),
    ("body_label_tokens", ("body_text_stats", "label_tokens")),
    ("inferred_offset_layout_hints", ("text_stats", "inferred_offset_layout_hints")),
    ("inferred_offset_field_previews", ("text_stats", "inferred_offset_field_previews")),
    ("inferred_offset_field_aliases", ("text_stats", "inferred_offset_field_aliases")),
    ("api_semantic_rejections", ("totals", "api_semantic_rejections")),
]

def read_metric(data, path):
    value = data
    for key in path:
        value = value.get(key, {}) if isinstance(value, dict) else {}
    return value if value != {} else None

for label, path in items:
    old_value = read_metric(old, path)
    new_value = read_metric(new, path)
    delta = None
    if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
        delta = new_value - old_value
    print(f"{label}: {old_value} -> {new_value}" + (f" ({delta:+})" if delta is not None else ""))
'@ | python - $OldQuality $NewQuality
```

## Metric Decision Rules

Use these rules for release decisions. They are deliberately conservative; a
small regression can be acceptable only when the diff is inspected and the
release notes explain why.

Hard fail:

- failed functions increase in a fixed replay set
- `llm_status` mode differs from the intended validation mode
- rule load errors or rule validation errors appear
- corpus quality analyzer fails
- generated artifacts are missing for successful functions
- a cleanup change rewrites ambiguous constants without stronger context

Investigate before release:

- warnings increase
- rename apply rate drops by more than 1.0 percentage point
- LLM apply rate drops in candidate replay
- code-body generic identifier tokens increase by more than 2 percent
- code-body status-like literal residue increases
- code-body profiled status-argument literal residue increases
- code-body offset dereference residue increases after a renderer change that should not
  affect structure access
- full-text residue increases; confirm whether the increase comes only from
  conservative header comments and whether code-body residue stayed flat
- temp or generic layout hints increase without a deliberate claim-ceiling
  change
- API semantic rejection reasons shift toward `conflict_target` or
  `large_dispatcher` unexpectedly

Positive release signals:

- warning count decreases with no missing artifacts
- rename apply rate rises while rejected warning classes remain explainable
- status-like literal residue decreases
- deterministic replay keeps `llm_status=disabled`
- candidate replay produces deterministic parity except for the intended
  validation/filter change
- layout hints, field previews, or field aliases increase only when claim
  ceilings and review wording remain conservative

## Release Checklist

Before running `release_pseudoforge.py` for a public release:

1. Run Tier 0.
2. Run Tier 1 on the current fixed replay set.
3. Run Tier 2 if any LLM rename path changed.
4. Run Tier 3 if the release notes make corpus-quality claims.
5. Inspect at least the top warning functions from the new quality report.
6. Inspect representative raw-vs-cleaned diffs for each major cleanup change.
7. Confirm `git status --short` contains only intended files.
8. Confirm generated corpus and replay outputs are not staged.
9. Write release notes with command outputs, replay size, and metric deltas.
10. Package the release:

```powershell
python -B .\tools\release_pseudoforge.py
```

PseudoForge release packages must not include Kernel Corpus artifacts. Publish
kernel corpus archives through the dedicated corpus artifact repository instead.

## Current Local Baseline Example

The latest local deterministic top30 no-LLM replay used during cleanup quality
work produced:

```text
processed=30
succeeded=30
failed=0
llm_statuses=disabled=30
warnings=10
rename_apply_rate=96.17
decimal_status_like_literals=5
hex_status_like_literals=1
profiled_status_argument_literals=1
inferred_offset_layout_hints=12
inferred_offset_field_previews=11
inferred_offset_field_aliases=0
body_generic_identifier_tokens=11609
body_offset_deref_patterns=719
body_label_tokens=541
body_decimal_status_like_literals=5
```

Treat this as an example of the report shape, not a permanent release gate.
Refresh the baseline whenever the fixed EA set, target build, IDA version,
symbol inputs, or intended cleanup claim changes.
