# PseudoForge Deterministic Rule Authoring

PseudoForge rules are data-only JSON rule packs. They add project-local or
user-global matching policy without allowing user Python, subprocesses, network
access, or arbitrary IDB writes.

Use rules for deterministic rename candidates, semantic comments, and
preview/report-only rewrite evidence. Do not use rules as a substitute for
reviewing the cleaned output.

## Load Paths

```text
ida_pseudoforge/rules/builtin/*.json
.\pseudoforge_rules\*.json
%APPDATA%\PseudoForge\rules\*.json
```

Interactive IDA analysis resolves `.\pseudoforge_rules` beside the analyzed
input. Offline CLI paths resolve project-local rules beside the pseudocode input
and also accept explicit `--rules-dir` / `--rules` paths.

## Authoring Workflow

1. Dump available facts from a representative function.

```powershell
python -B .\tools\pseudoforge_rule_author.py facts .\sample.cpp
```

2. Scaffold a starter pack.

```powershell
python -B .\tools\pseudoforge_rule_author.py scaffold assignment-rename --out .\pseudoforge_rules\project_rules.json
```

3. Validate the pack.

```powershell
python -B .\tools\pseudoforge_rule_author.py validate .\pseudoforge_rules
python -B .\tools\validate_pseudoforge_rules.py .\pseudoforge_rules
```

4. Run rules against one input with opt-in miss reasons.

```powershell
python -B .\tools\pseudoforge_rule_author.py run .\sample.cpp --rules .\pseudoforge_rules --phase rename --explain
```

5. Use the normal CLI or IDA workflow after the rule is stable.

```powershell
python -B .\tools\pseudoforge_cli.py .\sample.cpp --rules-dir .\pseudoforge_rules --rule-report $env:TEMP\pseudoforge_rules --out $env:TEMP\pseudoforge_cli_smoke
```

## Typed Fact Operators

Schema version 2 supports typed fact operators in both `scope` and `match`.
Typed operators match facts already extracted into `RuleContext`; they do not
execute code and do not parse arbitrary C++ expressions.

Supported typed operators:

```text
lvar
assignment
call_site
profile_function
```

`lvar` selectors:

```json
{
  "name": "v1",
  "name_regex": "^v\\d+$",
  "type_contains": "NTSTATUS",
  "type_regex": "\\bPVOID\\b",
  "is_arg": false,
  "index": 1
}
```

Bindings: `$lvar`, `$lvar_name`, `$lvar_type`, `$lvar_index`,
`$lvar_location`.

`assignment` selectors:

```json
{
  "target_regex": "^v\\d+$",
  "rhs_identifier_any": ["inputBuffer"],
  "rhs_literal_all": ["8", "1"],
  "rhs_call_name": "ProbeForRead",
  "rhs_call_arg_count": 3,
  "rhs_call_arg_literal": {
    "argument_index": 2,
    "value": "1"
  }
}
```

Bindings: `$assignment_target`, `$assignment_rhs`, `$rhs_call`,
`$rhs_arg0`, `$rhs_arg1`, and so on.

`call_site` selectors:

```json
{
  "function_name": "ProbeForRead",
  "arg_count": 3,
  "arg_contains": {
    "argument_index": 0,
    "value": "input"
  },
  "arg_regex": {
    "argument_index": 1,
    "regex": "^8$"
  }
}
```

Bindings: `$call`, `$call_name`, `$call_line`, `$call_arg0`, `$call_arg1`,
and so on. Argument selectors are evaluated against the same call site.
Do not combine typed `match.call_site` with legacy `call_arg_count` or
`call_arg_literal` gates; put the arity and argument constraints in the
`call_site` selector instead.

`profile_function` selectors:

```json
{
  "function_name": "ProbeForRead",
  "header_contains": "wdm",
  "return_type_contains": "VOID",
  "param_count": 3,
  "param": {
    "index": 2,
    "name": "Alignment",
    "type_regex": "^ULONG$",
    "kind": "flags",
    "enum": "PROBE_FLAGS"
  }
}
```

Bindings: `$profile_function`, `$profile_header`, `$profile_return_type`,
`$profile_alias_of`, `$profile_alias_kind`, `$profile_param_name`,
`$profile_param_type`, `$profile_param_kind`, and `$profile_param_enum`.

## Example

```json
{
  "schema_version": 2,
  "id": "project.kernel_rules",
  "description": "Project-local PseudoForge rules.",
  "rules": [
    {
      "id": "project.rename.probe_status",
      "phase": "rename",
      "priority": 100,
      "confidence": 0.92,
      "scope": {
        "call_site": {
          "function_name": "ProbeForRead"
        }
      },
      "match": {
        "assignment": {
          "rhs_call_name": "ProbeForRead",
          "rhs_call_arg_count": 3,
          "rhs_call_arg_literal": {
            "argument_index": 2,
            "value": "1"
          }
        }
      },
      "emit": {
        "kind": "rename",
        "rename_kind": "lvar",
        "target": "$assignment_target",
        "new_name": "probeStatus",
        "evidence": "Local receives ProbeForRead status"
      }
    }
  ]
}
```

## Diagnostics

Normal IDA and CLI reports stay compact. The authoring CLI adds
`missed_rules` only when `--explain` is used. Rule report paths are redacted to
stable labels such as `builtin/foo.json`, `project/foo.json`, `user/foo.json`,
or `external/foo.json`.

Report fields:

```text
matched_rules
missed_rules
rewrite_emissions
rejected_emissions
load_errors
validation_errors
```

## Safety Boundaries

1. Rule files are JSON data only.
2. User Python execution is not supported.
3. Rules cannot use filesystem, network, subprocess, shell, URL, or command
   fields.
4. Invalid packs fail closed.
5. Runtime exceptions reject only the offending rule.
6. Rule renames still pass `validate_renames()`.
7. `call_arg_rewrite`, `text_rewrite`, and `flow` remain preview/report-only.
8. `flow` rules can only report already recovered dispatcher facts.
