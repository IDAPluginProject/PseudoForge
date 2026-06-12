from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder
from tools.kernel_corpus.lifecycle import main, trace_lifecycle
from tools.kernel_corpus.schema import EVIDENCE_PACK_SCHEMA_VERSION


class KernelCorpusLifecycleTests(unittest.TestCase):
    def test_process_graph_maps_seed_functions_to_expected_phases(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], ["0x140003000"]),
            _function("0x140003000", "PspInitializeProcess", ["process_thread"], ["initialize", "process"], ["0x140004000"]),
            _function("0x140004000", "PspInsertProcess", ["process_thread", "object_manager"], ["insert", "process"], ["0x140005000", "0x140006000"]),
            _function("0x140005000", "ObInsertObject", ["object_manager"], ["insert", "object"], []),
            _function("0x140006000", "PspCallProcessNotifyRoutines", ["process_thread", "callback"], ["notify", "process"], []),
            _function("0x140007000", "PspExitProcess", ["process_thread"], ["exit", "process"], ["0x140008000"]),
            _function("0x140008000", "PspRundownSingleProcess", ["process_thread"], ["rundown", "process"], ["0x140009000"]),
            _function("0x140009000", "PspProcessDelete", ["process_thread", "object_manager"], ["delete", "process"], ["0x14000a000"]),
            _function("0x14000a000", "ObDereferenceObject", ["object_manager"], ["dereference", "object"], []),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=20, depth=2)

            phases = _phase_by_name(pack)
            self.assertEqual(EVIDENCE_PACK_SCHEMA_VERSION, pack["schema"])
            self.assertEqual("entry", phases["NtCreateUserProcess"])
            self.assertEqual("allocate", phases["PspAllocateProcess"])
            self.assertEqual("initialize", phases["PspInitializeProcess"])
            self.assertEqual("publish", phases["PspInsertProcess"])
            self.assertEqual("publish", phases["ObInsertObject"])
            self.assertEqual("notify", phases["PspCallProcessNotifyRoutines"])
            self.assertEqual("exit", phases["PspExitProcess"])
            self.assertEqual("rundown", phases["PspRundownSingleProcess"])
            self.assertEqual("delete", phases["PspProcessDelete"])
            self.assertIn(("0x140001000", "0x140002000"), _edge_pairs(pack))
            self.assertIn(("0x140004000", "0x140006000"), _edge_pairs(pack))

    def test_ambiguous_functions_receive_lower_confidence(self) -> None:
        functions = [
            _function("0x140001000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
            _function("0x140002000", "PspProcessWorker", ["process_thread"], ["process"], []),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1)

            candidates = {item["name"]: item for item in pack["candidates"]}
            self.assertLess(candidates["PspProcessWorker"]["confidence"], candidates["PspAllocateProcess"]["confidence"])
            self.assertEqual("steady_state", candidates["PspProcessWorker"]["phase"])
            self.assertIn("allocate", candidates["PspAllocateProcess"]["phase"])

    def test_missing_exact_seed_still_allows_term_based_candidates(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], []),
            _function(
                "0x140002000",
                "PspTerminateProcessWorker",
                ["process_thread"],
                ["exit", "terminate", "process"],
                [],
                excerpt="void PspTerminateProcessWorker(...) { /* process exit terminate */ }",
            ),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1)

            candidates = {item["name"]: item for item in pack["candidates"]}
            self.assertEqual("exit", candidates["PspTerminateProcessWorker"]["phase"])
            self.assertTrue(
                any("seed term match: exit" in item for item in candidates["PspTerminateProcessWorker"]["why_selected"])
            )
            self.assertIn("Exact seed not found: PspExitProcess", pack["gaps"])

    def test_evidence_pack_contains_paths_phase_labels_and_writes_output(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
        ]
        with _built_pack(functions) as pack_root:
            output_path = pack_root / "evidence-packs" / "process_object.json"
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1, output_path=output_path)
            written = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual(str(output_path.resolve()), pack["output_path"])
            self.assertEqual(pack["output_path"], written["output_path"])
            function = _function_by_name(pack, "NtCreateUserProcess")
            self.assertEqual("entry", function["phase"])
            self.assertGreaterEqual(function["confidence"], 0.5)
            self.assertTrue(Path(function["artifacts"]["summary"]).is_absolute())
            self.assertTrue(Path(function["evidence"][0]["path"]).is_absolute())
            self.assertIn("phase entry", " ".join(function["why_selected"]))

    def test_cli_writes_lifecycle_json_output(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
        ]
        with _built_pack(functions) as pack_root:
            output_path = pack_root / "evidence-packs" / "process_object.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--pack-root",
                        str(pack_root),
                        "--topic",
                        "process_object",
                        "--depth",
                        "1",
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("process_object", payload["topic"])
            self.assertEqual(str(output_path.resolve()), payload["output_path"])
            self.assertTrue(output_path.is_file())


@contextlib.contextmanager
def _built_pack(functions: list[dict[str, Any]]):
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        corpus_root = root / "corpus"
        pack_root = root / "pack"
        _write_corpus(corpus_root, functions)
        builder.build_pack(corpus_root, pack_root)
        yield pack_root


def _write_corpus(corpus_root: Path, functions: list[dict[str, Any]]) -> None:
    (corpus_root / "functions").mkdir(parents=True)
    index = {
        "schema": "pseudoforge_corpus_index_v1",
        "pseudoforge_version": "test",
        "generated_at": "2026-06-12T00:00:00+00:00",
        "functions": [],
        "overview": {
            "functions": len(functions),
            "report_status_counts": {
                "ok": len(functions),
            },
        },
        "metadata": {
            "target_path": "synthetic.i64",
        },
        "report_summary": {
            "status_counts": {
                "ok": len(functions),
            },
        },
    }
    for function in functions:
        item = dict(function)
        stem = "%016x_%s" % (int(str(item["ea"]), 0), item["name"])
        function_dir = corpus_root / "functions" / stem
        function_dir.mkdir(parents=True)
        cleaned = function_dir / "function.cleaned.cpp"
        raw = function_dir / "function.raw.cpp"
        summary = function_dir / "function.ida-batch-summary.json"
        cleaned.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        raw.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        summary.write_text(json.dumps({"ea": item["ea"], "name": item["name"]}, ensure_ascii=True), encoding="utf-8")
        item["directory"] = str(Path("functions") / stem)
        item["summary_path"] = str(Path("functions") / stem / "function.ida-batch-summary.json")
        item["artifacts"] = {
            "cleaned_pseudocode": str(Path("functions") / stem / "function.cleaned.cpp"),
            "raw_pseudocode": str(Path("functions") / stem / "function.raw.cpp"),
            "summary": str(Path("functions") / stem / "function.ida-batch-summary.json"),
        }
        index["functions"].append(item)
    (corpus_root / "pseudoforge-corpus-index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )


def _function(
    ea: str,
    name: str,
    tags: list[str],
    terms: list[str],
    callees: list[str],
    *,
    excerpt: str | None = None,
) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "tags": tags,
        "terms": terms,
        "mode": "synthetic",
        "counts": {
            "warnings": 0,
            "buffer_contracts": 0,
        },
        "llm_status": "ok",
        "callee_eas": callees,
        "caller_eas": [],
        "imports_called": [],
        "strings_referenced": [],
        "interesting_lines": terms,
        "cleaned_excerpt": excerpt or ("%s synthetic evidence: %s" % (name, " ".join(terms))),
    }


def _phase_by_name(pack: dict[str, Any]) -> dict[str, str]:
    return {
        function["name"]: phase["id"]
        for phase in pack["phases"]
        for function in phase["functions"]
    }


def _function_by_name(pack: dict[str, Any], name: str) -> dict[str, Any]:
    for phase in pack["phases"]:
        for function in phase["functions"]:
            if function["name"] == name:
                return function
    raise AssertionError("function not found: %s" % name)


def _edge_pairs(pack: dict[str, Any]) -> list[tuple[str, str]]:
    return [(edge["src_ea"], edge["dst_ea"]) for edge in pack["edges"]]


if __name__ == "__main__":
    unittest.main()
