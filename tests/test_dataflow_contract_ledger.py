from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.dataflow_contract_ledger import build_cross_function_contract_ledger


class DataflowContractLedgerTests(unittest.TestCase):
    def test_builds_validated_contract_from_ir_use_def_and_sink_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "00001000_Sample"
            function_dir.mkdir(parents=True)
            _write_rename_map(
                function_dir / "function.rename-map.json",
                function_name="Sample",
                source_name="Curl_cmalloc",
                sink_name="Curl_cfree",
                variable="buffer",
            )

            ledger = build_cross_function_contract_ledger(
                [root / "functions"],
                corpus_name="public_sample_windows_user_pe_0",
                target_family="windows_user_pe",
                reference_prefix="unit://contracts",
            )

        self.assertEqual("pseudoforge_cross_function_contract_ledger_v1", ledger["schema"])
        self.assertEqual(1, len(ledger["contracts"]))
        contract = ledger["contracts"][0]
        self.assertEqual("Curl_cmalloc", contract["source_function"])
        self.assertEqual("Curl_cfree", contract["sink_function"])
        self.assertEqual("validated", contract["status"])
        self.assertIn("buffer", contract["proof"])

    def test_rejects_unrelated_compile_release_name_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "00002000_Noise"
            function_dir.mkdir(parents=True)
            _write_rename_map(
                function_dir / "function.rename-map.json",
                function_name="Noise",
                source_name="sqlite3_compileoption_used",
                sink_name="vdbeReleaseAndSetInt64",
                variable="value",
            )

            ledger = build_cross_function_contract_ledger(
                [root / "functions"],
                corpus_name="public_sample_windows_user_pe_0",
                target_family="windows_user_pe",
            )

        self.assertEqual([], ledger["contracts"])

    def test_cli_writes_contract_ledger(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            function_dir = root / "functions" / "00001000_Sample"
            function_dir.mkdir(parents=True)
            _write_rename_map(
                function_dir / "function.rename-map.json",
                function_name="Sample",
                source_name="socket",
                sink_name="closesocket",
                variable="fd",
            )
            out_path = root / "ledger.json"

            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_dataflow_contract_ledger.py"),
                    str(root / "functions"),
                    "--corpus-name",
                    "public_sample_windows_user_pe_0",
                    "--target-family",
                    "windows_user_pe",
                    "--json-out",
                    str(out_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            payload = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(payload["contracts"]))


def _write_rename_map(
    path: Path,
    *,
    function_name: str,
    source_name: str,
    sink_name: str,
    variable: str,
) -> None:
    payload = {
        "function_ea": 4096,
        "function_name": function_name,
        "input_fingerprint": "a" * 64,
        "ir_evidence": {
            "schema": "pseudoforge_ir_evidence_v1",
            "adapter": "hexrays_cfunc_v1",
            "source": "hexrays_cfunc",
            "available": True,
            "use_def_chains": [
                {
                    "variable": variable,
                    "definitions": ["line:1:%s" % source_name],
                    "uses": ["line:2"],
                    "confidence": 0.55,
                    "evidence": "unit test",
                }
            ],
            "call_site_signatures": [
                {
                    "call_name": sink_name,
                    "argument_names": [variable],
                    "confidence": 0.6,
                    "evidence": "unit test",
                }
            ],
        },
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
