from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.atlas import SUBSYSTEMS, generate_atlas, main
from tools.kernel_corpus.lifecycle import trace_lifecycle


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"
EXPECTED_PAGES = {
    "process.md",
    "thread.md",
    "object-manager.md",
    "memory.md",
    "io-manager.md",
    "registry.md",
    "security.md",
    "etw-wmi.md",
    "driver-load-unload.md",
}


class KernelCorpusAtlasTests(unittest.TestCase):
    def test_generate_atlas_writes_expected_pages(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"

            result = generate_atlas(pack_root, output_dir, limit=8)

            self.assertTrue(result["ok"])
            self.assertEqual(len(SUBSYSTEMS), result["page_count"])
            self.assertEqual(EXPECTED_PAGES, {item["filename"] for item in result["pages"]})
            for filename in EXPECTED_PAGES:
                self.assertTrue((output_dir / filename).is_file(), filename)

    def test_each_page_contains_corpus_identity(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            for filename in EXPECTED_PAGES:
                text = (output_dir / filename).read_text(encoding="utf-8")
                self.assertIn("## Corpus Identity", text)
                self.assertIn("Pack root:", text)
                self.assertIn("Schema: `kernel_corpus_pack_v1`", text)
                self.assertIn("Target: `minimal.i64`", text)
                self.assertIn("Functions: `3`", text)
                self.assertIn("Manifest:", text)
                self.assertIn("SQLite:", text)

    def test_function_evidence_contains_ea_and_artifact_path(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "process.md").read_text(encoding="utf-8")
            self.assertIn("`0x140001000` `NtCreateUserProcess`", text)
            self.assertIn("function.ida-batch-summary.json", text)
            self.assertIn("function.cleaned.cpp", text)
            self.assertIn(str((FIXTURE_ROOT / "functions").resolve()), text)

    def test_missing_subsystem_data_has_clear_gap_section(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "registry.md").read_text(encoding="utf-8")
            self.assertIn("## Gaps And Uncertainty", text)
            self.assertIn("No high-signal functions matched", text)
            self.assertIn("- No matching functions selected.", text)

    def test_lifecycle_pack_is_referenced_when_available(self) -> None:
        with _built_pack() as pack_root:
            trace_lifecycle(
                pack_root,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=pack_root / "evidence-packs" / "process_object.json",
            )
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "process.md").read_text(encoding="utf-8")
            self.assertIn("## Lifecycle Evidence Packs", text)
            self.assertIn("`process_object`: available", text)
            self.assertIn("evidence-packs", text)

    def test_cli_outputs_json_manifest(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--pack-root",
                        str(pack_root),
                        "--output-dir",
                        str(output_dir),
                        "--limit",
                        "8",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertTrue(payload["ok"])
            self.assertEqual(len(SUBSYSTEMS), payload["page_count"])
            self.assertTrue((output_dir / "process.md").is_file())


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


if __name__ == "__main__":
    unittest.main()
