from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.atlas import generate_atlas
from tools.kernel_corpus.lifecycle import trace_lifecycle
from tools.kernel_corpus.relocate_pack import main, relocate_kernel_pack
from tools.kernel_corpus.validate_pack import validate_pack


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusRelocatePackTests(unittest.TestCase):
    def test_relocate_installed_pack_repairs_derived_pack_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_pack = temp_root / "source-pack"
            packaged_pack = temp_root / "packaged" / "kernel-pack"
            expected_pack_root = temp_root / "expected-install" / "ntoskrnl-test-r1" / "kernel-pack"
            actual_pack_root = temp_root / "actual-install" / "ntoskrnl-test-r1" / "kernel-pack"

            builder.build_pack(FIXTURE_ROOT, source_pack)
            trace_lifecycle(
                source_pack,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=source_pack / "evidence-packs" / "process_object.json",
            )
            generate_atlas(source_pack, source_pack / "reports" / "atlas", limit=8)

            shutil.copytree(source_pack, packaged_pack)
            prepared = relocate_kernel_pack(
                packaged_pack,
                target_pack_root=expected_pack_root,
                from_pack_roots=[str(source_pack)],
            )
            self.assertGreater(prepared["text_files_rewritten"], 0)
            self.assertGreater(prepared["sqlite_rows_rewritten"], 0)

            shutil.copytree(packaged_pack, actual_pack_root)
            before = validate_pack(actual_pack_root, include_derived=True)
            self.assertFalse(before["ok"])
            self.assertTrue(
                any(issue.get("code") == "evidence_pack_root_mismatch" for issue in before["issues"]),
                before["issues"],
            )
            self.assertTrue(
                any(issue.get("code") == "atlas_pack_root_mismatch" for issue in before["issues"]),
                before["issues"],
            )

            dry_run = relocate_kernel_pack(actual_pack_root, dry_run=True)
            self.assertTrue(dry_run["dry_run"])
            self.assertGreater(dry_run["text_files_rewritten"], 0)
            self.assertGreater(dry_run["sqlite_rows_rewritten"], 0)
            self.assertFalse(validate_pack(actual_pack_root, include_derived=True)["ok"])

            relocated = relocate_kernel_pack(actual_pack_root)
            self.assertIn(str(expected_pack_root.resolve(strict=False)), relocated["source_pack_roots"])
            self.assertEqual(str(actual_pack_root.resolve(strict=False)), relocated["target_pack_root"])
            self.assertGreater(relocated["text_files_rewritten"], 0)
            self.assertGreater(relocated["sqlite_rows_rewritten"], 0)

            after = validate_pack(actual_pack_root, include_derived=True)
            self.assertTrue(after["ok"], after["issues"])

    def test_relocate_cli_can_validate_after_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_pack = temp_root / "source-pack"
            actual_pack = temp_root / "install" / "ntoskrnl-test-r1" / "kernel-pack"

            builder.build_pack(FIXTURE_ROOT, source_pack)
            shutil.copytree(source_pack, actual_pack)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "--pack-root",
                        str(actual_pack),
                        "--from-pack-root",
                        str(source_pack),
                        "--validate",
                        "--format",
                        "text",
                    ]
                )

            self.assertEqual(0, code)
            self.assertIn("Kernel Corpus pack relocation: PASS", output.getvalue())
            self.assertIn("Kernel Corpus pack validation: PASS", output.getvalue())
            validation = validate_pack(actual_pack)
            self.assertTrue(validation["ok"], validation["issues"])


if __name__ == "__main__":
    unittest.main()
