from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.corpus_catalog import corpus_manifest_from_public_catalog, load_public_corpus_catalog
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence, summarize_corpus_manifests


class CorpusCatalogTests(unittest.TestCase):
    def test_public_catalog_converts_to_claim_safe_manifest(self) -> None:
        catalog_path = Path(__file__).resolve().parent / "fixtures" / "general_corpus" / "public_corpus_catalog.json"

        catalog = load_public_corpus_catalog(catalog_path)
        manifest = corpus_manifest_from_public_catalog(catalog)
        evidence = summarize_corpus_manifests([manifest])

        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertEqual(260, evidence["real_corpus_function_count"])
        self.assertEqual(["linux_elf_user", "windows_user_pe"], evidence["target_families"])
        self.assertEqual(0, evidence["qualified_ground_truth_pair_count"])

    def test_claim_eligible_public_artifact_requires_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_public_corpus_catalog_v1",
                        "artifacts": [
                            {
                                "name": "missing_hash",
                                "target_family": "windows_user_pe",
                                "source_reference": "public-corpus://missing-hash",
                                "artifact_uri": "https://example.com/missing-hash.zip",
                                "license": "MIT",
                                "function_count": 10,
                                "claim_eligible": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "sha256 is required"):
                load_public_corpus_catalog(path)

    def test_claim_eligible_public_artifact_rejects_malformed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_public_corpus_catalog_v1",
                        "artifacts": [
                            {
                                "name": "bad_hash",
                                "target_family": "windows_user_pe",
                                "source_reference": "public-corpus://bad-hash",
                                "artifact_uri": "https://example.com/bad-hash.zip",
                                "license": "MIT",
                                "sha256": "not-a-sha256",
                                "function_count": 10,
                                "claim_eligible": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "64-character hex digest"):
                load_public_corpus_catalog(path)

    def test_claim_eligible_public_artifact_rejects_unsupported_uri_scheme(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_public_corpus_catalog_v1",
                        "artifacts": [
                            {
                                "name": "bad_uri",
                                "target_family": "windows_user_pe",
                                "source_reference": "public-corpus://bad-uri",
                                "artifact_uri": "ftp://example.com/bad-uri.zip",
                                "license": "MIT",
                                "sha256": "a" * 64,
                                "function_count": 10,
                                "claim_eligible": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unsupported scheme"):
                load_public_corpus_catalog(path)

    def test_corpus_catalog_tool_writes_manifest(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        catalog_path = repo_root / "tests" / "fixtures" / "general_corpus" / "public_corpus_catalog.json"

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_corpus_catalog.py"),
                    str(catalog_path),
                    "--json-out",
                    str(manifest_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", completed.stderr)
            self.assertEqual(0, completed.returncode)
            evidence = load_corpus_evidence([manifest_path])

        self.assertEqual(2, evidence["real_corpus_count"])
        self.assertEqual(260, evidence["real_corpus_function_count"])


if __name__ == "__main__":
    unittest.main()
