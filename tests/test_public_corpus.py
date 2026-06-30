from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence
from ida_pseudoforge.core.public_corpus import (
    bootstrap_public_corpus,
    corpus_manifest_from_public_bootstrap_report,
    load_public_corpus_plan,
    summarize_public_corpus_report,
)


class PublicCorpusTests(unittest.TestCase):
    def test_seed_plan_loads_pinned_public_projects(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        plan_path = repo_root / "tests" / "fixtures" / "general_corpus" / "public_corpus_seed_plan.json"

        plan = load_public_corpus_plan(plan_path)

        self.assertEqual("pseudoforge_public_corpus_plan_v1", plan["schema"])
        self.assertEqual(3, len(plan["projects"]))
        self.assertEqual("zlib-v1.3.1", plan["projects"][0]["name"])
        self.assertEqual("51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf", plan["projects"][0]["source"]["commit"])

    def test_git_source_requires_expected_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad-plan.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_public_corpus_plan_v1",
                        "projects": [
                            {
                                "name": "bad",
                                "target_family": "windows_user_pe",
                                "license": "MIT",
                                "source": {
                                    "kind": "git",
                                    "repo_url": "https://example.com/repo.git",
                                    "ref": "refs/tags/v1",
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "commit is required"):
                load_public_corpus_plan(path)

    def test_archive_source_bootstrap_extracts_and_scans_pinned_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("sample-1/sample.c", "int archived_entry(void) {\n    return 7;\n}\n")
                archive.writestr("sample-1/sample.h", "int archived_entry(void);\n")
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_archive_plan(archive_path.as_uri(), digest)), encoding="utf-8")

            plan = load_public_corpus_plan(plan_path)
            report = bootstrap_public_corpus(plan, root / "workspace", fetch=True, build=False)

        self.assertEqual(1, report["source_ready_count"])
        self.assertEqual("archive", report["projects"][0]["source"]["kind"])
        self.assertEqual(1, report["candidate_function_count"])
        self.assertEqual("not_run", report["projects"][0]["build_results"][0]["status"])

    def test_archive_source_blocks_on_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("sample-1/sample.c", "int archived_entry(void) {\n    return 7;\n}\n")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_archive_plan(archive_path.as_uri(), "0" * 64)), encoding="utf-8")

            plan = load_public_corpus_plan(plan_path)
            report = bootstrap_public_corpus(plan, root / "workspace", fetch=True, build=False)

        self.assertEqual(0, report["source_ready_count"])
        self.assertEqual("archive_sha256_mismatch", report["projects"][0]["blockers"][0]["code"])

    def test_local_source_bootstrap_scans_functions_without_claim_inflation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "sample.c").write_text(
                "\n".join(
                    [
                        "int add_pair(int a, int b) {",
                        "    return a + b;",
                        "}",
                        "static void close_pair(void) {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_local_plan(source)), encoding="utf-8")

            plan = load_public_corpus_plan(plan_path)
            report = bootstrap_public_corpus(plan, root / "workspace", fetch=False, build=False)
            manifest = corpus_manifest_from_public_bootstrap_report(report)
            evidence_path = root / "manifest.json"
            evidence_path.write_text(json.dumps(manifest), encoding="utf-8")
            evidence = load_corpus_evidence([evidence_path])

        self.assertEqual(1, report["source_ready_count"])
        self.assertEqual(2, report["candidate_function_count"])
        self.assertEqual(0, report["build_ready_count"])
        self.assertEqual(0, evidence["real_corpus_count"])
        self.assertEqual(0, evidence["qualified_semantic_ground_truth_pair_count"])

    def test_built_artifact_catalog_does_not_claim_replay_evidence(self) -> None:
        report = {
            "schema": "pseudoforge_public_corpus_bootstrap_report_v1",
            "projects": [
                {
                    "name": "local-sample",
                    "target_family": "windows_user_pe",
                    "source": {"kind": "local", "path": "source"},
                    "source_path": "source",
                    "source_status": "present",
                    "source_hash": "a" * 64,
                    "candidate_function_count": 2,
                    "actual_commit": "",
                    "semantic_seeds": [
                        {
                            "id": "sample-add",
                            "function": "add_pair",
                            "semantic_kind": "arithmetic",
                            "oracle": "add_pair returns a + b",
                            "validation": "source oracle plus binary replay",
                            "status": "validated",
                        }
                    ],
                    "build_results": [
                        {
                            "id": "fixture",
                            "status": "passed",
                            "artifacts": [
                                {
                                    "path": "sample.exe",
                                    "sha256": "b" * 64,
                                    "size": 4096,
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        manifest = corpus_manifest_from_public_bootstrap_report(report)

        self.assertFalse(manifest["corpora"][0]["claim_eligible"])
        self.assertEqual(2, manifest["corpora"][0]["function_count"])
        self.assertEqual("validated", manifest["corpora"][0]["semantic_ground_truth_pairs"][0]["status"])
        self.assertEqual("blocked", manifest["corpora"][0]["real_replay_targets"][0]["status"])

    def test_public_corpus_cli_validates_and_bootstraps_no_fetch(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "sample.c").write_text("int local_entry(void) {\n    return 1;\n}\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(_local_plan(source)), encoding="utf-8")
            workspace = root / "workspace"

            validate = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_public_corpus.py"),
                    "validate-plan",
                    str(plan_path),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            bootstrap = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(repo_root / "tools" / "pseudoforge_public_corpus.py"),
                    "bootstrap",
                    str(plan_path),
                    "--out-dir",
                    str(workspace),
                    "--no-fetch",
                    "--candidate-limit",
                    "10",
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual("", validate.stderr)
            self.assertEqual(0, validate.returncode)
            self.assertEqual("", bootstrap.stderr)
            self.assertEqual(0, bootstrap.returncode)
            summary = json.loads((workspace / "reports" / "public-corpus-summary.json").read_text(encoding="utf-8"))

        self.assertEqual(1, summary["source_ready_count"])
        self.assertEqual(0, summary["claim_eligible_corpus_count"])

    def test_report_summary_lists_blocked_projects(self) -> None:
        report = {
            "schema": "pseudoforge_public_corpus_bootstrap_report_v1",
            "projects": [
                {
                    "name": "missing-source",
                    "source_status": "blocked",
                    "candidate_function_count": 0,
                    "semantic_seeds": [],
                    "blockers": [
                        {
                            "stage": "source",
                            "code": "source_missing_no_fetch",
                            "detail": "sources/missing-source",
                        }
                    ],
                    "build_results": [],
                }
            ],
        }

        summary = summarize_public_corpus_report(report)

        self.assertEqual(1, len(summary["blocked_projects"]))
        self.assertEqual("source_missing_no_fetch", summary["blocked_projects"][0]["blockers"][0]["code"])


def _local_plan(source: Path) -> dict[str, object]:
    return {
        "schema": "pseudoforge_public_corpus_plan_v1",
        "projects": [
            {
                "name": "local-sample",
                "target_family": "windows_user_pe",
                "license": "MIT",
                "source": {
                    "kind": "local",
                    "path": str(source),
                },
                "source_globs": ["**/*.c"],
                "semantic_seeds": [
                    {
                        "id": "local-add",
                        "function": "add_pair",
                        "semantic_kind": "arithmetic",
                        "oracle": "add_pair returns a + b",
                        "validation": "source oracle plus binary replay",
                        "status": "planned",
                    }
                ],
            }
        ],
    }


def _archive_plan(url: str, sha256: str) -> dict[str, object]:
    return {
        "schema": "pseudoforge_public_corpus_plan_v1",
        "projects": [
            {
                "name": "archive-sample",
                "target_family": "windows_user_pe",
                "license": "Test",
                "source": {
                    "kind": "archive",
                    "url": url,
                    "sha256": sha256,
                    "strip_prefix": "sample-1",
                },
                "source_globs": ["**/*.c", "**/*.h"],
                "build_recipes": [
                    {
                        "id": "msvc-dll",
                        "system": "msvc_cl",
                        "source_files": ["sample.c"],
                        "output_name": "sample.dll",
                        "artifact_globs": ["*.dll", "*.lib", "*.pdb"],
                    }
                ],
                "semantic_seeds": [
                    {
                        "id": "archive-entry",
                        "function": "archived_entry",
                        "semantic_kind": "fixture",
                        "oracle": "archived_entry returns 7.",
                        "validation": "source oracle plus binary replay",
                        "status": "planned",
                    }
                ],
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
