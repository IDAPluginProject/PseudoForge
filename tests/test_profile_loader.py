from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.profiles import loader as profile_loader
from ida_pseudoforge.core import kernel_api
from tools.profile_load_smoke import run_smoke


class ProfileLoaderTests(unittest.TestCase):
    def test_built_in_split_kernel_api_profiles_have_manifest_entries(self) -> None:
        profile_loader.clear_profile_caches()
        try:
            manifest = profile_loader.load_profiles_manifest()
            profiles = manifest.get("profiles", {}) if isinstance(manifest, dict) else {}

            for family, file_name in profile_loader.KERNEL_API_FAMILY_FILES.items():
                entry = profiles.get(file_name, {})

                self.assertTrue((profile_loader.PROFILE_DIR / file_name).exists(), file_name)
                self.assertEqual(entry.get("profile_kind"), "kernel_api_%s" % family)
                self.assertEqual(entry.get("source_version"), "10.0.26100.0")
                self.assertTrue(entry.get("sha256"), file_name)
                self.assertTrue(entry.get("counts"), file_name)
        finally:
            profile_loader.clear_profile_caches()

    def test_active_profile_manifests_reports_loaded_profiles(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                manifest = {
                    "schema_version": 1,
                    "profiles": {
                        "sample.json": {
                            "name": "manifest-should-not-override-loaded-name.json",
                            "profile_kind": "sample",
                            "source": "unit test",
                            "source_version": "1",
                            "sha256": "ABCDEF",
                            "counts": {"entries": 1},
                        }
                    },
                }
                (Path(temp_dir) / profile_loader.PROFILE_MANIFEST_NAME).write_text(
                    json.dumps(manifest),
                    encoding="utf-8",
                )
                (Path(temp_dir) / "sample.json").write_text(
                    json.dumps({"1": "STATUS_SAMPLE"}),
                    encoding="utf-8",
                )

                self.assertEqual(profile_loader.load_json_profile("sample.json"), {"1": "STATUS_SAMPLE"})
                manifests = profile_loader.active_profile_manifests()

                self.assertEqual(len(manifests), 1)
                self.assertEqual(manifests[0]["name"], "sample.json")
                self.assertEqual(manifests[0]["profile_kind"], "sample")
                self.assertEqual(manifests[0]["counts"], {"entries": 1})
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_configure_profile_dir_selects_alternate_root_and_clears_cache(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first_path = Path(first_dir)
            second_path = Path(second_dir)
            (first_path / "sample.json").write_text(json.dumps({"1": "FIRST"}), encoding="utf-8")
            (second_path / "sample.json").write_text(json.dumps({"1": "SECOND"}), encoding="utf-8")
            try:
                profile_loader.configure_profile_dir(first_path)
                self.assertEqual(profile_loader.load_profile("sample.json"), {"1": "FIRST"})

                selected = profile_loader.configure_profile_dir(second_path)
                self.assertEqual(selected, second_path)
                self.assertEqual(profile_loader.active_profile_root(), str(second_path))
                self.assertEqual(profile_loader.load_profile("sample.json"), {"1": "SECOND"})
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_configure_profile_dir_empty_selection_honors_environment_override(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        original_env = os.environ.get("PSEUDOFORGE_PROFILE_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            try:
                os.environ["PSEUDOFORGE_PROFILE_DIR"] = str(temp_path)

                selected = profile_loader.configure_profile_dir("")

                self.assertEqual(selected, temp_path)
                self.assertEqual(profile_loader.active_profile_root(), str(temp_path))
            finally:
                if original_env is None:
                    os.environ.pop("PSEUDOFORGE_PROFILE_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_PROFILE_DIR"] = original_env
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_profile_load_smoke_accepts_profile_dir_selection(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "kernel_functions.json").write_text(
                json.dumps({"ExUnitTest": {"return_type": "NTSTATUS", "params": []}}),
                encoding="utf-8",
            )
            try:
                result = run_smoke("functions", profile_dir=temp_path, repeat=2)

                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["active_profiles"], ["kernel_functions.json"])
                self.assertTrue(result["loaded_split_profile"])
                self.assertFalse(result["loaded_monolithic_profile"])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_missing_profiles_manifest_does_not_warn(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                (Path(temp_dir) / "sample.json").write_text(
                    json.dumps({"1": "STATUS_SAMPLE"}),
                    encoding="utf-8",
                )

                self.assertEqual(profile_loader.load_json_profile("sample.json"), {"1": "STATUS_SAMPLE"})
                self.assertEqual(profile_loader.active_profile_manifests(), [])
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_invalid_json_profile_records_visible_warning(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                (Path(temp_dir) / "broken.json").write_text("{broken", encoding="utf-8")

                self.assertEqual(profile_loader.load_json_profile("broken.json"), {})
                warnings = profile_loader.profile_load_warnings()

                self.assertEqual(len(warnings), 1)
                self.assertIn("broken.json", warnings[0])
                self.assertIn("invalid JSON", warnings[0])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_kernel_api_family_prefers_split_file_without_monolithic_profile(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                manifest = {
                    "schema_version": 1,
                    "profiles": {
                        "kernel_functions.json": {
                            "profile_kind": "kernel_api_functions",
                            "source": "unit test",
                            "source_version": "1",
                            "sha256": "ABCDEF",
                            "counts": {"functions": 1},
                        }
                    },
                }
                (Path(temp_dir) / profile_loader.PROFILE_MANIFEST_NAME).write_text(
                    json.dumps(manifest),
                    encoding="utf-8",
                )
                (Path(temp_dir) / "kernel_functions.json").write_text(
                    json.dumps({"ExUnitTest": {"return_type": "NTSTATUS", "params": []}}),
                    encoding="utf-8",
                )

                family = profile_loader.load_kernel_api_family("functions")
                manifests = profile_loader.active_profile_manifests()

                self.assertIn("ExUnitTest", family)
                self.assertFalse((Path(temp_dir) / "kernel_api.json").exists())
                self.assertEqual(len(manifests), 1)
                self.assertEqual(manifests[0]["name"], "kernel_functions.json")
                self.assertEqual(manifests[0]["profile_kind"], "kernel_api_functions")
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_kernel_api_family_falls_back_to_monolithic_profile(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                profile = {
                    "schema_version": 2,
                    "functions": {
                        "ExUnitTest": {
                            "return_type": "NTSTATUS",
                            "params": [],
                        }
                    },
                }
                (Path(temp_dir) / "kernel_api.json").write_text(
                    json.dumps(profile),
                    encoding="utf-8",
                )

                family = profile_loader.load_kernel_api_family("functions")

                self.assertEqual(family, profile["functions"])
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()

    def test_kernel_api_rewrites_use_split_families_without_monolithic_profile(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            profile_loader.PROFILE_DIR = Path(temp_dir)
            profile_loader.clear_profile_caches()
            try:
                functions = {
                    "ExAcquireResourceExclusiveLite": {
                        "return_type": "BOOLEAN",
                        "params": [
                            {"name": "Resource", "kind": "pointer"},
                            {"name": "Wait", "kind": "bool", "enum": "BOOLEAN"},
                        ],
                    }
                }
                enums = {
                    "BOOLEAN": {
                        "0": "FALSE",
                        "1": "TRUE",
                    }
                }
                indices = {
                    "rewrite_functions": ["ExAcquireResourceExclusiveLite"],
                }
                (Path(temp_dir) / "kernel_functions.json").write_text(
                    json.dumps(functions),
                    encoding="utf-8",
                )
                (Path(temp_dir) / "kernel_enums.json").write_text(
                    json.dumps(enums),
                    encoding="utf-8",
                )
                (Path(temp_dir) / "kernel_indices.json").write_text(
                    json.dumps(indices),
                    encoding="utf-8",
                )
                (Path(temp_dir) / "kernel_api_overrides.json").write_text("{}", encoding="utf-8")

                metadata = kernel_api.kernel_function_metadata("ExAcquireResourceExclusiveLite")
                rendered = kernel_api.apply_kernel_api_rewrites(
                    "ExAcquireResourceExclusiveLite(Resource, 1);"
                )

                self.assertEqual(metadata["params"][1]["kind"], "bool")
                self.assertIn("ExAcquireResourceExclusiveLite(Resource, TRUE);", rendered)
                self.assertFalse((Path(temp_dir) / "kernel_api.json").exists())
                self.assertEqual(profile_loader.profile_load_warnings(), [])
            finally:
                profile_loader.PROFILE_DIR = original_dir
                profile_loader.clear_profile_caches()


if __name__ == "__main__":
    unittest.main()
