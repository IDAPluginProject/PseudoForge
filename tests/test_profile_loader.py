from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.profiles import loader as profile_loader


class ProfileLoaderTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
