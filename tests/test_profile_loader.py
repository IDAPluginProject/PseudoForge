from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.profiles import loader as profile_loader


class ProfileLoaderTests(unittest.TestCase):
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
