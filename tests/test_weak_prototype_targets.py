from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TARGETS_PATH = ROOT / "tools" / "kernel_corpus" / "weak_prototype_targets.json"
DOMAIN_PROFILE_DIR = ROOT / "ida_pseudoforge" / "profiles" / "domain_identity"


class WeakPrototypeTargetsTests(unittest.TestCase):
    def test_targets_reference_existing_domain_profiles(self) -> None:
        payload = _read_json(TARGETS_PATH)
        profile_ids = _domain_profile_ids()

        self.assertEqual("pseudoforge_weak_prototype_targets_v1", payload["schema"])
        self.assertIn("pseudoforge_out", payload["recommended_quality_command"])
        self.assertIn("pseudoforge_out", payload["recommended_compare_command"])
        self.assertGreaterEqual(len(payload["targets"]), 6)
        self.assertGreaterEqual(len(payload["negative_controls"]), 1)
        for target in payload["targets"]:
            with self.subTest(target=target.get("function_name")):
                self.assertIn(target["profile_id"], profile_ids)
                self.assertTrue(target["expected_corrections"])
                self.assertTrue(target["weak_hexrays_types"])
                self.assertTrue(target["reason"])


def _domain_profile_ids() -> set[str]:
    profile_ids: set[str] = set()
    for path in DOMAIN_PROFILE_DIR.glob("*.json"):
        payload = _read_json(path)
        for profile in payload.get("profiles", []) or []:
            if isinstance(profile, dict) and profile.get("id"):
                profile_ids.add(str(profile["id"]))
    return profile_ids


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AssertionError("expected JSON object: %s" % path)
    return data


if __name__ == "__main__":
    unittest.main()
