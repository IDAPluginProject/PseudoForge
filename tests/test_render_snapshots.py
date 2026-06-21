from __future__ import annotations

import difflib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader
from tests.fixtures.ntset_samples import NTSET_SYSTEM_INFORMATION_SAMPLE
from tests.fixtures.snapshot_samples import (
    DRIVER_ENTRY_SAMPLE,
    IOCTL_DISPATCH_SAMPLE,
    SINGLE_LINE_IF_SAMPLE,
)


SNAPSHOT_DIR = Path(__file__).with_name("snapshots")
UPDATE_SNAPSHOTS = os.environ.get("PSEUDOFORGE_UPDATE_SNAPSHOTS") == "1"


OB_PRE_OPERATION_SAMPLE = r"""
__int64 __fastcall PfkpObjectPreOperation(__int64 a1, __int64 a2)
{
  unsigned int desiredAccess;

  desiredAccess = 0;
  if ( *(_DWORD *)a2 == 1 )
  {
    desiredAccess = *(_DWORD *)(*(_QWORD *)(a2 + 32) + 4LL);
  }
  else
  {
    if ( *(_DWORD *)a2 == 2 )
    {
      desiredAccess = *(_DWORD *)(*(_QWORD *)(a2 + 32) + 4LL);
    }
  }
  return 0LL;
}
"""


class _JsonRenameProvider:
    def __init__(self, renames: list[dict[str, object]]) -> None:
        self._renames = renames

    def suggest_renames(self, capture) -> str:
        return json.dumps({"renames": self._renames})


def _ioctl_provider() -> _JsonRenameProvider:
    return _JsonRenameProvider(
        [
            {"old": "v4", "new": "deviceContext", "confidence": 0.90},
            {"old": "MasterIrp", "new": "systemBuffer", "confidence": 0.90},
            {"old": "v5", "new": "inputBufferLength", "confidence": 0.90},
            {"old": "v6", "new": "outputBufferLength", "confidence": 0.88},
            {"old": "v9", "new": "ioControlCode", "confidence": 0.97},
            {"old": "v10", "new": "ioStack", "confidence": 0.90},
        ]
    )


SNAPSHOT_CASES = (
    {
        "name": "ntset_system_information",
        "sample": NTSET_SYSTEM_INFORMATION_SAMPLE,
        "provider": None,
    },
    {
        "name": "driver_entry_device_extension",
        "sample": DRIVER_ENTRY_SAMPLE,
        "provider": None,
    },
    {
        "name": "ioctl_dispatch",
        "sample": IOCTL_DISPATCH_SAMPLE,
        "provider": _ioctl_provider(),
    },
    {
        "name": "ob_pre_operation_callback",
        "sample": OB_PRE_OPERATION_SAMPLE,
        "provider": None,
    },
    {
        "name": "generic_function_style",
        "sample": SINGLE_LINE_IF_SAMPLE,
        "provider": None,
    },
)


def _render_snapshot(sample: str, provider: object | None) -> str:
    capture = capture_from_pseudocode(sample)
    plan = build_clean_plan(capture, rename_provider=provider)
    return _normalize_snapshot_text(render_cleaned_pseudocode(capture, plan))


def _normalize_snapshot_text(text: str) -> str:
    text = re.sub(r"Version: .+", "Version: <VERSION>", text)
    text = re.sub(r"Fingerprint: [0-9a-f]{64}", "Fingerprint: <FINGERPRINT>", text)
    return text.rstrip() + "\n"


def _read_snapshot(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_snapshot(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


class RenderSnapshotTests(unittest.TestCase):
    maxDiff = None

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_rendered_output_matches_golden_snapshots(self) -> None:
        for case in SNAPSHOT_CASES:
            with self.subTest(case=case["name"]):
                snapshot_path = SNAPSHOT_DIR / f"{case['name']}.cleaned.cpp"
                actual = _render_snapshot(
                    sample=str(case["sample"]),
                    provider=case["provider"],
                )
                if UPDATE_SNAPSHOTS:
                    _write_snapshot(snapshot_path, actual)
                    continue
                if not snapshot_path.exists():
                    self.fail(
                        "Missing renderer snapshot %s. Run with "
                        "PSEUDOFORGE_UPDATE_SNAPSHOTS=1 to create it."
                        % snapshot_path
                    )
                expected = _read_snapshot(snapshot_path)
                if expected != actual:
                    diff = "\n".join(
                        difflib.unified_diff(
                            expected.splitlines(),
                            actual.splitlines(),
                            fromfile=str(snapshot_path),
                            tofile="actual",
                            lineterm="",
                        )
                    )
                    self.fail("Renderer snapshot mismatch:\n%s" % diff)

    def test_profile_directory_switch_clears_profile_backed_rewrite_caches(self) -> None:
        original_dir = profile_loader.PROFILE_DIR
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                profile_loader.configure_profile_dir(temp_dir)
                primed_without_profile = _render_snapshot(OB_PRE_OPERATION_SAMPLE, None)
                self.assertIn("*(_DWORD *)preOperationInfo", primed_without_profile)

            profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)
            rendered = _render_snapshot(OB_PRE_OPERATION_SAMPLE, None)

            self.assertIn("preOperationInfo->Operation == 1", rendered)
            self.assertIn(
                "preOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess",
                rendered,
            )
            self.assertNotIn("*(_DWORD *)preOperationInfo", rendered)
        finally:
            profile_loader.PROFILE_DIR = original_dir
            profile_loader.clear_profile_caches()


if __name__ == "__main__":
    unittest.main()
