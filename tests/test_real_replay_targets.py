from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.real_replay_targets import (
    corpus_real_replay_records_from_targets,
    load_real_replay_targets,
)


class RealReplayTargetsTests(unittest.TestCase):
    def test_real_replay_targets_capture_non_windows_family_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "replay-targets.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "pseudoforge_real_replay_targets_v1",
                        "targets": [
                            {
                                "family": "linux_elf_user",
                                "tool": "ida",
                                "reference": "replay://linux",
                                "function_count": 100,
                                "status": "passed",
                            },
                            {
                                "family": "macos_macho_user",
                                "tool": "ghidra",
                                "reference": "replay://macos",
                                "function_count": 80,
                                "status": "validated",
                            },
                            {
                                "family": "firmware_uefi",
                                "tool": "ida",
                                "reference": "replay://uefi",
                                "function_count": 10,
                                "status": "blocked",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            targets = load_real_replay_targets(path)
            records = corpus_real_replay_records_from_targets(targets)

        self.assertEqual(3, targets["summary"]["target_count"])
        self.assertEqual(2, targets["summary"]["qualified_target_count"])
        self.assertEqual(["linux_elf_user", "macos_macho_user"], targets["summary"]["qualified_families"])
        self.assertEqual("linux_elf_user", records[0]["family"])


if __name__ == "__main__":
    unittest.main()
