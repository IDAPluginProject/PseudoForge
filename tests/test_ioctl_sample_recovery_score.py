from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_score_ioctl_recovery import score_ioctl_recovery


class IoctlSampleRecoveryScoreTests(unittest.TestCase):
    def test_score_ioctl_recovery_matches_manifest_offsets_and_predicates(self) -> None:
        manifest = {
            "schema": "pseudoforge_ioctl_recovery_ground_truth_v1",
            "ioctls": [
                {
                    "name": "TEST_IOCTL",
                    "code": "0x8338E404",
                    "role": "inout",
                    "required_input_size": 16,
                    "required_output_size": 8,
                    "fields": [
                        {"offset": 0, "size": 4, "name": "Size", "type": "ULONG"},
                        {"offset": 8, "size": 8, "name": "SessionId", "type": "ULONGLONG"},
                    ],
                    "requirements": [
                        {"offset": 0, "relation": "==", "value": "16"},
                        {"offset": 8, "relation": "!=", "value": "0"},
                    ],
                }
            ],
        }
        recovered = [
            {
                "command_value": 0x8338E404,
                "buffers": [
                    {
                        "size_constraints": [
                            {
                                "length": "inputBufferLength",
                                "valid_relation": ">=",
                                "valid_value": "16",
                            },
                            {
                                "length": "outputBufferLength",
                                "valid_relation": ">=",
                                "valid_value": "8",
                            },
                        ],
                        "field_accesses": [
                            {"offset": 0, "type": "ULONG"},
                            {"offset": 8, "type": "ULONGLONG"},
                        ],
                        "field_constraints": [
                            {"offset": 0, "valid_relation": "==", "valid_value": "0x10"},
                            {"offset": 8, "valid_relation": "!=", "valid_value": "0"},
                        ],
                    }
                ],
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "TEST_IOCTL.buffer-contracts.json").write_text(json.dumps(recovered), encoding="utf-8")
            report = score_ioctl_recovery(manifest_path=manifest_path, recovered_dir=root)

        self.assertEqual(1.0, report["overall_score"])
        self.assertEqual(1.0, report["component_scores"]["predicate"])

    def test_score_ioctl_recovery_gives_partial_credit_for_predicate_offset(self) -> None:
        manifest = {
            "ioctls": [
                {
                    "name": "TEST_IOCTL",
                    "code": "0x8338E408",
                    "role": "inout",
                    "fields": [{"offset": 32, "size": 4, "name": "Severity", "type": "ULONG"}],
                    "requirements": [{"offset": 32, "relation": "<=", "value": "5"}],
                }
            ]
        }
        recovered = [
            {
                "command_value": 0x8338E408,
                "buffers": [
                    {
                        "field_accesses": [{"offset": 32, "type": "ULONG"}],
                        "field_constraints": [{"offset": 32, "relation": "<", "value": "6"}],
                    }
                ],
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "TEST_IOCTL.buffer-contracts.json").write_text(json.dumps(recovered), encoding="utf-8")
            report = score_ioctl_recovery(manifest_path=manifest_path, recovered_dir=root)

        self.assertLess(report["overall_score"], 1.0)
        self.assertEqual(0.5, report["cases"][0]["components"]["predicate"][0])

    def test_score_ioctl_recovery_credits_wide_and_split_field_coverage(self) -> None:
        manifest = {
            "ioctls": [
                {
                    "name": "TEST_IOCTL",
                    "code": "0x83386400",
                    "role": "output",
                    "fields": [
                        {"offset": 4, "size": 4, "name": "Version", "type": "ULONG"},
                        {"offset": 40, "size": 8, "name": "EventId", "type": "ULONGLONG"},
                    ],
                    "requirements": [],
                }
            ]
        }
        recovered = [
            {
                "command_value": 0x83386400,
                "buffers": [
                    {
                        "field_accesses": [
                            {"offset": 4, "type": "ULONGLONG"},
                            {"offset": 40, "type": "ULONG"},
                            {"offset": 44, "type": "ULONG"},
                        ]
                    }
                ],
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "TEST_IOCTL.buffer-contracts.json").write_text(json.dumps(recovered), encoding="utf-8")
            report = score_ioctl_recovery(manifest_path=manifest_path, recovered_dir=root)

        self.assertEqual(1.0, report["component_scores"]["field"])

    def test_score_ioctl_recovery_accepts_seen_no_buffer_control(self) -> None:
        manifest = {
            "ioctls": [
                {
                    "name": "RESET_STATE",
                    "code": "0x8338A410",
                    "role": "none",
                    "fields": [],
                    "requirements": [],
                }
            ]
        }
        coverage = {"cases": [{"case_value": "0x8338A410"}]}

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "selector-coverage-summary.json").write_text(json.dumps(coverage), encoding="utf-8")
            report = score_ioctl_recovery(manifest_path=manifest_path, recovered_dir=root)

        self.assertEqual(1.0, report["overall_score"])
        self.assertEqual(1.0, report["cases"][0]["score"])


if __name__ == "__main__":
    unittest.main()
