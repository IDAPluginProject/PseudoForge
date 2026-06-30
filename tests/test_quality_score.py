from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.quality_score import (
    GENERIC_QUALITY_BUCKET,
    WINDOWS_KERNEL_QUALITY_BUCKET,
    quality_summary_to_markdown,
    score_compare_directory,
    score_pseudocode_quality,
)
from tools.score_pseudoforge_quality import main as score_quality_main


RAW_ARTIFACT_SAMPLE = r"""
__int64 __fastcall sub_140001000(__int64 a1)
{
  __int64 v1;

  v1 = *(_QWORD *)(a1 + 24);
  qword_140006000 = v1;
  if ( LOBYTE(v1) )
  {
    return 0xC000000DLL;
  }
  return sub_140002000(v1);
}
"""


SEMANTIC_SAMPLE = r"""
NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  PIO_STACK_LOCATION stackLocation;
  NTSTATUS status;

  stackLocation = irp->Tail.Overlay.CurrentStackLocation;
  switch ( stackLocation->Parameters.DeviceIoControl.IoControlCode )
  {
    case CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS):
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  return status;
}
"""


GENERIC_C_SAMPLE = r"""
int __fastcall parse_header(int input)
{
  int value;

  value = *(_DWORD *)(input + 4);
  return sub_401000(value);
}
"""


class QualityScoreTests(unittest.TestCase):
    def test_semantic_output_scores_higher_than_raw_artifacts(self) -> None:
        raw_score = score_pseudocode_quality(RAW_ARTIFACT_SAMPLE)
        semantic_score = score_pseudocode_quality(SEMANTIC_SAMPLE)

        self.assertGreater(semantic_score.score, raw_score.score)
        self.assertTrue(any(item.category == "raw_argument_name" for item in raw_score.findings))
        self.assertTrue(any(item.category == "raw_pointer_offset" for item in raw_score.findings))
        self.assertTrue(any(item.category == "trusted_kernel_type" for item in semantic_score.rewards))
        self.assertGreater(semantic_score.quality_buckets[WINDOWS_KERNEL_QUALITY_BUCKET]["reward"], 0)
        self.assertGreaterEqual(semantic_score.quality_buckets[GENERIC_QUALITY_BUCKET]["reward"], 0)

    def test_generic_c_fixture_does_not_receive_kernel_rewards(self) -> None:
        score = score_pseudocode_quality(GENERIC_C_SAMPLE)

        self.assertGreater(score.quality_buckets[GENERIC_QUALITY_BUCKET]["opportunity"], 0)
        self.assertEqual(0, score.quality_buckets[WINDOWS_KERNEL_QUALITY_BUCKET]["reward"])
        self.assertFalse(
            any(item.bucket == WINDOWS_KERNEL_QUALITY_BUCKET for item in score.rewards)
        )
        self.assertIn("win_user_pe", score.quality_buckets)
        self.assertTrue(score.quality_buckets["win_user_pe"]["reserved"])

    def test_quality_scorer_strips_generated_comment_metadata(self) -> None:
        text = """
// PseudoForge preview panel. IDB was not modified.
/*
    Renames: a1->driverObject, v1->status
*/
NTSTATUS __fastcall DriverEntry(PDRIVER_OBJECT driverObject)
{
  return STATUS_SUCCESS;
}
"""

        score = score_pseudocode_quality(text)

        self.assertFalse(any(item.category == "raw_argument_name" for item in score.findings))
        self.assertFalse(any(item.category == "compiler_local_name" for item in score.findings))

    def test_compare_directory_summary_ranks_worst_function_first(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            compare_dir = root / "compare"
            raw_dir = compare_dir / "raw"
            cleaned_dir = compare_dir / "cleaned"
            raw_dir.mkdir(parents=True)
            cleaned_dir.mkdir(parents=True)
            bad_name = "0000000140001000_sub_140001000.cpp"
            good_name = "0000000140002000_DispatchDeviceControl.cpp"
            (raw_dir / bad_name).write_text(RAW_ARTIFACT_SAMPLE, encoding="utf-8")
            (cleaned_dir / bad_name).write_text(RAW_ARTIFACT_SAMPLE, encoding="utf-8")
            (raw_dir / good_name).write_text(RAW_ARTIFACT_SAMPLE, encoding="utf-8")
            (cleaned_dir / good_name).write_text(SEMANTIC_SAMPLE, encoding="utf-8")
            report_path = root / "ida_batch.jsonl"
            report_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event": "function",
                                "ea": "0x140001000",
                                "name": "sub_140001000",
                                "comparison": {"cleaned_path": str(cleaned_dir / bad_name)},
                            }
                        ),
                        json.dumps(
                            {
                                "event": "function",
                                "ea": "0x140002000",
                                "name": "DispatchDeviceControl",
                                "comparison": {"cleaned_path": str(cleaned_dir / good_name)},
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            summary = score_compare_directory(compare_dir, report_path=report_path, top=2)
            markdown = quality_summary_to_markdown(summary, top=2)

            self.assertEqual(summary["function_count"], 2)
            self.assertEqual(summary["worst_functions"][0]["name"], "sub_140001000")
            self.assertIn("quality_buckets", summary)
            self.assertIn(WINDOWS_KERNEL_QUALITY_BUCKET, summary["domain_buckets"])
            self.assertGreater(summary["quality_buckets"][GENERIC_QUALITY_BUCKET]["opportunity"], 0)
            self.assertGreater(summary["domain_buckets"][WINDOWS_KERNEL_QUALITY_BUCKET]["reward"], 0)
            self.assertIn("## Quality Buckets", markdown)
            self.assertIn("`windows_kernel`", markdown)
            self.assertIn("raw_pointer_offset", markdown)
            self.assertIn("DispatchDeviceControl", markdown)

    def test_quality_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            compare_dir = root / "compare"
            (compare_dir / "raw").mkdir(parents=True)
            (compare_dir / "cleaned").mkdir(parents=True)
            file_name = "0000000140001000_sub_140001000.cpp"
            (compare_dir / "raw" / file_name).write_text(RAW_ARTIFACT_SAMPLE, encoding="utf-8")
            (compare_dir / "cleaned" / file_name).write_text(SEMANTIC_SAMPLE, encoding="utf-8")
            json_output = root / "quality.json"
            markdown_output = root / "quality.md"

            exit_code = score_quality_main(
                [
                    "--compare-dir",
                    str(compare_dir),
                    "--json-output",
                    str(json_output),
                    "--markdown-output",
                    str(markdown_output),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(json_output.exists())
            self.assertTrue(markdown_output.exists())
            payload = json.loads(json_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "pseudoforge_quality_v1")
            self.assertIn("quality_buckets", payload)
            self.assertIn(GENERIC_QUALITY_BUCKET, payload["quality_buckets"])
            self.assertIn(WINDOWS_KERNEL_QUALITY_BUCKET, payload["domain_buckets"])


if __name__ == "__main__":
    unittest.main()
