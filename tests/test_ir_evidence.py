from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ir_evidence import ir_evidence_summary, textual_flow_ir_evidence
from ida_pseudoforge.core.lvar_analysis import build_clean_plan


PSEUDOCODE = r"""
__int64 __fastcall IrEvidenceSample(void)
{
  HANDLE hFile;
  void *region;

  hFile = CreateFileW(L"C:\\temp\\input.bin", 0x80000000, 1u, 0i64, 3u, 0x80u, 0i64);
  region = VirtualAlloc(0i64, 0x1000ui64, 0x3000u, 4u);
  if ( hFile == 0i64 )
    return 0;
  if ( region != 0i64 )
    CloseHandle(hFile);
  return region != 0i64;
}
"""


class IrEvidenceTests(unittest.TestCase):
    def test_textual_ir_evidence_is_opt_in_and_records_flow_facts(self) -> None:
        capture = capture_from_pseudocode(
            PSEUDOCODE,
            profile_context={
                "format": "pe",
                "platform": "windows",
                "privilege_domain": "user",
                "enable_textual_ir_evidence": True,
            },
        )
        plan = build_clean_plan(capture)

        summary = ir_evidence_summary(plan.ir_evidence)

        self.assertEqual("textual_flow_v1", summary["adapter"])
        self.assertTrue(summary["available"])
        self.assertGreaterEqual(summary["call_site_signatures"], 3)
        self.assertGreaterEqual(summary["use_def_chains"], 2)
        self.assertGreaterEqual(summary["local_type_snapshots"], 2)
        self.assertGreaterEqual(summary["diagnostics"], 2)

    def test_default_capture_keeps_text_only_ir_evidence(self) -> None:
        capture = capture_from_pseudocode(PSEUDOCODE)

        summary = ir_evidence_summary(capture.ir_evidence)

        self.assertEqual("text_only", summary["adapter"])
        self.assertFalse(summary["available"])

    def test_textual_ir_does_not_treat_nonzero_hex_literal_as_null_check(self) -> None:
        evidence = textual_flow_ir_evidence(
            """
            void *p;
            p = VirtualAlloc(0i64, 0x1000ui64, 0x3000u, 4u);
            if ( p != 0x1000 )
              return p;
            """,
            [],
            ["VirtualAlloc"],
        )

        self.assertEqual([], evidence.diagnostics)

    def test_summary_accepts_duck_typed_ir_evidence_payload(self) -> None:
        class ForeignIrEvidence:
            def to_dict(self):
                return {
                    "schema": "pseudoforge_ir_evidence_v1",
                    "adapter": "hexrays_cfunc_v1",
                    "source": "hexrays_cfunc",
                    "available": True,
                    "use_def_chains": [],
                    "value_ranges": [],
                    "local_type_snapshots": [{"name": "status", "type_text": "int"}],
                    "constant_origins": [],
                    "call_site_signatures": [],
                    "diagnostics": [],
                }

        summary = ir_evidence_summary(ForeignIrEvidence())

        self.assertEqual("hexrays_cfunc_v1", summary["adapter"])
        self.assertEqual("hexrays_cfunc", summary["source"])
        self.assertTrue(summary["available"])
        self.assertEqual(1, summary["local_type_snapshots"])


if __name__ == "__main__":
    unittest.main()
