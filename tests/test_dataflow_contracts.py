from __future__ import annotations

import unittest

from ida_pseudoforge.core.dataflow_contracts import dataflow_contracts_from_ir_evidence
from ida_pseudoforge.core.ir_evidence import textual_flow_ir_evidence


SAMPLE = r"""
int __fastcall OpenCloseSample(void)
{
  int fd;

  fd = open("/tmp/a", 0);
  write(fd, "x", 1);
  close(fd);
  return 0;
}
"""


class DataflowContractsTests(unittest.TestCase):
    def test_dataflow_contract_records_source_to_sink_use_def(self) -> None:
        ir_evidence = textual_flow_ir_evidence(SAMPLE, [], ["open", "write", "close"])

        report = dataflow_contracts_from_ir_evidence(
            "OpenCloseSample",
            ir_evidence,
            source_calls=["open"],
            sink_calls=["close"],
            reference_prefix="dataflow://unit",
        )

        self.assertEqual(1, report["contract_count"])
        contract = report["contracts"][0]
        self.assertEqual("open", contract["source_function"])
        self.assertEqual("close", contract["sink_function"])
        self.assertEqual("validated", contract["status"])
        self.assertIn("fd", contract["proof"])

    def test_dataflow_contract_rejects_unconsumed_source_result(self) -> None:
        ir_evidence = textual_flow_ir_evidence(
            "int __fastcall Leaky(void) { int fd; fd = open(\"/tmp/a\", 0); return fd; }",
            [],
            ["open", "close"],
        )

        report = dataflow_contracts_from_ir_evidence(
            "Leaky",
            ir_evidence,
            source_calls=["open"],
            sink_calls=["close"],
        )

        self.assertEqual(0, report["contract_count"])


if __name__ == "__main__":
    unittest.main()
