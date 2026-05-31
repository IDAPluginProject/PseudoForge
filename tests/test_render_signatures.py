from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.core.render import _find_signature_end as legacy_find_signature_end
from ida_pseudoforge.core.render_signatures import apply_known_function_signature, find_signature_end


class RenderSignatureTests(unittest.TestCase):
    def test_apply_known_function_signature_uses_prototype_name_when_capture_name_is_empty(self) -> None:
        prototype = "__int64 __fastcall DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)"
        text = "\n".join(
            [
                prototype,
                "{",
                "  Irp->IoStatus.Status = 0;",
                "  IofCompleteRequest(Irp, 0);",
                "  return 0;",
                "}",
            ]
        )
        capture = FunctionCapture(name="", prototype=prototype, pseudocode=text)

        rendered = apply_known_function_signature(text, capture)

        self.assertIn("NTSTATUS __fastcall DispatchDeviceControl(", rendered)
        self.assertIn("        PDEVICE_OBJECT deviceObject,", rendered)
        self.assertIn("        PIRP irp)", rendered)

    def test_find_signature_end_handles_multiline_signatures(self) -> None:
        lines = [
            "NTSTATUS Sample(",
            "        PVOID input,",
            "        ULONG length)",
            "{",
        ]

        self.assertEqual(find_signature_end(lines, 0), 2)
        self.assertEqual(legacy_find_signature_end(lines, 0), 2)


if __name__ == "__main__":
    unittest.main()
