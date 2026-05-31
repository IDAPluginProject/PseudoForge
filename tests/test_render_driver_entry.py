from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_driver_entry import (
    driver_entry_signature_override,
    normalize_driver_entry_body,
)


class RenderDriverEntryTests(unittest.TestCase):
    def test_driver_entry_signature_override_uses_canonical_parameters(self) -> None:
        self.assertEqual(
            driver_entry_signature_override(),
            [
                "NTSTATUS __fastcall DriverEntry(",
                "        PDRIVER_OBJECT driverObject,",
                "        PUNICODE_STRING registryPath)",
            ],
        )

    def test_normalize_driver_entry_body_rewrites_driver_setup_constants(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS __fastcall DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)",
                "{",
                "  int status;",
                "  int majorIndex;",
                "",
                "  while ( majorIndex <= 27 )",
                "  {",
                "    driverObject->MajorFunction[0] = DispatchCreate;",
                "    driverObject->MajorFunction[2] = DispatchClose;",
                "    driverObject->MajorFunction[14] = DispatchDeviceControl;",
                "  }",
                "  status = IoCreateDevice(driverObject, 0x340u, &deviceName, 0x8337u, 0x100u, FALSE, &deviceObject);",
                "  deviceObject->Flags |= 4u;",
                "  deviceObject->Flags &= ~0x80u;",
                "  if ( status >= 0 )",
                "    return (unsigned int)status;",
                "  if ( status < 0 )",
                "    return (unsigned int)status;",
                "}",
            ]
        )

        rendered = normalize_driver_entry_body(text)

        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("majorIndex <= IRP_MJ_MAXIMUM_FUNCTION", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CREATE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CLOSE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]", rendered)
        self.assertIn("0x8337u, FILE_DEVICE_SECURE_OPEN, FALSE", rendered)
        self.assertIn("deviceObject->Flags |= DO_BUFFERED_IO;", rendered)
        self.assertIn("deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;", rendered)
        self.assertIn("if ( NT_SUCCESS(status) )", rendered)
        self.assertIn("if ( !NT_SUCCESS(status) )", rendered)
        self.assertIn("return status;", rendered)


if __name__ == "__main__":
    unittest.main()
