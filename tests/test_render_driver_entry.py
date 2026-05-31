from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_driver_entry import (
    driver_entry_signature_override,
    normalize_driver_entry_body,
)


NO_PDB_DRIVER_ENTRY_SAMPLE = r"""
__int64 __fastcall EntryCandidate(PDRIVER_OBJECT DriverObject, unsigned __int16 *a2)
{
  int v4; // edi
  char *DeviceExtension; // rbx
  struct _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-10h] BYREF
  PDEVICE_OBJECT DeviceObject; // [rsp+80h] [rbp+30h] BYREF

  DeviceObject = 0LL;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\AnyDevice");
  memset64(DriverObject->MajorFunction, (unsigned __int64)DefaultDispatch, 0x1CuLL);
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)DeviceControlDispatch;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnloadRoutine;
  v4 = IoCreateDevice(DriverObject, 0x340u, &DestinationString, 0xA123u, 0x100u, 0, &DeviceObject);
  if ( v4 >= 0 )
  {
    DeviceObject->Flags |= 4u;
    DeviceExtension = (char *)DeviceObject->DeviceExtension;
    *((_QWORD *)DeviceExtension + 1) = DeviceObject;
    v4 = InitializeExtension((__int64)DeviceExtension);
    if ( v4 >= 0 )
    {
      DeviceObject->Flags &= ~0x80u;
      return (unsigned int)v4;
    }
  }
  return (unsigned int)v4;
}
"""


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

    def test_no_pdb_driver_entry_renames_status_device_and_extension_conservatively(self) -> None:
        capture = capture_from_pseudocode(NO_PDB_DRIVER_ENTRY_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["DriverObject"], "driverObject")
        self.assertEqual(rename_map["a2"], "registryPath")
        self.assertEqual(rename_map["v4"], "status")
        self.assertEqual(rename_map["DeviceObject"], "deviceObject")
        self.assertEqual(rename_map["DeviceExtension"], "extension")
        self.assertEqual(rename_map["DestinationString"], "deviceName")
        self.assertIn("NTSTATUS __fastcall DriverEntry(", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("PDEVICE_OBJECT deviceObject;", rendered)
        self.assertIn("status = IoCreateDevice(driverObject", rendered)
        self.assertIn("if ( NT_SUCCESS(status) )", rendered)
        self.assertIn("extension = (char *)deviceObject->DeviceExtension;", rendered)
        self.assertIn("deviceObject->Flags |= DO_BUFFERED_IO;", rendered)
        self.assertIn("deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;", rendered)
        self.assertIn("return status;", rendered)
        self.assertNotIn("int status;", rendered)
        self.assertNotIn("return (unsigned int)status;", rendered)

    def test_driver_entry_wrapper_comment_does_not_claim_device_creation_sequence(self) -> None:
        sample = r"""
__int64 __fastcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  return RealEntry(DriverObject, RegistryPath);
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("DriverEntry entrypoint or wrapper detected", rendered)
        self.assertNotIn("device creation sequence detected", rendered)
        self.assertNotIn("driver_dispatch_table", rendered)


if __name__ == "__main__":
    unittest.main()
