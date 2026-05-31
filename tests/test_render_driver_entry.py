from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import (
    display_warning_count,
    render_cleaned_pseudocode,
)
from ida_pseudoforge.core.render_driver_entry import (
    driver_entry_signature_override,
    normalize_driver_entry_body,
)


DRIVER_ENTRY_SAMPLE = r"""
__int64 __fastcall sub_140003530(struct _DRIVER_OBJECT *a1, __int64 a2)
{
  NTSTATUS v3; // [rsp+40h] [rbp-38h]
  unsigned int i; // [rsp+44h] [rbp-34h]
  _DWORD *DeferredContext; // [rsp+48h] [rbp-30h]
  PDEVICE_OBJECT DeviceObject; // [rsp+50h] [rbp-28h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+58h] [rbp-20h] BYREF

  DeviceObject = 0LL;
  DeferredContext = 0LL;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\PfKernelPattern");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\PfKernelPattern");
  for ( i = 0; i <= 0x1B; ++i )
    a1->MajorFunction[i] = (PDRIVER_DISPATCH)sub_140003430;
  a1->MajorFunction[0] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[2] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[14] = (PDRIVER_DISPATCH)sub_1400013F0;
  a1->DriverUnload = (PDRIVER_UNLOAD)sub_140003270;
  v3 = IoCreateDevice(a1, 0x340u, &DestinationString, 0x8337u, 0x100u, 0, &DeviceObject);
  if ( v3 >= 0 )
  {
    DeviceObject->Flags |= 4u;
    DeferredContext = DeviceObject->DeviceExtension;
    memset(DeferredContext, 0, 0x340uLL);
    *DeferredContext = 1883981392;
    *((_QWORD *)DeferredContext + 1) = DeviceObject;
    DeferredContext[184] = 64;
    qword_140005010 = (__int64)DeviceObject;
    sub_1400039D0(DeferredContext + 4);
    sub_1400039D0(DeferredContext + 18);
    KeInitializeSpinLock((PKSPIN_LOCK)DeferredContext + 16);
    sub_140003A70(DeferredContext + 34);
    sub_140003A70(DeferredContext + 38);
    sub_140003A70(DeferredContext + 42);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48),
      0LL,
      0LL,
      0,
      0x38uLL,
      0x724B4650u,
      0);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80),
      0LL,
      0LL,
      0,
      0x28uLL,
      0x6C4B4650u,
      0);
    KeInitializeTimerEx((PKTIMER)DeferredContext + 7, NotificationTimer);
    KeInitializeDpc((PRKDPC)DeferredContext + 8, DeferredRoutine, DeferredContext);
    KeInitializeEvent((PRKEVENT)(DeferredContext + 146), NotificationEvent, 1u);
    ExInitializeRundownProtection((PEX_RUNDOWN_REF)DeferredContext + 76);
    ExInitializeResourceLite((PERESOURCE)(DeferredContext + 154));
    v3 = sub_140002D60(DeferredContext);
    if ( v3 >= 0 )
    {
      v3 = sub_1400010D0(DeferredContext + 180, a2);
      if ( v3 >= 0 )
      {
        sub_140002950(DeferredContext);
        *((_QWORD *)DeferredContext + 72) = IoAllocateWorkItem(DeviceObject);
        if ( *((_QWORD *)DeferredContext + 72) )
        {
          v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
          if ( v3 >= 0 )
            DeviceObject->Flags &= ~0x80u;
        }
        else
        {
          v3 = -1073741670;
        }
      }
    }
  }
  if ( v3 < 0 )
  {
    if ( DeferredContext )
    {
      if ( *((_QWORD *)DeferredContext + 72) )
      {
        IoFreeWorkItem(*((PIO_WORKITEM *)DeferredContext + 72));
        *((_QWORD *)DeferredContext + 72) = 0LL;
      }
      if ( *((_QWORD *)DeferredContext + 91) )
      {
        ExFreePoolWithTag(*((PVOID *)DeferredContext + 91), 0x704B4650u);
        memset(DeferredContext + 180, 0, 0x10uLL);
      }
      ExDeleteResourceLite((PERESOURCE)(DeferredContext + 154));
      sub_140001310(DeferredContext);
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80));
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48));
    }
    if ( DeviceObject )
    {
      IoDeleteDevice(DeviceObject);
      qword_140005010 = 0LL;
    }
  }
  return (unsigned int)v3;
}
"""


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

    def test_driver_entry_device_extension_semantics(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "a1", "new": "DriverObject", "confidence": 0.99},
                            {"old": "a2", "new": "RegistryPath", "confidence": 0.99},
                            {"old": "sub_140003530", "new": "DriverEntry", "confidence": 0.99},
                            {"old": "sub_1400011D0", "new": "DispatchCreateClose", "confidence": 0.99},
                            {"old": "sub_1400013F0", "new": "DispatchDeviceControl", "confidence": 0.99},
                            {"old": "sub_140003430", "new": "DispatchDefault", "confidence": 0.99},
                            {"old": "sub_140003270", "new": "DriverUnload", "confidence": 0.99},
                            {"old": "sub_1400010D0", "new": "LoadConfiguration", "confidence": 0.60},
                            {"old": "DeferredContext", "new": "devExt", "confidence": 0.95},
                        ],
                        "warnings": [
                            (
                                "DeferredContext is IDA-misnamed; it is the DeviceObject->DeviceExtension, "
                                "not a DPC deferred context"
                            ),
                            (
                                "Field offsets into deviceExtension (e.g. +4,+18,+72,+91,+180) "
                                "suggest a struct should be defined for DeviceExtension"
                            ),
                            (
                                "Sub-function renames (sub_1400039D0, sub_140003A70, sub_140002D60, "
                                "sub_1400010D0, sub_140002950, sub_140001310) are inferred from call "
                                "context only; verify by inspecting each callee"
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(DRIVER_ENTRY_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        forge_section = render_forge_function_section(capture, plan, rendered)

        self.assertEqual(rename_map["a1"], "driverObject")
        self.assertEqual(rename_map["a2"], "registryPath")
        self.assertEqual(rename_map["v3"], "status")
        self.assertEqual(rename_map["DeferredContext"], "extension")
        self.assertEqual(rename_map["DeviceObject"], "deviceObject")
        self.assertEqual(rename_map["DestinationString"], "deviceName")
        self.assertEqual(rename_map["i"], "majorIndex")

        self.assertIn("NTSTATUS __fastcall DriverEntry(", rendered)
        self.assertIn("PDRIVER_OBJECT driverObject", rendered)
        self.assertIn("PUNICODE_STRING registryPath", rendered)
        self.assertIn("Kernel semantic rewrites: 4", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertIn("// Warnings: 0", forge_section)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("DriverEntry-style dispatch table", rendered)
        self.assertIn("typedef struct _INFERRED_DRIVER_DEVICE_EXTENSION", rendered)
        self.assertIn("} INFERRED_DRIVER_DEVICE_EXTENSION;\n\nNTSTATUS __fastcall DriverEntry", rendered)
        self.assertIn("INFERRED_DRIVER_DEVICE_EXTENSION *extension", rendered)
        self.assertIn("majorIndex <= IRP_MJ_MAXIMUM_FUNCTION", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CREATE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CLOSE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]", rendered)
        self.assertIn(
            "IoCreateDevice(driverObject, 0x340u, &deviceName, 0x8337u, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject)",
            rendered,
        )
        self.assertIn("0x8337u, FILE_DEVICE_SECURE_OPEN", rendered)
        self.assertIn("FILE_DEVICE_SECURE_OPEN", rendered)
        self.assertNotIn("PFKP_DEVICE_TYPE", rendered)
        self.assertNotIn("sizeof(INFERRED_DRIVER_DEVICE_EXTENSION)", rendered)
        self.assertIn("deviceObject->Flags |= DO_BUFFERED_IO;", rendered)
        self.assertIn("deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;", rendered)
        self.assertIn("memset(extension, 0, 0x340uLL);", rendered)
        self.assertIn("extension->Signature = POOL_TAG('P', 'F', 'K', 'p');", rendered)
        self.assertIn("extension->DeviceObject = deviceObject;", rendered)
        self.assertIn("extension->MaxRecords = 64;", rendered)
        self.assertIn("ExInitializeFastMutex(&extension->StateLock);", rendered)
        self.assertIn("InitializeListHead(&extension->ProcessBlacklist);", rendered)
        self.assertIn("KeInitializeSpinLock(&extension->EventLock);", rendered)
        self.assertIn("ExInitializeNPagedLookasideList(&extension->RecordLookaside", rendered)
        self.assertIn("POOL_TAG('P', 'F', 'K', 'r')", rendered)
        self.assertIn("POOL_TAG('P', 'F', 'K', 'l')", rendered)
        self.assertIn("KeInitializeTimerEx(&extension->Timer, NotificationTimer);", rendered)
        self.assertIn("KeInitializeDpc(&extension->TimerDpc, DeferredRoutine, extension);", rendered)
        self.assertIn("KeInitializeEvent(&extension->WorkItemIdleEvent, NotificationEvent, TRUE);", rendered)
        self.assertIn("ExInitializeRundownProtection(&extension->Rundown);", rendered)
        self.assertIn("ExInitializeResourceLite(&extension->Resource);", rendered)
        self.assertIn("status = sub_1400010D0(&extension->RegistryPath, registryPath);", rendered)
        self.assertIn("extension->WorkItem = IoAllocateWorkItem(deviceObject);", rendered)
        self.assertIn("IoFreeWorkItem(extension->WorkItem);", rendered)
        self.assertIn("ExFreePoolWithTag(extension->RegistryPath.Buffer, POOL_TAG('P', 'F', 'K', 'p'));", rendered)
        self.assertIn("memset(&extension->RegistryPath, 0, sizeof(extension->RegistryPath));", rendered)
        self.assertIn("ExDeleteNPagedLookasideList(&extension->ProcessRuleLookaside);", rendered)
        self.assertIn("if ( NT_SUCCESS(status) )", rendered)
        self.assertIn("if ( !NT_SUCCESS(status) )", rendered)
        self.assertIn("return status;", rendered)
        self.assertNotIn("Skipped PascalCase LLM rename", rendered)
        self.assertNotIn("Warning detail:", rendered)
        self.assertNotIn("DeferredContext is IDA-misnamed", rendered)
        self.assertNotIn("Field offsets into deviceExtension", rendered)
        self.assertNotIn("Sub-function renames", rendered)
        self.assertNotIn("devExt", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("MajorFunction[14]", rendered)
        self.assertNotIn("Flags |= 4u", rendered)
        self.assertNotIn("Flags &= ~0x80u", rendered)
        self.assertNotIn("DeferredContext + 180", rendered)

    def test_driver_entry_extension_rewrite_requires_dword_scaled_offsets(self):
        sample = DRIVER_ENTRY_SAMPLE.replace("_DWORD *DeferredContext", "_QWORD *DeferredContext", 1)
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("typedef struct _INFERRED_DRIVER_DEVICE_EXTENSION", rendered)
        self.assertNotIn("INFERRED_DRIVER_DEVICE_EXTENSION *extension", rendered)
        self.assertNotIn("extension->StateLock", rendered)
        self.assertIn("memset(extension, 0, 0x340uLL);", rendered)

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
