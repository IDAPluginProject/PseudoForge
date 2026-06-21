from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.domain_identity_summary import (
    domain_identity_summary_payload,
    format_domain_identity_summary,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class IoManagerDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_create_device_roles_are_report_only(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)
{
  PVOID referencedObject;

  referencedObject = 0;
  *DeviceObject = (PDEVICE_OBJECT)referencedObject;
  return DeviceType ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
"""
        )

        identities = self._profile_identities(plan, "windows.io_manager.create_device")
        roles = {item["trusted_role"]: item["structure_name"] for item in identities}

        self.assertEqual("DRIVER_OBJECT", roles["driverObject"])
        self.assertEqual("DEVICE_EXTENSION_SIZE", roles["deviceExtensionSize"])
        self.assertEqual("UNICODE_STRING", roles["deviceName"])
        self.assertEqual("DEVICE_TYPE", roles["deviceType"])
        self.assertEqual("DEVICE_CHARACTERISTICS", roles["deviceCharacteristics"])
        self.assertEqual("BOOLEAN", roles["exclusiveDevice"])
        self.assertEqual("DEVICE_OBJECT_OUTPUT", roles["deviceObjectOutput"])
        self.assertEqual("OBJECT_BODY", roles["securityOrNameObject"])
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertTrue(all("profile_report_only" in item["blockers"] for item in identities))
        summary = domain_identity_summary_payload(plan)
        summary_text = format_domain_identity_summary(plan)
        rendered = render_cleaned_pseudocode(
            capture_from_pseudocode(
                """
NTSTATUS __stdcall IoCreateDevice(PDRIVER_OBJECT DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)
{
  PVOID referencedObject;

  referencedObject = 0;
  *DeviceObject = (PDEVICE_OBJECT)referencedObject;
  return DeviceType ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
""",
                source_path=SOURCE_PATH,
            ),
            plan,
        )

        self.assertEqual(len(identities), summary["total_hits"])
        self.assertEqual(len(identities), summary["report_only_hits"])
        self.assertEqual(0, summary["canonical_rewrite_eligible_hits"])
        self.assertEqual(len(identities), summary["blocker_counts"]["profile_report_only"])
        self.assertIn("windows.io_manager.create_device", summary["top_profile_ids"])
        self.assertIn("I/O Manager", summary["top_subsystems"])
        self.assertEqual(len(identities), summary["subsystem_counts"]["I/O Manager"])
        self.assertIn("Domain identities:", summary_text)
        self.assertIn("Top subsystems: I/O Manager=", summary_text)
        self.assertIn("profile_report_only=", summary_text)
        self.assertIn("Domain identities:", rendered)

    def test_create_device_secure_requires_create_device_handoff(self) -> None:
        without_handoff = self._plan(
            """
__int64 __fastcall IoCreateDeviceSecure(PDRIVER_OBJECT DriverObject, ULONG ExtensionSize, UNICODE_STRING *DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, const void **Sddl, __int64 ClassGuid, PDEVICE_OBJECT *DeviceObject)
{
  return STATUS_SUCCESS;
}
"""
        )
        with_handoff = self._plan(
            """
__int64 __fastcall IoCreateDeviceSecure(PDRIVER_OBJECT DriverObject, ULONG ExtensionSize, UNICODE_STRING *DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, const void **Sddl, __int64 ClassGuid, PDEVICE_OBJECT *DeviceObject)
{
  PDEVICE_OBJECT DeviceObjectLocal;
  NTSTATUS status;

  DeviceObjectLocal = 0;
  status = IoCreateDevice(DriverObject, ExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, &DeviceObjectLocal);
  if ( status >= 0 )
  {
    *DeviceObject = DeviceObjectLocal;
  }
  return status;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.io_manager.create_device_secure"
                for item in self._identities(without_handoff)
            )
        )
        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                with_handoff,
                "windows.io_manager.create_device_secure",
            )
        }

        self.assertEqual("DRIVER_OBJECT", roles["driverObject"])
        self.assertEqual("UNICODE_STRING", roles["deviceName"])
        self.assertEqual("DEVICE_TYPE", roles["deviceType"])
        self.assertEqual("DEVICE_CHARACTERISTICS", roles["deviceCharacteristics"])
        self.assertEqual("UNICODE_STRING", roles["securityDescriptorString"])
        self.assertEqual("DEVICE_OBJECT_OUTPUT", roles["deviceObjectOutput"])

    def test_delete_device_profile_corrects_generic_parameter_type_in_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
void __stdcall IoDeleteDevice(__int64 a1)
{
  IopCompleteUnloadOrDelete((ULONG_PTR)a1);
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(1, len(plan.type_corrections))
        self.assertEqual("windows.io_manager.delete_device", plan.type_corrections[0].profile_id)
        self.assertEqual("__int64", plan.type_corrections[0].old_type)
        self.assertEqual("PDEVICE_OBJECT", plan.type_corrections[0].canonical_type)
        self.assertTrue(plan.type_corrections[0].apply_to_preview)
        self.assertFalse(plan.type_corrections[0].apply_to_idb)
        self.assertIn("void __stdcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)", rendered)
        self.assertIn("IopCompleteUnloadOrDelete((ULONG_PTR)deviceObject);", rendered)
        self.assertNotIn("__int64 deviceObject", rendered)
        self.assertFalse(
            any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments)
        )

    def test_attach_detach_and_attached_reference_roles(self) -> None:
        attach_plan = self._plan(
            """
NTSTATUS __stdcall IoAttachDeviceToDeviceStackSafe(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice, PDEVICE_OBJECT *AttachedToDeviceObject)
{
  return IopAttachDeviceToDeviceStackSafe((__int64)SourceDevice, TargetDevice, AttachedToDeviceObject) ? STATUS_SUCCESS : STATUS_NO_SUCH_DEVICE;
}
"""
        )
        detach_plan = self._plan(
            """
void __stdcall IoDetachDevice(PDEVICE_OBJECT TargetDevice)
{
  struct _DEVOBJ_EXTENSION *DeviceObjectExtension;

  DeviceObjectExtension = TargetDevice->DeviceObjectExtension;
  TargetDevice->AttachedDevice = 0;
}
"""
        )
        reference_plan = self._plan(
            """
PDEVICE_OBJECT __stdcall IoGetAttachedDeviceReference(PDEVICE_OBJECT DeviceObject)
{
  struct _DEVICE_OBJECT *i;

  for ( i = DeviceObject->AttachedDevice; i; i = i->AttachedDevice )
  {
    DeviceObject = i;
  }
  ObfReferenceObjectWithTag(DeviceObject, 0x746C6644);
  return DeviceObject;
}
"""
        )

        attach_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                attach_plan,
                "windows.io_manager.attach_device_to_stack_safe",
            )
        }
        detach_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                detach_plan,
                "windows.io_manager.detach_device",
            )
        }
        reference_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                reference_plan,
                "windows.io_manager.get_attached_device_reference",
            )
        }

        self.assertEqual("DEVICE_OBJECT", attach_roles["sourceDeviceObject"])
        self.assertEqual("DEVICE_OBJECT", attach_roles["targetDeviceObject"])
        self.assertEqual("DEVICE_OBJECT_OUTPUT", attach_roles["attachedDeviceOutput"])
        self.assertEqual("DEVICE_OBJECT", detach_roles["targetDeviceObject"])
        self.assertEqual("DEVOBJ_EXTENSION", detach_roles["deviceObjectExtension"])
        self.assertEqual("DEVICE_OBJECT", reference_roles["startingDeviceObject"])
        self.assertEqual("DEVICE_OBJECT", reference_roles["topAttachedDeviceObject"])

    def test_call_and_complete_request_roles(self) -> None:
        call_plan = self._plan(
            """
NTSTATUS __stdcall IofCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  return IopfCallDriver(DeviceObject, Irp);
}
"""
        )
        private_call_plan = self._plan(
            """
__int64 __fastcall IopfCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  struct _IO_STACK_LOCATION *currentStackLocation;

  currentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
  currentStackLocation->DeviceObject = DeviceObject;
  return 0;
}
"""
        )
        complete_plan = self._plan(
            """
void __stdcall IofCompleteRequest(PIRP Irp, CCHAR PriorityBoost)
{
  IopfCompleteRequest(Irp, PriorityBoost);
}
"""
        )
        private_complete_plan = self._plan(
            """
void __fastcall IopfCompleteRequest(PIRP Irp, char PriorityBoost)
{
  struct _IO_STACK_LOCATION *currentStackLocation;
  PDEVICE_OBJECT deviceObject;

  currentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
  deviceObject = currentStackLocation->DeviceObject;
}
"""
        )

        call_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(call_plan, "windows.io_manager.call_driver")
        }
        private_call_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                private_call_plan,
                "windows.io_manager.call_driver_private",
            )
        }
        complete_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(complete_plan, "windows.io_manager.complete_request")
        }
        private_complete_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                private_complete_plan,
                "windows.io_manager.complete_request_private",
            )
        }

        self.assertEqual("DEVICE_OBJECT", call_roles["targetDeviceObject"])
        self.assertEqual("IRP", call_roles["irp"])
        self.assertEqual("DEVICE_OBJECT", private_call_roles["targetDeviceObject"])
        self.assertEqual("IRP", private_call_roles["irp"])
        self.assertEqual("IO_STACK_LOCATION", private_call_roles["currentStackLocation"])
        self.assertEqual("IRP", complete_roles["irp"])
        self.assertEqual("IO_PRIORITY_BOOST", complete_roles["priorityBoost"])
        self.assertEqual("IRP", private_complete_roles["irp"])
        self.assertEqual("IO_STACK_LOCATION", private_complete_roles["currentStackLocation"])
        self.assertEqual("DEVICE_OBJECT", private_complete_roles["completionDeviceObject"])

    def test_iop_complete_request_identifies_completion_apc(self) -> None:
        without_callees = self._plan(
            """
void __fastcall IopCompleteRequest(__int64 a1, __int64 a2, _QWORD *a3, ULONG_PTR *a4, _QWORD *a5)
{
  *(_BYTE *)a1 = 18;
  *(_QWORD *)(a1 + 32) = IopUserRundown;
}
"""
        )
        with_callees = self._plan(
            """
void __fastcall IopCompleteRequest(__int64 a1, __int64 a2, _QWORD *a3, ULONG_PTR *a4, _QWORD *a5)
{
  __int64 irp;

  irp = a1 - 120;
  IopProcessBufferedIoCompletion(irp);
  *(_BYTE *)a1 = 18;
  *(_BYTE *)(a1 + 2) = 88;
  *(_QWORD *)(a1 + 8) = KeGetCurrentThread();
  *(_QWORD *)(a1 + 32) = IopUserRundown;
  *(_QWORD *)(a1 + 40) = IopUserRundown;
  KeInsertQueueApc(a1, *(_QWORD *)(irp + 72), 0LL, 2LL, 0);
}
"""
        )

        identity = self._single_identity(
            with_callees,
            "windows.io_manager.iop_complete_request_apc",
            role="completionApc",
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.io_manager.iop_complete_request_apc"
                for item in self._identities(without_callees)
            )
        )
        self.assertEqual("KAPC", identity["structure_name"])
        self.assertEqual("completionApc", self._rename_map(with_callees).get("a1"))
        self.assertTrue(identity["suppress_layout_inference"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_layout"
                and item.get("base") == "completionApc"
                for item in with_callees.comments
            )
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_blockers"
                and item.get("base") == "completionApc"
                for item in with_callees.comments
            )
        )

    def test_irp_lifecycle_and_device_ioctl_roles(self) -> None:
        allocate_plan = self._plan(
            """
PIRP __stdcall IoAllocateIrp(CCHAR StackSize, BOOLEAN ChargeQuota)
{
  return (PIRP)IopAllocateIrpPrivate(0, StackSize, ChargeQuota);
}
"""
        )
        initialize_plan = self._plan(
            """
void __stdcall IoInitializeIrp(PIRP Irp, USHORT PacketSize, CCHAR StackSize)
{
  memset(Irp, 0, PacketSize);
  Irp->StackCount = StackSize;
}
"""
        )
        build_plan = self._plan(
            """
PIRP __stdcall IoBuildDeviceIoControlRequest(ULONG IoControlCode, PDEVICE_OBJECT DeviceObject, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, BOOLEAN InternalDeviceIoControl, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock)
{
  return (PIRP)IopBuildDeviceIoControlRequest(IoControlCode, DeviceObject, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, InternalDeviceIoControl, Event, IoStatusBlock);
}
"""
        )
        private_build_plan = self._plan(
            """
IRP *__fastcall IopBuildDeviceIoControlRequest(int IoControlCode, PDEVICE_OBJECT DeviceObject, const void *InputBuffer, unsigned int InputLength, PVOID OutputBuffer, unsigned int OutputLength, char InternalDeviceIoControl, struct _KEVENT *Event, struct _IO_STATUS_BLOCK *IoStatusBlock)
{
  IRP *Irp;

  Irp = IopAllocateIrpExReturn(DeviceObject, 4, 0);
  Irp->UserEvent = Event;
  Irp->UserIosb = IoStatusBlock;
  return Irp;
}
"""
        )
        free_plan = self._plan(
            """
void __stdcall IoFreeIrp(PIRP Irp)
{
  ExFreePoolWithTag(Irp, 0);
}
"""
        )

        allocate_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(allocate_plan, "windows.io_manager.allocate_irp")
        }
        initialize_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(initialize_plan, "windows.io_manager.initialize_irp")
        }
        build_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                build_plan,
                "windows.io_manager.build_device_io_control_request",
            )
        }
        private_build_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                private_build_plan,
                "windows.io_manager.build_device_io_control_request_private",
            )
        }
        free_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(free_plan, "windows.io_manager.free_irp")
        }

        self.assertEqual("IRP_STACK_SIZE", allocate_roles["stackSize"])
        self.assertEqual("BOOLEAN", allocate_roles["chargeQuota"])
        self.assertEqual("IRP", initialize_roles["irp"])
        self.assertEqual("IRP_PACKET_SIZE", initialize_roles["packetSize"])
        self.assertEqual("IRP_STACK_SIZE", initialize_roles["stackSize"])
        self.assertEqual("IOCTL_CODE", build_roles["ioControlCode"])
        self.assertEqual("DEVICE_OBJECT", build_roles["targetDeviceObject"])
        self.assertEqual("KEVENT", build_roles["completionEvent"])
        self.assertEqual("IO_STATUS_BLOCK", build_roles["ioStatusBlock"])
        self.assertEqual("DEVICE_OBJECT", private_build_roles["targetDeviceObject"])
        self.assertEqual("IRP", private_build_roles["allocatedIrp"])
        self.assertEqual("IRP", free_roles["irp"])

    def test_device_object_pointer_related_device_and_symbolic_link_roles(self) -> None:
        pointer_plan = self._plan(
            """
NTSTATUS __stdcall IoGetDeviceObjectPointer(PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, PFILE_OBJECT *FileObject, PDEVICE_OBJECT *DeviceObject)
{
  PVOID referencedObject;
  HANDLE fileHandle;

  ZwOpenFile(&fileHandle, DesiredAccess, 0, 0, 3, 0x40);
  ObReferenceObjectByHandle(fileHandle, 0, IoFileObjectType, 0, &referencedObject, 0);
  *FileObject = (PFILE_OBJECT)referencedObject;
  *DeviceObject = IoGetRelatedDeviceObject((PFILE_OBJECT)referencedObject);
  return STATUS_SUCCESS;
}
"""
        )
        related_plan = self._plan(
            """
PDEVICE_OBJECT __stdcall IoGetRelatedDeviceObject(PFILE_OBJECT FileObject)
{
  PDEVICE_OBJECT result;
  struct _DEVICE_OBJECT *i;

  result = FileObject->DeviceObject;
  for ( i = result->AttachedDevice; i; i = i->AttachedDevice )
  {
    result = i;
  }
  return result;
}
"""
        )
        create_link_plan = self._plan(
            """
NTSTATUS __stdcall IoCreateSymbolicLink(PUNICODE_STRING LinkName, PUNICODE_STRING DeviceName)
{
  return IoCreateSymbolicLink2(LinkName, DeviceName);
}
"""
        )
        delete_link_plan = self._plan(
            """
NTSTATUS __stdcall IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
{
  OBJECT_ATTRIBUTES ObjectAttributes;
  HANDLE LinkHandle;

  ZwOpenSymbolicLinkObject(&LinkHandle, 0x10000, &ObjectAttributes);
  return ZwMakeTemporaryObject(LinkHandle);
}
"""
        )

        pointer_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                pointer_plan,
                "windows.io_manager.get_device_object_pointer",
            )
        }
        related_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                related_plan,
                "windows.io_manager.get_related_device_object",
            )
        }
        create_link_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                create_link_plan,
                "windows.io_manager.create_symbolic_link",
            )
        }
        delete_link_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                delete_link_plan,
                "windows.io_manager.delete_symbolic_link",
            )
        }

        self.assertEqual("UNICODE_STRING", pointer_roles["objectName"])
        self.assertEqual("ACCESS_MASK", pointer_roles["desiredAccess"])
        self.assertEqual("FILE_OBJECT_OUTPUT", pointer_roles["fileObjectOutput"])
        self.assertEqual("DEVICE_OBJECT_OUTPUT", pointer_roles["deviceObjectOutput"])
        self.assertEqual("FILE_OBJECT", pointer_roles["referencedFileObject"])
        self.assertEqual("FILE_OBJECT", related_roles["fileObject"])
        self.assertEqual("DEVICE_OBJECT", related_roles["relatedDeviceObject"])
        self.assertEqual("UNICODE_STRING", create_link_roles["symbolicLinkName"])
        self.assertEqual("UNICODE_STRING", create_link_roles["targetDeviceName"])
        self.assertEqual("UNICODE_STRING", delete_link_roles["symbolicLinkName"])
        self.assertEqual("HANDLE", delete_link_roles["symbolicLinkHandle"])
        self.assertEqual("OBJECT_ATTRIBUTES", delete_link_roles["objectAttributes"])

    def test_driver_create_delete_and_reinit_roles(self) -> None:
        create_plan = self._plan(
            """
__int64 __fastcall IoCreateDriver(_OWORD *DriverName, unsigned __int64 DriverInit)
{
  struct _FILE_OBJECT *pDriverFileObject;
  PVOID pReferencedDriverObj;
  HANDLE hInsertedObj;

  ObCreateObjectEx(0, IoDriverObjectType, 0, 0, 0, 424, 0, 0, &pDriverFileObject, 0);
  ObInsertObjectEx(pDriverFileObject, 0, 1, 0, 0, 0, (__int64)&hInsertedObj);
  ObReferenceObjectByHandle(hInsertedObj, 0, IoDriverObjectType, 0, &pReferencedDriverObj, 0);
  return guard_dispatch_icall_no_overrides(pReferencedDriverObj, DriverInit);
}
"""
        )
        delete_plan = self._plan(
            """
LONG_PTR __fastcall IoDeleteDriver(PDRIVER_OBJECT DriverObject)
{
  ObMakeTemporaryObject(DriverObject);
  return ObfDereferenceObject(DriverObject);
}
"""
        )
        reinit_plan = self._plan(
            """
void __stdcall IoRegisterDriverReinitialization(PDRIVER_OBJECT DriverObject, PDRIVER_REINITIALIZE DriverReinitializationRoutine, PVOID Context)
{
  _QWORD *Pool2;

  Pool2 = (_QWORD *)ExAllocatePool2(0x40, 0x28, 0x69526F49);
  Pool2[2] = DriverObject;
  Pool2[3] = DriverReinitializationRoutine;
  Pool2[4] = Context;
  IopInterlockedInsertTailList((__int64)&IopDriverReinitializeQueueHead, Pool2);
}
"""
        )

        create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(create_plan, "windows.io_manager.create_driver")
        }
        delete_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(delete_plan, "windows.io_manager.delete_driver")
        }
        reinit_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                reinit_plan,
                "windows.io_manager.register_driver_reinitialization",
            )
        }

        self.assertEqual("UNICODE_STRING", create_roles["driverName"])
        self.assertEqual("DRIVER_INITIALIZE", create_roles["driverInitialize"])
        self.assertEqual("DRIVER_OBJECT", create_roles["driverObject"])
        self.assertEqual("HANDLE", create_roles["driverHandle"])
        self.assertEqual("DRIVER_OBJECT", delete_roles["driverObject"])
        self.assertEqual("DRIVER_OBJECT", reinit_roles["driverObject"])
        self.assertEqual("DRIVER_REINITIALIZE", reinit_roles["driverReinitializationRoutine"])
        self.assertEqual("DRIVER_REINIT_CONTEXT", reinit_roles["driverReinitContext"])
        self.assertEqual("IO_DRIVER_REINIT_ENTRY", reinit_roles["driverReinitQueueEntry"])

    def test_connect_interrupt_context_body_identity_promotes_internal_helper(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall sub_140506ED0(__int64 a1, __int64 a2)
{
  ULONG_PTR numberOfBytes;
  char *Pool2;
  __int64 v2;

  if ( *(_QWORD *)a1 < 0x40uLL
    || *(_DWORD *)(a1 + 8) != (unsigned int)KiGetNtDdiVersion()
    || *(_DWORD *)(a1 + 12)
    || (*(_DWORD *)(a1 + 20) & 0x7FFFFFFE) != 0
    || *(_QWORD *)(a1 + 24)
    || *(_QWORD *)(a1 + 32)
    || *(_QWORD *)(a1 + 40) )
  {
    return STATUS_INVALID_PARAMETER;
  }
  numberOfBytes = *(unsigned int *)(a1 + 16);
  v2 = *(unsigned int *)(a1 + 48) + *(unsigned int *)(a1 + 52);
  if ( (_DWORD)v2 == 16 && KeVerifyGroupAffinity(*(_QWORD *)(a1 + 56), 0) )
  {
    Pool2 = (char *)ExAllocatePool2(POOL_FLAG_NON_PAGED, numberOfBytes, POOL_TAG('K', 'I', 'n', 't'));
    return *(_DWORD *)(a1 + 20) + *(_QWORD *)(a1 + 56) + (unsigned __int64)Pool2;
  }
  return *(_DWORD *)(a1 + 16);
}
"""
        )

        rename_map = self._rename_map(plan)
        identity = self._single_identity(
            plan,
            "windows.io_manager.connect_interrupt_ex_context",
            role="connectInterruptParameters",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "connectInterruptParameters"
        ]
        ready = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_ready"
            and item.get("base") == "connectInterruptParameters"
        ]
        previews = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_preview"
            and item.get("base") == "connectInterruptParameters"
        ]

        self.assertEqual("connectInterruptParameters", rename_map["a1"])
        self.assertEqual("connectInterruptParameters", identity["base"])
        self.assertEqual("IO_CONNECT_INTERRUPT_PARAMETERS", identity["structure_name"])
        self.assertEqual("canonical-rewrite-eligible", identity["effective_mode"])
        self.assertTrue(
            any(field.get("name") == "field_38" and field.get("offset") == 0x38 for field in identity["fields"])
        )
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("domain_identity", ready[0]["source_provenance"])
        self.assertEqual("windows.io_manager.connect_interrupt_ex_context", ready[0]["domain_profile_id"])
        self.assertEqual(1, len(previews))
        self.assertIn("field_8", previews[0]["text"])

    def test_report_only_device_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __stdcall IoDeleteDevice(__int64 deviceObject)
{
  __int64 probe;

  probe = *(_QWORD *)(deviceObject + 16)
        + *(_QWORD *)(deviceObject + 24)
        + *(_QWORD *)(deviceObject + 32)
        + *(_QWORD *)(deviceObject + 40)
        + *(_QWORD *)(deviceObject + 48)
        + *(_QWORD *)(deviceObject + 56)
        + *(_QWORD *)(deviceObject + 64)
        + *(_QWORD *)(deviceObject + 72)
        + *(_QWORD *)(deviceObject + 16)
        + *(_QWORD *)(deviceObject + 24)
        + *(_QWORD *)(deviceObject + 32)
        + *(_QWORD *)(deviceObject + 40);
  IopCompleteUnloadOrDelete((ULONG_PTR)deviceObject + probe);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.io_manager.delete_device",
            "deviceObject",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "deviceObject"
        ]

        self.assertEqual("DEVICE_OBJECT", identity["structure_name"])
        self.assertEqual("deviceObject", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "deviceObject"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __stdcall IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
  IopCompleteUnloadOrDelete((ULONG_PTR)DeviceObject);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.io_manager.delete_device",
            role="deviceObject",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertEqual(1, len(plan.type_corrections))
        self.assertIn("build_mismatch", plan.type_corrections[0].blockers)
        self.assertFalse(plan.type_corrections[0].apply_to_preview)

    def test_accepted_type_guard_blocks_wrong_driver_object_type(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall IoCreateDevice(int DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, ULONG DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)
{
  return STATUS_SUCCESS;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.io_manager.create_device"
                and item["trusted_role"] == "driverObject"
                for item in self._identities(plan)
            )
        )

    def test_io_manager_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __stdcall IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
  IopCompleteUnloadOrDelete((ULONG_PTR)DeviceObject);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/io_manager.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _rename_map(self, plan) -> dict[str, str]:
        return {item.old: item.new for item in plan.renames if item.apply}

    def _single_identity(
        self,
        plan,
        profile_id: str,
        role: str = "",
    ) -> dict[str, object]:
        identities = self._profile_identities(plan, profile_id)
        if role:
            identities = [item for item in identities if item.get("trusted_role") == role]
        self.assertEqual(1, len(identities))
        return identities[0]

    def _identity_for_base(self, plan, profile_id: str, base: str) -> dict[str, object]:
        identities = [
            item
            for item in self._identities(plan)
            if item.get("profile_id") == profile_id and item.get("base") == base
        ]
        self.assertEqual(1, len(identities))
        return identities[0]
