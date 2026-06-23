from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class PnpPowerDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_invalidate_device_state_and_relations_roles(self) -> None:
        state_plan = self._plan(
            """
void __stdcall IoInvalidateDeviceState(PDEVICE_OBJECT PhysicalDeviceObject)
{
  PDEVICE_NODE deviceNode;
  PDRIVER_OBJECT driverObject;

  deviceNode = PhysicalDeviceObject->DeviceObjectExtension->DeviceNode;
  driverObject = PhysicalDeviceObject->DriverObject;
  PnpRequestDeviceAction(PhysicalDeviceObject, 0, 0, 0, driverObject, 0, 0);
}
"""
        )
        relations_plan = self._plan(
            """
void __stdcall IoInvalidateDeviceRelations(PDEVICE_OBJECT DeviceObject, DEVICE_RELATION_TYPE Type)
{
  PDEVICE_NODE deviceNodePtr;

  deviceNodePtr = DeviceObject->DeviceObjectExtension->DeviceNode;
  IopQueueInvalidateBusRelationsRequest(DeviceObject);
  PnpRequestDeviceAction(DeviceObject, Type, 0, deviceNodePtr, 0, 0, 0);
}
"""
        )

        state_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                state_plan,
                "windows.pnp_power.invalidate_device_state",
            )
        }
        relations_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                relations_plan,
                "windows.pnp_power.invalidate_device_relations",
            )
        }

        self.assertEqual("DEVICE_OBJECT", state_roles["physicalDeviceObject"])
        self.assertEqual("DEVICE_NODE", state_roles["deviceNode"])
        self.assertEqual("DRIVER_OBJECT", state_roles["driverObject"])
        self.assertEqual("DEVICE_OBJECT", relations_roles["deviceObject"])
        self.assertEqual("DEVICE_RELATION_TYPE", relations_roles["relationType"])
        self.assertEqual("DEVICE_NODE", relations_roles["deviceNode"])

    def test_request_device_action_roles(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall PnpRequestDeviceAction(PDEVICE_OBJECT DeviceObject, PNP_DEVICE_ACTION Action, unsigned char Flags, PVOID ActionData, PVOID Callback, PVOID Context, PVOID *ActionEntry)
{
  PNP_DEVICE_ACTION_ENTRY *newProviderRecord;

  newProviderRecord = (PNP_DEVICE_ACTION_ENTRY *)ExAllocatePool2(0x100, 0x58, 0x326E7050);
  ObfReferenceObjectWithTag(DeviceObject, 0x326E7050);
  *ActionEntry = newProviderRecord;
  return Flags + (unsigned __int64)ActionData + Action;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.pnp_power.request_device_action",
            )
        }

        self.assertEqual("DEVICE_OBJECT", roles["targetDeviceObject"])
        self.assertEqual("PNP_DEVICE_ACTION", roles["deviceAction"])
        self.assertEqual("PNP_DEVICE_ACTION_FLAGS", roles["actionFlags"])
        self.assertEqual("PNP_DEVICE_ACTION_DATA", roles["actionData"])
        self.assertEqual("PNP_DEVICE_ACTION_ENTRY_OUTPUT", roles["actionEntryOutput"])
        self.assertEqual("PNP_DEVICE_ACTION_ENTRY", roles["deviceActionEntry"])
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in self._profile_identities(plan, "windows.pnp_power.request_device_action")))

    def test_popfx_current_component_perf_state_corrects_weak_parameter_types(self) -> None:
        capture = capture_from_pseudocode(
            """
_BYTE *__fastcall PopFxQueryCurrentComponentPerfState(__int64 a1, __int64 a2, unsigned int a3, char a4, _QWORD *a5, _BYTE *a6)
{
  __int64 query;
  query = *(_QWORD *)(a1 + 64);
  if ( query )
  {
    guard_dispatch_icall_no_overrides(34, &query);
  }
  *a5 = *(_QWORD *)(a2 + 32 * a3 + 8);
  *a6 = a4 != 0;
  return a6;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.pnp_power.popfx_query_current_component_perf_state"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identities = self._profile_identities(plan, profile_id)

        self.assertEqual(6, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertTrue(all(not item.apply_to_idb for item in corrections))
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
        self.assertEqual([], plan.corrected_parameter_map)
        for fragment in [
            "PPOP_FX_DEVICE device",
            "PPOP_FX_COMPONENT component",
            "ULONG perfStateUnit",
            "BOOLEAN updateReason",
            "PULONG64 currentPerfState",
            "PBOOLEAN changed",
        ]:
            self.assertIn(fragment, rendered)

    def test_device_node_allocation_and_state_roles(self) -> None:
        allocate_plan = self._plan(
            """
NTSTATUS __fastcall PipAllocateDeviceNode(PDEVICE_NODE ParentNode, PDEVICE_NODE *DeviceNode)
{
  PDEVICE_NODE newProviderRecord;

  newProviderRecord = (PDEVICE_NODE)ExAllocatePool2(0x100, 0x300, 0x646F6E44);
  *DeviceNode = newProviderRecord;
  return ParentNode ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
"""
        )
        state_plan = self._plan(
            """
void __fastcall PipSetDevNodeState(PDEVICE_NODE deviceNode, PNP_DEVNODE_STATE newDevNodeState)
{
  PNP_DRIVER_LOAD_STATE driverListPtr;

  driverListPtr = deviceNode->State;
  PnpRemoveDeviceActionRequests(deviceNode, newDevNodeState);
}
"""
        )

        allocate_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                allocate_plan,
                "windows.pnp_power.allocate_device_node",
            )
        }
        state_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                state_plan,
                "windows.pnp_power.set_devnode_state",
            )
        }

        self.assertEqual("DEVICE_NODE", allocate_roles["parentDeviceNode"])
        self.assertEqual("DEVICE_NODE_OUTPUT", allocate_roles["deviceNodeOutput"])
        self.assertEqual("DEVICE_NODE", allocate_roles["allocatedDeviceNode"])
        self.assertEqual("DEVICE_NODE", state_roles["deviceNode"])
        self.assertEqual("PNP_DEVNODE_STATE", state_roles["newDevNodeState"])
        self.assertEqual("PNP_DRIVER_LOAD_STATE", state_roles["devNodeDriverState"])

    def test_start_query_and_requery_roles(self) -> None:
        start_plan = self._plan(
            """
NTSTATUS __fastcall PnpStartDevice(PIRP StartIrp, POWER_STATE TargetState)
{
  PDEVICE_OBJECT deviceObject;
  IO_STACK_LOCATION stateCode;

  deviceObject = IoGetCurrentIrpStackLocation(StartIrp)->DeviceObject;
  PoFxPrepareDevice(deviceObject);
  return PnpSendIrp(deviceObject, &stateCode, TargetState);
}
"""
        )
        relations_plan = self._plan(
            """
NTSTATUS __fastcall PnpQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, DEVICE_RELATION_TYPE Type, PVOID Context, PIO_COMPLETION_ROUTINE CompletionRoutine)
{
  IO_STACK_LOCATION requestRelationCode;

  requestRelationCode.MinorFunction = Type;
  return PnpSendIrp(DeviceObject, &requestRelationCode, Context, CompletionRoutine);
}
"""
        )
        requery_plan = self._plan(
            """
void __fastcall PiProcessRequeryDeviceState(PVOID ActionEntry)
{
  PDEVICE_NODE v3;
  PDEVICE_NODE v9;

  v3 = ((PPNP_DEVICE_ACTION_ENTRY)ActionEntry)->DeviceNode;
  v9 = v3;
  PiProcessQueryDeviceState(v9, 0);
}
"""
        )
        query_state_plan = self._plan(
            """
NTSTATUS __fastcall PiProcessQueryDeviceState(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
  PDEVICE_NODE v5;
  IO_STACK_LOCATION v15;

  v5 = DeviceObject->DeviceObjectExtension->DeviceNode;
  return IopSynchronousCall(DeviceObject, &v15, Context, v5);
}
"""
        )

        start_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(start_plan, "windows.pnp_power.start_device")
        }
        relations_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                relations_plan,
                "windows.pnp_power.query_device_relations",
            )
        }
        requery_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                requery_plan,
                "windows.pnp_power.process_requery_device_state",
            )
        }
        query_state_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                query_state_plan,
                "windows.pnp_power.process_query_device_state",
            )
        }

        self.assertEqual("IRP", start_roles["startIrp"])
        self.assertEqual("POWER_STATE", start_roles["targetPowerState"])
        self.assertEqual("DEVICE_OBJECT", start_roles["deviceObject"])
        self.assertEqual("IO_STACK_LOCATION", start_roles["pnpIrpStackTemplate"])
        self.assertEqual("DEVICE_OBJECT", relations_roles["deviceObject"])
        self.assertEqual("DEVICE_RELATION_TYPE", relations_roles["relationType"])
        self.assertEqual("PNP_SEND_IRP_CONTEXT", relations_roles["irpContext"])
        self.assertEqual("IO_COMPLETION_ROUTINE", relations_roles["completionRoutine"])
        self.assertEqual("IO_STACK_LOCATION", relations_roles["pnpIrpStackTemplate"])
        self.assertEqual("PNP_DEVICE_ACTION_ENTRY", requery_roles["deviceActionEntry"])
        self.assertEqual("DEVICE_NODE", requery_roles["deviceNode"])
        self.assertEqual("DEVICE_OBJECT", query_state_roles["deviceObject"])
        self.assertEqual("PNP_SEND_IRP_CONTEXT", query_state_roles["irpStackContext"])
        self.assertEqual("DEVICE_NODE", query_state_roles["deviceNode"])
        self.assertEqual("IO_STACK_LOCATION", query_state_roles["pnpIrpStackTemplate"])

    def test_pi_devcfg_configure_device_context_role(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall PiDevCfgConfigureDevice(__int64 DeviceNode, __int64 DeviceInfo, __int64 a3, int *Result, _DWORD *Flags)
{
  __int64 listHead;
  __int64 entry;
  PCWSTR devicePath;

  if ( !a3 )
    return STATUS_INVALID_PARAMETER;
  devicePath = *(PCWSTR *)(a3 + 48);
  if ( devicePath && *(unsigned __int16 *)(a3 + 40) )
    PiDevCfgSetObjectProperty(PiPnpRtlCtx, DeviceInfo, devicePath, 1, DeviceNode);
  PiDevCfgBuildIndirectString(a3, 0, 0, 0);
  PiDevCfgConfigureDeviceDriver(DeviceNode, DeviceInfo, a3, Result, Flags);
  PiDevCfgQueryDriverConfiguration(a3);
  listHead = a3 + 208;
  for ( entry = *(_QWORD *)(a3 + 208); entry != listHead; entry = *(_QWORD *)entry )
    PiDevCfgSetObjectProperty(PiPnpRtlCtx, DeviceInfo, *(PCWSTR *)(a3 + 48), 1, entry);
  return STATUS_SUCCESS;
}
"""
        )

        identity = self._single_identity(
            plan,
            "windows.pnp_power.pi_devcfg_configure_device",
            role="devCfgContext",
        )
        rename_map = self._rename_map(plan)

        self.assertEqual("PI_DEVCFG_CONTEXT", identity["structure_name"])
        self.assertEqual("devCfgContext", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual("devCfgContext", rename_map.get("a3"))

    def test_request_device_eject_roles(self) -> None:
        wrapper_plan = self._plan(
            """
void __stdcall IoRequestDeviceEject(PDEVICE_OBJECT PhysicalDeviceObject)
{
  IoRequestDeviceEjectEx(PhysicalDeviceObject, 0, 0, 0);
}
"""
        )
        ex_plan = self._plan(
            """
NTSTATUS __stdcall IoRequestDeviceEjectEx(PDEVICE_OBJECT PhysicalDeviceObject, PIO_DEVICE_EJECT_CALLBACK Callback, PVOID Context, PDRIVER_OBJECT DriverObject)
{
  PDEVICE_NODE DeviceNode;
  PNP_EJECT_WORK_ITEM *newProviderRecord;

  DeviceNode = PhysicalDeviceObject->DeviceObjectExtension->DeviceNode;
  newProviderRecord = (PNP_EJECT_WORK_ITEM *)ExAllocatePool2(0x100, 0x80, 0x46706E50);
  newProviderRecord->DriverObject = DriverObject;
  ExQueueWorkItem((PWORK_QUEUE_ITEM)PnpRequestDeviceEjectExWorker, 0);
  return (NTSTATUS)((unsigned __int64)Callback + (unsigned __int64)Context + (unsigned __int64)DeviceNode);
}
"""
        )

        wrapper_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                wrapper_plan,
                "windows.pnp_power.request_device_eject",
            )
        }
        ex_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                ex_plan,
                "windows.pnp_power.request_device_eject_ex",
            )
        }

        self.assertEqual("DEVICE_OBJECT", wrapper_roles["physicalDeviceObject"])
        self.assertEqual("DEVICE_OBJECT", ex_roles["physicalDeviceObject"])
        self.assertEqual("IO_DEVICE_EJECT_CALLBACK", ex_roles["ejectCallback"])
        self.assertEqual("PNP_EJECT_CONTEXT", ex_roles["ejectContext"])
        self.assertEqual("DRIVER_OBJECT", ex_roles["driverObject"])
        self.assertEqual("DEVICE_NODE", ex_roles["deviceNode"])
        self.assertEqual("PNP_EJECT_WORK_ITEM", ex_roles["ejectWorkItem"])

    def test_eject_worker_and_iop_eject_roles(self) -> None:
        worker_plan = self._plan(
            """
void __fastcall PnpRequestDeviceEjectExWorker(PVOID WorkItem)
{
  UNICODE_STRING DestinationString;

  RtlInitUnicodeString(&DestinationString, L"ROOT\\\\TEST");
  PnpQueueQueryAndRemoveEvent(&DestinationString, WorkItem);
  ExFreePoolWithTag(WorkItem, 0x46706E50);
}
"""
        )
        eject_plan = self._plan(
            """
NTSTATUS __fastcall IopEjectDevice(PDEVICE_OBJECT PhysicalDeviceObject, PVOID Context)
{
  PDEVICE_OBJECT AttachedDeviceReferenceWithTag;
  PIRP Irp;
  PIO_STACK_LOCATION CurrentStackLocation;

  AttachedDeviceReferenceWithTag = IoGetAttachedDeviceReference(PhysicalDeviceObject);
  Irp = IoAllocateIrp(AttachedDeviceReferenceWithTag->StackSize, 0);
  CurrentStackLocation = IoGetNextIrpStackLocation(Irp);
  PnpQueuePendingEject(PhysicalDeviceObject, Context);
  return IofCallDriver(AttachedDeviceReferenceWithTag, Irp);
}
"""
        )

        worker_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                worker_plan,
                "windows.pnp_power.request_device_eject_worker",
            )
        }
        eject_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(eject_plan, "windows.pnp_power.eject_device")
        }

        self.assertEqual("PNP_EJECT_WORK_ITEM", worker_roles["ejectWorkItem"])
        self.assertEqual("UNICODE_STRING", worker_roles["deviceInstanceName"])
        self.assertEqual("DEVICE_OBJECT", eject_roles["physicalDeviceObject"])
        self.assertEqual("PNP_EJECT_CONTEXT", eject_roles["ejectContext"])
        self.assertEqual("DEVICE_OBJECT", eject_roles["attachedDeviceObject"])
        self.assertEqual("IRP", eject_roles["ejectIrp"])
        self.assertEqual("IO_STACK_LOCATION", eject_roles["currentStackLocation"])

    def test_power_irp_roles(self) -> None:
        request_plan = self._plan(
            """
NTSTATUS __stdcall PoRequestPowerIrp(PDEVICE_OBJECT DeviceObject, UCHAR MinorFunction, POWER_STATE PowerState, PREQUEST_POWER_COMPLETE CompletionFunction, PVOID Context, PIRP *Irp)
{
  return PopRequestPowerIrp(DeviceObject, MinorFunction, PowerState, CompletionFunction, Context, 0, Irp);
}
"""
        )
        pop_plan = self._plan(
            """
NTSTATUS __fastcall PopRequestPowerIrp(PDEVICE_OBJECT DeviceObject, UCHAR MinorFunction, POWER_STATE PowerState, PREQUEST_POWER_COMPLETE CompletionFunction, PVOID Context, PVOID Extra, PIRP *IrpOut)
{
  PIRP v13;

  v13 = PopAllocateIrp(DeviceObject);
  *IrpOut = v13;
  return (NTSTATUS)((unsigned __int64)CompletionFunction + (unsigned __int64)Context + (unsigned __int64)Extra);
}
"""
        )
        call_plan = self._plan(
            """
NTSTATUS __stdcall PoCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  return IofCallDriver(DeviceObject, Irp);
}
"""
        )
        state_plan = self._plan(
            """
POWER_STATE __stdcall PoSetPowerState(PDEVICE_OBJECT DeviceObject, POWER_STATE_TYPE Type, POWER_STATE State)
{
  PDEVOBJ_EXTENSION deviceObjectExtension;

  deviceObjectExtension = DeviceObject->DeviceObjectExtension;
  deviceObjectExtension->PowerState = State;
  return State;
}
"""
        )
        dispatch_plan = self._plan(
            """
NTSTATUS __fastcall IopPowerDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PIO_STACK_LOCATION currentStackLocation;

  currentStackLocation = IoGetCurrentIrpStackLocation(Irp);
  IofCompleteRequest(Irp, 0);
  return currentStackLocation->MinorFunction + (unsigned __int64)DeviceObject;
}
"""
        )

        request_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(request_plan, "windows.pnp_power.request_power_irp")
        }
        pop_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(pop_plan, "windows.pnp_power.pop_request_power_irp")
        }
        call_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(call_plan, "windows.pnp_power.po_call_driver")
        }
        state_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(state_plan, "windows.pnp_power.set_power_state")
        }
        dispatch_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(dispatch_plan, "windows.pnp_power.power_dispatch")
        }

        self.assertEqual("DEVICE_OBJECT", request_roles["deviceObject"])
        self.assertEqual("POWER_IRP_MINOR_FUNCTION", request_roles["powerMinorFunction"])
        self.assertEqual("POWER_STATE", request_roles["powerState"])
        self.assertEqual("REQUEST_POWER_COMPLETE", request_roles["completionFunction"])
        self.assertEqual("POWER_IRP_CONTEXT", request_roles["completionContext"])
        self.assertEqual("IRP_OUTPUT", request_roles["powerIrpOutput"])
        self.assertEqual("DEVICE_OBJECT", pop_roles["deviceObject"])
        self.assertEqual("POWER_IRP_MINOR_FUNCTION", pop_roles["powerMinorFunction"])
        self.assertEqual("POWER_STATE", pop_roles["powerState"])
        self.assertEqual("IRP_OUTPUT", pop_roles["powerIrpOutput"])
        self.assertEqual("IRP", pop_roles["powerIrp"])
        self.assertEqual("DEVICE_OBJECT", call_roles["deviceObject"])
        self.assertEqual("IRP", call_roles["irp"])
        self.assertEqual("DEVICE_OBJECT", state_roles["deviceObject"])
        self.assertEqual("POWER_STATE_TYPE", state_roles["powerStateType"])
        self.assertEqual("POWER_STATE", state_roles["powerState"])
        self.assertEqual("DEVOBJ_EXTENSION", state_roles["deviceObjectExtension"])
        self.assertEqual("DEVICE_OBJECT", dispatch_roles["deviceObject"])
        self.assertEqual("IRP", dispatch_roles["irp"])
        self.assertEqual("IO_STACK_LOCATION", dispatch_roles["currentStackLocation"])

    def test_report_only_pnp_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __fastcall PipSetDevNodeState(__int64 deviceNode, int newDevNodeState)
{
  __int64 probe;

  probe = *(_QWORD *)(deviceNode + 16)
        + *(_QWORD *)(deviceNode + 24)
        + *(_QWORD *)(deviceNode + 32)
        + *(_QWORD *)(deviceNode + 40)
        + *(_QWORD *)(deviceNode + 48)
        + *(_QWORD *)(deviceNode + 56)
        + *(_QWORD *)(deviceNode + 64)
        + *(_QWORD *)(deviceNode + 72)
        + *(_QWORD *)(deviceNode + 16)
        + *(_QWORD *)(deviceNode + 24)
        + *(_QWORD *)(deviceNode + 32)
        + *(_QWORD *)(deviceNode + 40);
  PnpRemoveDeviceActionRequests(deviceNode, newDevNodeState + probe);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.pnp_power.set_devnode_state",
            "deviceNode",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "deviceNode"
        ]

        self.assertEqual("DEVICE_NODE", identity["structure_name"])
        self.assertEqual("deviceNode", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "deviceNode"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __fastcall PipSetDevNodeState(__int64 deviceNode, int newDevNodeState)
{
  PnpRemoveDeviceActionRequests(deviceNode, newDevNodeState);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.pnp_power.set_devnode_state",
            role="deviceNode",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_device_type(self) -> None:
        plan = self._plan(
            """
void __stdcall IoInvalidateDeviceState(int PhysicalDeviceObject)
{
  PnpRequestDeviceAction(PhysicalDeviceObject, 0, 0, 0, 0, 0, 0);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.pnp_power.invalidate_device_state"
                and item["trusted_role"] == "physicalDeviceObject"
                for item in self._identities(plan)
            )
        )

    def test_pnp_power_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __fastcall PipSetDevNodeState(__int64 deviceNode, int newDevNodeState)
{
  PnpRemoveDeviceActionRequests(deviceNode, newDevNodeState);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/pnp_power.json" for item in manifests)
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
