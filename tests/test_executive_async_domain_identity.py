from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ExecutiveAsyncDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_public_work_item_queue_roles(self) -> None:
        queue_plan = self._plan(
            """
void __stdcall ExQueueWorkItem(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType)
{
  ULONG_PTR originalQueueType;
  struct _KPRCB *currentPrcb;

  originalQueueType = QueueType;
  currentPrcb = KeGetCurrentPrcb();
  EtwTracePriQEnqueueWork(WorkItem, originalQueueType);
  KeSetEvent((PRKEVENT)currentPrcb, 0, 0);
}
"""
        )
        queue_ex_plan = self._plan(
            """
__int64 __fastcall ExQueueWorkItemEx(_QWORD *workItemPtr, unsigned int workItemType, unsigned int flags)
{
  unsigned int priority;

  ExpValidateWorkItem(workItemPtr, workItemType);
  priority = ExpTypeToPriority(workItemType);
  return ExpQueueWorkItem(ExpWorkerQueue, workItemPtr, priority, 0, flags);
}
"""
        )
        try_queue_plan = self._plan(
            """
__int64 __fastcall ExTryQueueWorkItem(__int64 workItemPtr, unsigned int queueType)
{
  return ExpTryQueueWorkItem(ExpWorkerQueue, (PWORK_QUEUE_ITEM)workItemPtr, queueType, 0);
}
"""
        )

        queue_roles = self._roles(queue_plan, "windows.executive_async.ex_queue_work_item")
        queue_ex_roles = self._roles(queue_ex_plan, "windows.executive_async.ex_queue_work_item_ex")
        try_queue_roles = self._roles(try_queue_plan, "windows.executive_async.ex_try_queue_work_item")

        self.assertEqual("WORK_QUEUE_ITEM", queue_roles["workItem"])
        self.assertEqual("WORK_QUEUE_TYPE", queue_roles["queueType"])
        self.assertEqual("WORK_QUEUE_TYPE", queue_roles["originalQueueType"])
        self.assertEqual("KPRCB", queue_roles["currentPrcb"])
        self.assertEqual("WORK_QUEUE_ITEM", queue_ex_roles["workItem"])
        self.assertEqual("WORK_QUEUE_TYPE", queue_ex_roles["workItemType"])
        self.assertEqual("WORK_QUEUE_FLAGS", queue_ex_roles["queueFlags"])
        self.assertEqual("WORK_QUEUE_PRIORITY", queue_ex_roles["priority"])
        self.assertEqual("WORK_QUEUE_ITEM", try_queue_roles["workItem"])
        self.assertEqual("WORK_QUEUE_TYPE", try_queue_roles["queueType"])

    def test_private_work_item_worker_roles(self) -> None:
        exp_queue_plan = self._plan(
            """
__int64 __fastcall ExpQueueWorkItem(__int64 queue_object_ptr, _QWORD *work_item_entry, unsigned int priority, unsigned int starting_node_idx, int thread_slot_offset)
{
  __int64 target_dispatcher_header;
  _LIST_ENTRY *wait_list_head_ptr;

  EtwTracePriQEnqueueWork(work_item_entry, priority);
  target_dispatcher_header = queue_object_ptr + 8;
  wait_list_head_ptr = (_LIST_ENTRY *)(queue_object_ptr + 16);
  KiWakePriQueueWaiter(target_dispatcher_header, wait_list_head_ptr);
  return thread_slot_offset + starting_node_idx;
}
"""
        )
        exp_try_plan = self._plan(
            """
char __fastcall ExpTryQueueWorkItem(__int64 queueObject, _QWORD *workItemEntry, int priority, int nodeIndex)
{
  unsigned __int8 currentIrql;

  currentIrql = KeGetCurrentIrql();
  EtwTracePriQEnqueueWork(workItemEntry, priority);
  ExpPartitionCreateThreadIfNecessary(queueObject, nodeIndex);
  return currentIrql != 0;
}
"""
        )
        validate_plan = self._plan(
            """
__int64 __fastcall ExpValidateWorkItem(_QWORD *workItem, int queueType)
{
  if ( !workItem )
  {
    KeBugCheckEx(0x96u, (ULONG_PTR)workItem, queueType, 0, 0);
  }
  return queueType;
}
"""
        )
        worker_plan = self._plan(
            """
LONG __fastcall ExpWorkerThread(ULONG_PTR workerContext)
{
  struct _KTHREAD *currentThread;
  struct _IO_WORKITEM *v16;
  ULONG_PTR BugCheckParameter4;

  currentThread = KeGetCurrentThread();
  BugCheckParameter4 = workerContext;
  v16 = (struct _IO_WORKITEM *)KeRemovePriQueue(workerContext, 0, 0);
  EtwTraceThreadWorkItem(v16, currentThread);
  guard_dispatch_icall_no_overrides(BugCheckParameter4);
  return 0;
}
"""
        )
        check_plan = self._plan(
            """
_QWORD *__fastcall ExpCheckForWorker(ULONG_PTR partition, __int64 queueContext)
{
  PsGetNextPartition(partition);
  KiAcquireKobjectLockSafe(queueContext);
  return 0;
}
"""
        )
        create_plan = self._plan(
            """
__int64 __fastcall ExpCreateWorkerThread(__int64 workerNode, int workerFlags)
{
  HANDLE Handle;
  PVOID referencedObject;

  ExpNodeCreateSystemThread(workerNode, workerFlags, &Handle);
  ObReferenceObjectByHandle(Handle, 0, 0, 0, &referencedObject, 0);
  KeBoostPriorityThread(referencedObject, 1);
  ObfDereferenceObject(referencedObject);
  ZwClose(Handle);
  return 0;
}
"""
        )

        exp_queue_roles = self._roles(exp_queue_plan, "windows.executive_async.exp_queue_work_item")
        exp_try_roles = self._roles(exp_try_plan, "windows.executive_async.exp_try_queue_work_item")
        validate_roles = self._roles(validate_plan, "windows.executive_async.exp_validate_work_item")
        worker_roles = self._roles(worker_plan, "windows.executive_async.exp_worker_thread")
        check_roles = self._roles(check_plan, "windows.executive_async.exp_check_for_worker")
        create_roles = self._roles(create_plan, "windows.executive_async.exp_create_worker_thread")

        self.assertEqual("KPRIQUEUE", exp_queue_roles["queueObject"])
        self.assertEqual("WORK_QUEUE_ITEM", exp_queue_roles["workItemEntry"])
        self.assertEqual("WORK_QUEUE_PRIORITY", exp_queue_roles["priority"])
        self.assertEqual("WORK_QUEUE_NODE_INDEX", exp_queue_roles["startingNodeIndex"])
        self.assertEqual("WORK_QUEUE_THREAD_SLOT_OFFSET", exp_queue_roles["threadSlotOffset"])
        self.assertEqual("DISPATCHER_HEADER", exp_queue_roles["targetDispatcherHeader"])
        self.assertEqual("LIST_ENTRY", exp_queue_roles["waitListHead"])
        self.assertEqual("KPRIQUEUE", exp_try_roles["queueObject"])
        self.assertEqual("WORK_QUEUE_ITEM", exp_try_roles["workItemEntry"])
        self.assertEqual("KIRQL", exp_try_roles["currentIrql"])
        self.assertEqual("WORK_QUEUE_ITEM", validate_roles["workItem"])
        self.assertEqual("WORK_QUEUE_TYPE", validate_roles["queueType"])
        self.assertEqual("WORK_QUEUE_THREAD_CONTEXT", worker_roles["workerContext"])
        self.assertEqual("ETHREAD", worker_roles["currentThread"])
        self.assertEqual("IO_WORKITEM", worker_roles["ioWorkItem"])
        self.assertEqual("WORK_QUEUE_ITEM_CONTEXT", worker_roles["workerRoutineContext"])
        self.assertEqual("EPARTITION", check_roles["partition"])
        self.assertEqual("WORK_QUEUE_CONTEXT", check_roles["queueContext"])
        self.assertEqual("WORK_QUEUE_NODE", create_roles["workerNode"])
        self.assertEqual("HANDLE", create_roles["threadHandle"])
        self.assertEqual("ETHREAD", create_roles["threadObject"])

    def test_dpc_roles(self) -> None:
        initialize_plan = self._plan(
            """
void __stdcall KeInitializeDpc(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
{
  Dpc->DeferredRoutine = DeferredRoutine;
  Dpc->DeferredContext = DeferredContext;
}
"""
        )
        insert_plan = self._plan(
            """
BOOLEAN __stdcall KeInsertQueueDpc(PRKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2)
{
  return KiInsertQueueDpc(Dpc, SystemArgument1, SystemArgument2);
}
"""
        )
        remove_plan = self._plan(
            """
BOOLEAN __stdcall KeRemoveQueueDpc(PRKDPC Dpc)
{
  return KeRemoveQueueDpcEx(Dpc, FALSE);
}
"""
        )

        initialize_roles = self._roles(initialize_plan, "windows.executive_async.ke_initialize_dpc")
        insert_roles = self._roles(insert_plan, "windows.executive_async.ke_insert_queue_dpc")
        remove_roles = self._roles(remove_plan, "windows.executive_async.ke_remove_queue_dpc")

        self.assertEqual("KDPC", initialize_roles["dpc"])
        self.assertEqual("KDEFERRED_ROUTINE", initialize_roles["deferredRoutine"])
        self.assertEqual("DPC_DEFERRED_CONTEXT", initialize_roles["deferredContext"])
        self.assertEqual("KDPC", insert_roles["dpc"])
        self.assertEqual("DPC_SYSTEM_ARGUMENT", insert_roles["systemArgument1"])
        self.assertEqual("DPC_SYSTEM_ARGUMENT", insert_roles["systemArgument2"])
        self.assertEqual("KDPC", remove_roles["dpc"])

    def test_apc_roles(self) -> None:
        initialize_plan = self._plan(
            """
__int64 __fastcall KeInitializeApc(__int64 Apc, __int64 Thread, int Environment, __int64 KernelRoutine, __int64 NormalRoutine, __int64 NormalContext, unsigned __int8 ProcessorMode, __int64 RoutineContext)
{
  *(_QWORD *)(Apc + 8) = Thread;
  *(_QWORD *)(Apc + 32) = KernelRoutine;
  *(_QWORD *)(Apc + 40) = NormalRoutine;
  *(_QWORD *)(Apc + 48) = NormalContext;
  *(_BYTE *)(Apc + 81) = ProcessorMode;
  *(_QWORD *)(Apc + 56) = RoutineContext;
  return Environment;
}
"""
        )
        insert_plan = self._plan(
            """
__int64 __fastcall KeInsertQueueApc(__int64 Apc, __int64 SystemArgument1, __int64 SystemArgument2, __int64 PriorityBoost)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  return (__int64)KiInsertQueueApc(Apc) + (__int64)currentThread + SystemArgument1 + SystemArgument2 + PriorityBoost;
}
"""
        )
        ki_insert_plan = self._plan(
            """
_QWORD *__fastcall KiInsertQueueApc(__int64 Apc)
{
  __int64 apcStatePtr;
  _QWORD *queueHeadPtr;
  _QWORD **specialListHeadPtr;

  apcStatePtr = *(_QWORD *)(Apc + 8);
  queueHeadPtr = (_QWORD *)(apcStatePtr + 152);
  specialListHeadPtr = (_QWORD **)(apcStatePtr + 600);
  if ( !queueHeadPtr )
  {
    __fastfail(3u);
  }
  return (_QWORD *)specialListHeadPtr;
}
"""
        )
        deliver_plan = self._plan(
            """
void __fastcall KiDeliverApc(char DeliveryMode, __int64 (__fastcall *KernelApcRoutine)(int, int, int, int, __int64), unsigned __int64 TrapFrame, __int64 ApcContext)
{
  struct _KTHREAD *currentThread;
  _KPROCESS *currentProcess;

  currentThread = KeGetCurrentThread();
  currentProcess = currentThread->ApcState.Process;
  guard_dispatch_icall_no_overrides(KernelApcRoutine);
}
"""
        )

        initialize_roles = self._roles(initialize_plan, "windows.executive_async.ke_initialize_apc")
        insert_roles = self._roles(insert_plan, "windows.executive_async.ke_insert_queue_apc")
        ki_insert_roles = self._roles(ki_insert_plan, "windows.executive_async.ki_insert_queue_apc")
        deliver_roles = self._roles(deliver_plan, "windows.executive_async.ki_deliver_apc")

        self.assertEqual("KAPC", initialize_roles["apc"])
        self.assertEqual("KTHREAD", initialize_roles["thread"])
        self.assertEqual("KAPC_ENVIRONMENT", initialize_roles["environment"])
        self.assertEqual("KERNEL_ROUTINE", initialize_roles["kernelRoutine"])
        self.assertEqual("NORMAL_ROUTINE", initialize_roles["normalRoutine"])
        self.assertEqual("APC_NORMAL_CONTEXT", initialize_roles["normalContext"])
        self.assertEqual("KPROCESSOR_MODE", initialize_roles["processorMode"])
        self.assertEqual("APC_ROUTINE_CONTEXT", initialize_roles["normalRoutineContext"])
        self.assertEqual("KAPC", insert_roles["apc"])
        self.assertEqual("APC_SYSTEM_ARGUMENT", insert_roles["systemArgument1"])
        self.assertEqual("APC_SYSTEM_ARGUMENT", insert_roles["systemArgument2"])
        self.assertEqual("KPRIORITY_INCREMENT", insert_roles["priorityBoost"])
        self.assertEqual("KTHREAD", insert_roles["currentThread"])
        self.assertEqual("KAPC", ki_insert_roles["apc"])
        self.assertEqual("KAPC_STATE", ki_insert_roles["apcState"])
        self.assertEqual("LIST_ENTRY", ki_insert_roles["queueHead"])
        self.assertEqual("APC_DELIVERY_MODE", deliver_roles["deliveryMode"])
        self.assertEqual("KERNEL_ROUTINE", deliver_roles["kernelApcRoutine"])
        self.assertEqual("KTRAP_FRAME", deliver_roles["trapFrame"])
        self.assertEqual("APC_ROUTINE_CONTEXT", deliver_roles["apcContext"])
        self.assertEqual("KTHREAD", deliver_roles["currentThread"])
        self.assertEqual("KPROCESS", deliver_roles["currentProcess"])

    def test_kernel_timer_roles(self) -> None:
        initialize_plan = self._plan(
            """
void __stdcall KeInitializeTimer(PKTIMER Timer)
{
  Timer->Header.Type = 8;
}
"""
        )
        initialize_ex_plan = self._plan(
            """
void __stdcall KeInitializeTimerEx(PKTIMER Timer, TIMER_TYPE Type)
{
  Timer->TimerType = Type;
}
"""
        )
        set_plan = self._plan(
            """
BOOLEAN __stdcall KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
{
  struct _KPRCB *CurrentPrcb;

  KeGetCurrentIrql();
  CurrentPrcb = KeGetCurrentPrcb();
  Timer->Dpc = Dpc;
  return CurrentPrcb != 0 && DueTime.QuadPart != 0;
}
"""
        )
        set_ex_plan = self._plan(
            """
BOOLEAN __stdcall KeSetTimerEx(PKTIMER Timer, LARGE_INTEGER DueTime, LONG Period, PKDPC Dpc)
{
  return KiSetTimerEx(Timer, DueTime, Period, Dpc);
}
"""
        )
        cancel_plan = self._plan(
            """
BOOLEAN __stdcall KeCancelTimer(PKTIMER Timer)
{
  EtwTraceKernelEvent(Timer, 0, 0);
  return TRUE;
}
"""
        )

        initialize_roles = self._roles(initialize_plan, "windows.executive_async.ke_initialize_timer")
        initialize_ex_roles = self._roles(initialize_ex_plan, "windows.executive_async.ke_initialize_timer_ex")
        set_roles = self._roles(set_plan, "windows.executive_async.ke_set_timer")
        set_ex_roles = self._roles(set_ex_plan, "windows.executive_async.ke_set_timer_ex")
        cancel_roles = self._roles(cancel_plan, "windows.executive_async.ke_cancel_timer")

        self.assertEqual("KTIMER", initialize_roles["timer"])
        self.assertEqual("KTIMER", initialize_ex_roles["timer"])
        self.assertEqual("TIMER_TYPE", initialize_ex_roles["timerType"])
        self.assertEqual("KTIMER", set_roles["timer"])
        self.assertEqual("LARGE_INTEGER", set_roles["dueTime"])
        self.assertEqual("KDPC", set_roles["dpc"])
        self.assertEqual("KPRCB", set_roles["currentPrcb"])
        self.assertEqual("KTIMER", set_ex_roles["timer"])
        self.assertEqual("LARGE_INTEGER", set_ex_roles["dueTime"])
        self.assertEqual("TIMER_PERIOD", set_ex_roles["period"])
        self.assertEqual("KDPC", set_ex_roles["dpc"])
        self.assertEqual("KTIMER", cancel_roles["timer"])

    def test_executive_timer_roles(self) -> None:
        allocate_plan = self._plan(
            """
__int64 __fastcall ExAllocateTimer(__int64 Callback, __int64 CallbackContext, unsigned int Attributes)
{
  return ExAllocateTimerInternal2(Callback, CallbackContext, 0, Attributes);
}
"""
        )
        set_plan = self._plan(
            """
__int64 __fastcall ExSetTimer(ULONG_PTR Timer, signed __int64 DueTime, signed __int64 Period, ULONG_PTR Parameters)
{
  KeGetCurrentThread();
  return KeSetTimer2(Timer, DueTime, Period, Parameters);
}
"""
        )
        cancel_plan = self._plan(
            """
__int64 __fastcall ExCancelTimer(ULONG_PTR Timer, __int64 CancelFlags)
{
  ExpCheckForFreedEnhancedTimer(Timer);
  return KeCancelTimer2(Timer, CancelFlags);
}
"""
        )
        delete_plan = self._plan(
            """
__int64 __fastcall ExDeleteTimer(ULONG_PTR Timer, char TimerType, char CancelPending, unsigned int *StatusOut)
{
  _QWORD disableCtx;

  ExpCheckForFreedEnhancedTimer(Timer);
  disableCtx = Timer;
  return KeDisableTimer2(Timer, TimerType, CancelPending, StatusOut, &disableCtx);
}
"""
        )

        allocate_roles = self._roles(allocate_plan, "windows.executive_async.ex_allocate_timer")
        set_roles = self._roles(set_plan, "windows.executive_async.ex_set_timer")
        cancel_roles = self._roles(cancel_plan, "windows.executive_async.ex_cancel_timer")
        delete_roles = self._roles(delete_plan, "windows.executive_async.ex_delete_timer")

        self.assertEqual("EXTIMER_CALLBACK", allocate_roles["callback"])
        self.assertEqual("EXTIMER_CALLBACK_CONTEXT", allocate_roles["callbackContext"])
        self.assertEqual("EXTIMER_ATTRIBUTES", allocate_roles["attributes"])
        self.assertEqual("EXTIMER", set_roles["timer"])
        self.assertEqual("LARGE_INTEGER", set_roles["dueTime"])
        self.assertEqual("TIMER_PERIOD", set_roles["period"])
        self.assertEqual("EXTIMER_SET_PARAMETERS", set_roles["parameters"])
        self.assertEqual("EXTIMER", cancel_roles["timer"])
        self.assertEqual("EXTIMER_CANCEL_FLAGS", cancel_roles["cancelFlags"])
        self.assertEqual("EXTIMER", delete_roles["timer"])
        self.assertEqual("EXTIMER_DELETE_TYPE", delete_roles["timerType"])
        self.assertEqual("BOOLEAN", delete_roles["cancelPending"])
        self.assertEqual("NTSTATUS_OUTPUT", delete_roles["statusOut"])
        self.assertEqual("EXTIMER_DISABLE_CONTEXT", delete_roles["disableContext"])

    def test_timer_object_and_timer_callback_roles(self) -> None:
        set_object_plan = self._plan(
            """
__int64 __fastcall ExpSetTimerObject(ULONG_PTR TimerObject, char WakeTimer, LARGE_INTEGER *DueTime, __int64 Period, __int64 ResumeContext, __int64 ApcContext, char Wake, ULONG InputLength, ULONG TolerableDelay, _BYTE *PreviousState)
{
  struct _KTHREAD *currentThread;
  PVOID referencedObject;

  currentThread = KeGetCurrentThread();
  referencedObject = (PVOID)TimerObject;
  ExpCheckWakeTimerAccess(currentThread, WakeTimer);
  return InputLength + TolerableDelay + (ULONG)(DueTime != 0) + (ULONG)(PreviousState != 0) + (ULONG)(referencedObject != 0);
}
"""
        )
        dpc_routine_plan = self._plan(
            """
void __fastcall ExpTimerDpcRoutine(struct _KDPC *Dpc, __int64 DeferredContext, unsigned __int64 SystemArgument1, unsigned __int64 SystemArgument2)
{
  KeInsertQueueApc((PKAPC)DeferredContext, (PVOID)SystemArgument1, (PVOID)SystemArgument2, 0);
  KeSetCoalescableTimer((PKTIMER)DeferredContext, 0, 0, Dpc, 0);
}
"""
        )
        apc_routine_plan = self._plan(
            """
LONG_PTR __fastcall ExpTimerApcRoutine(__int64 NormalContext, _QWORD *SystemArguments)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  ObfDereferenceObjectWithTag((PVOID)NormalContext, 0);
  return (LONG_PTR)currentThread + (LONG_PTR)SystemArguments;
}
"""
        )

        set_object_roles = self._roles(set_object_plan, "windows.executive_async.exp_set_timer_object")
        dpc_roles = self._roles(dpc_routine_plan, "windows.executive_async.exp_timer_dpc_routine")
        apc_roles = self._roles(apc_routine_plan, "windows.executive_async.exp_timer_apc_routine")

        self.assertEqual("KTIMER", set_object_roles["timerObject"])
        self.assertEqual("LARGE_INTEGER", set_object_roles["dueTime"])
        self.assertEqual("BUFFER_LENGTH", set_object_roles["inputLength"])
        self.assertEqual("TIMER_TOLERABLE_DELAY", set_object_roles["tolerableDelay"])
        self.assertEqual("BOOLEAN_OUTPUT", set_object_roles["previousState"])
        self.assertEqual("KTHREAD", set_object_roles["currentThread"])
        self.assertEqual("OBJECT_BODY", set_object_roles["referencedObject"])
        self.assertEqual("KDPC", dpc_roles["dpc"])
        self.assertEqual("EXTIMER", dpc_roles["deferredContext"])
        self.assertEqual("DPC_SYSTEM_ARGUMENT", dpc_roles["systemArgument1"])
        self.assertEqual("DPC_SYSTEM_ARGUMENT", dpc_roles["systemArgument2"])
        self.assertEqual("EXTIMER", apc_roles["normalContext"])
        self.assertEqual("APC_SYSTEM_ARGUMENTS", apc_roles["systemArguments"])
        self.assertEqual("KTHREAD", apc_roles["currentThread"])

    def test_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall KeSetTimer(__int64 timer, __int64 dueTime, __int64 dpc)
{
  struct _KPRCB *CurrentPrcb;
  unsigned __int64 probe;

  CurrentPrcb = KeGetCurrentPrcb();
  KeGetCurrentIrql();
  probe = *(_QWORD *)(timer + 16)
        + *(_QWORD *)(timer + 24)
        + *(_QWORD *)(timer + 32)
        + *(_QWORD *)(timer + 40)
        + *(_QWORD *)(timer + 48)
        + *(_QWORD *)(timer + 56)
        + *(_QWORD *)(timer + 64)
        + *(_QWORD *)(timer + 72)
        + *(_QWORD *)(timer + 80)
        + *(_QWORD *)(timer + 88)
        + *(_QWORD *)(timer + 96)
        + *(_QWORD *)(timer + 104);
  return CurrentPrcb != 0 && probe != 0 && dueTime != 0 && dpc != 0;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.executive_async.ke_set_timer",
            "timer",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "timer"
        ]

        self.assertEqual("KTIMER", identity["structure_name"])
        self.assertEqual("timer", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "timer"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall KeSetTimerEx(PKTIMER Timer, LARGE_INTEGER DueTime, LONG Period, PKDPC Dpc)
{
  return KiSetTimerEx(Timer, DueTime, Period, Dpc);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.executive_async.ke_set_timer_ex",
            role="timer",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_dpc_type(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall KeInsertQueueDpc(int Dpc, PVOID SystemArgument1, PVOID SystemArgument2)
{
  return KiInsertQueueDpc(Dpc, SystemArgument1, SystemArgument2);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.executive_async.ke_insert_queue_dpc"
                and item["trusted_role"] == "dpc"
                for item in self._identities(plan)
            )
        )

    def test_executive_async_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
BOOLEAN __stdcall KeInsertQueueDpc(PRKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2)
{
  return KiInsertQueueDpc(Dpc, SystemArgument1, SystemArgument2);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/executive_async.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _roles(self, plan, profile_id: str) -> dict[str, str]:
        return {
            str(item["trusted_role"]): str(item["structure_name"])
            for item in self._profile_identities(plan, profile_id)
        }

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
