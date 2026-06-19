from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class DispatcherSynchronizationDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_event_and_semaphore_roles(self) -> None:
        init_event_plan = self._plan(
            """
void __stdcall KeInitializeEvent(PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
  Event->Header.Type = Type;
  Event->Header.SignalState = State;
}
"""
        )
        set_event_plan = self._plan(
            """
LONG __stdcall KeSetEvent(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)
{
  KiTryUnwaitThread(KeGetCurrentPrcb(), Event->Header.WaitListHead.Flink, Increment, Wait);
  return Event->Header.SignalState;
}
"""
        )
        reset_event_plan = self._plan(
            """
LONG __stdcall KeResetEvent(PRKEVENT Event)
{
  LONG signalState;

  signalState = Event->Header.SignalState;
  Event->Header.SignalState = 0;
  KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), 0);
  return signalState;
}
"""
        )
        pulse_event_plan = self._plan(
            """
LONG __stdcall KePulseEvent(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)
{
  LONG signalState;

  signalState = Event->Header.SignalState;
  KiTryUnwaitThread(KeGetCurrentPrcb(), Event->Header.WaitListHead.Flink, Increment, Wait);
  return signalState;
}
"""
        )
        init_sem_plan = self._plan(
            """
void __stdcall KeInitializeSemaphore(PRKSEMAPHORE Semaphore, LONG Count, LONG Limit)
{
  Semaphore->Header.SignalState = Count;
  Semaphore->Limit = Limit;
}
"""
        )
        release_sem_plan = self._plan(
            """
LONG __stdcall KeReleaseSemaphore(PRKSEMAPHORE Semaphore, KPRIORITY Increment, LONG Adjustment, BOOLEAN Wait)
{
  Semaphore->Header.SignalState += Adjustment;
  KiTryUnwaitThread(KeGetCurrentPrcb(), Semaphore->Header.WaitListHead.Flink, Increment, Wait);
  return Semaphore->Header.SignalState;
}
"""
        )
        read_sem_plan = self._plan(
            """
LONG __stdcall KeReadStateSemaphore(PRKSEMAPHORE Semaphore)
{
  return Semaphore->Header.SignalState;
}
"""
        )

        init_event_roles = self._roles(init_event_plan, "windows.dispatcher_synchronization.ke_initialize_event")
        set_event_roles = self._roles(set_event_plan, "windows.dispatcher_synchronization.ke_set_event")
        reset_event_roles = self._roles(reset_event_plan, "windows.dispatcher_synchronization.ke_reset_event")
        pulse_event_roles = self._roles(pulse_event_plan, "windows.dispatcher_synchronization.ke_pulse_event")
        init_sem_roles = self._roles(init_sem_plan, "windows.dispatcher_synchronization.ke_initialize_semaphore")
        release_sem_roles = self._roles(release_sem_plan, "windows.dispatcher_synchronization.ke_release_semaphore")
        read_sem_roles = self._roles(read_sem_plan, "windows.dispatcher_synchronization.ke_read_state_semaphore")

        self.assertEqual("KEVENT", init_event_roles["event"])
        self.assertEqual("EVENT_TYPE", init_event_roles["eventType"])
        self.assertEqual("BOOLEAN", init_event_roles["initialState"])
        self.assertEqual("KEVENT", set_event_roles["event"])
        self.assertEqual("KPRIORITY", set_event_roles["increment"])
        self.assertEqual("BOOLEAN", set_event_roles["wait"])
        self.assertEqual("KEVENT", reset_event_roles["event"])
        self.assertEqual("SIGNAL_STATE", reset_event_roles["previousSignalState"])
        self.assertEqual("KEVENT", pulse_event_roles["event"])
        self.assertEqual("SIGNAL_STATE", pulse_event_roles["previousSignalState"])
        self.assertEqual("KSEMAPHORE", init_sem_roles["semaphore"])
        self.assertEqual("SEMAPHORE_COUNT", init_sem_roles["count"])
        self.assertEqual("SEMAPHORE_LIMIT", init_sem_roles["limit"])
        self.assertEqual("KSEMAPHORE", release_sem_roles["semaphore"])
        self.assertEqual("SEMAPHORE_ADJUSTMENT", release_sem_roles["adjustment"])
        self.assertEqual("KSEMAPHORE", read_sem_roles["semaphore"])

    def test_mutant_mutex_and_queue_roles(self) -> None:
        init_mutant_plan = self._plan(
            """
void __stdcall KeInitializeMutant(PRKMUTANT Mutant, BOOLEAN InitialOwner)
{
  KiInitializeMutant(Mutant, InitialOwner);
}
"""
        )
        release_mutant_plan = self._plan(
            """
LONG __stdcall KeReleaseMutant(PRKMUTANT Mutant, KPRIORITY Increment, BOOLEAN Abandoned, BOOLEAN Wait)
{
  return KeReleaseMutantEx(Mutant, Increment, Abandoned, Wait);
}
"""
        )
        init_mutex_plan = self._plan(
            """
void __stdcall KeInitializeMutex(PRKMUTEX Mutex, ULONG Level)
{
  Mutex->Header.SignalState = 1;
  Mutex->Level = Level;
}
"""
        )
        release_mutex_plan = self._plan(
            """
LONG __stdcall KeReleaseMutex(PRKMUTEX Mutex, BOOLEAN Wait)
{
  return KeReleaseMutantEx(Mutex, 0, 0, Wait);
}
"""
        )
        init_queue_plan = self._plan(
            """
void __stdcall KeInitializeQueue(PRKQUEUE Queue, ULONG Count)
{
  Queue->CurrentCount = Count;
}
"""
        )
        insert_queue_plan = self._plan(
            """
LONG __stdcall KeInsertQueue(PRKQUEUE Queue, PLIST_ENTRY Entry)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  EtwTraceEnqueueWork(Queue, Entry);
  KiWakeQueueWaiter(Queue, currentThread);
  return Queue->Header.SignalState;
}
"""
        )
        remove_queue_plan = self._plan(
            """
PLIST_ENTRY __stdcall KeRemoveQueue(PRKQUEUE Queue, KPROCESSOR_MODE WaitMode, PLARGE_INTEGER Timeout)
{
  return KeRemoveQueueEx(Queue, WaitMode, Timeout, 1, 0);
}
"""
        )
        rundown_queue_plan = self._plan(
            """
PLIST_ENTRY __stdcall KeRundownQueue(PRKQUEUE Queue)
{
  return KeRundownQueueEx(Queue);
}
"""
        )

        init_mutant_roles = self._roles(init_mutant_plan, "windows.dispatcher_synchronization.ke_initialize_mutant")
        release_mutant_roles = self._roles(release_mutant_plan, "windows.dispatcher_synchronization.ke_release_mutant")
        init_mutex_roles = self._roles(init_mutex_plan, "windows.dispatcher_synchronization.ke_initialize_mutex")
        release_mutex_roles = self._roles(release_mutex_plan, "windows.dispatcher_synchronization.ke_release_mutex")
        init_queue_roles = self._roles(init_queue_plan, "windows.dispatcher_synchronization.ke_initialize_queue")
        insert_queue_roles = self._roles(insert_queue_plan, "windows.dispatcher_synchronization.ke_insert_queue")
        remove_queue_roles = self._roles(remove_queue_plan, "windows.dispatcher_synchronization.ke_remove_queue")
        rundown_queue_roles = self._roles(rundown_queue_plan, "windows.dispatcher_synchronization.ke_rundown_queue")

        self.assertEqual("KMUTANT", init_mutant_roles["mutant"])
        self.assertEqual("BOOLEAN", init_mutant_roles["initialOwner"])
        self.assertEqual("KMUTANT", release_mutant_roles["mutant"])
        self.assertEqual("KPRIORITY", release_mutant_roles["increment"])
        self.assertEqual("BOOLEAN", release_mutant_roles["abandoned"])
        self.assertEqual("KMUTEX", init_mutex_roles["mutex"])
        self.assertEqual("MUTEX_LEVEL", init_mutex_roles["level"])
        self.assertEqual("KMUTEX", release_mutex_roles["mutex"])
        self.assertEqual("KQUEUE", init_queue_roles["queue"])
        self.assertEqual("QUEUE_THREAD_COUNT", init_queue_roles["count"])
        self.assertEqual("KQUEUE", insert_queue_roles["queue"])
        self.assertEqual("LIST_ENTRY", insert_queue_roles["entry"])
        self.assertEqual("KTHREAD", insert_queue_roles["currentThread"])
        self.assertEqual("KQUEUE", remove_queue_roles["queue"])
        self.assertEqual("KPROCESSOR_MODE", remove_queue_roles["waitMode"])
        self.assertEqual("LARGE_INTEGER", remove_queue_roles["timeout"])
        self.assertEqual("KQUEUE", rundown_queue_roles["queue"])

    def test_wait_roles(self) -> None:
        single_plan = self._plan(
            """
NTSTATUS __stdcall KeWaitForSingleObject(PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  return currentThread != 0 && Object != 0 && Timeout != 0 && Alertable ? WaitReason : WaitMode;
}
"""
        )
        multiple_plan = self._plan(
            """
NTSTATUS __stdcall KeWaitForMultipleObjects(ULONG Count, PVOID *Objects, WAIT_TYPE WaitType, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PKWAIT_BLOCK WaitBlockArray)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  return Count && Objects && WaitBlockArray && currentThread ? WaitType + WaitReason + WaitMode + Alertable + (Timeout != 0) : STATUS_TIMEOUT;
}
"""
        )

        single_roles = self._roles(single_plan, "windows.dispatcher_synchronization.ke_wait_for_single_object")
        multiple_roles = self._roles(multiple_plan, "windows.dispatcher_synchronization.ke_wait_for_multiple_objects")

        self.assertEqual("DISPATCHER_OBJECT", single_roles["object"])
        self.assertEqual("KWAIT_REASON", single_roles["waitReason"])
        self.assertEqual("KPROCESSOR_MODE", single_roles["waitMode"])
        self.assertEqual("BOOLEAN", single_roles["alertable"])
        self.assertEqual("LARGE_INTEGER", single_roles["timeout"])
        self.assertEqual("KTHREAD", single_roles["currentThread"])
        self.assertEqual("WAIT_OBJECT_COUNT", multiple_roles["count"])
        self.assertEqual("DISPATCHER_OBJECT_ARRAY", multiple_roles["objects"])
        self.assertEqual("WAIT_TYPE", multiple_roles["waitType"])
        self.assertEqual("KWAIT_REASON", multiple_roles["waitReason"])
        self.assertEqual("KPROCESSOR_MODE", multiple_roles["waitMode"])
        self.assertEqual("BOOLEAN", multiple_roles["alertable"])
        self.assertEqual("LARGE_INTEGER", multiple_roles["timeout"])
        self.assertEqual("KWAIT_BLOCK", multiple_roles["waitBlockArray"])

    def test_push_lock_and_fast_mutex_roles(self) -> None:
        init_plan = self._plan(
            """
void __stdcall ExInitializePushLock(PEX_PUSH_LOCK PushLock)
{
  *PushLock = 0;
}
"""
        )
        acquire_exclusive_plan = self._plan(
            """
void __fastcall ExAcquirePushLockExclusiveEx(PEX_PUSH_LOCK PushLock, ULONG_PTR Flags)
{
  ExfAcquirePushLockExclusiveEx(PushLock, Flags, 0);
}
"""
        )
        acquire_shared_plan = self._plan(
            """
__int64 __fastcall ExAcquirePushLockSharedEx(PEX_PUSH_LOCK PushLock, ULONG_PTR Flags)
{
  return ExfAcquirePushLockSharedEx(PushLock, Flags, 0, 0);
}
"""
        )
        release_plan = self._plan(
            """
__int64 __fastcall ExReleasePushLockEx(ULONG_PTR PushLock, ULONG_PTR Flags)
{
  return ExfReleasePushLock((PEX_PUSH_LOCK)PushLock) + Flags;
}
"""
        )
        release_shared_plan = self._plan(
            """
__int64 __fastcall ExReleasePushLockSharedEx(ULONG_PTR PushLock, ULONG_PTR Flags)
{
  return ExfReleasePushLockShared((PEX_PUSH_LOCK)PushLock) + Flags;
}
"""
        )
        fast_mutex_plan = self._plan(
            """
void __stdcall ExAcquireFastMutex(PKGUARDED_MUTEX Mutex)
{
  KeWaitForSingleObject(Mutex, Executive, KernelMode, FALSE, 0);
}
"""
        )

        init_roles = self._roles(init_plan, "windows.dispatcher_synchronization.ex_initialize_push_lock")
        acquire_exclusive_roles = self._roles(acquire_exclusive_plan, "windows.dispatcher_synchronization.ex_acquire_push_lock_exclusive")
        acquire_shared_roles = self._roles(acquire_shared_plan, "windows.dispatcher_synchronization.ex_acquire_push_lock_shared")
        release_roles = self._roles(release_plan, "windows.dispatcher_synchronization.ex_release_push_lock")
        release_shared_roles = self._roles(release_shared_plan, "windows.dispatcher_synchronization.ex_release_push_lock_shared")
        fast_mutex_roles = self._roles(fast_mutex_plan, "windows.dispatcher_synchronization.ex_acquire_fast_mutex")

        self.assertEqual("EX_PUSH_LOCK", init_roles["pushLock"])
        self.assertEqual("EX_PUSH_LOCK", acquire_exclusive_roles["pushLock"])
        self.assertEqual("PUSH_LOCK_FLAGS", acquire_exclusive_roles["flags"])
        self.assertEqual("EX_PUSH_LOCK", acquire_shared_roles["pushLock"])
        self.assertEqual("PUSH_LOCK_FLAGS", acquire_shared_roles["flags"])
        self.assertEqual("EX_PUSH_LOCK", release_roles["pushLock"])
        self.assertEqual("PUSH_LOCK_FLAGS", release_roles["flags"])
        self.assertEqual("EX_PUSH_LOCK", release_shared_roles["pushLock"])
        self.assertEqual("PUSH_LOCK_FLAGS", release_shared_roles["flags"])
        self.assertEqual("KGUARDED_MUTEX", fast_mutex_roles["mutex"])

    def test_resource_roles(self) -> None:
        init_plan = self._plan(
            """
NTSTATUS __stdcall ExInitializeResourceLite(PERESOURCE Resource)
{
  ULONG_PTR creatorBackTraceIndex;

  creatorBackTraceIndex = RtlStdLogStackTrace();
  Resource->CreatorBackTraceIndex = creatorBackTraceIndex;
  return STATUS_SUCCESS;
}
"""
        )
        acquire_exclusive_plan = self._plan(
            """
BOOLEAN __stdcall ExAcquireResourceExclusiveLite(PERESOURCE Resource, BOOLEAN Wait)
{
  struct _KTHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  return Resource != 0 && currentThread != 0 && Wait;
}
"""
        )
        acquire_shared_plan = self._plan(
            """
BOOLEAN __stdcall ExAcquireResourceSharedLite(PERESOURCE Resource, BOOLEAN Wait)
{
  return ExpAcquireResourceSharedLite(Resource, Wait, 0);
}
"""
        )
        release_plan = self._plan(
            """
void __stdcall ExReleaseResourceLite(PERESOURCE Resource)
{
  POWNER_ENTRY ownerTable;
  ERESOURCE_THREAD ownerThread;

  KeGetCurrentThread();
  ownerTable = Resource->OwnerTable;
  ownerThread = Resource->OwnerEntry.OwnerThread;
}
"""
        )
        delete_plan = self._plan(
            """
NTSTATUS __stdcall ExDeleteResourceLite(PERESOURCE Resource)
{
  POWNER_ENTRY ownerTable;

  ownerTable = Resource->OwnerTable;
  ExpResourceEnforcesOwnershipTransfer(Resource);
  return ownerTable != 0 ? STATUS_SUCCESS : STATUS_SUCCESS;
}
"""
        )
        release_for_thread_plan = self._plan(
            """
char __fastcall ExpReleaseResourceForThreadLite(ULONG_PTR Resource, ULONG_PTR ResourceThread, __int64 Flags, _DWORD *ReleaseState)
{
  KeGetCurrentIrql();
  *ReleaseState = (ULONG)Flags;
  return Resource != 0 && ResourceThread != 0;
}
"""
        )

        init_roles = self._roles(init_plan, "windows.dispatcher_synchronization.ex_initialize_resource_lite")
        acquire_exclusive_roles = self._roles(acquire_exclusive_plan, "windows.dispatcher_synchronization.ex_acquire_resource_exclusive_lite")
        acquire_shared_roles = self._roles(acquire_shared_plan, "windows.dispatcher_synchronization.ex_acquire_resource_shared_lite")
        release_roles = self._roles(release_plan, "windows.dispatcher_synchronization.ex_release_resource_lite")
        delete_roles = self._roles(delete_plan, "windows.dispatcher_synchronization.ex_delete_resource_lite")
        release_for_thread_roles = self._roles(release_for_thread_plan, "windows.dispatcher_synchronization.exp_release_resource_for_thread_lite")

        self.assertEqual("ERESOURCE", init_roles["resource"])
        self.assertEqual("STACK_TRACE_INDEX", init_roles["creatorBackTraceIndex"])
        self.assertEqual("ERESOURCE", acquire_exclusive_roles["resource"])
        self.assertEqual("BOOLEAN", acquire_exclusive_roles["wait"])
        self.assertEqual("KTHREAD", acquire_exclusive_roles["currentThread"])
        self.assertEqual("ERESOURCE", acquire_shared_roles["resource"])
        self.assertEqual("BOOLEAN", acquire_shared_roles["wait"])
        self.assertEqual("ERESOURCE", release_roles["resource"])
        self.assertEqual("OWNER_ENTRY", release_roles["ownerTable"])
        self.assertEqual("ERESOURCE_THREAD", release_roles["ownerThread"])
        self.assertEqual("ERESOURCE", delete_roles["resource"])
        self.assertEqual("OWNER_ENTRY", delete_roles["ownerTable"])
        self.assertEqual("ERESOURCE", release_for_thread_roles["resource"])
        self.assertEqual("ERESOURCE_THREAD", release_for_thread_roles["resourceThread"])
        self.assertEqual("RESOURCE_RELEASE_STATE", release_for_thread_roles["releaseState"])

    def test_rundown_and_spin_lock_roles(self) -> None:
        acquire_rundown_plan = self._plan(
            """
BOOLEAN __stdcall ExAcquireRundownProtectionEx(PEX_RUNDOWN_REF RunRef, ULONG Count)
{
  return RunRef->Count += Count;
}
"""
        )
        wait_rundown_plan = self._plan(
            """
void __stdcall ExWaitForRundownProtectionRelease(PEX_RUNDOWN_REF RunRef)
{
  ExfWaitForRundownProtectionRelease(RunRef);
}
"""
        )
        completed_rundown_plan = self._plan(
            """
void __stdcall ExRundownCompleted(PEX_RUNDOWN_REF RunRef)
{
  RunRef->Count = 1;
}
"""
        )
        reinit_rundown_plan = self._plan(
            """
void __stdcall ExReInitializeRundownProtection(PEX_RUNDOWN_REF RunRef)
{
  RunRef->Count = 0;
}
"""
        )
        acquire_spin_plan = self._plan(
            """
KIRQL __stdcall KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock)
{
  KIRQL CurrentIrql;

  CurrentIrql = KeGetCurrentIrql();
  KxWaitForSpinLockAndAcquire(SpinLock);
  return CurrentIrql;
}
"""
        )
        release_spin_plan = self._plan(
            """
void __stdcall KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)
{
  KiLowerIrqlProcessIrqlFlags(KeGetCurrentIrql(), NewIrql);
  *SpinLock = 0;
}
"""
        )
        kx_acquire_plan = self._plan(
            """
void __stdcall KxAcquireSpinLock(PKSPIN_LOCK SpinLock)
{
  KxWaitForSpinLockAndAcquire(SpinLock);
}
"""
        )
        kx_release_plan = self._plan(
            """
__int64 __fastcall KxReleaseSpinLock(volatile signed __int64 *SpinLock)
{
  KiReleaseSpinLockInstrumented(SpinLock);
  return 0;
}
"""
        )

        acquire_rundown_roles = self._roles(acquire_rundown_plan, "windows.dispatcher_synchronization.ex_acquire_rundown_protection_ex")
        wait_rundown_roles = self._roles(wait_rundown_plan, "windows.dispatcher_synchronization.ex_wait_for_rundown_protection_release")
        completed_rundown_roles = self._roles(completed_rundown_plan, "windows.dispatcher_synchronization.ex_rundown_completed")
        reinit_rundown_roles = self._roles(reinit_rundown_plan, "windows.dispatcher_synchronization.ex_reinitialize_rundown_protection")
        acquire_spin_roles = self._roles(acquire_spin_plan, "windows.dispatcher_synchronization.ke_acquire_spin_lock_raise_to_dpc")
        release_spin_roles = self._roles(release_spin_plan, "windows.dispatcher_synchronization.ke_release_spin_lock")
        kx_acquire_roles = self._roles(kx_acquire_plan, "windows.dispatcher_synchronization.kx_acquire_spin_lock")
        kx_release_roles = self._roles(kx_release_plan, "windows.dispatcher_synchronization.kx_release_spin_lock")

        self.assertEqual("EX_RUNDOWN_REF", acquire_rundown_roles["runRef"])
        self.assertEqual("RUNDOWN_REF_COUNT", acquire_rundown_roles["count"])
        self.assertEqual("EX_RUNDOWN_REF", wait_rundown_roles["runRef"])
        self.assertEqual("EX_RUNDOWN_REF", completed_rundown_roles["runRef"])
        self.assertEqual("EX_RUNDOWN_REF", reinit_rundown_roles["runRef"])
        self.assertEqual("KSPIN_LOCK", acquire_spin_roles["spinLock"])
        self.assertEqual("KIRQL", acquire_spin_roles["oldIrql"])
        self.assertEqual("KSPIN_LOCK", release_spin_roles["spinLock"])
        self.assertEqual("KIRQL", release_spin_roles["newIrql"])
        self.assertEqual("KSPIN_LOCK", kx_acquire_roles["spinLock"])
        self.assertEqual("KSPIN_LOCK", kx_release_roles["spinLock"])

    def test_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
BOOLEAN __stdcall ExAcquireResourceExclusiveLite(__int64 resource, BOOLEAN wait)
{
  struct _KTHREAD *currentThread;
  unsigned __int64 probe;

  currentThread = KeGetCurrentThread();
  probe = *(_QWORD *)(resource + 16)
        + *(_QWORD *)(resource + 24)
        + *(_QWORD *)(resource + 32)
        + *(_QWORD *)(resource + 40)
        + *(_QWORD *)(resource + 48)
        + *(_QWORD *)(resource + 56)
        + *(_QWORD *)(resource + 64)
        + *(_QWORD *)(resource + 72)
        + *(_QWORD *)(resource + 80)
        + *(_QWORD *)(resource + 88)
        + *(_QWORD *)(resource + 96)
        + *(_QWORD *)(resource + 104);
  return currentThread != 0 && probe != 0 && wait;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.dispatcher_synchronization.ex_acquire_resource_exclusive_lite",
            "resource",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "resource"
        ]

        self.assertEqual("ERESOURCE", identity["structure_name"])
        self.assertEqual("resource", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "resource"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
LONG __stdcall KeSetEvent(PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)
{
  KiTryUnwaitThread(KeGetCurrentPrcb(), Event->Header.WaitListHead.Flink, Increment, Wait);
  return Event->Header.SignalState;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.dispatcher_synchronization.ke_set_event",
            role="event",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_event_type(self) -> None:
        plan = self._plan(
            """
LONG __stdcall KeSetEvent(int Event, KPRIORITY Increment, BOOLEAN Wait)
{
  KiTryUnwaitThread(KeGetCurrentPrcb(), Event, Increment, Wait);
  return Event;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.dispatcher_synchronization.ke_set_event"
                and item["trusted_role"] == "event"
                for item in self._identities(plan)
            )
        )

    def test_dispatcher_synchronization_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __stdcall KeInitializeEvent(PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
{
  Event->Header.Type = Type;
  Event->Header.SignalState = State;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/dispatcher_synchronization.json" for item in manifests)
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
