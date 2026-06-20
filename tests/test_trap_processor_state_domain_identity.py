from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class TrapProcessorStateDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_context_kframes_conversion_roles(self) -> None:
        from_plan = self._plan(
            """
unsigned __int64 __fastcall KeContextFromKframes(PKTRAP_FRAME TrapFrame, PKEXCEPTION_FRAME ExceptionFrame, PCONTEXT ContextRecord)
{
  unsigned __int8 currentIrql;
  struct _KPRCB *currentPrcb;

  currentIrql = KeGetCurrentIrql();
  currentPrcb = KeGetCurrentPrcb();
  ContextRecord->ContextFlags = TrapFrame->SegCs + ExceptionFrame->P1Home + currentIrql + currentPrcb->Number;
  return ContextRecord->ContextFlags;
}
"""
        )
        to_plan = self._plan(
            """
__int64 __fastcall KeContextToKframes(PKTHREAD Thread, PKTRAP_FRAME TrapFrame, PCONTEXT ContextRecord, ULONG ContextFlags, PVOID XStateContext)
{
  __int64 status;

  status = KxContextToKframes(Thread, TrapFrame, ContextRecord, ContextFlags, XStateContext);
  _fxrstor((void *)((char *)ContextRecord + 256));
  return status;
}
"""
        )

        from_roles = self._roles(from_plan, "windows.trap_processor_state.ke_context_from_kframes")
        to_roles = self._roles(to_plan, "windows.trap_processor_state.ke_context_to_kframes")

        self.assertEqual("KTRAP_FRAME", from_roles["trapFrame"])
        self.assertEqual("KEXCEPTION_FRAME", from_roles["exceptionFrame"])
        self.assertEqual("CONTEXT", from_roles["contextRecord"])
        self.assertEqual("KTHREAD", to_roles["thread"])
        self.assertEqual("KTRAP_FRAME", to_roles["trapFrame"])
        self.assertEqual("CONTEXT", to_roles["contextRecord"])
        self.assertEqual("CONTEXT_FLAGS", to_roles["contextFlags"])
        self.assertEqual("XSTATE_CONTEXT", to_roles["xstateContext"])

    def test_exception_dispatch_roles(self) -> None:
        plan = self._plan(
            """
__int16 __fastcall KiDispatchException(PEXCEPTION_RECORD ExceptionRecord, PKEXCEPTION_FRAME ExceptionFrame, PKTRAP_FRAME TrapFrame, unsigned __int8 PreviousMode, unsigned __int8 FirstChance)
{
  struct _KTHREAD *currentThread;
  PEPROCESS currentProcess;
  struct _KPRCB *CurrentPrcb;
  _DWORD *SchedulerAssist;

  currentThread = KeGetCurrentThread();
  currentProcess = currentThread->ApcState.Process;
  CurrentPrcb = KeGetCurrentPrcb();
  SchedulerAssist = CurrentPrcb->SchedulerAssist;
  KeContextFromKframes(TrapFrame, ExceptionFrame, ExceptionRecord);
  KiPreprocessFault(ExceptionRecord, TrapFrame, PreviousMode);
  DbgkForwardException(ExceptionRecord, FirstChance, SchedulerAssist);
  return currentProcess != 0;
}
"""
        )

        roles = self._roles(plan, "windows.trap_processor_state.ki_dispatch_exception")

        self.assertEqual("EXCEPTION_RECORD", roles["exceptionRecord"])
        self.assertEqual("KEXCEPTION_FRAME", roles["exceptionFrame"])
        self.assertEqual("KTRAP_FRAME", roles["trapFrame"])
        self.assertEqual("KPROCESSOR_MODE", roles["previousMode"])
        self.assertEqual("BOOLEAN", roles["firstChance"])
        self.assertEqual("KTHREAD", roles["currentThread"])
        self.assertEqual("EPROCESS", roles["currentProcess"])
        self.assertEqual("KPRCB", roles["currentPrcb"])
        self.assertEqual("KPRCB_SCHEDULER_ASSIST", roles["schedulerAssist"])

    def test_processor_control_state_roles(self) -> None:
        save_plan = self._plan(
            """
__int64 __fastcall KiSaveProcessorControlState(PKSPECIAL_REGISTERS ProcessorControlState, ULONG Xcr0High)
{
  ProcessorControlState->Cr0 = __readcr0();
  __sgdt(&ProcessorControlState->Gdtr);
  return KeGetPcr()->Prcb.Number + Xcr0High;
}
"""
        )
        restore_plan = self._plan(
            """
__int64 __fastcall KiRestoreProcessorControlState(PKSPECIAL_REGISTERS ProcessorControlState)
{
  __writecr0(ProcessorControlState->Cr0);
  __lgdt(&ProcessorControlState->Gdtr);
  __writedr(7u, ProcessorControlState->KernelDr7);
  return 0;
}
"""
        )
        hibernate_plan = self._plan(
            """
__int64 __fastcall KeSaveStateForHibernate(PKPROCESSOR_STATE HibernationState)
{
  RtlCaptureContext(&HibernationState->ContextFrame);
  return KiSaveProcessorControlState(&HibernationState->SpecialRegisters, 0);
}
"""
        )

        save_roles = self._roles(save_plan, "windows.trap_processor_state.ki_save_processor_control_state")
        restore_roles = self._roles(restore_plan, "windows.trap_processor_state.ki_restore_processor_control_state")
        hibernate_roles = self._roles(hibernate_plan, "windows.trap_processor_state.ke_save_state_for_hibernate")

        self.assertEqual("KSPECIAL_REGISTERS", save_roles["processorControlState"])
        self.assertEqual("XSTATE_MASK_HIGH", save_roles["xcr0High"])
        self.assertEqual("KSPECIAL_REGISTERS", restore_roles["processorControlState"])
        self.assertEqual("KPROCESSOR_STATE", hibernate_roles["hibernationState"])

    def test_processor_state_save_restore_roles(self) -> None:
        save_plan = self._plan(
            """
__int64 __fastcall KiSaveProcessorState(PKTRAP_FRAME TrapFrame, PKEXCEPTION_FRAME ExceptionFrame)
{
  struct _KPRCB *CurrentPrcb;
  PCONTEXT Context;

  CurrentPrcb = KeGetCurrentPrcb();
  Context = CurrentPrcb->Context;
  KeContextFromKframes(TrapFrame, ExceptionFrame, Context);
  return KiSaveProcessorControlState(&CurrentPrcb->ProcessorState, 0);
}
"""
        )
        restore_plan = self._plan(
            """
__int64 __fastcall KiRestoreProcessorState(PKTRAP_FRAME TrapFrame, PKEXCEPTION_FRAME ExceptionFrame)
{
  struct _KPRCB *CurrentPrcb;
  PCONTEXT context;

  CurrentPrcb = KeGetCurrentPrcb();
  context = CurrentPrcb->Context;
  KeContextToKframes(CurrentPrcb->CurrentThread, TrapFrame, context, context->ContextFlags, 0);
  return KiRestoreProcessorControlState(&CurrentPrcb->ProcessorState);
}
"""
        )

        save_roles = self._roles(save_plan, "windows.trap_processor_state.ki_save_processor_state")
        restore_roles = self._roles(restore_plan, "windows.trap_processor_state.ki_restore_processor_state")

        self.assertEqual("KTRAP_FRAME", save_roles["trapFrame"])
        self.assertEqual("KEXCEPTION_FRAME", save_roles["exceptionFrame"])
        self.assertEqual("KPRCB", save_roles["currentPrcb"])
        self.assertEqual("CONTEXT", save_roles["contextRecord"])
        self.assertEqual("KTRAP_FRAME", restore_roles["trapFrame"])
        self.assertEqual("KEXCEPTION_FRAME", restore_roles["exceptionFrame"])
        self.assertEqual("KPRCB", restore_roles["currentPrcb"])
        self.assertEqual("CONTEXT", restore_roles["contextRecord"])

    def test_prcb_scheduler_and_idle_roles(self) -> None:
        processor_number_plan = self._plan(
            """
ULONG __stdcall KeGetCurrentProcessorNumberEx(PPROCESSOR_NUMBER ProcessorNumber)
{
  struct _KPRCB *CurrentPrcb;

  CurrentPrcb = KeGetCurrentPrcb();
  ProcessorNumber->Group = CurrentPrcb->Group;
  return CurrentPrcb->Number;
}
"""
        )
        initialize_plan = self._plan(
            """
__int64 __fastcall KiInitializeProcessor(PKPRCB CurrentPrcb)
{
  int processorDpcLimits[10];

  KeInitializeDpc((PRKDPC)&CurrentPrcb->DpcData, KiDpcWatchdog, CurrentPrcb);
  return KiApplyProcessorDpcLimits(CurrentPrcb, processorDpcLimits);
}
"""
        )
        swap_plan = self._plan(
            """
__int64 __fastcall KiSwapThread(PKTHREAD CurrentThread, PKPRCB CurrentPrcb, PVOID WaitStatus)
{
  PKTHREAD nextThread;
  PKCORE_CONTROL_BLOCK coreControlBlock;
  PKSCHEDULER_SUBNODE schedulerSubNode;

  KiAbProcessPreContextSwitch(CurrentThread, WaitStatus);
  coreControlBlock = CurrentPrcb->CoreControlBlock;
  schedulerSubNode = CurrentPrcb->SchedulerSubNode;
  nextThread = KiSearchForNewThread(CurrentPrcb, schedulerSubNode);
  KeGetCurrentPrcb();
  return nextThread != 0 && coreControlBlock != 0;
}
"""
        )
        idle_plan = self._plan(
            """
void __noreturn KiIdleLoop()
{
  struct _KPRCB *CurrentPrcb;
  PKTHREAD IdleThread;
  PKTHREAD NextThread;

  CurrentPrcb = KeGetCurrentPrcb();
  IdleThread = CurrentPrcb->IdleThread;
  NextThread = CurrentPrcb->NextThread;
  KiRetireDpcList(CurrentPrcb);
  SwapContext(NextThread != IdleThread);
}
"""
        )

        processor_number_roles = self._roles(
            processor_number_plan,
            "windows.trap_processor_state.ke_get_current_processor_number_ex",
        )
        initialize_roles = self._roles(initialize_plan, "windows.trap_processor_state.ki_initialize_processor")
        swap_roles = self._roles(swap_plan, "windows.trap_processor_state.ki_swap_thread")
        idle_roles = self._roles(idle_plan, "windows.trap_processor_state.ki_idle_loop")

        self.assertEqual("PROCESSOR_NUMBER_OUTPUT", processor_number_roles["processorNumber"])
        self.assertEqual("KPRCB", processor_number_roles["currentPrcb"])
        self.assertEqual("KPRCB", initialize_roles["currentPrcb"])
        self.assertEqual("DPC_LIMIT_CONFIGURATION", initialize_roles["processorDpcLimits"])
        self.assertEqual("KTHREAD", swap_roles["currentThread"])
        self.assertEqual("KPRCB", swap_roles["currentPrcb"])
        self.assertEqual("KTHREAD", swap_roles["nextThread"])
        self.assertEqual("KCORE_CONTROL_BLOCK", swap_roles["coreControlBlock"])
        self.assertEqual("KSCHEDULER_SUBNODE", swap_roles["schedulerSubNode"])
        self.assertEqual("KPRCB", idle_roles["currentPrcb"])
        self.assertEqual("KTHREAD", idle_roles["idleThread"])
        self.assertEqual("KTHREAD", idle_roles["nextThread"])

    def test_search_for_new_threads_on_target_roles(self) -> None:
        plan = self._plan(
            """
void __fastcall KiSearchForNewThreadsOnTarget(
        struct _KPRCB *argument0,
        __int64 argument1,
        __int64 affinityMask,
        __int64 rescheduleInput,
        unsigned __int64 targetProcessor,
        __int64 flags)
{
  _KI_RESCHEDULE_CONTEXT *staticRescheduleContext;
  unsigned __int64 idleSet;
  __int64 candidateThread;

  if ( argument0 == (struct _KPRCB *)targetProcessor )
  {
    KiSearchForNewThreadsInStandby((__int64)argument0, targetProcessor, argument1, rescheduleInput);
  }
  idleSet = affinityMask & *(_QWORD *)(argument1 + 8);
  candidateThread = *(_QWORD *)(argument1 + 192) + (*(unsigned __int16 *)(argument1 + 136) << 6);
  KiFindRankBiasedIdleSmtSet(argument1, &idleSet);
  staticRescheduleContext = argument0->StaticRescheduleContext;
  KiScheduleThreadToRescheduleContext(&staticRescheduleContext->ProcessorCount, candidateThread, argument1, 0, flags);
  KiCommitRescheduleContext(&staticRescheduleContext->ProcessorCount, argument0, 0, flags);
}
"""
        )

        roles = self._roles(
            plan,
            "windows.trap_processor_state.ki_search_for_new_threads_on_target",
        )
        rename_map = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("KPRCB", roles["targetPrcb"])
        self.assertEqual("KSCHEDULER_SUBNODE", roles["schedulerSubNode"])
        self.assertEqual("targetPrcb", rename_map["argument0"])
        self.assertEqual("schedulerSubNode", rename_map["argument1"])

    def test_search_for_new_threads_on_target_requires_reschedule_flow(self) -> None:
        plan = self._plan(
            """
void __fastcall KiSearchForNewThreadsOnTarget(struct _KPRCB *argument0, __int64 argument1)
{
  unsigned __int64 idleSet;

  idleSet = *(_QWORD *)(argument1 + 8);
  KiFindRankBiasedIdleSmtSet(argument1, &idleSet);
}
"""
        )

        self.assertEqual(
            [],
            self._profile_identities(
                plan,
                "windows.trap_processor_state.ki_search_for_new_threads_on_target",
            ),
        )

    def test_thread_cycle_accumulation_context_swap_roles(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall KiStartThreadCycleAccumulationContextSwap(__int64 argument0, __int64 argument1, __int64 timerContext)
{
  struct _KPRCB *CurrentPrcb;
  _DWORD *schedulerAssist;
  __int64 cycles;

  if ( !*(_BYTE *)(argument0 + 34524) )
  {
    return 0;
  }
  cycles = HalpTimerGetInternalData(HalpPerformanceCounter, argument1, timerContext, 10000000LL);
  *(_QWORD *)(argument0 + 34560) += cycles;
  if ( (*(_BYTE *)(argument1 + 2) & 4) != 0 )
  {
    CurrentPrcb = KeGetCurrentPrcb();
    schedulerAssist = CurrentPrcb->SchedulerAssist;
    KiRemoveSystemWorkPriorityKick(CurrentPrcb, 0, schedulerAssist, 0);
  }
  if ( *(char *)(argument1 + 195) >= 16 )
  {
    *(_QWORD *)(argument1 + 1080) = 0LL;
  }
  return KiInsertDeferredPreemptionApc(argument0, argument1, 1);
}
"""
        )

        roles = self._roles(
            plan,
            "windows.trap_processor_state.ki_start_thread_cycle_accumulation_context_swap",
        )
        rename_map = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("KPRCB", roles["targetPrcb"])
        self.assertEqual("KTHREAD", roles["thread"])
        self.assertEqual("targetPrcb", rename_map["argument0"])
        self.assertEqual("thread", rename_map["argument1"])

    def test_thread_cycle_accumulation_context_swap_requires_scheduler_flow(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall KiStartThreadCycleAccumulationContextSwap(__int64 argument0, __int64 argument1, __int64 timerContext)
{
  return HalpTimerGetInternalData(HalpPerformanceCounter, argument1, timerContext, 10000000LL);
}
"""
        )

        self.assertEqual(
            [],
            self._profile_identities(
                plan,
                "windows.trap_processor_state.ki_start_thread_cycle_accumulation_context_swap",
            ),
        )

    def test_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall KiSaveProcessorControlState(__int64 processorControlState, ULONG xcr0High)
{
  __int64 probe;

  probe = *(_QWORD *)(processorControlState + 0)
        + *(_QWORD *)(processorControlState + 8)
        + *(_QWORD *)(processorControlState + 16)
        + *(_QWORD *)(processorControlState + 24)
        + *(_QWORD *)(processorControlState + 32)
        + *(_QWORD *)(processorControlState + 40)
        + *(_QWORD *)(processorControlState + 48)
        + *(_QWORD *)(processorControlState + 56)
        + *(_QWORD *)(processorControlState + 64)
        + *(_QWORD *)(processorControlState + 72)
        + *(_QWORD *)(processorControlState + 80)
        + *(_QWORD *)(processorControlState + 88);
  __readcr0();
  __sgdt((void *)(processorControlState + 86));
  KeGetPcr();
  return probe + xcr0High;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.trap_processor_state.ki_save_processor_control_state",
            "processorControlState",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "processorControlState"
        ]

        self.assertEqual("KSPECIAL_REGISTERS", identity["structure_name"])
        self.assertEqual("processorControlState", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "processorControlState"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall KiSaveProcessorState(PKTRAP_FRAME TrapFrame, PKEXCEPTION_FRAME ExceptionFrame)
{
  struct _KPRCB *CurrentPrcb;
  PCONTEXT Context;

  CurrentPrcb = KeGetCurrentPrcb();
  Context = CurrentPrcb->Context;
  KeContextFromKframes(TrapFrame, ExceptionFrame, Context);
  return KiSaveProcessorControlState(&CurrentPrcb->ProcessorState, 0);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.trap_processor_state.ki_save_processor_state",
            role="trapFrame",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_trap_frame_type(self) -> None:
        plan = self._plan(
            """
unsigned __int64 __fastcall KeContextFromKframes(int TrapFrame, PKEXCEPTION_FRAME ExceptionFrame, PCONTEXT ContextRecord)
{
  KeGetCurrentIrql();
  KeGetCurrentPrcb();
  return ContextRecord->ContextFlags + ExceptionFrame->P1Home + TrapFrame;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.trap_processor_state.ke_context_from_kframes"
                and item["trusted_role"] == "trapFrame"
                for item in self._identities(plan)
            )
        )

    def test_trap_processor_state_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall KiRestoreProcessorControlState(PKSPECIAL_REGISTERS ProcessorControlState)
{
  __writecr0(ProcessorControlState->Cr0);
  __lgdt(&ProcessorControlState->Gdtr);
  __writedr(7u, ProcessorControlState->KernelDr7);
  return 0;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/trap_processor_state.json" for item in manifests)
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
