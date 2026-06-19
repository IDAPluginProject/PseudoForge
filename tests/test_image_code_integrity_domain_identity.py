from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ImageCodeIntegrityDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_system_image_load_and_unload_roles(self) -> None:
        load_plan = self._plan(
            """
__int64 __fastcall MmLoadSystemImage(PUNICODE_STRING ImageFileName, int ImportName, int ImageFileObject, ULONG LoadFlags, PVOID *SectionPointer, PVOID *ImageBaseAddress)
{
  return MmLoadSystemImageEx(ImageFileName, ImportName, ImageFileObject, LoadFlags, LoadFlags, SectionPointer, ImageBaseAddress);
}
"""
        )
        load_ex_plan = self._plan(
            """
__int64 __fastcall MmLoadSystemImageEx(PUNICODE_STRING ImageFileName, __int64 ImportName, __int64 ImageFileObject, unsigned int UnusedFlags, unsigned int LoadFlags, PVOID *ImageBaseAddress, PLDR_DATA_TABLE_ENTRY *LoaderEntry)
{
  PLDR_DATA_TABLE_ENTRY BaseLoaderPortion;

  BaseLoaderPortion = MiObtainSectionForDriver(ImageFileName, LoadFlags);
  MiMapSystemImage(BaseLoaderPortion, ImageBaseAddress);
  MiValidateStrongCodeDriverImage(BaseLoaderPortion, ImageFileObject);
  *LoaderEntry = BaseLoaderPortion;
  return *ImageBaseAddress != 0;
}
"""
        )
        unload_plan = self._plan(
            """
__int64 __fastcall MmUnloadSystemImage(ULONG_PTR ImageBaseAddress)
{
  MiUnloadSystemImage(ImageBaseAddress);
  return ImageBaseAddress != 0;
}
"""
        )
        mi_unload_plan = self._plan(
            """
void __fastcall MiUnloadSystemImage(ULONG_PTR ImageBaseAddress)
{
  PLDR_DATA_TABLE_ENTRY BaseLoaderPortion;

  BaseLoaderPortion = MiGetBaseLoaderPortion(ImageBaseAddress);
  MiClearDriverTablePtes(BaseLoaderPortion);
}
"""
        )

        load_roles = self._roles(load_plan, "windows.image_code_integrity.mm_load_system_image")
        load_ex_roles = self._roles(load_ex_plan, "windows.image_code_integrity.mm_load_system_image_ex")
        unload_roles = self._roles(unload_plan, "windows.image_code_integrity.mm_unload_system_image")
        mi_unload_roles = self._roles(mi_unload_plan, "windows.image_code_integrity.mi_unload_system_image")

        self.assertEqual("UNICODE_STRING", load_roles["imageFileName"])
        self.assertEqual("SYSTEM_IMAGE_LOAD_FLAGS", load_roles["loadFlags"])
        self.assertEqual("SECTION_OBJECT_OUTPUT", load_roles["sectionPointer"])
        self.assertEqual("IMAGE_BASE_OUTPUT", load_roles["imageBaseAddress"])
        self.assertEqual("UNICODE_STRING", load_ex_roles["imageFileName"])
        self.assertEqual("SYSTEM_IMAGE_LOAD_FLAGS", load_ex_roles["loadFlags"])
        self.assertEqual("IMAGE_BASE_OUTPUT", load_ex_roles["imageBaseAddress"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY_OUTPUT", load_ex_roles["loaderEntry"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", load_ex_roles["baseLoaderPortion"])
        self.assertEqual("IMAGE_BASE", unload_roles["imageBaseAddress"])
        self.assertEqual("IMAGE_BASE", mi_unload_roles["imageBaseAddress"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", mi_unload_roles["baseLoaderPortion"])

    def test_loaded_module_lookup_and_query_roles(self) -> None:
        lookup_plan = self._plan(
            """
__int64 *__fastcall MmFindDataTableEntryByAddress(unsigned __int64 TargetVa)
{
  __int64 moduleEntry;
  unsigned __int64 imageBase;

  moduleEntry = 0;
  imageBase = TargetVa & 0xFFFFFFFFFFFFF000ui64;
  if ( MiImageContainsVa(moduleEntry, TargetVa) )
  {
    return (__int64 *)moduleEntry;
  }
  return (__int64 *)imageBase;
}
"""
        )
        image_info_plan = self._plan(
            """
NTSTATUS __fastcall MmGetImageInformation(unsigned __int64 ImageBaseAddress, PSECTION_IMAGE_INFORMATION ImageInformation, _QWORD *Output, _DWORD *Flags)
{
  PVOID vad;

  vad = MiObtainReferencedVadEx(ImageBaseAddress, Output);
  *Flags = vad != 0;
  return ImageInformation != 0 ? STATUS_SUCCESS : STATUS_SUCCESS;
}
"""
        )
        signature_plan = self._plan(
            """
char __fastcall MmGetImageFileSignatureInformation(void *SectionObject)
{
  MiLockSectionControlArea(SectionObject);
  return SectionObject != 0;
}
"""
        )
        lock_plan = self._plan(
            """
__int64 __fastcall MmLockLoadedDataTableEntry(PLDR_DATA_TABLE_ENTRY LoaderEntry)
{
  return MiLockLoadedDataTableEntry(LoaderEntry);
}
"""
        )
        unlock_plan = self._plan(
            """
__int64 __fastcall MmUnlockLoadedDataTableEntry(PLDR_DATA_TABLE_ENTRY LoaderEntry)
{
  PKTHREAD currentThread;

  currentThread = KeGetCurrentThread();
  MiUnlockLoaderEntry(LoaderEntry);
  MiReleaseLoadLock(currentThread);
  return LoaderEntry != 0;
}
"""
        )
        enumerate_plan = self._plan(
            """
__int64 __fastcall MmEnumerateSystemImages(ULONG InformationClass, PVOID Buffer)
{
  return MiEnumerateSystemImages(InformationClass, Buffer);
}
"""
        )
        query_plan = self._plan(
            """
__int64 __fastcall ExpQueryModuleInformation(int InformationClass, PVOID ModuleInformation, unsigned int BufferLength, ULONG *ReturnLength)
{
  return MmEnumerateSystemImagesShared(InformationClass, ModuleInformation, BufferLength, ReturnLength);
}
"""
        )
        convert_plan = self._plan(
            """
__int64 __fastcall ExpConvertLdrEntryToModuleInfo(ULONG InformationClass, PLDR_DATA_TABLE_ENTRY LoaderEntry, __int16 Index, int Flags, PVOID ModuleInformation)
{
  RtlUnicodeStringToAnsiString(ModuleInformation, LoaderEntry, Flags);
  return InformationClass + Index;
}
"""
        )

        lookup_roles = self._roles(lookup_plan, "windows.image_code_integrity.mm_find_data_table_entry_by_address")
        image_info_roles = self._roles(image_info_plan, "windows.image_code_integrity.mm_get_image_information")
        signature_roles = self._roles(signature_plan, "windows.image_code_integrity.mm_get_image_file_signature_information")
        lock_roles = self._roles(lock_plan, "windows.image_code_integrity.mm_lock_loaded_data_table_entry")
        unlock_roles = self._roles(unlock_plan, "windows.image_code_integrity.mm_unlock_loaded_data_table_entry")
        enumerate_roles = self._roles(enumerate_plan, "windows.image_code_integrity.mm_enumerate_system_images")
        query_roles = self._roles(query_plan, "windows.image_code_integrity.exp_query_module_information")
        convert_roles = self._roles(convert_plan, "windows.image_code_integrity.exp_convert_ldr_entry_to_module_info")

        self.assertEqual("VIRTUAL_ADDRESS", lookup_roles["targetVa"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", lookup_roles["loaderEntry"])
        self.assertEqual("IMAGE_BASE", lookup_roles["imageBase"])
        self.assertEqual("IMAGE_BASE", image_info_roles["imageBaseAddress"])
        self.assertEqual("SECTION_IMAGE_INFORMATION_OUTPUT", image_info_roles["imageInformation"])
        self.assertEqual("SECTION_OBJECT", signature_roles["sectionObject"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", lock_roles["loaderEntry"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", unlock_roles["loaderEntry"])
        self.assertEqual("KTHREAD", unlock_roles["currentThread"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_CLASS", enumerate_roles["informationClass"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_BUFFER", enumerate_roles["buffer"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_CLASS", query_roles["informationClass"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_BUFFER", query_roles["moduleInformation"])
        self.assertEqual("BUFFER_LENGTH", query_roles["bufferLength"])
        self.assertEqual("BUFFER_LENGTH_OUTPUT", query_roles["returnLength"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_CLASS", convert_roles["informationClass"])
        self.assertEqual("LDR_DATA_TABLE_ENTRY", convert_roles["loaderEntry"])
        self.assertEqual("SYSTEM_MODULE_INFORMATION_BUFFER", convert_roles["moduleInformation"])

    def test_image_notify_roles(self) -> None:
        set_plan = self._plan(
            """
NTSTATUS __stdcall PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
  return PsSetLoadImageNotifyRoutineEx(NotifyRoutine, 0);
}
"""
        )
        set_ex_plan = self._plan(
            """
NTSTATUS __fastcall PsSetLoadImageNotifyRoutineEx(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine, ULONG Flags)
{
  int routineIndex;

  routineIndex = ExAllocateCallBack(NotifyRoutine, Flags);
  PspLogAuditSetLoadImageNotifyRoutineEvent(NotifyRoutine, routineIndex);
  return routineIndex;
}
"""
        )
        remove_plan = self._plan(
            """
NTSTATUS __stdcall PsRemoveLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
  ExWaitForRundownProtectionRelease(NotifyRoutine);
  ExFreePoolWithTag(NotifyRoutine, 0);
  return STATUS_SUCCESS;
}
"""
        )
        call_plan = self._plan(
            """
__int64 __fastcall PsCallImageNotifyRoutines(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo, __int64 CreateInfo)
{
  PKTHREAD currentThread;

  currentThread = KeGetCurrentThread();
  guard_dispatch_icall_no_overrides(FullImageName, ProcessId, ImageInfo);
  PerfLogImageLoad(FullImageName, ProcessId, CreateInfo);
  return currentThread != 0;
}
"""
        )

        set_roles = self._roles(set_plan, "windows.image_code_integrity.ps_set_load_image_notify_routine")
        set_ex_roles = self._roles(set_ex_plan, "windows.image_code_integrity.ps_set_load_image_notify_routine_ex")
        remove_roles = self._roles(remove_plan, "windows.image_code_integrity.ps_remove_load_image_notify_routine")
        call_roles = self._roles(call_plan, "windows.image_code_integrity.ps_call_image_notify_routines")

        self.assertEqual("PLOAD_IMAGE_NOTIFY_ROUTINE", set_roles["notifyRoutine"])
        self.assertEqual("PLOAD_IMAGE_NOTIFY_ROUTINE", set_ex_roles["notifyRoutine"])
        self.assertEqual("IMAGE_NOTIFY_FLAGS", set_ex_roles["flags"])
        self.assertEqual("IMAGE_NOTIFY_ROUTINE_INDEX", set_ex_roles["routineIndex"])
        self.assertEqual("PLOAD_IMAGE_NOTIFY_ROUTINE", remove_roles["notifyRoutine"])
        self.assertEqual("UNICODE_STRING", call_roles["fullImageName"])
        self.assertEqual("HANDLE", call_roles["processId"])
        self.assertEqual("IMAGE_INFO", call_roles["imageInfo"])
        self.assertEqual("KTHREAD", call_roles["currentThread"])

    def test_code_integrity_validation_roles(self) -> None:
        validate_plan = self._plan(
            """
__int64 __fastcall SeValidateImageData(ULONG InformationClass, PVOID ObjectInformation)
{
  return guard_dispatch_icall_no_overrides(InformationClass, ObjectInformation);
}
"""
        )
        validate_file_plan = self._plan(
            """
__int64 __fastcall SeValidateFileAsImageType(PFILE_OBJECT FileObject, ULONG ImageType)
{
  return guard_dispatch_icall_no_overrides(FileObject, ImageType);
}
"""
        )
        signing_plan = self._plan(
            """
__int64 __fastcall SeGetImageRequiredSigningLevel(PFILE_OBJECT FileObject, __int64 ImageInfo, char Audit, char Flags, unsigned __int8 *SigningLevel)
{
  PEPROCESS currentProcess;

  currentProcess = IoGetCurrentProcess();
  *SigningLevel = SeCompareSigningLevels(Audit, Flags);
  guard_dispatch_icall_no_overrides(FileObject, SigningLevel);
  return currentProcess != 0;
}
"""
        )
        release_plan = self._plan(
            """
void __fastcall SeReleaseImageValidationContext(void *ValidationContext, __int64 Flags)
{
  guard_dispatch_icall_no_overrides(ValidationContext);
  ExFreePoolWithTag(ValidationContext, Flags);
}
"""
        )
        register_plan = self._plan(
            """
__int64 __fastcall SeRegisterImageVerificationCallback(ULONG InformationClass, int IsBlockMode, CALLBACK_FUNCTION *CallbackRoutine, PVOID CallbackContext, __int64 ReservedFlags, PVOID *CallbackHandle)
{
  *CallbackHandle = ExRegisterCallback(InformationClass, CallbackRoutine, CallbackContext);
  return IsBlockMode + ReservedFlags;
}
"""
        )
        unregister_plan = self._plan(
            """
void __fastcall SeUnregisterImageVerificationCallback(PVOID CallbackHandle)
{
  ExUnregisterCallback(CallbackHandle);
}
"""
        )

        validate_roles = self._roles(validate_plan, "windows.image_code_integrity.se_validate_image_data")
        validate_file_roles = self._roles(validate_file_plan, "windows.image_code_integrity.se_validate_file_as_image_type")
        signing_roles = self._roles(signing_plan, "windows.image_code_integrity.se_get_image_required_signing_level")
        release_roles = self._roles(release_plan, "windows.image_code_integrity.se_release_image_validation_context")
        register_roles = self._roles(register_plan, "windows.image_code_integrity.se_register_image_verification_callback")
        unregister_roles = self._roles(unregister_plan, "windows.image_code_integrity.se_unregister_image_verification_callback")

        self.assertEqual("IMAGE_VALIDATION_INFORMATION_CLASS", validate_roles["informationClass"])
        self.assertEqual("IMAGE_VALIDATION_DATA", validate_roles["objectInformation"])
        self.assertEqual("FILE_OBJECT", validate_file_roles["fileObject"])
        self.assertEqual("IMAGE_TYPE", validate_file_roles["imageType"])
        self.assertEqual("FILE_OBJECT", signing_roles["fileObject"])
        self.assertEqual("SIGNING_LEVEL_OUTPUT", signing_roles["signingLevel"])
        self.assertEqual("EPROCESS", signing_roles["currentProcess"])
        self.assertEqual("IMAGE_VALIDATION_CONTEXT", release_roles["validationContext"])
        self.assertEqual("IMAGE_VERIFICATION_INFORMATION_CLASS", register_roles["informationClass"])
        self.assertEqual("IMAGE_VERIFICATION_CALLBACK", register_roles["callbackRoutine"])
        self.assertEqual("CALLBACK_CONTEXT", register_roles["callbackContext"])
        self.assertEqual("CALLBACK_HANDLE_OUTPUT", register_roles["callbackHandle"])
        self.assertEqual("CALLBACK_HANDLE", unregister_roles["callbackHandle"])

    def test_ci_initialization_callback_and_policy_roles(self) -> None:
        initialize_plan = self._plan(
            """
__int64 SepInitializeCodeIntegrity()
{
  ULONG ciInfoClass;
  PVOID ciContextPtr;
  PVOID bootOptionsPtr;
  PVOID bootCommandLine;

  ciInfoClass = 0;
  ciContextPtr = bootOptionsPtr;
  bootCommandLine = bootOptionsPtr;
  return CiInitialize(ciInfoClass, ciContextPtr, bootCommandLine);
}
"""
        )
        worker_plan = self._plan(
            """
void __fastcall SepImageVerificationCallbackWorker(unsigned int *ParameterBlock)
{
  PVOID callbackObj;

  callbackObj = ParameterBlock;
  ExNotifyWithProcessing(callbackObj, ParameterBlock);
}
"""
        )
        schedule_plan = self._plan(
            """
__int64 __fastcall SepScheduleImageVerificationCallbacks(PVOID CallbackData, unsigned int InformationClass, int Flags, int QueueType)
{
  PVOID newProviderRecord;

  newProviderRecord = ExAllocatePool2(0, 128, 0x496D6753u);
  ExQueueWorkItem(newProviderRecord, QueueType);
  return InformationClass + Flags + (CallbackData != 0);
}
"""
        )
        min_tcb_plan = self._plan(
            """
__int64 __fastcall SepIsImageInMinTcbList(PVOID MinTcbList, unsigned int EntryCount, const UNICODE_STRING *TargetImagePath, char ProcessFlags, unsigned __int8 Attributes, char AuditMode, unsigned __int8 *SigningLevel, char *SecondChar, unsigned __int8 *StatusFlags)
{
  *SigningLevel = Attributes;
  return EntryCount + ProcessFlags + AuditMode + StatusFlags[0] + TargetImagePath->Length + SecondChar[0] + (MinTcbList != 0);
}
"""
        )

        initialize_roles = self._roles(initialize_plan, "windows.image_code_integrity.sep_initialize_code_integrity")
        worker_roles = self._roles(worker_plan, "windows.image_code_integrity.sep_image_verification_callback_worker")
        schedule_roles = self._roles(schedule_plan, "windows.image_code_integrity.sep_schedule_image_verification_callbacks")
        min_tcb_roles = self._roles(min_tcb_plan, "windows.image_code_integrity.sep_is_image_in_min_tcb_list")

        self.assertEqual("CI_INFORMATION_CLASS", initialize_roles["ciInfoClass"])
        self.assertEqual("CI_INITIALIZATION_CONTEXT", initialize_roles["ciContext"])
        self.assertEqual("LOADER_PARAMETER_BLOCK", initialize_roles["bootOptions"])
        self.assertEqual("IMAGE_VERIFICATION_CALLBACK_BLOCK", worker_roles["parameterBlock"])
        self.assertEqual("CALLBACK_OBJECT", worker_roles["callbackObject"])
        self.assertEqual("IMAGE_VERIFICATION_CALLBACK_DATA", schedule_roles["callbackData"])
        self.assertEqual("IMAGE_VERIFICATION_INFORMATION_CLASS", schedule_roles["informationClass"])
        self.assertEqual("WORK_QUEUE_ITEM", schedule_roles["workItem"])
        self.assertEqual("MIN_TCB_IMAGE_LIST", min_tcb_roles["minTcbList"])
        self.assertEqual("IMAGE_LIST_ENTRY_COUNT", min_tcb_roles["entryCount"])
        self.assertEqual("UNICODE_STRING", min_tcb_roles["targetImagePath"])
        self.assertEqual("SIGNING_LEVEL_OUTPUT", min_tcb_roles["signingLevel"])

    def test_protection_signature_and_driver_block_roles(self) -> None:
        protection_plan = self._plan(
            """
__int64 __fastcall PspGetProcessProtectionRequirementsFromImage(PVOID SectionObject)
{
  char protectionFlag;

  protectionFlag = RtlTestProtectedAccess(SectionObject);
  MiSectionControlArea(SectionObject);
  return protectionFlag;
}
"""
        )
        signature_plan = self._plan(
            """
NTSTATUS __fastcall PsQuerySectionSignatureInformation(_KPROCESS *Process, PVOID SignatureInformation)
{
  ExAcquireRundownProtection_0(Process);
  MiSectionControlArea(SignatureInformation);
  return STATUS_SUCCESS;
}
"""
        )
        blocked_plan = self._plan(
            """
NTSTATUS __fastcall PiIsDriverBlocked(PUNICODE_STRING DriverName, __int64 Version, __int64 Catalog, ULONG DriverFlags, PVOID DriverBlockInfo)
{
  PiIsHVCIEnabled();
  return PiNotifyCiDriverBlocked(DriverBlockInfo, DriverFlags, DriverName);
}
"""
        )
        notify_plan = self._plan(
            """
NTSTATUS __fastcall PiNotifyCiDriverBlocked(PVOID DriverInfo, NTSTATUS DriverStatus, PVOID *PayloadPointers)
{
  PVOID ciDataBlock;

  ciDataBlock = DriverInfo;
  ZwUpdateWnfStateData(ciDataBlock, PayloadPointers, DriverStatus);
  return DriverStatus;
}
"""
        )

        protection_roles = self._roles(protection_plan, "windows.image_code_integrity.psp_get_process_protection_requirements_from_image")
        signature_roles = self._roles(signature_plan, "windows.image_code_integrity.ps_query_section_signature_information")
        blocked_roles = self._roles(blocked_plan, "windows.image_code_integrity.pi_is_driver_blocked")
        notify_roles = self._roles(notify_plan, "windows.image_code_integrity.pi_notify_ci_driver_blocked")

        self.assertEqual("SECTION_OBJECT", protection_roles["sectionObject"])
        self.assertEqual("PS_PROTECTION", protection_roles["protectionFlag"])
        self.assertEqual("EPROCESS", signature_roles["process"])
        self.assertEqual("SECTION_SIGNATURE_INFORMATION_OUTPUT", signature_roles["signatureInformation"])
        self.assertEqual("UNICODE_STRING", blocked_roles["driverName"])
        self.assertEqual("DRIVER_BLOCK_FLAGS", blocked_roles["driverFlags"])
        self.assertEqual("CI_BLOCKED_DRIVER_INFO", blocked_roles["driverBlockInfo"])
        self.assertEqual("CI_BLOCKED_DRIVER_INFO", notify_roles["driverInfo"])
        self.assertEqual("NTSTATUS", notify_roles["driverStatus"])
        self.assertEqual("WNF_PAYLOAD_POINTER_ARRAY", notify_roles["payloadPointers"])
        self.assertEqual("CI_BLOCKED_DRIVER_INFO", notify_roles["ciDataBlock"])

    def test_report_only_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall MmLockLoadedDataTableEntry(__int64 loaderEntry)
{
  __int64 probe;

  probe = *(_QWORD *)(loaderEntry + 16)
        + *(_QWORD *)(loaderEntry + 24)
        + *(_QWORD *)(loaderEntry + 32)
        + *(_QWORD *)(loaderEntry + 40)
        + *(_QWORD *)(loaderEntry + 48)
        + *(_QWORD *)(loaderEntry + 56)
        + *(_QWORD *)(loaderEntry + 64)
        + *(_QWORD *)(loaderEntry + 72)
        + *(_QWORD *)(loaderEntry + 80)
        + *(_QWORD *)(loaderEntry + 88)
        + *(_QWORD *)(loaderEntry + 96)
        + *(_QWORD *)(loaderEntry + 104);
  return probe + MiLockLoadedDataTableEntry(loaderEntry);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.image_code_integrity.mm_lock_loaded_data_table_entry",
            "loaderEntry",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "loaderEntry"
        ]

        self.assertEqual("LDR_DATA_TABLE_ENTRY", identity["structure_name"])
        self.assertEqual("loaderEntry", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "loaderEntry"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
  return PsSetLoadImageNotifyRoutineEx(NotifyRoutine, 0);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.image_code_integrity.ps_set_load_image_notify_routine",
            role="notifyRoutine",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_notify_type(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall PsSetLoadImageNotifyRoutine(int NotifyRoutine)
{
  return PsSetLoadImageNotifyRoutineEx(NotifyRoutine, 0);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.image_code_integrity.ps_set_load_image_notify_routine"
                and item["trusted_role"] == "notifyRoutine"
                for item in self._identities(plan)
            )
        )

    def test_image_code_integrity_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
NTSTATUS __stdcall PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
  return PsSetLoadImageNotifyRoutineEx(NotifyRoutine, 0);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/image_code_integrity.json" for item in manifests)
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
