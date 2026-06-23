from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class FileCacheSectionDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_nt_create_and_open_file_roles(self) -> None:
        create_plan = self._plan(
            """
NTSTATUS __stdcall NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
  return IopCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength, 0, 0, 0, 32, 0);
}
"""
        )
        open_plan = self._plan(
            """
NTSTATUS __stdcall NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
  return IopCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, 0, 0, ShareAccess, 1, OpenOptions, 0, 0, 0, 0, 0, 32, 0);
}
"""
        )

        create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                create_plan,
                "windows.file_cache_section.nt_create_file",
            )
        }
        open_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                open_plan,
                "windows.file_cache_section.nt_open_file",
            )
        }

        self.assertEqual("HANDLE_OUTPUT", create_roles["fileHandleOutput"])
        self.assertEqual("ACCESS_MASK", create_roles["desiredAccess"])
        self.assertEqual("OBJECT_ATTRIBUTES", create_roles["objectAttributes"])
        self.assertEqual("IO_STATUS_BLOCK", create_roles["ioStatusBlock"])
        self.assertEqual("LARGE_INTEGER", create_roles["allocationSize"])
        self.assertEqual("FILE_ATTRIBUTES", create_roles["fileAttributes"])
        self.assertEqual("FILE_SHARE_ACCESS", create_roles["shareAccess"])
        self.assertEqual("FILE_CREATE_DISPOSITION", create_roles["createDisposition"])
        self.assertEqual("FILE_CREATE_OPTIONS", create_roles["createOptions"])
        self.assertEqual("FILE_EA_BUFFER", create_roles["eaBuffer"])
        self.assertEqual("BUFFER_LENGTH", create_roles["eaLength"])
        self.assertEqual("HANDLE_OUTPUT", open_roles["fileHandleOutput"])
        self.assertEqual("FILE_SHARE_ACCESS", open_roles["shareAccess"])
        self.assertEqual("FILE_OPEN_OPTIONS", open_roles["openOptions"])

    def test_io_create_file_and_ex_roles(self) -> None:
        create_plan = self._plan(
            """
NTSTATUS __stdcall IoCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, CREATE_FILE_TYPE CreateFileType, PVOID InternalParameters, ULONG Options)
{
  return IopCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, 0, 0);
}
"""
        )
        ex_plan = self._plan(
            """
NTSTATUS __stdcall IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, CREATE_FILE_TYPE CreateFileType, PVOID InternalParameters, ULONG Options, PIO_DRIVER_CREATE_CONTEXT DriverContext)
{
  PECP_LIST BugCheckParameter4;
  struct _LIST_ENTRY *Flink;

  BugCheckParameter4 = DriverContext->ExtraCreateParameter;
  Flink = BugCheckParameter4->EcpList.Flink;
  return IopCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options, 1, DriverContext);
}
"""
        )

        create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                create_plan,
                "windows.file_cache_section.io_create_file",
            )
        }
        ex_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                ex_plan,
                "windows.file_cache_section.io_create_file_ex",
            )
        }

        self.assertEqual("HANDLE_OUTPUT", create_roles["fileHandleOutput"])
        self.assertEqual("OBJECT_ATTRIBUTES", create_roles["objectAttributes"])
        self.assertEqual("IO_STATUS_BLOCK", create_roles["ioStatusBlock"])
        self.assertEqual("CREATE_FILE_TYPE", create_roles["createFileType"])
        self.assertEqual("IO_CREATE_INTERNAL_PARAMETERS", create_roles["internalParameters"])
        self.assertEqual("HANDLE_OUTPUT", ex_roles["fileHandleOutput"])
        self.assertEqual("IO_DRIVER_CREATE_CONTEXT", ex_roles["driverCreateContext"])
        self.assertEqual("ECP_LIST", ex_roles["extraCreateParameterList"])
        self.assertEqual("ECP_ENTRY", ex_roles["extraCreateParameterEntry"])

    def test_iop_create_file_roles(self) -> None:
        plan = self._plan(
            """
NTSTATUS __fastcall IopCreateFile(HANDLE *a1, int a2, __int64 a3, NTSTATUS *a4, HANDLE *a5, int a6, int a7, unsigned int a8, int a9, __int64 a10, unsigned int a11, int a12, _DWORD *a13, int a14, int a15, __int16 *Src)
{
  HANDLE Handle;
  PECP_LIST EcpList;
  __int64 newProviderRecord;
  struct _KTHREAD *currentThread;

  EcpList = 0;
  newProviderRecord = ExAllocatePool2(0x100, 0x6C, 0x6A536F49);
  currentThread = KeGetCurrentThread();
  ObOpenObjectByNameEx(a3, IoFileObjectType, 0, 0, a2, EcpList, 0, &Handle);
  *a1 = Handle;
  return *a4 + a15 + (NTSTATUS)newProviderRecord + currentThread->OtherOperationCount;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.file_cache_section.iop_create_file",
            )
        }

        self.assertEqual("HANDLE_OUTPUT", roles["fileHandleOutput"])
        self.assertEqual("ACCESS_MASK", roles["desiredAccess"])
        self.assertEqual("OBJECT_ATTRIBUTES", roles["objectAttributes"])
        self.assertEqual("IO_STATUS_BLOCK", roles["ioStatusBlock"])
        self.assertEqual("FILE_EA_BUFFER", roles["eaBuffer"])
        self.assertEqual("IO_CREATE_FILE_FLAGS", roles["createFlags"])
        self.assertEqual("HANDLE", roles["openedFileHandle"])
        self.assertEqual("ECP_LIST", roles["extraCreateParameterList"])
        self.assertEqual("ECP_ENTRY", roles["extraCreateParameterEntry"])
        self.assertEqual("ETHREAD", roles["currentThread"])
        self.assertTrue(all(item["effective_mode"] == "report-only" for item in self._profile_identities(plan, "windows.file_cache_section.iop_create_file")))
        self.assertEqual("eaBuffer", self._rename_map(plan).get("a10"))

    def test_iop_parse_device_roles(self) -> None:
        plan = self._plan(
            """
NTSTATUS __fastcall IopParseDevice(unsigned int *ParseObject, POBJECT_TYPE *ObjectType, struct _ACCESS_STATE *AccessState, unsigned __int8 ParseMode, unsigned int Attributes, UNICODE_STRING *RemainingName, const UNICODE_STRING *CompleteName, __int64 ParseContext, __int64 SecurityQos, _QWORD *ParseInformation, _QWORD *ExtensionData)
{
  PFILE_OBJECT relatedFileObject;
  PDEVICE_OBJECT relatedDeviceObject;
  PDRIVER_OBJECT driverObject;
  PFAST_IO_DISPATCH fastIoDispatch;
  PIRP Irp;

  relatedFileObject = (PFILE_OBJECT)ParseObject;
  relatedDeviceObject = IoGetRelatedDeviceObject(relatedFileObject);
  driverObject = relatedDeviceObject->DriverObject;
  fastIoDispatch = driverObject->FastIoDispatch;
  Irp = IoAllocateIrp(relatedDeviceObject->StackSize, 0);
  return RemainingName->Length + AccessState->RemainingDesiredAccess + (NTSTATUS)ParseInformation[0] + (NTSTATUS)Irp + (NTSTATUS)fastIoDispatch;
}
"""
        )

        roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                plan,
                "windows.file_cache_section.iop_parse_device",
            )
        }

        self.assertEqual("ACCESS_STATE", roles["accessState"])
        self.assertEqual("UNICODE_STRING", roles["remainingName"])
        self.assertEqual("OPEN_PACKET", roles["parseContext"])
        self.assertEqual("IO_PARSE_INFORMATION_OUTPUT", roles["parseInformationOutput"])
        self.assertEqual("FILE_OBJECT", roles["relatedFileObject"])
        self.assertEqual("DEVICE_OBJECT", roles["relatedDeviceObject"])
        self.assertEqual("DRIVER_OBJECT", roles["driverObject"])
        self.assertEqual("FAST_IO_DISPATCH", roles["fastIoDispatch"])
        self.assertEqual("IRP", roles["parseIrp"])

    def test_iop_parse_device_parse_context_open_packet_fields(self) -> None:
        plan = self._plan(
            """
NTSTATUS __fastcall IopParseDevice(unsigned int *ParseObject, POBJECT_TYPE *ObjectType, struct _ACCESS_STATE *AccessState, unsigned __int8 ParseMode, unsigned int Attributes, UNICODE_STRING *RemainingName, const UNICODE_STRING *CompleteName, __int64 a8, __int64 SecurityQos, _QWORD *ParseInformation, _QWORD *ExtensionData)
{
  PFILE_OBJECT relatedFileObject;
  PDEVICE_OBJECT relatedDeviceObject;

  if ( !a8 || *(_WORD *)a8 != 8 || *(_WORD *)(a8 + 2) != 224 )
    return STATUS_INVALID_PARAMETER;
  relatedFileObject = *(PFILE_OBJECT *)(a8 + 8);
  relatedDeviceObject = IoGetRelatedDeviceObject(relatedFileObject);
  *(_DWORD *)(a8 + 16) = STATUS_SUCCESS;
  *(_QWORD *)(a8 + 24) = ParseInformation[0];
  *(_DWORD *)(a8 + 32) = 0;
  *(_QWORD *)(a8 + 40) = relatedFileObject;
  *(_DWORD *)(a8 + 64) |= Attributes;
  *(_WORD *)(a8 + 68) = 0x80;
  *(_WORD *)(a8 + 70) = 7;
  *(_DWORD *)(a8 + 84) |= 1;
  *(_DWORD *)(a8 + 88) = 1;
  *(_BYTE *)(a8 + 136) = 1;
  *(_BYTE *)(a8 + 137) = 0;
  *(_BYTE *)(a8 + 138) = 0;
  *(_BYTE *)(a8 + 139) = 1;
  *(_DWORD *)(a8 + 152) |= 0x10;
  *(_QWORD *)(a8 + 168) = SecurityQos;
  return (NTSTATUS)relatedDeviceObject;
}
"""
        )

        identity = self._single_identity(
            plan,
            "windows.file_cache_section.iop_parse_device",
            "parseContext",
        )
        fields = {item["name"]: item["offset"] for item in identity["fields"]}
        aliases = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_field_aliases"
            and item.get("base") == identity["base"]
        ]

        self.assertEqual("OPEN_PACKET", identity["structure"])
        self.assertIn(identity["effective_mode"], {"preview-rewrite", "report-only"})
        self.assertEqual(0x0, fields["Type"])
        self.assertEqual(0x2, fields["Size"])
        self.assertEqual(0x8, fields["FileObject"])
        self.assertEqual(0x10, fields["FinalStatus"])
        self.assertEqual(0x98, fields["InternalFlags"])
        self.assertEqual(0xA8, fields["DriverCreateContext"])
        self.assertTrue(any("FinalStatus=+0x10 NTSTATUS" in item["text"] for item in aliases))
        self.assertTrue(
            any(
                field.get("name") == "DriverCreateContext"
                for item in aliases
                for field in item.get("fields", [])
            )
        )

    def test_section_create_and_map_roles(self) -> None:
        nt_create_plan = self._plan(
            """
NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
  return MiCreateSectionCommon(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, 0, 0, 1, 0);
}
"""
        )
        mm_create_plan = self._plan(
            """
__int64 __fastcall MmCreateSection(int SectionHandle, __int64 ObjectAttributes, int DesiredAccess, _QWORD *MaximumSize, int PageProtection, int AllocationAttributes, __int64 FileHandle, __int64 Reserved)
{
  return MmCreateSectionEx(SectionHandle, DesiredAccess, *MaximumSize, PageProtection, AllocationAttributes, FileHandle, Reserved, 0, 0, 0, 0);
}
"""
        )
        mi_create_plan = self._plan(
            """
__int64 __fastcall MiCreateImageOrDataSection(__int64 SectionCreateContext)
{
  PVOID referencedObject;
  PFILE_OBJECT v6;
  __int64 FileMemoryPartitionInformation;
  __int64 *v36;

  ObpReferenceObjectByHandleWithTag(*(HANDLE *)(SectionCreateContext + 40), 0, IoFileObjectType, 0, 0, &referencedObject, 0, 0);
  v6 = (PFILE_OBJECT)referencedObject;
  FileMemoryPartitionInformation = IoGetFileMemoryPartitionInformation(v6);
  v36 = 0;
  return (NTSTATUS)((unsigned __int64)v6 + FileMemoryPartitionInformation + (unsigned __int64)v36);
}
"""
        )
        nt_map_plan = self._plan(
            """
__int64 __fastcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONGLONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, int InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
  return MiMapViewOfSectionCommon(ProcessHandle, SectionHandle, 0, BaseAddress, ViewSize, SectionOffset, Win32Protect, ZeroBits, 0, 0);
}
"""
        )
        mi_map_plan = self._plan(
            """
__int64 __fastcall MiMapViewOfSection(__int64 SectionObject, __int64 Vad, unsigned __int64 *BaseAddress, unsigned __int64 ViewSize, _WORD *BaseAddressPtr, int InheritDisposition, int ExecuteInheritance)
{
  struct _KPROCESS *associated_process;
  unsigned __int64 section_control_area_ptr;

  associated_process = *(struct _KPROCESS **)(Vad + 88);
  section_control_area_ptr = MiSectionControlArea(SectionObject);
  return (NTSTATUS)((unsigned __int64)associated_process + section_control_area_ptr + *BaseAddress + ViewSize);
}
"""
        )

        nt_create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(nt_create_plan, "windows.file_cache_section.nt_create_section")
        }
        mm_create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(mm_create_plan, "windows.file_cache_section.mm_create_section")
        }
        mi_create_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(mi_create_plan, "windows.file_cache_section.mi_create_image_or_data_section")
        }
        nt_map_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(nt_map_plan, "windows.file_cache_section.nt_map_view_of_section")
        }
        mi_map_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(mi_map_plan, "windows.file_cache_section.mi_map_view_of_section")
        }

        self.assertEqual("HANDLE_OUTPUT", nt_create_roles["sectionHandleOutput"])
        self.assertEqual("ACCESS_MASK", nt_create_roles["desiredAccess"])
        self.assertEqual("OBJECT_ATTRIBUTES", nt_create_roles["objectAttributes"])
        self.assertEqual("LARGE_INTEGER", nt_create_roles["maximumSize"])
        self.assertEqual("PAGE_PROTECTION", nt_create_roles["sectionPageProtection"])
        self.assertEqual("SECTION_ALLOCATION_ATTRIBUTES", nt_create_roles["allocationAttributes"])
        self.assertEqual("HANDLE", nt_create_roles["fileHandle"])
        self.assertEqual("HANDLE_OUTPUT", mm_create_roles["sectionHandleOutput"])
        self.assertEqual("HANDLE", mm_create_roles["fileHandle"])
        self.assertEqual("MI_SECTION_CREATE_CONTEXT", mi_create_roles["sectionCreateContext"])
        self.assertEqual("FILE_OBJECT", mi_create_roles["referencedFileObject"])
        self.assertEqual("FILE_MEMORY_PARTITION_INFORMATION", mi_create_roles["fileMemoryPartitionInformation"])
        self.assertEqual("CONTROL_AREA_OUTPUT", mi_create_roles["controlAreaOutput"])
        self.assertEqual("HANDLE", nt_map_roles["sectionHandle"])
        self.assertEqual("HANDLE", nt_map_roles["processHandle"])
        self.assertEqual("VIRTUAL_ADDRESS_OUTPUT", nt_map_roles["baseAddressOutput"])
        self.assertEqual("SIZE_T_OUTPUT", nt_map_roles["viewSizeOutput"])
        self.assertEqual("PAGE_PROTECTION", nt_map_roles["win32Protect"])
        self.assertEqual("SECTION_OBJECT", mi_map_roles["sectionObject"])
        self.assertEqual("MMVAD", mi_map_roles["vad"])
        self.assertEqual("VIRTUAL_ADDRESS_OUTPUT", mi_map_roles["baseAddressOutput"])
        self.assertEqual("SIZE_T", mi_map_roles["viewSize"])
        self.assertEqual("EPROCESS", mi_map_roles["associatedProcess"])
        self.assertEqual("CONTROL_AREA", mi_map_roles["sectionControlArea"])

    def test_mi_map_view_of_data_section_identifies_control_area(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall MiMapViewOfDataSection(__int64 argument0, __int64 viewContext, unsigned __int64 *baseAddress, unsigned __int64 *sectionOffset)
{
  unsigned __int64 controlAreaPtes;
  unsigned int *subsectionNode;

  if ( MiAweControlArea(argument0) )
  {
    return STATUS_INVALID_PARAMETER;
  }
  controlAreaPtes = MiGetControlAreaPtes(argument0, 0, 0, 0);
  if ( *sectionOffset >= controlAreaPtes )
  {
    MiDereferenceControlArea(argument0);
    return STATUS_INVALID_VIEW_SIZE;
  }
  subsectionNode = MiLocateSubsectionNode(argument0, *sectionOffset, 0, 0);
  MiInsertSharedCommitNode(argument0, *baseAddress, 0);
  return subsectionNode[9];
}
"""
        )

        identity = self._single_identity(
            plan,
            "windows.file_cache_section.mi_map_view_of_data_section",
            role="controlArea",
        )
        rename_map = self._rename_map(plan)

        self.assertEqual("CONTROL_AREA", identity["structure_name"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual("controlArea", rename_map["argument0"])

    def test_mi_map_view_of_data_section_requires_control_area_flow(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall MiMapViewOfDataSection(__int64 argument0, __int64 viewContext)
{
  if ( MiAweControlArea(argument0) )
  {
    return STATUS_INVALID_PARAMETER;
  }
  return viewContext;
}
"""
        )

        self.assertEqual(
            [],
            self._profile_identities(plan, "windows.file_cache_section.mi_map_view_of_data_section"),
        )

    def test_cache_map_initialize_uninitialize_and_sizes_roles(self) -> None:
        init_plan = self._plan(
            """
void __stdcall CcInitializeCacheMap(PFILE_OBJECT FileObject, PCC_FILE_SIZES FileSizes, BOOLEAN PinAccess, PCACHE_MANAGER_CALLBACKS Callbacks, PVOID LazyWriteContext)
{
  CcInitializeCacheMapInternal(FileObject, FileSizes, LazyWriteContext, PinAccess);
}
"""
        )
        uninit_plan = self._plan(
            """
BOOLEAN __stdcall CcUninitializeCacheMap(PFILE_OBJECT FileObject, PLARGE_INTEGER TruncateSize, PCACHE_UNINITIALIZE_EVENT UninitializeEvent)
{
  PFILE_OBJECT *privateCacheMap;
  char *sharedCacheMap;
  PVOID fsContext;

  privateCacheMap = (PFILE_OBJECT *)FileObject->PrivateCacheMap;
  sharedCacheMap = (char *)FileObject->SectionObjectPointer->SharedCacheMap;
  fsContext = FileObject->FsContext;
  return privateCacheMap != 0 || sharedCacheMap != 0 || fsContext != 0 || TruncateSize || UninitializeEvent;
}
"""
        )
        sizes_plan = self._plan(
            """
void __stdcall CcSetFileSizes(PFILE_OBJECT FileObject, PCC_FILE_SIZES FileSizes)
{
  CcSetFileSizesEx(FileObject, FileSizes);
}
"""
        )

        init_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(init_plan, "windows.file_cache_section.cc_initialize_cache_map")
        }
        uninit_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(uninit_plan, "windows.file_cache_section.cc_uninitialize_cache_map")
        }
        sizes_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(sizes_plan, "windows.file_cache_section.cc_set_file_sizes")
        }

        self.assertEqual("FILE_OBJECT", init_roles["fileObject"])
        self.assertEqual("CC_FILE_SIZES", init_roles["fileSizes"])
        self.assertEqual("BOOLEAN", init_roles["pinAccess"])
        self.assertEqual("CACHE_MANAGER_CALLBACKS", init_roles["callbacks"])
        self.assertEqual("CACHE_LAZY_WRITE_CONTEXT", init_roles["lazyWriteContext"])
        self.assertEqual("FILE_OBJECT", uninit_roles["fileObject"])
        self.assertEqual("LARGE_INTEGER", uninit_roles["truncateSize"])
        self.assertEqual("CACHE_UNINITIALIZE_EVENT", uninit_roles["uninitializeEvent"])
        self.assertEqual("PRIVATE_CACHE_MAP", uninit_roles["privateCacheMap"])
        self.assertEqual("SHARED_CACHE_MAP", uninit_roles["sharedCacheMap"])
        self.assertEqual("FSRTL_COMMON_FCB_HEADER", uninit_roles["fsContext"])
        self.assertEqual("FILE_OBJECT", sizes_roles["fileObject"])
        self.assertEqual("CC_FILE_SIZES", sizes_roles["fileSizes"])

    def test_cache_io_flush_purge_roles(self) -> None:
        flush_plan = self._plan(
            """
void __stdcall CcFlushCache(PSECTION_OBJECT_POINTERS SectionObjectPointer, PLARGE_INTEGER FileOffset, ULONG Length, PIO_STATUS_BLOCK IoStatus)
{
  CcFlushCachePriv(SectionObjectPointer, FileOffset, Length, 0, 0, IoStatus, 0);
}
"""
        )
        purge_plan = self._plan(
            """
BOOLEAN __stdcall CcPurgeCacheSection(PSECTION_OBJECT_POINTERS SectionObjectPointer, PLARGE_INTEGER FileOffset, ULONG Length, ULONG Flags)
{
  _QWORD *SharedCacheMap;
  _QWORD *i;

  SharedCacheMap = SectionObjectPointer->SharedCacheMap;
  for ( i = SharedCacheMap + 29; i != SharedCacheMap; i = (_QWORD *)*i )
  {
    CcUninitializeCacheMap(*(PFILE_OBJECT *)(*i - 88), 0, 0);
  }
  return MmTrimSection(SectionObjectPointer, FileOffset, Length, Flags) >= 0;
}
"""
        )
        read_plan = self._plan(
            """
BOOLEAN __stdcall CcCopyRead(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, PVOID Buffer, PIO_STATUS_BLOCK IoStatus)
{
  return CcCopyReadEx(FileObject, FileOffset, Length, Wait, Buffer, IoStatus, 0);
}
"""
        )
        write_plan = self._plan(
            """
BOOLEAN __stdcall CcCopyWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, PVOID Buffer)
{
  return CcCopyWriteEx(FileObject, Buffer, Length);
}
"""
        )

        flush_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(flush_plan, "windows.file_cache_section.cc_flush_cache")
        }
        purge_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(purge_plan, "windows.file_cache_section.cc_purge_cache_section")
        }
        read_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(read_plan, "windows.file_cache_section.cc_copy_read")
        }
        write_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(write_plan, "windows.file_cache_section.cc_copy_write")
        }

        self.assertEqual("SECTION_OBJECT_POINTERS", flush_roles["sectionObjectPointers"])
        self.assertEqual("LARGE_INTEGER", flush_roles["fileOffset"])
        self.assertEqual("BUFFER_LENGTH", flush_roles["length"])
        self.assertEqual("IO_STATUS_BLOCK", flush_roles["ioStatusBlock"])
        self.assertEqual("SECTION_OBJECT_POINTERS", purge_roles["sectionObjectPointers"])
        self.assertEqual("CC_PURGE_FLAGS", purge_roles["purgeFlags"])
        self.assertEqual("SHARED_CACHE_MAP", purge_roles["sharedCacheMap"])
        self.assertEqual("VACB", purge_roles["vacbEntry"])
        self.assertEqual("FILE_OBJECT", read_roles["fileObject"])
        self.assertEqual("USER_BUFFER", read_roles["buffer"])
        self.assertEqual("IO_STATUS_BLOCK", read_roles["ioStatusBlock"])
        self.assertEqual("FILE_OBJECT", write_roles["fileObject"])
        self.assertEqual("USER_BUFFER", write_roles["buffer"])

    def test_shared_cache_map_reference_and_paging_file_roles(self) -> None:
        reference_plan = self._plan(
            """
__int64 __fastcall CcReferenceSharedCacheMapFileObject(__int64 fileObjectPtr)
{
  signed __int64 currentSharedCacheMapValue;
  ULONG_PTR baseCacheMapPtr;

  currentSharedCacheMapValue = *(_QWORD *)(fileObjectPtr + 96);
  baseCacheMapPtr = currentSharedCacheMapValue & 0xFFFFFFFFFFFFFFF0uLL;
  ObpTraceObjectReferenceIfActive(baseCacheMapPtr - 48, 1, 1666409283);
  return baseCacheMapPtr;
}
"""
        )
        paging_plan = self._plan(
            """
_BOOL8 __fastcall MmIsFileObjectAPagingFile(unsigned __int64 fileObjectPtr, __int64 pebLockPtr, __int64 contextPtr1, __int64 contextPtr2)
{
  unsigned __int64 targetFileObject;
  _QWORD *tailLink;

  targetFileObject = fileObjectPtr;
  tailLink = (_QWORD *)qword_140E37300;
  return tailLink && targetFileObject;
}
"""
        )

        reference_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                reference_plan,
                "windows.file_cache_section.cc_reference_shared_cache_map_file_object",
            )
        }
        paging_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                paging_plan,
                "windows.file_cache_section.mm_is_file_object_a_paging_file",
            )
        }

        self.assertEqual("FILE_OBJECT", reference_roles["fileObject"])
        self.assertEqual("SHARED_CACHE_MAP_ENCODED", reference_roles["sharedCacheMapEncodedValue"])
        self.assertEqual("SHARED_CACHE_MAP", reference_roles["sharedCacheMap"])
        self.assertEqual("FILE_OBJECT", paging_roles["fileObject"])
        self.assertEqual("FILE_OBJECT", paging_roles["targetFileObject"])
        self.assertEqual("MM_PAGING_FILE_NODE", paging_roles["pagingFileTreeNode"])

    def test_fsrtl_mod_write_roles(self) -> None:
        acquire_plan = self._plan(
            """
NTSTATUS __fastcall FsRtlAcquireFileForModWriteEx(PFILE_OBJECT FileObject, __int64 Flags, __int64 ResourceOut)
{
  PDEVICE_OBJECT relatedDeviceObject;
  PDEVICE_OBJECT baseFileSystemDeviceObject;
  PFAST_IO_DISPATCH fastIoDispatch;
  PVOID fsContext;

  relatedDeviceObject = IoGetRelatedDeviceObject(FileObject);
  baseFileSystemDeviceObject = IoGetBaseFileSystemDeviceObject(FileObject);
  fastIoDispatch = baseFileSystemDeviceObject->DriverObject->FastIoDispatch;
  fsContext = FileObject->FsContext;
  return Flags + ResourceOut + relatedDeviceObject->StackSize + (NTSTATUS)fastIoDispatch + (NTSTATUS)fsContext;
}
"""
        )
        release_plan = self._plan(
            """
int *__fastcall FsRtlReleaseFileForModWrite(PFILE_OBJECT FileObject, struct _ERESOURCE *Resource)
{
  PDEVICE_OBJECT relatedDeviceObject;
  PDEVICE_OBJECT baseFileSystemDeviceObject;
  PFAST_IO_DISPATCH fastIoDispatch;

  relatedDeviceObject = IoGetRelatedDeviceObject(FileObject);
  baseFileSystemDeviceObject = IoGetBaseFileSystemDeviceObject(FileObject);
  fastIoDispatch = baseFileSystemDeviceObject->DriverObject->FastIoDispatch;
  return (int *)(relatedDeviceObject->StackSize + (ULONG_PTR)Resource + (ULONG_PTR)fastIoDispatch);
}
"""
        )

        acquire_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                acquire_plan,
                "windows.file_cache_section.fsrtl_acquire_file_for_mod_write_ex",
            )
        }
        release_roles = {
            item["trusted_role"]: item["structure_name"]
            for item in self._profile_identities(
                release_plan,
                "windows.file_cache_section.fsrtl_release_file_for_mod_write",
            )
        }

        self.assertEqual("FILE_OBJECT", acquire_roles["fileObject"])
        self.assertEqual("FSRTL_MOD_WRITE_FLAGS", acquire_roles["modWriteFlags"])
        self.assertEqual("ERESOURCE_OUTPUT", acquire_roles["resourceOutput"])
        self.assertEqual("DEVICE_OBJECT", acquire_roles["relatedDeviceObject"])
        self.assertEqual("DEVICE_OBJECT", acquire_roles["baseFileSystemDeviceObject"])
        self.assertEqual("FAST_IO_DISPATCH", acquire_roles["fastIoDispatch"])
        self.assertEqual("FSRTL_COMMON_FCB_HEADER", acquire_roles["fsContext"])
        self.assertEqual("FILE_OBJECT", release_roles["fileObject"])
        self.assertEqual("ERESOURCE", release_roles["resource"])
        self.assertEqual("DEVICE_OBJECT", release_roles["relatedDeviceObject"])
        self.assertEqual("DEVICE_OBJECT", release_roles["baseFileSystemDeviceObject"])
        self.assertEqual("FAST_IO_DISPATCH", release_roles["fastIoDispatch"])

    def test_report_only_file_object_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CcReferenceSharedCacheMapFileObject(__int64 fileObjectPtr)
{
  __int64 probe;

  probe = *(_QWORD *)(fileObjectPtr + 16)
        + *(_QWORD *)(fileObjectPtr + 24)
        + *(_QWORD *)(fileObjectPtr + 32)
        + *(_QWORD *)(fileObjectPtr + 40)
        + *(_QWORD *)(fileObjectPtr + 48)
        + *(_QWORD *)(fileObjectPtr + 56)
        + *(_QWORD *)(fileObjectPtr + 64)
        + *(_QWORD *)(fileObjectPtr + 72)
        + *(_QWORD *)(fileObjectPtr + 16)
        + *(_QWORD *)(fileObjectPtr + 24)
        + *(_QWORD *)(fileObjectPtr + 32)
        + *(_QWORD *)(fileObjectPtr + 40);
  ObpTraceObjectReferenceIfActive(probe, 1, 1666409283);
  return probe;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.file_cache_section.cc_reference_shared_cache_map_file_object",
            "fileObjectPtr",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "fileObjectPtr"
        ]

        self.assertEqual("FILE_OBJECT", identity["structure_name"])
        self.assertEqual("fileObject", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "fileObjectPtr"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __stdcall CcSetFileSizes(PFILE_OBJECT FileObject, PCC_FILE_SIZES FileSizes)
{
  CcSetFileSizesEx(FileObject, FileSizes);
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.file_cache_section.cc_set_file_sizes",
            role="fileObject",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_file_object_type(self) -> None:
        plan = self._plan(
            """
void __stdcall CcInitializeCacheMap(int FileObject, PCC_FILE_SIZES FileSizes, BOOLEAN PinAccess, PCACHE_MANAGER_CALLBACKS Callbacks, PVOID LazyWriteContext)
{
  CcInitializeCacheMapInternal(FileObject, FileSizes, LazyWriteContext, PinAccess);
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.file_cache_section.cc_initialize_cache_map"
                and item["trusted_role"] == "fileObject"
                for item in self._identities(plan)
            )
        )

    def test_file_cache_section_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __stdcall CcSetFileSizes(PFILE_OBJECT FileObject, PCC_FILE_SIZES FileSizes)
{
  CcSetFileSizesEx(FileObject, FileSizes);
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/file_cache_section.json" for item in manifests)
        )

    def test_queue_async_get_device_guid_work_item_fields_are_report_only(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall CcQueueAsyncGetDeviceGuid(__int64 argument0, void *object)
{
  char *PoolWithTag;

  PoolWithTag = (char *)ExAllocatePoolWithTag((POOL_TYPE)1536, 0x30uLL, 0x65546343u);
  if ( PoolWithTag )
  {
    ObfReferenceObjectWithTag(object, 0);
    *((_QWORD *)PoolWithTag + 1) = object;
    *(_QWORD *)PoolWithTag = argument0;
    *((_QWORD *)PoolWithTag + 2) = 0LL;
    *((_QWORD *)PoolWithTag + 4) = CcGetDeviceGuidAsync;
    *((_QWORD *)PoolWithTag + 5) = PoolWithTag;
    ExQueueWorkItem((PWORK_QUEUE_ITEM)(PoolWithTag + 16), NormalWorkQueue);
  }
  return 0;
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.file_cache_section.cc_queue_async_get_device_guid",
            "PoolWithTag",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "PoolWithTag"
        ]

        self.assertEqual("CC_DEVICE_GUID_WORK_ITEM", identity["structure_name"])
        self.assertEqual("deviceGuidWorkItem", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertEqual({0x0, 0x8, 0x10, 0x20, 0x28}, self._field_offsets(identity))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "PoolWithTag"
                for item in plan.comments
            )
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _rename_map(self, plan) -> dict[str, str]:
        return {item.old: item.new for item in plan.renames if item.apply}

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

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

    def _field_offsets(self, identity: dict[str, object]) -> set[int]:
        return {
            int(field.get("offset", -1))
            for field in identity.get("fields", []) or []
            if isinstance(field, dict)
        }
