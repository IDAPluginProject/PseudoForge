from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class AlpcPortDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_create_and_initialize_port_roles(self) -> None:
        nt_create_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes)
{
  return AlpcpCreateConnectionPort(PortHandle, ObjectAttributes, PortAttributes);
}
"""
        )
        create_internal_plan = self._plan(
            """
NTSTATUS __fastcall AlpcpCreatePort(int PreviousMode, POBJECT_ATTRIBUTES ObjectAttributes, PVOID *PortObject)
{
  NTSTATUS referencedObject;

  referencedObject = ObCreateObjectEx(PreviousMode, AlpcPortObjectType, ObjectAttributes, 0, 0, 0, 0, 0, PortObject, 0);
  return referencedObject;
}
"""
        )
        initialize_plan = self._plan(
            """
void __fastcall AlpcpInitializePort(__int64 PortObject, char ConnectionPort, unsigned __int8 WaitablePort)
{
  KSEMAPHORE *lookasideEntry;

  lookasideEntry = AlpcpNPLookasides;
  InitializeListHead((PLIST_ENTRY)(PortObject + 16));
  InsertTailList(&AlpcpPortList, (PLIST_ENTRY)(PortObject + 32));
  if ( WaitablePort )
  {
    KeInitializeSemaphore(lookasideEntry, 0, 1);
  }
}
"""
        )

        nt_create_roles = self._roles(nt_create_plan, "windows.alpc_port.nt_create_port")
        create_internal_roles = self._roles(
            create_internal_plan,
            "windows.alpc_port.create_port_internal",
        )
        initialize_roles = self._roles(
            initialize_plan,
            "windows.alpc_port.initialize_port",
        )

        self.assertEqual("HANDLE_OUTPUT", nt_create_roles["portHandleOutput"])
        self.assertEqual("OBJECT_ATTRIBUTES", nt_create_roles["objectAttributes"])
        self.assertEqual("ALPC_PORT_ATTRIBUTES", nt_create_roles["portAttributes"])
        self.assertEqual("ALPC_CREATE_PORT_CONTEXT", create_internal_roles["accessModeOrObjectContext"])
        self.assertEqual("OBJECT_ATTRIBUTES", create_internal_roles["objectAttributes"])
        self.assertEqual("ALPC_PORT_OUTPUT", create_internal_roles["portObjectOutput"])
        self.assertEqual("NTSTATUS", create_internal_roles["createStatus"])
        self.assertEqual("ALPC_PORT", initialize_roles["portObject"])
        self.assertEqual("BOOLEAN", initialize_roles["connectionPortFlag"])
        self.assertEqual("BOOLEAN", initialize_roles["waitablePortFlag"])
        self.assertEqual("KSEMAPHORE", initialize_roles["waitSemaphore"])

    def test_connect_accept_disconnect_roles(self) -> None:
        connect_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSID ServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PPORT_MESSAGE ReceiveMessage, PULONG ReceiveLength, PALPC_MESSAGE_ATTRIBUTES MessageAttributes)
{
  return AlpcpConnectPort(PortHandle, PortName, 0, ObjectAttributes, PortAttributes, ServerSid, Flags, 0, ConnectionMessage, BufferLength, ReceiveMessage, ReceiveLength, MessageAttributes);
}
"""
        )
        connect_ex_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcConnectPortEx(PHANDLE PortHandle, HANDLE ConnectionPortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSID ServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PPORT_MESSAGE ReceiveMessage, PULONG ReceiveLength, PALPC_MESSAGE_ATTRIBUTES MessageAttributes)
{
  return AlpcpConnectPort(PortHandle, 0, ConnectionPortHandle, ObjectAttributes, PortAttributes, ServerSid, Flags, 0, ConnectionMessage, BufferLength, ReceiveMessage, ReceiveLength, MessageAttributes);
}
"""
        )
        internal_plan = self._plan(
            """
NTSTATUS __fastcall AlpcpConnectPort(HANDLE *PortHandle, PUNICODE_STRING PortName, int Flags, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, PSID ServerSid, int RequiredServerSid, int Reserved, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PPORT_MESSAGE ReceiveMessage, PULONG ReceiveLength, PALPC_MESSAGE_ATTRIBUTES MessageAttributes)
{
  HANDLE Handle;
  PVOID referencedObject;
  PVOID v21;

  Handle = 0;
  referencedObject = AlpcpCreateClientPort(ObjectAttributes, PortAttributes);
  v21 = referencedObject;
  AlpcpProcessConnectionRequest(v21, ConnectionMessage);
  *PortHandle = Handle;
  return STATUS_SUCCESS;
}
"""
        )
        accept_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcAcceptConnectPort(PHANDLE PortHandle, HANDLE ConnectionPortHandle, ULONG Flags, PPORT_MESSAGE ConnectionMessage, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PALPC_PORT_ATTRIBUTES PortAttributes, PVOID PortContext, PALPC_MESSAGE_ATTRIBUTES MessageAttributes, BOOLEAN AcceptConnection)
{
  return AlpcpAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ConnectionMessage, SecurityQos, PortAttributes, PortContext, MessageAttributes, AcceptConnection);
}
"""
        )
        disconnect_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDisconnectPort(HANDLE PortHandle, ULONG Flags)
{
  PVOID referencedObject;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  AlpcpDisconnectPort(referencedObject, Flags);
  ObfDereferenceObject(referencedObject);
  return STATUS_SUCCESS;
}
"""
        )

        connect_roles = self._roles(connect_plan, "windows.alpc_port.nt_connect_port")
        connect_ex_roles = self._roles(connect_ex_plan, "windows.alpc_port.nt_connect_port_ex")
        internal_roles = self._roles(internal_plan, "windows.alpc_port.connect_port_internal")
        accept_roles = self._roles(accept_plan, "windows.alpc_port.nt_accept_connect_port")
        disconnect_roles = self._roles(disconnect_plan, "windows.alpc_port.nt_disconnect_port")

        self.assertEqual("HANDLE_OUTPUT", connect_roles["portHandleOutput"])
        self.assertEqual("UNICODE_STRING", connect_roles["portName"])
        self.assertEqual("OBJECT_ATTRIBUTES", connect_roles["objectAttributes"])
        self.assertEqual("ALPC_PORT_ATTRIBUTES", connect_roles["portAttributes"])
        self.assertEqual("PORT_MESSAGE", connect_roles["connectionMessage"])
        self.assertEqual("PORT_MESSAGE", connect_roles["receiveMessage"])
        self.assertEqual("HANDLE_OUTPUT", connect_ex_roles["portHandleOutput"])
        self.assertEqual("HANDLE", connect_ex_roles["connectionPortHandle"])
        self.assertEqual("SID", connect_ex_roles["serverSid"])
        self.assertEqual("HANDLE_OUTPUT", internal_roles["portHandleOutput"])
        self.assertEqual("OBJECT_ATTRIBUTES", internal_roles["objectAttributes"])
        self.assertEqual("ALPC_PORT_ATTRIBUTES", internal_roles["portAttributes"])
        self.assertEqual("PORT_MESSAGE", internal_roles["connectionMessage"])
        self.assertEqual("HANDLE", internal_roles["clientPortHandle"])
        self.assertEqual("ALPC_PORT", internal_roles["clientPortObject"])
        self.assertEqual("HANDLE_OUTPUT", accept_roles["portHandleOutput"])
        self.assertEqual("HANDLE", accept_roles["connectionPortHandle"])
        self.assertEqual("PORT_MESSAGE", accept_roles["connectionMessage"])
        self.assertEqual("SECURITY_QUALITY_OF_SERVICE", accept_roles["securityQos"])
        self.assertEqual("ALPC_MESSAGE_ATTRIBUTES", accept_roles["messageAttributes"])
        self.assertEqual("HANDLE", disconnect_roles["portHandle"])
        self.assertEqual("ALPC_DISCONNECT_FLAGS", disconnect_roles["disconnectFlags"])
        self.assertEqual("ALPC_PORT", disconnect_roles["referencedPortObject"])

    def test_send_receive_message_roles(self) -> None:
        syscall_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage, PALPC_MESSAGE_ATTRIBUTES SendAttributes, PPORT_MESSAGE ReceiveMessage, PSIZE_T ReceiveMessageSize, PALPC_MESSAGE_ATTRIBUTES MessageAttributes, PLARGE_INTEGER Timeout)
{
  PVOID referencedObject;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  AlpcpSendMessage(referencedObject, SendMessage, SendAttributes, 0);
  AlpcpReceiveMessage(referencedObject, ReceiveMessage, ReceiveMessageSize, MessageAttributes, Timeout);
  return STATUS_SUCCESS;
}
"""
        )
        send_plan = self._plan(
            """
NTSTATUS __fastcall AlpcpSendMessage(__int64 *CommunicationInfo, PPORT_MESSAGE Message, PALPC_MESSAGE_ATTRIBUTES MessageAttributes, char PreviousMode)
{
  PVOID newProviderRecord;
  struct _ETHREAD *currentThread;

  newProviderRecord = ExAllocatePool2(0x100, 0x80, 0x6D704C41);
  currentThread = KeGetCurrentThread();
  AlpcpValidateDataInformation(Message, MessageAttributes);
  AlpcpCaptureAttributes(MessageAttributes, PreviousMode);
  AlpcpDispatchNewMessage(CommunicationInfo, newProviderRecord, currentThread);
  return STATUS_SUCCESS;
}
"""
        )
        receive_plan = self._plan(
            """
NTSTATUS __fastcall AlpcpReceiveMessage(__int64 CommunicationInfo, PPORT_MESSAGE ReceiveMessage, PSIZE_T ReceiveMessageSize, PALPC_MESSAGE_ATTRIBUTES MessageAttributes, PLARGE_INTEGER Timeout)
{
  PVOID BugCheckParameter2;
  struct _ETHREAD *currentThread;

  currentThread = KeGetCurrentThread();
  BugCheckParameter2 = AlpcpReceiveMessagePort(CommunicationInfo, ReceiveMessage, ReceiveMessageSize, MessageAttributes, Timeout);
  return BugCheckParameter2 ? STATUS_SUCCESS : STATUS_TIMEOUT;
}
"""
        )
        reference_plan = self._plan(
            """
NTSTATUS __fastcall AlpcpReferenceMessageByWaitingThread(PVOID WaitingThreadMessageContext, PVOID *MessageOutput)
{
  PVOID currentPortObj;
  PVOID portEntry;

  currentPortObj = WaitingThreadMessageContext;
  portEntry = AlpcpReferenceMessageByWaitingThreadPort(currentPortObj, MessageOutput);
  return portEntry ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
"""
        )

        syscall_roles = self._roles(syscall_plan, "windows.alpc_port.nt_send_wait_receive_port")
        send_roles = self._roles(send_plan, "windows.alpc_port.send_message_internal")
        receive_roles = self._roles(receive_plan, "windows.alpc_port.receive_message_internal")
        reference_roles = self._roles(reference_plan, "windows.alpc_port.reference_message_by_waiting_thread")

        self.assertEqual("HANDLE", syscall_roles["portHandle"])
        self.assertEqual("ALPC_SEND_RECEIVE_FLAGS", syscall_roles["sendReceiveFlags"])
        self.assertEqual("PORT_MESSAGE", syscall_roles["sendMessage"])
        self.assertEqual("PORT_MESSAGE", syscall_roles["receiveMessage"])
        self.assertEqual("SIZE_T_OUTPUT", syscall_roles["receiveMessageSize"])
        self.assertEqual("ALPC_MESSAGE_ATTRIBUTES", syscall_roles["messageAttributes"])
        self.assertEqual("LARGE_INTEGER", syscall_roles["timeout"])
        self.assertEqual("ALPC_PORT", syscall_roles["referencedPortObject"])
        self.assertEqual("ALPC_COMMUNICATION_INFO", send_roles["communicationInfo"])
        self.assertEqual("PORT_MESSAGE", send_roles["message"])
        self.assertEqual("ALPC_MESSAGE_ATTRIBUTES", send_roles["messageAttributes"])
        self.assertEqual("KPROCESSOR_MODE", send_roles["previousMode"])
        self.assertEqual("ALPC_MESSAGE", send_roles["messageBuffer"])
        self.assertEqual("ETHREAD", send_roles["currentThread"])
        self.assertEqual("ALPC_COMMUNICATION_INFO", receive_roles["communicationInfo"])
        self.assertEqual("PORT_MESSAGE", receive_roles["receiveMessage"])
        self.assertEqual("SIZE_T_OUTPUT", receive_roles["receiveMessageSize"])
        self.assertEqual("ALPC_MESSAGE_ATTRIBUTES", receive_roles["messageAttributes"])
        self.assertEqual("LARGE_INTEGER", receive_roles["timeout"])
        self.assertEqual("ALPC_MESSAGE", receive_roles["receivedMessage"])
        self.assertEqual("ETHREAD", receive_roles["currentThread"])
        self.assertEqual("ALPC_WAIT_CONTEXT", reference_roles["waitingThreadMessageContext"])
        self.assertEqual("ALPC_MESSAGE_OUTPUT", reference_roles["messageOutput"])
        self.assertEqual("ALPC_PORT", reference_roles["currentPortObject"])
        self.assertEqual("ALPC_PORT", reference_roles["portListEntry"])

    def test_complete_dispatch_message_context_roles(self) -> None:
        plan = self._plan(
            """
LONG_PTR __fastcall AlpcpCompleteDispatchMessage(__int64 context)
{
  __int64 object;
  ULONG_PTR v4;

  object = *(_QWORD *)(context + 32);
  v4 = *(_QWORD *)(context + 8);
  AlpcpCaptureMessageDataSafe(v4);
  AlpcpInsertMessagePendingQueue(object, v4);
  AlpcpUnlockMessage(v4);
  return ObfDereferenceObject((PVOID)object);
}
"""
        )

        roles = self._roles(plan, "windows.alpc_port.complete_dispatch_message")
        identity = self._single_identity(
            plan,
            "windows.alpc_port.complete_dispatch_message",
            role="dispatchContext",
        )
        rename_map = {item.old: item.new for item in plan.active_renames()}

        self.assertEqual("ALPC_DISPATCH_MESSAGE_CONTEXT", roles["dispatchContext"])
        self.assertEqual("dispatchContext", rename_map["context"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])

    def test_section_and_reserve_blob_roles(self) -> None:
        create_section_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcCreatePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle, SIZE_T SectionSize, PVOID *AlpcSectionHandle, PSIZE_T ActualSectionSize)
{
  PVOID referencedObject;
  PVOID BugCheckParameter2;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  BugCheckParameter2 = AlpcpCreateSection(referencedObject, SectionHandle, SectionSize);
  *AlpcSectionHandle = BugCheckParameter2;
  return STATUS_SUCCESS;
}
"""
        )
        delete_section_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDeletePortSection(HANDLE PortHandle, ULONG Flags, ULONG SectionHandle)
{
  PVOID referencedObject;
  PVOID v7;
  PVOID v8;

  referencedObject = 0;
  v7 = AlpcReferenceBlobByHandle(referencedObject, SectionHandle);
  v8 = v7;
  AlpcpDeleteBlob(v8);
  return STATUS_SUCCESS;
}
"""
        )
        create_reserve_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcCreateResourceReserve(HANDLE PortHandle, ULONG Flags, SIZE_T MessageSize, ULONG *ResourceReserveHandle)
{
  PVOID referencedObject;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  *ResourceReserveHandle = AlpcpCreateReserve(referencedObject, MessageSize);
  return STATUS_SUCCESS;
}
"""
        )
        delete_reserve_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDeleteResourceReserve(HANDLE PortHandle, ULONG Flags, ULONG ResourceReserveHandle)
{
  PVOID referencedObject;
  PVOID v8;
  PVOID v9;

  referencedObject = 0;
  v8 = AlpcReferenceBlobByHandle(referencedObject, ResourceReserveHandle);
  v9 = v8;
  AlpcpDeleteBlob(v9);
  return STATUS_SUCCESS;
}
"""
        )

        create_section_roles = self._roles(
            create_section_plan,
            "windows.alpc_port.nt_create_port_section",
        )
        delete_section_roles = self._roles(
            delete_section_plan,
            "windows.alpc_port.nt_delete_port_section",
        )
        create_reserve_roles = self._roles(
            create_reserve_plan,
            "windows.alpc_port.nt_create_resource_reserve",
        )
        delete_reserve_roles = self._roles(
            delete_reserve_plan,
            "windows.alpc_port.nt_delete_resource_reserve",
        )

        self.assertEqual("HANDLE", create_section_roles["portHandle"])
        self.assertEqual("HANDLE", create_section_roles["sectionHandle"])
        self.assertEqual("SIZE_T", create_section_roles["sectionSize"])
        self.assertEqual("ALPC_HANDLE_OUTPUT", create_section_roles["alpcSectionHandleOutput"])
        self.assertEqual("SIZE_T_OUTPUT", create_section_roles["actualSectionSizeOutput"])
        self.assertEqual("ALPC_PORT", create_section_roles["referencedPortObject"])
        self.assertEqual("ALPC_SECTION", create_section_roles["createdSectionBlob"])
        self.assertEqual("HANDLE", delete_section_roles["portHandle"])
        self.assertEqual("ALPC_HANDLE", delete_section_roles["sectionHandle"])
        self.assertEqual("ALPC_PORT", delete_section_roles["referencedPortObject"])
        self.assertEqual("ALPC_SECTION", delete_section_roles["sectionBlob"])
        self.assertEqual("HANDLE", create_reserve_roles["portHandle"])
        self.assertEqual("SIZE_T", create_reserve_roles["messageSize"])
        self.assertEqual("ALPC_HANDLE_OUTPUT", create_reserve_roles["resourceReserveOutput"])
        self.assertEqual("ALPC_PORT", create_reserve_roles["referencedPortObject"])
        self.assertEqual("HANDLE", delete_reserve_roles["portHandle"])
        self.assertEqual("ALPC_HANDLE", delete_reserve_roles["resourceReserveHandle"])
        self.assertEqual("ALPC_PORT", delete_reserve_roles["referencedPortObject"])
        self.assertEqual("ALPC_RESERVE", delete_reserve_roles["reserveBlob"])

    def test_view_and_security_blob_roles(self) -> None:
        create_view_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcCreateSectionView(HANDLE PortHandle, ULONG Flags, PALPC_DATA_VIEW_ATTR SectionView)
{
  PVOID referencedObject;
  PVOID v11;
  PVOID BugCheckParameter2;

  referencedObject = 0;
  v11 = AlpcReferenceBlobByHandle(referencedObject, SectionView);
  BugCheckParameter2 = AlpcpCreateSectionView(referencedObject, v11, SectionView);
  return BugCheckParameter2 ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
}
"""
        )
        delete_view_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDeleteSectionView(HANDLE PortHandle, ULONG Flags, ULONG_PTR ViewBase)
{
  PVOID referencedObject;
  PVOID v11;
  PVOID BugCheckParameter2;

  referencedObject = 0;
  v11 = AlpcpEnumerateResourcesPort(referencedObject, ViewBase);
  BugCheckParameter2 = v11;
  AlpcpDeleteView(BugCheckParameter2);
  return STATUS_SUCCESS;
}
"""
        )
        create_security_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcCreateSecurityContext(HANDLE PortHandle, ULONG Flags, PALPC_SECURITY_ATTR SecurityContext)
{
  PVOID referencedObject;
  SECURITY_QUALITY_OF_SERVICE ClientSecurityQos;
  PVOID newProviderRecord;
  struct _ETHREAD *ClientThread;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  newProviderRecord = ExAllocatePool2(0x100, 0x40, 0x63704C41);
  ClientThread = KeGetCurrentThread();
  SecurityContext->ContextHandle = newProviderRecord;
  return ClientSecurityQos.Length + ClientThread->Cid.UniqueThread ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
"""
        )
        delete_security_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDeleteSecurityContext(HANDLE PortHandle, ULONG Flags, ULONG_PTR SecurityContextHandle)
{
  PVOID referencedObject;
  PVOID v7;
  PVOID v8;

  referencedObject = 0;
  v7 = AlpcReferenceBlobByHandle(referencedObject, SecurityContextHandle);
  v8 = v7;
  AlpcpDeleteBlob(v8);
  return STATUS_SUCCESS;
}
"""
        )

        create_view_roles = self._roles(
            create_view_plan,
            "windows.alpc_port.nt_create_section_view",
        )
        delete_view_roles = self._roles(
            delete_view_plan,
            "windows.alpc_port.nt_delete_section_view",
        )
        create_security_roles = self._roles(
            create_security_plan,
            "windows.alpc_port.nt_create_security_context",
        )
        delete_security_roles = self._roles(
            delete_security_plan,
            "windows.alpc_port.nt_delete_security_context",
        )

        self.assertEqual("HANDLE", create_view_roles["portHandle"])
        self.assertEqual("ALPC_DATA_VIEW_ATTR", create_view_roles["sectionView"])
        self.assertEqual("ALPC_PORT", create_view_roles["referencedPortObject"])
        self.assertEqual("ALPC_SECTION", create_view_roles["sectionBlob"])
        self.assertEqual("ALPC_VIEW", create_view_roles["sectionViewBlob"])
        self.assertEqual("HANDLE", delete_view_roles["portHandle"])
        self.assertEqual("VIRTUAL_ADDRESS", delete_view_roles["viewBase"])
        self.assertEqual("ALPC_PORT", delete_view_roles["referencedPortObject"])
        self.assertEqual("ALPC_VIEW", delete_view_roles["sectionViewBlob"])
        self.assertEqual("HANDLE", create_security_roles["portHandle"])
        self.assertEqual("ALPC_SECURITY_ATTR", create_security_roles["securityContext"])
        self.assertEqual("ALPC_PORT", create_security_roles["referencedPortObject"])
        self.assertEqual("SECURITY_QUALITY_OF_SERVICE", create_security_roles["clientSecurityQos"])
        self.assertEqual("ALPC_SECURITY_CONTEXT", create_security_roles["securityContextBlob"])
        self.assertEqual("ETHREAD", create_security_roles["clientThread"])
        self.assertEqual("HANDLE", delete_security_roles["portHandle"])
        self.assertEqual("ALPC_HANDLE", delete_security_roles["securityContextHandle"])
        self.assertEqual("ALPC_PORT", delete_security_roles["referencedPortObject"])
        self.assertEqual("ALPC_SECURITY_CONTEXT", delete_security_roles["securityContextBlob"])

    def test_impersonation_and_sender_open_roles(self) -> None:
        impersonate_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcImpersonateClientOfPort(HANDLE PortHandle, PALPC_MESSAGE_ATTRIBUTES MessageAttributes, ULONG_PTR Flags)
{
  PVOID referencedObject;
  PVOID HandlePointer;
  PSID SourceSid;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  HandlePointer = MessageAttributes;
  SourceSid = SepTokenGetSid(HandlePointer);
  return SourceSid && Flags ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}
"""
        )
        sender_process_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcOpenSenderProcess(PHANDLE ProcessHandle, HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
  PVOID referencedObject;
  PVOID BugCheckParameter2;

  referencedObject = 0;
  BugCheckParameter2 = AlpcpLookupMessage(referencedObject, Message);
  *ProcessHandle = PsOpenProcess(BugCheckParameter2, DesiredAccess, ObjectAttributes);
  return STATUS_SUCCESS;
}
"""
        )
        sender_thread_plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcOpenSenderThread(PHANDLE ThreadHandle, HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
  PVOID referencedObject;
  PVOID BugCheckParameter2;

  referencedObject = 0;
  BugCheckParameter2 = AlpcpLookupMessage(referencedObject, Message);
  *ThreadHandle = PsOpenThread(BugCheckParameter2, DesiredAccess, ObjectAttributes);
  return STATUS_SUCCESS;
}
"""
        )

        impersonate_roles = self._roles(
            impersonate_plan,
            "windows.alpc_port.nt_impersonate_client_of_port",
        )
        sender_process_roles = self._roles(
            sender_process_plan,
            "windows.alpc_port.nt_open_sender_process",
        )
        sender_thread_roles = self._roles(
            sender_thread_plan,
            "windows.alpc_port.nt_open_sender_thread",
        )

        self.assertEqual("HANDLE", impersonate_roles["portHandle"])
        self.assertEqual("ALPC_MESSAGE_ATTRIBUTES", impersonate_roles["messageAttributes"])
        self.assertEqual("ALPC_IMPERSONATION_FLAGS", impersonate_roles["impersonationFlags"])
        self.assertEqual("ALPC_PORT", impersonate_roles["referencedPortObject"])
        self.assertEqual("ALPC_MESSAGE", impersonate_roles["messageObject"])
        self.assertEqual("SID", impersonate_roles["sourceSid"])
        self.assertEqual("HANDLE_OUTPUT", sender_process_roles["processHandleOutput"])
        self.assertEqual("HANDLE", sender_process_roles["portHandle"])
        self.assertEqual("PORT_MESSAGE", sender_process_roles["message"])
        self.assertEqual("ACCESS_MASK", sender_process_roles["desiredAccess"])
        self.assertEqual("ALPC_PORT", sender_process_roles["referencedPortObject"])
        self.assertEqual("ALPC_MESSAGE", sender_process_roles["messageObject"])
        self.assertEqual("HANDLE_OUTPUT", sender_thread_roles["threadHandleOutput"])
        self.assertEqual("HANDLE", sender_thread_roles["portHandle"])
        self.assertEqual("PORT_MESSAGE", sender_thread_roles["message"])
        self.assertEqual("ACCESS_MASK", sender_thread_roles["desiredAccess"])
        self.assertEqual("ALPC_PORT", sender_thread_roles["referencedPortObject"])
        self.assertEqual("ALPC_MESSAGE", sender_thread_roles["messageObject"])

    def test_port_delete_destroy_roles(self) -> None:
        delete_plan = self._plan(
            """
void __fastcall AlpcpDeletePort(__int64 PortObject)
{
  PVOID v3;
  PVOID v5;
  PVOID v6;
  PVOID v8;
  PVOID v10;

  v3 = AlpcpCloseMessagePort(PortObject);
  v5 = v3;
  v6 = AlpcpReleaseCompletionPacket(PortObject);
  v8 = AlpcpDeleteBlob(v5);
  v10 = v5;
  AlpcpDestroyPort(PortObject);
}
"""
        )
        destroy_plan = self._plan(
            """
void __fastcall AlpcpDestroyPort(__int64 *PortObject)
{
  PVOID next_list_entry;
  PVOID prev_list_entry_ptr;
  PVOID lookaside_buffer;

  KeAbPreAcquire(PortObject);
  next_list_entry = PortObject[2];
  prev_list_entry_ptr = PortObject[3];
  lookaside_buffer = PortObject[4];
}
"""
        )

        delete_roles = self._roles(delete_plan, "windows.alpc_port.delete_port_internal")
        destroy_roles = self._roles(destroy_plan, "windows.alpc_port.destroy_port_internal")

        self.assertEqual("ALPC_PORT", delete_roles["portObject"])
        self.assertEqual("ALPC_CONNECTION", delete_roles["connectionBlob"])
        self.assertEqual("IO_COMPLETION_PACKET", delete_roles["completionPacket"])
        self.assertEqual("SECURITY_CLIENT_CONTEXT", delete_roles["clientSecurity"])
        self.assertEqual("ALPC_PORT", destroy_roles["portObject"])
        self.assertEqual("ALPC_PORT", destroy_roles["nextPortListEntry"])
        self.assertEqual("ALPC_PORT", destroy_roles["previousPortListEntry"])
        self.assertEqual("ALPC_LOOKASIDE_BUFFER", destroy_roles["lookasideBuffer"])

    def test_report_only_alpc_identity_blocks_offset_rewrite(self) -> None:
        plan = self._plan(
            """
void __fastcall AlpcpInitializePort(__int64 PortObject, char ConnectionPort, unsigned __int8 WaitablePort)
{
  __int64 probe;

  probe = *(_QWORD *)(PortObject + 16)
        + *(_QWORD *)(PortObject + 24)
        + *(_QWORD *)(PortObject + 32)
        + *(_QWORD *)(PortObject + 40)
        + *(_QWORD *)(PortObject + 48)
        + *(_QWORD *)(PortObject + 56)
        + *(_QWORD *)(PortObject + 64)
        + *(_QWORD *)(PortObject + 72)
        + *(_QWORD *)(PortObject + 16)
        + *(_QWORD *)(PortObject + 24)
        + *(_QWORD *)(PortObject + 32)
        + *(_QWORD *)(PortObject + 40);
  InsertTailList(&AlpcpPortList, (PLIST_ENTRY)probe);
}
"""
        )

        identity = self._identity_for_base(
            plan,
            "windows.alpc_port.initialize_port",
            "PortObject",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "PortObject"
        ]

        self.assertEqual("ALPC_PORT", identity["structure_name"])
        self.assertEqual("portObject", identity["trusted_role"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "PortObject"
                for item in plan.comments
            )
        )

    def test_build_mismatch_fails_closed(self) -> None:
        plan = self._plan(
            """
void __fastcall AlpcpInitializePort(__int64 PortObject, char ConnectionPort, unsigned __int8 WaitablePort)
{
  InsertTailList(&AlpcpPortList, (PLIST_ENTRY)(PortObject + 32));
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.alpc_port.initialize_port",
            role="portObject",
        )

        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])
        self.assertEqual([], identity["fields"])

    def test_accepted_type_guard_blocks_wrong_handle_type(self) -> None:
        plan = self._plan(
            """
NTSTATUS __stdcall NtAlpcDisconnectPort(int PortHandle, ULONG Flags)
{
  PVOID referencedObject;

  ObReferenceObjectByHandle(PortHandle, 0, AlpcPortObjectType, 0, &referencedObject, 0);
  AlpcpDisconnectPort(referencedObject, Flags);
  return STATUS_SUCCESS;
}
"""
        )

        self.assertFalse(
            any(
                item["profile_id"] == "windows.alpc_port.nt_disconnect_port"
                and item["trusted_role"] == "portHandle"
                for item in self._identities(plan)
            )
        )

    def test_alpc_port_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
void __fastcall AlpcpInitializePort(__int64 PortObject, char ConnectionPort, unsigned __int8 WaitablePort)
{
  InsertTailList(&AlpcpPortList, (PLIST_ENTRY)(PortObject + 32));
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/alpc_port.json" for item in manifests)
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
