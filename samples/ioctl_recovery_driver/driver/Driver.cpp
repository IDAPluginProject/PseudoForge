#include <ntifs.h>

#define INITGUID
#include "../shared/PfIoctlRecoveryIoctl.h"

typedef struct _PFIR_DEVICE_EXTENSION
{
    ULONG Signature;
    PDEVICE_OBJECT DeviceObject;
    FAST_MUTEX Lock;
    ULONG Configured;
    ULONG EventCount;
    ULONG LastStatus;
    ULONG LastMode;
    ULONG LastRuleCount;
    ULONGLONG LastSessionId;
    PFIR_EVENT_RECORD Events[PFIR_MAX_EVENTS];
} PFIR_DEVICE_EXTENSION, *PPFIR_DEVICE_EXTENSION;

static PDEVICE_OBJECT g_DeviceObject;
static UNICODE_STRING g_DosDeviceName;

extern "C" DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD PfirUnload;
static DRIVER_DISPATCH PfirCreateClose;
static DRIVER_DISPATCH PfirDeviceControl;
static DRIVER_DISPATCH PfirUnsupported;

static NTSTATUS PfirHandleGetCapabilities(_Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);
static NTSTATUS PfirHandleConfigure(_Inout_ PPFIR_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(OutputLength) PVOID Buffer, _In_ ULONG InputLength, _In_ ULONG OutputLength, _Out_ PULONG_PTR Information);
static NTSTATUS PfirHandleSubmitEvent(_Inout_ PPFIR_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);
static NTSTATUS PfirHandleListEvents(_Inout_ PPFIR_DEVICE_EXTENSION Extension, _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _Out_ PULONG_PTR Information);
static VOID PfirResetState(_Inout_ PPFIR_DEVICE_EXTENSION Extension);

extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    PDEVICE_OBJECT deviceObject;
    PPFIR_DEVICE_EXTENSION extension;
    ULONG index;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = STATUS_SUCCESS;
    deviceObject = NULL;
    extension = NULL;

    RtlInitUnicodeString(&deviceName, PFIR_NT_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosDeviceName, PFIR_DOS_DEVICE_NAME);

    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index)
    {
        DriverObject->MajorFunction[index] = PfirUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = PfirCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PfirCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PfirDeviceControl;
    DriverObject->DriverUnload = PfirUnload;

    status = IoCreateDevice(
        DriverObject,
        sizeof(PFIR_DEVICE_EXTENSION),
        &deviceName,
        PFIR_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    extension = (PPFIR_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));
    extension->Signature = PFIR_POOL_TAG;
    extension->DeviceObject = deviceObject;
    ExInitializeFastMutex(&extension->Lock);
    PfirResetState(extension);

    status = IoCreateSymbolicLink(&g_DosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    g_DeviceObject = deviceObject;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:
    if (!NT_SUCCESS(status))
    {
        if (deviceObject != NULL)
        {
            IoDeleteDevice(deviceObject);
            g_DeviceObject = NULL;
        }
    }

    return status;
}

static
VOID
PfirUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT deviceObject;

    deviceObject = DriverObject->DeviceObject;
    IoDeleteSymbolicLink(&g_DosDeviceName);
    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }
    g_DeviceObject = NULL;
}

static
NTSTATUS
PfirUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

static
NTSTATUS
PfirCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfirDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PPFIR_DEVICE_EXTENSION extension;
    PIO_STACK_LOCATION stack;
    PVOID systemBuffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG ioControlCode;
    NTSTATUS status;
    ULONG_PTR information;

    extension = (PPFIR_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    status = STATUS_INVALID_DEVICE_REQUEST;
    information = 0;

    if (systemBuffer == NULL && (inputLength != 0 || outputLength != 0))
    {
        status = STATUS_INVALID_USER_BUFFER;
        goto Complete;
    }

    switch (ioControlCode)
    {
    case PFIR_IOCTL_GET_CAPABILITIES:
        status = PfirHandleGetCapabilities(systemBuffer, outputLength, &information);
        break;
    case PFIR_IOCTL_CONFIGURE_SESSION:
        status = PfirHandleConfigure(extension, systemBuffer, inputLength, outputLength, &information);
        break;
    case PFIR_IOCTL_SUBMIT_EVENT:
        status = PfirHandleSubmitEvent(extension, systemBuffer, inputLength, &information);
        break;
    case PFIR_IOCTL_LIST_EVENTS:
        status = PfirHandleListEvents(extension, systemBuffer, outputLength, &information);
        break;
    case PFIR_IOCTL_RESET_STATE:
        PfirResetState(extension);
        status = STATUS_SUCCESS;
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    if (!NT_SUCCESS(status))
    {
        extension->LastStatus = (ULONG)status;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static
NTSTATUS
PfirHandleGetCapabilities(
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    PFIR_CAPABILITIES_REPLY *reply;

    if (Length < sizeof(PFIR_CAPABILITIES_REPLY))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(Buffer, Length);
    reply = (PFIR_CAPABILITIES_REPLY *)Buffer;
    reply->Header.Size = sizeof(PFIR_CAPABILITIES_REPLY);
    reply->Header.Version = PFIR_ABI_VERSION;
    reply->Header.Flags = 0;
    reply->DriverVersion = PFIR_DRIVER_VERSION;
    reply->SupportedFeatures = PFIR_FEATURE_ALL;
    reply->MaxRules = PFIR_MAX_RULES;
    reply->MaxEvents = PFIR_MAX_EVENTS;
    reply->MaxNameBytes = PFIR_MAX_NAME_BYTES;
    reply->Alignment = 8;
    *Information = sizeof(PFIR_CAPABILITIES_REPLY);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfirHandleConfigure(
    _Inout_ PPFIR_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(OutputLength) PVOID Buffer,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
    )
{
    PFIR_CONFIGURE_REQUEST *request;
    PFIR_CONFIGURE_REPLY *reply;
    ULONG effectiveTimeout;

    if (InputLength < sizeof(PFIR_CONFIGURE_REQUEST))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (OutputLength < sizeof(PFIR_CONFIGURE_REPLY))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PFIR_CONFIGURE_REQUEST *)Buffer;
    if (request->Header.Size != sizeof(PFIR_CONFIGURE_REQUEST))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Header.Version != PFIR_ABI_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if ((request->Header.Flags & ~PFIR_HEADER_FLAGS_ALLOWED) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->SessionId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Mode < PFIR_MODE_PASSIVE || request->Mode > PFIR_MODE_AUDIT)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->RuleCount > PFIR_MAX_RULES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Threshold < PFIR_MIN_THRESHOLD || request->Threshold > PFIR_MAX_THRESHOLD)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->TimeoutMs < PFIR_MIN_TIMEOUT_MS || request->TimeoutMs > PFIR_MAX_TIMEOUT_MS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->FeatureMask == 0 || (request->FeatureMask & ~PFIR_FEATURE_ALL) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->NameLength > sizeof(request->Name) || (request->NameLength & 1u) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    effectiveTimeout = request->TimeoutMs;
    if ((request->Header.Flags & PFIR_HEADER_FLAG_STRICT) != 0 && effectiveTimeout < 1000)
    {
        effectiveTimeout = 1000;
    }

    ExAcquireFastMutex(&Extension->Lock);
    Extension->Configured = 1;
    Extension->LastSessionId = request->SessionId;
    Extension->LastMode = request->Mode;
    Extension->LastRuleCount = request->RuleCount;
    Extension->LastStatus = STATUS_SUCCESS;
    ExReleaseFastMutex(&Extension->Lock);

    RtlZeroMemory(Buffer, OutputLength);
    reply = (PFIR_CONFIGURE_REPLY *)Buffer;
    reply->Header.Size = sizeof(PFIR_CONFIGURE_REPLY);
    reply->Header.Version = PFIR_ABI_VERSION;
    reply->Header.Flags = request->Header.Flags & PFIR_HEADER_FLAGS_ALLOWED;
    reply->SessionId = request->SessionId;
    reply->EffectiveFlags = request->FeatureMask;
    reply->EffectiveTimeoutMs = effectiveTimeout;
    reply->AcceptedRules = request->RuleCount;
    reply->Status = STATUS_SUCCESS;
    *Information = sizeof(PFIR_CONFIGURE_REPLY);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfirHandleSubmitEvent(
    _Inout_ PPFIR_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    PFIR_EVENT_SUBMIT *request;
    PFIR_EVENT_RECORD *record;
    ULONG index;

    if (Length < sizeof(PFIR_EVENT_SUBMIT))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    request = (PFIR_EVENT_SUBMIT *)Buffer;
    if (request->Header.Size != sizeof(PFIR_EVENT_SUBMIT))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Header.Version != PFIR_ABI_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if ((request->Header.Flags & ~PFIR_HEADER_FLAGS_ALLOWED) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->EventId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Severity > PFIR_MAX_SEVERITY)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->Category == 0 || request->Category > PFIR_MAX_CATEGORY)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->PayloadSize > PFIR_MAX_PAYLOAD_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Extension->Lock);
    index = Extension->EventCount % PFIR_MAX_EVENTS;
    record = &Extension->Events[index];
    RtlZeroMemory(record, sizeof(*record));
    record->RecordSize = sizeof(*record);
    record->Severity = request->Severity;
    record->EventId = request->EventId;
    record->ProcessId = request->ProcessId;
    record->Category = request->Category;
    record->PayloadHash = request->PayloadHash;
    record->ResultCode = STATUS_SUCCESS;
    ++Extension->EventCount;
    Extension->LastStatus = STATUS_SUCCESS;
    ExReleaseFastMutex(&Extension->Lock);

    request->ResultCode = STATUS_SUCCESS;
    request->StoredIndex = index;
    *Information = sizeof(PFIR_EVENT_SUBMIT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
PfirHandleListEvents(
    _Inout_ PPFIR_DEVICE_EXTENSION Extension,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_ PULONG_PTR Information
    )
{
    PFIR_EVENT_LIST *list;
    ULONG headerSize;
    ULONG capacity;
    ULONG copied;
    ULONG available;
    ULONG index;

    headerSize = FIELD_OFFSET(PFIR_EVENT_LIST, Records);
    if (Length < headerSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    capacity = (Length - headerSize) / sizeof(PFIR_EVENT_RECORD);
    RtlZeroMemory(Buffer, Length);
    list = (PFIR_EVENT_LIST *)Buffer;
    list->Header.Size = headerSize;
    list->Header.Version = PFIR_ABI_VERSION;
    list->RecordSize = sizeof(PFIR_EVENT_RECORD);

    copied = 0;
    ExAcquireFastMutex(&Extension->Lock);
    available = Extension->EventCount;
    list->RequiredRecordCount = available;
    while (copied < capacity && copied < available && copied < PFIR_MAX_EVENTS)
    {
        index = copied % PFIR_MAX_EVENTS;
        RtlCopyMemory(&list->Records[copied], &Extension->Events[index], sizeof(PFIR_EVENT_RECORD));
        ++copied;
    }
    ExReleaseFastMutex(&Extension->Lock);

    list->RecordCount = copied;
    list->Truncated = (available > copied) ? 1u : 0u;
    *Information = headerSize + ((ULONG_PTR)copied * sizeof(PFIR_EVENT_RECORD));
    return STATUS_SUCCESS;
}

static
VOID
PfirResetState(
    _Inout_ PPFIR_DEVICE_EXTENSION Extension
    )
{
    ExAcquireFastMutex(&Extension->Lock);
    Extension->Configured = 0;
    Extension->EventCount = 0;
    Extension->LastStatus = STATUS_SUCCESS;
    Extension->LastMode = 0;
    Extension->LastRuleCount = 0;
    Extension->LastSessionId = 0;
    RtlZeroMemory(Extension->Events, sizeof(Extension->Events));
    ExReleaseFastMutex(&Extension->Lock);
}

