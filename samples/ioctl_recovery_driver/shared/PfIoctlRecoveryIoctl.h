#pragma once

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define PFIR_DEVICE_TYPE 0x8338u

#define PFIR_NT_DEVICE_NAME L"\\Device\\PfIoctlRecovery"
#define PFIR_DOS_DEVICE_NAME L"\\DosDevices\\PfIoctlRecovery"
#define PFIR_WIN32_DEVICE_NAME L"\\\\.\\PfIoctlRecovery"

#define PFIR_MAKE_POOL_TAG(a, b, c, d) ((unsigned long)(a) | ((unsigned long)(b) << 8) | ((unsigned long)(c) << 16) | ((unsigned long)(d) << 24))
#define PFIR_POOL_TAG PFIR_MAKE_POOL_TAG('P', 'F', 'I', 'r')

#define PFIR_IOCTL_GET_CAPABILITIES CTL_CODE(PFIR_DEVICE_TYPE, 0x900u, METHOD_BUFFERED, FILE_READ_DATA)
#define PFIR_IOCTL_CONFIGURE_SESSION CTL_CODE(PFIR_DEVICE_TYPE, 0x901u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PFIR_IOCTL_SUBMIT_EVENT CTL_CODE(PFIR_DEVICE_TYPE, 0x902u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PFIR_IOCTL_LIST_EVENTS CTL_CODE(PFIR_DEVICE_TYPE, 0x903u, METHOD_BUFFERED, FILE_READ_DATA)
#define PFIR_IOCTL_RESET_STATE CTL_CODE(PFIR_DEVICE_TYPE, 0x904u, METHOD_BUFFERED, FILE_WRITE_DATA)

#define PFIR_ABI_VERSION 1u
#define PFIR_DRIVER_VERSION 0x20260702u
#define PFIR_FEATURE_TRACE 0x00000001u
#define PFIR_FEATURE_FILTER 0x00000002u
#define PFIR_FEATURE_SNAPSHOT 0x00000004u
#define PFIR_FEATURE_ALL (PFIR_FEATURE_TRACE | PFIR_FEATURE_FILTER | PFIR_FEATURE_SNAPSHOT)
#define PFIR_HEADER_FLAG_STRICT 0x00000001u
#define PFIR_HEADER_FLAG_ALLOW_PARTIAL 0x00000002u
#define PFIR_HEADER_FLAGS_ALLOWED (PFIR_HEADER_FLAG_STRICT | PFIR_HEADER_FLAG_ALLOW_PARTIAL)
#define PFIR_MODE_PASSIVE 1u
#define PFIR_MODE_FILTER 2u
#define PFIR_MODE_AUDIT 3u
#define PFIR_MAX_RULES 16u
#define PFIR_MAX_EVENTS 8u
#define PFIR_MAX_NAME_BYTES 32u
#define PFIR_MIN_THRESHOLD 10u
#define PFIR_MAX_THRESHOLD 100000u
#define PFIR_MIN_TIMEOUT_MS 100u
#define PFIR_MAX_TIMEOUT_MS 60000u
#define PFIR_MAX_PAYLOAD_BYTES 256u
#define PFIR_MAX_CATEGORY 8u
#define PFIR_MAX_SEVERITY 5u

#pragma pack(push, 8)

typedef struct _PFIR_HEADER
{
    unsigned int Size;
    unsigned int Version;
    unsigned int Flags;
    unsigned int Reserved;
} PFIR_HEADER;

typedef struct _PFIR_CAPABILITIES_REPLY
{
    PFIR_HEADER Header;
    unsigned int DriverVersion;
    unsigned int SupportedFeatures;
    unsigned int MaxRules;
    unsigned int MaxEvents;
    unsigned int MaxNameBytes;
    unsigned int Alignment;
} PFIR_CAPABILITIES_REPLY;

typedef struct _PFIR_CONFIGURE_REQUEST
{
    PFIR_HEADER Header;
    unsigned __int64 SessionId;
    unsigned int Mode;
    unsigned int RuleCount;
    unsigned int Threshold;
    unsigned int TimeoutMs;
    unsigned int FeatureMask;
    unsigned int ClientProcessId;
    unsigned int NameLength;
    wchar_t Name[16];
    unsigned int Reserved2;
} PFIR_CONFIGURE_REQUEST;

typedef struct _PFIR_CONFIGURE_REPLY
{
    PFIR_HEADER Header;
    unsigned __int64 SessionId;
    unsigned int EffectiveFlags;
    unsigned int EffectiveTimeoutMs;
    unsigned int AcceptedRules;
    unsigned int Status;
} PFIR_CONFIGURE_REPLY;

typedef struct _PFIR_EVENT_SUBMIT
{
    PFIR_HEADER Header;
    unsigned __int64 EventId;
    unsigned int ProcessId;
    unsigned int ThreadId;
    unsigned int Severity;
    unsigned int Category;
    unsigned int PayloadSize;
    unsigned int PayloadHash;
    unsigned int ResultCode;
    unsigned int StoredIndex;
} PFIR_EVENT_SUBMIT;

typedef struct _PFIR_EVENT_RECORD
{
    unsigned int RecordSize;
    unsigned int Severity;
    unsigned __int64 EventId;
    unsigned int ProcessId;
    unsigned int Category;
    unsigned int PayloadHash;
    unsigned int ResultCode;
} PFIR_EVENT_RECORD;

typedef struct _PFIR_EVENT_LIST
{
    PFIR_HEADER Header;
    unsigned int RecordSize;
    unsigned int RecordCount;
    unsigned int RequiredRecordCount;
    unsigned int Truncated;
    PFIR_EVENT_RECORD Records[1];
} PFIR_EVENT_LIST;

#pragma pack(pop)

