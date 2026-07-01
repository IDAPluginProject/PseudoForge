from __future__ import annotations


FUNCTION_PARAMETER_NAMES = {
    "NtQuerySystemInformation": [
        "systemInformationClass",
        "systemInformation",
        "systemInformationLength",
        "returnLength",
    ],
    "NtQueryInformationProcess": [
        "processHandle",
        "processInformationClass",
        "processInformation",
        "processInformationLength",
        "returnLength",
    ],
    "NtQueryInformationThread": [
        "threadHandle",
        "threadInformationClass",
        "threadInformation",
        "threadInformationLength",
        "returnLength",
    ],
    "NtSetSystemInformation": [
        "systemInformationClass",
        "systemInformation",
        "systemInformationLength",
    ],
    "NtSetInformationProcess": [
        "processHandle",
        "processInformationClass",
        "processInformation",
        "processInformationLength",
    ],
    "NtSetInformationThread": [
        "threadHandle",
        "threadInformationClass",
        "threadInformation",
        "threadInformationLength",
    ],
}


FUNCTION_SIGNATURE_OVERRIDES = {
    "NtQuerySystemInformation": [
        "NTSTATUS NTAPI NtQuerySystemInformation(",
        "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
        "        PVOID systemInformation,",
        "        ULONG systemInformationLength,",
        "        PULONG returnLength)",
    ],
    "NtQueryInformationProcess": [
        "NTSTATUS NTAPI NtQueryInformationProcess(",
        "        HANDLE processHandle,",
        "        PROCESSINFOCLASS processInformationClass,",
        "        PVOID processInformation,",
        "        ULONG processInformationLength,",
        "        PULONG returnLength)",
    ],
    "NtQueryInformationThread": [
        "NTSTATUS NTAPI NtQueryInformationThread(",
        "        HANDLE threadHandle,",
        "        THREADINFOCLASS threadInformationClass,",
        "        PVOID threadInformation,",
        "        ULONG threadInformationLength,",
        "        PULONG returnLength)",
    ],
    "NtSetSystemInformation": [
        "NTSTATUS NTAPI NtSetSystemInformation(",
        "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
        "        PVOID systemInformation,",
        "        ULONG systemInformationLength)",
    ],
    "NtSetInformationProcess": [
        "NTSTATUS NTAPI NtSetInformationProcess(",
        "        HANDLE processHandle,",
        "        PROCESSINFOCLASS processInformationClass,",
        "        PVOID processInformation,",
        "        ULONG processInformationLength)",
    ],
    "NtSetInformationThread": [
        "NTSTATUS NTAPI NtSetInformationThread(",
        "        HANDLE threadHandle,",
        "        THREADINFOCLASS threadInformationClass,",
        "        PVOID threadInformation,",
        "        ULONG threadInformationLength)",
    ],
}


LOCAL_NAME_RULES = {
    "PreviousMode": ("previousMode", 0.99, "Hex-Rays kept kernel PreviousMode casing"),
    "CurrentThread": ("currentThread", 0.99, "KTHREAD pointer returned by KeGetCurrentThread"),
    "ActiveProcessorCount": ("activeProcessorCount", 0.98, "processor count local naming normalization"),
    "Process": ("currentProcess", 0.94, "local holds the current thread process object"),
    "updated": ("status", 0.95, "local accumulates NTSTATUS-style return values"),
    "Object": ("referencedObject", 0.92, "local is used as object reference output"),
    "DriverServiceName": ("driverServiceName", 0.98, "UNICODE_STRING local naming normalization"),
    "PrivilegeValue": ("privilegeValue", 0.90, "LUID privilege local naming normalization"),
    "SessionId": ("sessionId", 0.98, "session identifier local naming normalization"),
}


STATUS_ARGUMENT_INDEXES = {
    "SetFailureLocation": {3},
}


try:
    from ida_pseudoforge.profiles.loader import load_profile
except Exception:
    load_profile = None


_FALLBACK_NTSTATUS_RETURN_MAP = {
    "3221225474": "STATUS_NOT_IMPLEMENTED",
    "3221225476": "STATUS_INFO_LENGTH_MISMATCH",
    "3221225485": "STATUS_INVALID_PARAMETER",
    "3221225488": "STATUS_INVALID_DEVICE_REQUEST",
    "3221225506": "STATUS_ACCESS_DENIED",
    "3221225507": "STATUS_BUFFER_TOO_SMALL",
    "3221225558": "STATUS_DELETE_PENDING",
    "3221225569": "STATUS_PRIVILEGE_NOT_HELD",
    "3221225595": "STATUS_OBJECT_PATH_NOT_FOUND",
    "3221225626": "STATUS_INSUFFICIENT_RESOURCES",
    "3221225635": "STATUS_DEVICE_NOT_READY",
    "3221225659": "STATUS_INVALID_IMAGE_FORMAT",
    "3221225704": "STATUS_INVALID_USER_BUFFER",
    "3221225711": "STATUS_NAME_TOO_LONG",
    "3221225712": "STATUS_INVALID_PARAMETER_MIX",
    "2147483665": "STATUS_DEVICE_BUSY",
    "-1073741821": "STATUS_INVALID_INFO_CLASS",
    "-1073741822": "STATUS_NOT_IMPLEMENTED",
    "-1073741820": "STATUS_INFO_LENGTH_MISMATCH",
    "-1073741811": "STATUS_INVALID_PARAMETER",
    "-1073741808": "STATUS_INVALID_DEVICE_REQUEST",
    "-1073741790": "STATUS_ACCESS_DENIED",
    "-1073741789": "STATUS_BUFFER_TOO_SMALL",
    "-1073741738": "STATUS_DELETE_PENDING",
    "-1073741727": "STATUS_PRIVILEGE_NOT_HELD",
    "-1073741670": "STATUS_INSUFFICIENT_RESOURCES",
    "-1073741661": "STATUS_DEVICE_NOT_READY",
    "-1073741637": "STATUS_NOT_SUPPORTED",
    "-1073741592": "STATUS_INVALID_USER_BUFFER",
    "-1073741584": "STATUS_INVALID_PARAMETER_1",
    "-2147483631": "STATUS_DEVICE_BUSY",
    "-1073741554": "STATUS_IMAGE_ALREADY_LOADED",
    "1073741824": "STATUS_OBJECT_NAME_EXISTS",
    "0x40000000": "STATUS_OBJECT_NAME_EXISTS",
}


if load_profile is not None:
    NTSTATUS_RETURN_MAP = load_profile("status_codes.json") or _FALLBACK_NTSTATUS_RETURN_MAP
else:
    NTSTATUS_RETURN_MAP = _FALLBACK_NTSTATUS_RETURN_MAP
