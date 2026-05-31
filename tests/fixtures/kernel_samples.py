from __future__ import annotations


FIRMWARE_SAMPLE = r"""
__int64 __fastcall ExpRegisterFirmwareTableInformationHandler(
        SYSTEM_FIRMWARE_TABLE_HANDLER *pTableHandler,
        unsigned int tableHandlerSize,
        KPROCESSOR_MODE previousMode)
{
  unsigned int v3;
  struct _KTHREAD *CurrentThread;
  _DWORD *i;
  _DWORD *v7;
  __int64 v8;
  _QWORD *v9;
  __int64 Pool2;
  _QWORD *v11;
  _QWORD *v12;

  v3 = 0;
  if ( previousMode )
    return (unsigned int)-1073741727;
  if ( !pTableHandler || tableHandlerSize < 0x18 )
    return (unsigned int)-1073741820;
  CurrentThread = KeGetCurrentThread();
  --CurrentThread->KernelApcDisable;
  ExAcquireResourceExclusiveLite(&ExpFirmwareTableResource, 1u);
  for ( i = (_DWORD *)(ExpFirmwareTableProviderListHead - 24); ; i = (_DWORD *)(*(_QWORD *)v7 - 24LL) )
  {
    v7 = i + 6;
    if ( &ExpFirmwareTableProviderListHead == (__int64 *)(i + 6) )
      break;
    if ( *i == pTableHandler->ProviderSignature )
    {
      if ( pTableHandler->Register )
      {
        v3 = 0x40000000;
        goto LABEL_22;
      }
      if ( (PVOID)*((_QWORD *)i + 2) == pTableHandler->DriverObject )
      {
        v8 = *(_QWORD *)v7;
        if ( *(_DWORD **)(*(_QWORD *)v7 + 8LL) == v7 )
        {
          v9 = (_QWORD *)*((_QWORD *)i + 4);
          if ( (_DWORD *)*v9 == v7 )
          {
            *v9 = v8;
            *(_QWORD *)(v8 + 8) = v9;
            ObfDereferenceObject(*((PVOID *)i + 2));
            ExFreePoolWithTag(i, 0x54465241u);
            goto LABEL_22;
          }
        }
LABEL_19:
        __fastfail(3u);
      }
      goto LABEL_21;
    }
  }
  if ( !pTableHandler->Register )
  {
LABEL_21:
    v3 = -1073741811;
    goto LABEL_22;
  }
  Pool2 = ExAllocatePool2(0x100uLL, 0x28uLL, 0x54465241u);
  if ( Pool2 )
  {
    v11 = (_QWORD *)(Pool2 + 24);
    *(_DWORD *)Pool2 = pTableHandler->ProviderSignature;
    *(_QWORD *)(Pool2 + 8) = pTableHandler->FirmwareTableHandler;
    *(_QWORD *)(Pool2 + 16) = pTableHandler->DriverObject;
    *(_QWORD *)(Pool2 + 32) = Pool2 + 24;
    *(_QWORD *)(Pool2 + 24) = Pool2 + 24;
    PsReferenceSiloContext(*(_QWORD *)(Pool2 + 16));
    v12 = (_QWORD *)qword_140EFEDD8;
    if ( *(__int64 **)qword_140EFEDD8 != &ExpFirmwareTableProviderListHead )
      goto LABEL_19;
    *v11 = &ExpFirmwareTableProviderListHead;
    v11[1] = v12;
    *v12 = v11;
    qword_140EFEDD8 = (__int64)v11;
  }
  else
  {
    v3 = -1073741670;
  }
LABEL_22:
  ExReleaseResourceLite(&ExpFirmwareTableResource);
  KeLeaveCriticalRegion();
  return v3;
}
"""


DUPLICATE_SEMANTIC_LABEL_SAMPLE = r"""
NTSTATUS __fastcall DuplicateSemanticLabelSample(int a1, int a2)
{
  int status;

  if ( a1 )
  {
    status = -1073741592;
LABEL_40:
    goto LABEL_41;
  }
  if ( a2 )
  {
LABEL_17:
    status = -1073741820;
    goto LABEL_40;
  }
LABEL_21:
  status = -1073741811;
  goto LABEL_40;
LABEL_41:
  return status;
}
"""
