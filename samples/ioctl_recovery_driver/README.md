# PfIoctlRecovery

`PfIoctlRecovery` is a small WDM driver fixture for PseudoForge IOCTL buffer
contract recovery. It exists to test symbol-less recovery against a real built
`.sys`, not to be live-loaded.

## IOCTL Surface

- `PFIR_IOCTL_GET_CAPABILITIES`: output-only fixed reply.
- `PFIR_IOCTL_CONFIGURE_SESSION`: METHOD_BUFFERED request/reply with size,
  version, mode, count, range, mask, and name-length validation.
- `PFIR_IOCTL_SUBMIT_EVENT`: inout event submission with caller-controlled
  fields and output result fields.
- `PFIR_IOCTL_LIST_EVENTS`: variable-length output list using
  `FIELD_OFFSET(PFIR_EVENT_LIST, Records)`.
- `PFIR_IOCTL_RESET_STATE`: control command with no buffer contract.

## Build

```powershell
.\tools\build.ps1 -Configuration Release
```

Expected output:

```text
x64\Release\PfIoctlRecovery.sys
```

Do not live-load this fixture as part of PseudoForge validation. The intended
flow is static IDA analysis with PDB loading disabled.

