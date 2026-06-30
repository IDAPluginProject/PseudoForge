import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ir_evidence import ir_evidence_summary
from ida_pseudoforge.ida import decompiler as decompiler_module
from ida_pseudoforge.ida.hexrays_ir import hexrays_cfunc_ir_evidence


class FakePseudocodeLine:
    def __init__(self, line: str) -> None:
        self.line = line


class FakeLvar:
    def __init__(self, name: str, type_text: str, is_arg: bool = False) -> None:
        self.name = name
        self.type = type_text
        self._is_arg = is_arg

    def is_arg_var(self) -> bool:
        return self._is_arg


class FakeCallSite:
    call_name = "CreateFileW"
    return_type = "HANDLE"
    argument_types = ["LPCWSTR", "DWORD", "DWORD"]
    argument_names = ["path", "access", "share"]
    confidence = 0.91
    evidence = "fake ctree call expression"


class FakeUseDef:
    variable = "fileHandle"
    definitions = ["ctree:call:CreateFileW"]
    uses = ["ctree:if:fileHandle", "ctree:call:CloseHandle"]
    confidence = 0.88
    evidence = "fake ctree assignment flow"


class FakeCfunc:
    def __init__(
        self,
        lines: list[str] | None = None,
        lvars: list[FakeLvar] | None = None,
        call_sites: list[object] | None = None,
        use_defs: list[object] | None = None,
    ) -> None:
        self._lines = [FakePseudocodeLine(line) for line in lines or []]
        self.lvars = lvars or []
        self.call_site_signatures = call_sites or []
        self.use_def_chains = use_defs or []

    def get_pseudocode(self) -> list[FakePseudocodeLine]:
        return self._lines


class HexraysIrEvidenceTests(unittest.TestCase):
    def test_cfunc_adapter_promotes_structured_hexrays_evidence(self) -> None:
        capture = capture_from_pseudocode(
            "__int64 __fastcall OpenThing(wchar_t *path)\n"
            "{\n"
            "  HANDLE fileHandle;\n"
            "  fileHandle = CreateFileW(path, 0x80000000, 1, 0, 3, 0, 0);\n"
            "  if ( fileHandle != 0 )\n"
            "    CloseHandle(fileHandle);\n"
            "  return 0;\n"
            "}"
        )
        cfunc = FakeCfunc(
            lvars=[
                FakeLvar("path", "wchar_t *", True),
                FakeLvar("fileHandle", "HANDLE", False),
            ],
            call_sites=[FakeCallSite()],
            use_defs=[FakeUseDef()],
        )

        evidence = hexrays_cfunc_ir_evidence(cfunc, capture)
        summary = ir_evidence_summary(evidence)

        self.assertTrue(evidence.available)
        self.assertEqual("hexrays_cfunc_v1", evidence.adapter)
        self.assertEqual("hexrays_cfunc", evidence.source)
        self.assertEqual(2, summary["local_type_snapshots"])
        self.assertEqual(1, summary["call_site_signatures"])
        self.assertEqual(1, summary["use_def_chains"])
        self.assertEqual("CreateFileW", evidence.call_site_signatures[0].call_name)
        self.assertEqual(["path", "access", "share"], evidence.call_site_signatures[0].argument_names)
        self.assertEqual("fileHandle", evidence.use_def_chains[0].variable)

    def test_cfunc_adapter_uses_pseudocode_fallback_without_explicit_ctree_facts(self) -> None:
        capture = capture_from_pseudocode(
            "__int64 __fastcall SendThing(char *buffer)\n"
            "{\n"
            "  int result;\n"
            "  result = send(socketHandle, buffer, 16, 0);\n"
            "  if ( result < 0 )\n"
            "    return -1;\n"
            "  return result;\n"
            "}"
        )
        cfunc = FakeCfunc(
            lvars=[
                FakeLvar("buffer", "char *", True),
                FakeLvar("result", "int", False),
            ]
        )

        evidence = hexrays_cfunc_ir_evidence(cfunc, capture)

        self.assertTrue(evidence.available)
        self.assertGreaterEqual(len(evidence.call_site_signatures), 1)
        self.assertGreaterEqual(len(evidence.use_def_chains), 1)
        self.assertIn("send", [item.call_name for item in evidence.call_site_signatures])
        self.assertIn("result", [item.variable for item in evidence.use_def_chains])

    def test_empty_cfunc_does_not_claim_available_ir(self) -> None:
        evidence = hexrays_cfunc_ir_evidence(FakeCfunc())

        self.assertFalse(evidence.available)
        self.assertEqual("hexrays_cfunc_v1", evidence.adapter)

    def test_decompiler_attach_replaces_text_only_evidence_when_available(self) -> None:
        capture = capture_from_pseudocode(
            "__int64 __fastcall Sample()\n"
            "{\n"
            "  HANDLE fileHandle;\n"
            "  fileHandle = CreateFileW(L\"a\", 0, 0, 0, 3, 0, 0);\n"
            "  return fileHandle != 0;\n"
            "}"
        )
        cfunc = FakeCfunc(lvars=[FakeLvar("fileHandle", "HANDLE", False)])

        decompiler_module._attach_hexrays_ir_evidence(capture, cfunc)

        self.assertTrue(capture.ir_evidence.available)
        self.assertEqual("hexrays_cfunc_v1", capture.ir_evidence.adapter)


if __name__ == "__main__":
    unittest.main()
