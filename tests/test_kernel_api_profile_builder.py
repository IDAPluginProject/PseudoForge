import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.kernel_api import (
    apply_kernel_api_rewrites,
    decode_pool_tag_literal,
    kernel_function_metadata,
    lookup_kernel_symbol,
)
from tools.build_kernel_api_profile import (
    _eval_int_expression,
    _extract_function_declaration,
    _extract_function_declarations,
    _extract_pool_flags,
    _merge_function_semantics,
    _split_kernel_api_profile,
    _write_split_profile_files,
)


class KernelApiProfileBuilderTests(unittest.TestCase):
    def test_parser_rejects_iprtrmib_comment_prose_as_function(self):
        header = r"""
/*
Abstract:
    This file contains definitions used by the IP Router Manager
    (as mentioned in ipinfoid.h).
*/
#define NUMBER_OF_EXPORTED_VARIABLES 1
typedef struct _MIB_OPAQUE_QUERY {
    DWORD dwVarId;
    DWORD dwVarIndex[1];
} MIB_OPAQUE_QUERY, *PMIB_OPAQUE_QUERY;

NTKERNELAPI
NTSTATUS
NTAPI
RealKernelFunction(
    _In_ HANDLE Handle
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertNotIn("Manager", declarations)
        self.assertNotIn("MIB_OPAQUE_QUERY", declarations)
        self.assertIn("RealKernelFunction", declarations)
        self.assertEqual(declarations["RealKernelFunction"]["return_type"], "NTSTATUS")

    def test_parser_keeps_markerless_plain_prototypes(self):
        header = r"""
PIMAGE_EXPORT_DIRECTORY
AuxKlibGetImageExportDirectory(
    _In_ PVOID ImageBase
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertIn("AuxKlibGetImageExportDirectory", declarations)
        self.assertEqual(
            declarations["AuxKlibGetImageExportDirectory"]["return_type"],
            "PIMAGE_EXPORT_DIRECTORY",
        )

    def test_parser_keeps_marker_split_by_comment_line(self):
        header = r"""
NTKERNELAPI
/* _Check_return_ */
NTSTATUS
PsGetSiloContext(
    _In_ PESILO Silo
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertIn("PsGetSiloContext", declarations)
        self.assertEqual(declarations["PsGetSiloContext"]["return_type"], "NTSTATUS")

    def test_parser_does_not_cross_previous_declaration_after_spaced_blank(self):
        header = (
            "NTAPI\n"
            "PreviousFunction(\n"
            "    VOID\n"
            "    );\n"
            "    \n"
            "KSDDKAPI\n"
            "NTSTATUS\n"
            "NTAPI\n"
            "KsGetBusEnumIdentifier(\n"
            "    _Inout_ PIRP Irp\n"
            "    );\n"
        )

        declarations = _extract_function_declarations(header)

        self.assertIn("KsGetBusEnumIdentifier", declarations)
        self.assertNotIn("PreviousFunction", declarations)
        self.assertEqual(
            declarations["KsGetBusEnumIdentifier"]["return_type"],
            "KSDDKAPI NTSTATUS",
        )

    def test_ast_integer_expression_evaluator_accepts_needed_macro_math(self):
        symbols = {
            "POOL_FLAG_USE_QUOTA": 1,
            "POOL_FLAG_PAGED": 0x100,
        }

        self.assertEqual(
            _eval_int_expression("POOL_FLAG_USE_QUOTA | POOL_FLAG_PAGED", symbols),
            0x101,
        )
        self.assertEqual(_eval_int_expression("(ULONG)(1 << 8)", {}), 0x100)
        self.assertEqual(_eval_int_expression("5 / 2", {}), 2)
        self.assertEqual(_eval_int_expression("~0", {}), -1)

    def test_ast_integer_expression_evaluator_rejects_unsupported_nodes(self):
        self.assertIsNone(_eval_int_expression("__import__('os').system('whoami')", {}))
        self.assertIsNone(_eval_int_expression("1 if 1 else 0", {}))
        self.assertIsNone(_eval_int_expression("1 << -1", {}))
        self.assertIsNone(_eval_int_expression("1 / 0", {}))

    def test_merge_function_semantics_remains_compatible(self):
        declaration = {
            "return_type": "NTSTATUS",
            "raw_signature": "NTSTATUS ExAllocatePool2(...);",
            "params": [
                {"name": "Flags", "type": "POOL_FLAGS"},
                {"name": "NumberOfBytes", "type": "SIZE_T"},
                {"name": "Tag", "type": "ULONG"},
            ],
        }

        metadata = _merge_function_semantics("ExAllocatePool2", declaration, Path("wdm.h"))

        self.assertEqual(metadata["params"][0]["kind"], "flags")
        self.assertEqual(metadata["params"][2]["kind"], "pool_tag")

    def test_split_kernel_api_profile_emits_loader_family_files(self):
        profile = {
            "functions": {"ExUnitTest": {"params": []}},
            "enums": {"BOOLEAN": {"1": "TRUE"}},
            "structures": {"_UNIT_TEST": {"fields": []}},
            "aliases": {"PUNIT_TEST": {"target": "_UNIT_TEST *"}},
            "macros": {"UNIT_TEST_MACRO": {"value": "1"}},
            "symbols": {"ExUnitTest": [{"kind": "function"}]},
            "indices": {"rewrite_functions": ["ExUnitTest"]},
        }

        split = _split_kernel_api_profile(profile)

        self.assertEqual(split["kernel_functions.json"], profile["functions"])
        self.assertEqual(split["kernel_enums.json"], profile["enums"])
        self.assertEqual(split["kernel_structures.json"], profile["structures"])
        self.assertEqual(split["kernel_aliases.json"], profile["aliases"])
        self.assertEqual(split["kernel_macros.json"], profile["macros"])
        self.assertEqual(split["kernel_symbol_index.json"], profile["symbols"])
        self.assertEqual(split["kernel_indices.json"], profile["indices"])

    def test_write_split_profile_files_writes_family_json(self):
        profile = {
            "functions": {"ExUnitTest": {"params": []}},
            "enums": {"BOOLEAN": {"1": "TRUE"}},
            "indices": {"rewrite_functions": ["ExUnitTest"]},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = _write_split_profile_files(profile, Path(temp_dir))

            self.assertEqual(len(paths), 7)
            self.assertEqual(
                json.loads((Path(temp_dir) / "kernel_functions.json").read_text(encoding="utf-8")),
                profile["functions"],
            )
            self.assertEqual(
                json.loads((Path(temp_dir) / "kernel_indices.json").read_text(encoding="utf-8")),
                profile["indices"],
            )
            self.assertEqual(
                json.loads((Path(temp_dir) / "kernel_aliases.json").read_text(encoding="utf-8")),
                {},
            )

    def test_kernel_api_profile_rewrites_pool_flags_and_tags(self):
        text = (
            "a = ExAllocatePool2(0x101uLL, size, 0x54465241u);\n"
            "ExFreePool2(a, 0x54465241u, 0LL, 0u);\n"
            "ExFreePoolWithTag(a, 0x54465241u);\n"
            "ExAcquireResourceExclusiveLite(r, 1u);\n"
            "ObReferenceObjectByHandleWithTag(h, 512, t, mode, 0x79517350u, &o, 0LL);\n"
            "ObpReferenceObjectByHandleWithTag((ULONG_PTR)h, 512, (__int64)t, mode, 0x79517350u, &o, 0LL, 0LL);\n"
            "ObfDereferenceObjectWithTag(o, 0x79517350u);\n"
            "PsSetCreateProcessNotifyRoutine(cb, 1u);\n"
            "PspSetCreateProcessNotifyRoutine(cb, 0u);\n"
            "FltTagFile(instance, fileObject, 0x54465241u);\n"
        )
        rendered = apply_kernel_api_rewrites(text)

        self.assertIn(
            "ExAllocatePool2(POOL_FLAG_USE_QUOTA | POOL_FLAG_PAGED, size, POOL_TAG('A', 'R', 'F', 'T'))",
            rendered,
        )
        self.assertIn("ExFreePool2(a, POOL_TAG('A', 'R', 'F', 'T'), 0LL, 0u)", rendered)
        self.assertIn("ExFreePoolWithTag(a, POOL_TAG('A', 'R', 'F', 'T'))", rendered)
        self.assertIn("ExAcquireResourceExclusiveLite(r, TRUE)", rendered)
        self.assertIn(
            "ObReferenceObjectByHandleWithTag(h, 512, t, mode, POOL_TAG('P', 's', 'Q', 'y'), &o, 0LL)",
            rendered,
        )
        self.assertIn(
            "ObpReferenceObjectByHandleWithTag((ULONG_PTR)h, 512, (__int64)t, mode, POOL_TAG('P', 's', 'Q', 'y'), &o, 0LL, 0LL)",
            rendered,
        )
        self.assertIn("ObfDereferenceObjectWithTag(o, POOL_TAG('P', 's', 'Q', 'y'))", rendered)
        self.assertIn("PsSetCreateProcessNotifyRoutine(cb, TRUE)", rendered)
        self.assertIn("PspSetCreateProcessNotifyRoutine(cb, FALSE)", rendered)
        self.assertIn("FltTagFile(instance, fileObject, 0x54465241u)", rendered)
        self.assertEqual(decode_pool_tag_literal("0x54465241u"), "ARFT")

    def test_kernel_api_profile_resolves_private_wrapper_aliases(self):
        ob = kernel_function_metadata("ObReferenceObjectByHandleWithTag")
        obp = kernel_function_metadata("ObpReferenceObjectByHandleWithTag")
        psp = kernel_function_metadata("PspSetCreateProcessNotifyRoutine")
        alias_entries = lookup_kernel_symbol("ObpReferenceObjectByHandleWithTag")

        self.assertEqual(ob["params"][4]["kind"], "pool_tag")
        self.assertEqual(obp.get("profile_alias_of"), "ObReferenceObjectByHandleWithTag")
        self.assertEqual(obp.get("profile_alias_kind"), "explicit")
        self.assertEqual(obp["params"][4]["kind"], "pool_tag")
        self.assertEqual(psp.get("profile_alias_of"), "PsSetCreateProcessNotifyRoutine")
        self.assertEqual(psp["params"][1]["kind"], "bool")
        self.assertTrue(any(entry.get("kind") == "function_alias" for entry in alias_entries))

    def test_wdk_profile_parser_handles_nested_sal_and_calling_convention(self):
        header = r"""
_IRQL_requires_max_(APC_LEVEL)
_Requires_lock_held_(_Global_critical_region_)
_When_(Wait!=0, _Post_satisfies_(return == 1))
_When_(Wait==0, _Post_satisfies_(return == 0 || return == 1) _Must_inspect_result_)
NTKERNELAPI
BOOLEAN
ExAcquireResourceExclusiveLite (
    _Inout_ _Requires_lock_not_held_(*_Curr_)
    _When_(return!=0, _Acquires_exclusive_lock_(*_Curr_))
    PERESOURCE Resource,
    _In_ _Literal_ BOOLEAN Wait
    );

_Requires_lock_held_(_Global_critical_region_)
_Requires_lock_held_(*Resource)
_Releases_lock_(*Resource)
_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
ExReleaseResourceLite(
    _Inout_ PERESOURCE Resource
    );

#define POOL_FLAG_USE_QUOTA 0x0000000000000001UI64
#define POOL_FLAG_PAGED 0x0000000000000100UI64
"""

        acquire = _extract_function_declaration(header, "ExAcquireResourceExclusiveLite")
        release = _extract_function_declaration(header, "ExReleaseResourceLite")
        pool_flags = _extract_pool_flags(header)

        self.assertIsNotNone(acquire)
        self.assertIsNotNone(release)
        self.assertEqual(acquire["return_type"], "BOOLEAN")
        self.assertEqual(acquire["params"][0], {"name": "Resource", "type": "PERESOURCE"})
        self.assertEqual(acquire["params"][1], {"name": "Wait", "type": "BOOLEAN"})
        self.assertEqual(release["return_type"], "VOID")
        self.assertEqual(release["calling_convention"], "FASTCALL")
        self.assertEqual(release["params"][0], {"name": "Resource", "type": "PERESOURCE"})
        self.assertEqual(pool_flags["1"], "POOL_FLAG_USE_QUOTA")
        self.assertEqual(pool_flags["256"], "POOL_FLAG_PAGED")

    def test_wdk_profile_builder_infers_common_argument_semantics(self):
        declaration = {
            "return_type": "NTSTATUS",
            "raw_signature": "NTSTATUS ObReferenceObjectByHandleWithTag(...);",
            "params": [
                {"name": "Handle", "type": "HANDLE"},
                {"name": "DesiredAccess", "type": "ACCESS_MASK"},
                {"name": "ObjectType", "type": "POBJECT_TYPE"},
                {"name": "AccessMode", "type": "KPROCESSOR_MODE"},
                {"name": "Tag", "type": "ULONG"},
                {"name": "Object", "type": "PVOID*"},
                {"name": "HandleInformation", "type": "POBJECT_HANDLE_INFORMATION"},
            ],
        }
        metadata = _merge_function_semantics("ObReferenceObjectByHandleWithTag", declaration, Path("wdm.h"))
        callback = _merge_function_semantics(
            "PsSetCreateProcessNotifyRoutine",
            {
                "return_type": "NTSTATUS",
                "raw_signature": "NTSTATUS PsSetCreateProcessNotifyRoutine(...);",
                "params": [
                    {"name": "NotifyRoutine", "type": "PCREATE_PROCESS_NOTIFY_ROUTINE"},
                    {"name": "Remove", "type": "BOOLEAN"},
                ],
            },
            Path("wdm.h"),
        )

        self.assertEqual(metadata["params"][4]["kind"], "pool_tag")
        self.assertEqual(callback["params"][1]["kind"], "bool")
        self.assertEqual(callback["params"][1]["enum"], "BOOLEAN")

    def test_wdk_profile_parser_extracts_broad_kernel_prototypes(self):
        header = r"""
//@[comment("MVI_tracked")]
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess
    );

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
FLTAPI
FltRegisterFilter (
    _In_ PDRIVER_OBJECT Driver,
    _In_ CONST FLT_REGISTRATION *Registration,
    _Outptr_ PFLT_FILTER *RetFilter
    );
"""

        declarations = _extract_function_declarations(header)

        self.assertIn("ZwCreateFile", declarations)
        self.assertIn("FltRegisterFilter", declarations)
        self.assertEqual(declarations["ZwCreateFile"]["return_type"], "NTSTATUS")
        self.assertEqual(declarations["ZwCreateFile"]["calling_convention"], "NTAPI")
        self.assertEqual(declarations["FltRegisterFilter"]["return_type"], "NTSTATUS")
        self.assertEqual(declarations["FltRegisterFilter"]["calling_convention"], "FLTAPI")
        self.assertEqual(declarations["FltRegisterFilter"]["params"][1]["type"], "CONST FLT_REGISTRATION*")

    def test_kernel_api_profile_symbol_lookup_is_broad(self):
        ndis_entries = lookup_kernel_symbol("NdisRegisterProtocolDriver")
        pool_entries = lookup_kernel_symbol("POOL_FLAG_PAGED")
        driver_object_entries = lookup_kernel_symbol("PDRIVER_OBJECT")
        flt_register = kernel_function_metadata("FltRegisterFilter")

        self.assertTrue(any(entry.get("kind") == "function" for entry in ndis_entries))
        self.assertTrue(any(entry.get("kind") == "macro" for entry in pool_entries))
        self.assertTrue(any(entry.get("kind") == "enum_member" for entry in pool_entries))
        self.assertTrue(any(entry.get("kind") == "alias" for entry in driver_object_entries))
        self.assertEqual(flt_register.get("return_type"), "NTSTATUS")
        self.assertEqual(flt_register.get("calling_convention"), "FLTAPI")


if __name__ == "__main__":
    unittest.main()
