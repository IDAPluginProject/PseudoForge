from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_kernel_hints import (
    annotate_kernel_hints,
    rewrite_critical_region_entry,
)
from tests.fixtures.kernel_samples import FIRMWARE_SAMPLE


def _plan(*comment_kinds: str) -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="ExpRegisterFirmwareTableInformationHandler",
        input_fingerprint="fp",
        comments=[{"kind": kind} for kind in comment_kinds],
    )


class RenderKernelHintTests(unittest.TestCase):
    def test_rewrite_critical_region_entry_replaces_inline_apc_disable(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  struct _KTHREAD *CurrentThread;",
                "  CurrentThread = KeGetCurrentThread();",
                "  --CurrentThread->KernelApcDisable;",
                "  KeLeaveCriticalRegion();",
                "}",
            ]
        )

        rewritten = rewrite_critical_region_entry(text, _plan("critical_region"))

        self.assertIn("  KeEnterCriticalRegion();", rewritten)
        self.assertNotIn("--CurrentThread->KernelApcDisable", rewritten)
        self.assertNotIn("struct _KTHREAD *CurrentThread;", rewritten)

    def test_rewrite_critical_region_entry_pairs_thread_leave(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  struct _KTHREAD *currentThread;",
                "  currentThread = KeGetCurrentThread();",
                "  --currentThread->KernelApcDisable;",
                "  DoWork();",
                "  KeLeaveCriticalRegionThread((__int64)currentThread);",
                "}",
            ]
        )

        rewritten = rewrite_critical_region_entry(text, _plan("critical_region"))

        self.assertIn("  KeEnterCriticalRegion();", rewritten)
        self.assertIn("  KeLeaveCriticalRegion();", rewritten)
        self.assertNotIn("KeLeaveCriticalRegionThread", rewritten)
        self.assertNotIn("--currentThread->KernelApcDisable", rewritten)
        self.assertNotIn("struct _KTHREAD *currentThread;", rewritten)

    def test_rewrite_critical_region_entry_keeps_reused_thread_variable(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  struct _KTHREAD *currentThread;",
                "  currentThread = KeGetCurrentThread();",
                "  --currentThread->KernelApcDisable;",
                "  UseThread(currentThread);",
                "  KeLeaveCriticalRegionThread((__int64)currentThread);",
                "}",
            ]
        )

        rewritten = rewrite_critical_region_entry(text, _plan("critical_region"))

        self.assertIn("  currentThread = KeGetCurrentThread();", rewritten)
        self.assertIn("  --currentThread->KernelApcDisable;", rewritten)
        self.assertIn("  KeLeaveCriticalRegionThread((__int64)currentThread);", rewritten)

    def test_rewrite_critical_region_entry_pairs_direct_current_thread_leave(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  struct _KTHREAD *currentThread;",
                "  currentThread = KeGetCurrentThread();",
                "  --currentThread->KernelApcDisable;",
                "  DoWork();",
                "  KeLeaveCriticalRegionThread((__int64)KeGetCurrentThread());",
                "}",
            ]
        )

        rewritten = rewrite_critical_region_entry(text, _plan("critical_region"))

        self.assertIn("  KeEnterCriticalRegion();", rewritten)
        self.assertIn("  KeLeaveCriticalRegion();", rewritten)
        self.assertNotIn("KeLeaveCriticalRegionThread", rewritten)
        self.assertNotIn("currentThread = KeGetCurrentThread();", rewritten)
        self.assertNotIn("--currentThread->KernelApcDisable", rewritten)

    def test_rewrite_critical_region_entry_requires_semantic_comment(self) -> None:
        text = "CurrentThread = KeGetCurrentThread();\n--CurrentThread->KernelApcDisable;"

        self.assertEqual(rewrite_critical_region_entry(text, _plan()), text)

    def test_annotate_kernel_hints_adds_list_and_provider_comments(self) -> None:
        text = "\n".join(
            [
                "  providerLink = &providerRecord->Link;",
                "  RemoveEntryList(providerLink);",
                "  InsertTailList(providerListHead, newProviderLink);",
            ]
        )

        annotated = annotate_kernel_hints(
            text,
            _plan("inferred_record_layout", "list_entry_unlink", "list_entry_insert_tail"),
        )

        self.assertIn("// PseudoForge: providerLink is providerRecord->Link at offset +0x18.", annotated)
        self.assertIn("// PseudoForge: validated RemoveEntryList(providerLink).", annotated)
        self.assertIn("// PseudoForge: validated InsertTailList(providerListHead, newProviderLink).", annotated)

    def test_suspicious_ps_reference_silo_context_variable_operand_is_annotated(self) -> None:
        capture = capture_from_pseudocode(
            """
NTSTATUS __fastcall SuspiciousReferenceTargetSample(PFILE_OBJECT fileObject)
{
  PsReferenceSiloContext(fileObject);
  ObfDereferenceObject(fileObject);
  return 0;
}
"""
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertTrue(any("Potential bad call target PsReferenceSiloContext" in warning for warning in plan.warnings))
        self.assertTrue(any("object pointer" in warning for warning in plan.warnings))
        self.assertIn("likely object reference paired with ObfDereferenceObject", rendered)
        self.assertIn("original recovered call target was PsReferenceSiloContext", rendered)
        self.assertIn("PsReferenceSiloContext(fileObject);", rendered)

    def test_kernel_driver_semantics(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "i",
                                "new": "providerEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic list entry name",
                            },
                            {
                                "old": "v7",
                                "new": "providerListEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic link name",
                            },
                            {
                                "old": "Pool2",
                                "new": "newProviderEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic allocation name",
                            },
                        ],
                        "warnings": [
                            {
                                "message": (
                                    "PsReferenceSiloContext is likely a bad import/name recovery "
                                    "for an object reference routine."
                                )
                            },
                            {
                                "old": "BadReferenceName",
                                "reason": "operand and paired release routine do not match",
                            }
                        ],
                    }
                )

        capture = capture_from_pseudocode(FIRMWARE_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v3"], "status")
        self.assertEqual(rename_map["i"], "providerRecord")
        self.assertEqual(rename_map["v7"], "providerLink")
        self.assertEqual(rename_map["v8"], "nextLink")
        self.assertEqual(rename_map["v9"], "previousLink")
        self.assertEqual(rename_map["Pool2"], "newProviderRecord")
        self.assertEqual(rename_map["v11"], "newProviderLink")
        self.assertEqual(rename_map["v12"], "tailLink")

        self.assertIn("status = STATUS_SUCCESS;", rendered)
        self.assertIn("return STATUS_PRIVILEGE_NOT_HELD;", rendered)
        self.assertIn("return STATUS_INFO_LENGTH_MISMATCH;", rendered)
        self.assertIn("status = STATUS_OBJECT_NAME_EXISTS;", rendered)
        self.assertIn("status = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("status = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("Kernel semantic rewrites:", rendered)
        self.assertIn("Kernel insights:", rendered)
        self.assertIn("Inline critical region entry can be normalized to KeEnterCriticalRegion", rendered)
        self.assertIn("LIST_ENTRY unlink pattern detected", rendered)
        self.assertIn("LIST_ENTRY tail insertion pattern detected", rendered)
        self.assertIn("Inferred provider record layout", rendered)
        self.assertIn("Pool tag 0x54465241 decodes to 'ARFT'", rendered)
        self.assertIn("providerRecord owns providerLink at Link offset +0x18", rendered)
        self.assertIn("validated RemoveEntryList(providerLink)", rendered)
        self.assertIn("validated InsertTailList(providerListHead, newProviderLink)", rendered)
        self.assertIn("PseudoForge: inferred record layout", rendered)
        self.assertIn("PDRIVER_OBJECT DriverObject;", rendered)
        self.assertIn("INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD *providerRecord", rendered)
        self.assertIn("NTSTATUS __fastcall ExpRegisterFirmwareTableInformationHandler", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("KeEnterCriticalRegion();", rendered)
        self.assertNotIn("--CurrentThread->KernelApcDisable", rendered)
        self.assertNotIn("--currentThread->KernelApcDisable", rendered)
        self.assertNotIn("struct _KTHREAD *CurrentThread", rendered)
        self.assertIn("LIST_ENTRY *providerListHead;", rendered)
        self.assertIn("providerListHead = (LIST_ENTRY *)&ExpFirmwareTableProviderListHead;", rendered)
        self.assertIn(
            "for ( providerLink = providerListHead->Flink; providerLink != providerListHead; providerLink = providerLink->Flink )",
            rendered,
        )
        self.assertIn("providerRecord = CONTAINING_RECORD(providerLink, INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link);", rendered)
        self.assertIn("if ( providerRecord->DriverObject == pTableHandler->DriverObject )", rendered)
        self.assertIn("goto InvalidParameter;", rendered)
        self.assertIn("goto CorruptListEntry;", rendered)
        self.assertIn("if ( nextLink->Blink == providerLink )", rendered)
        self.assertIn("RemoveEntryList(providerLink);", rendered)
        self.assertIn("InitializeListHead(newProviderLink);", rendered)
        self.assertIn("tailLink = providerListHead->Blink;", rendered)
        self.assertIn("InsertTailList(providerListHead, newProviderLink);", rendered)
        self.assertIn("likely object reference paired with ObfDereferenceObject", rendered)
        self.assertIn("original recovered call target was PsReferenceSiloContext", rendered)
        self.assertIn("PsReferenceSiloContext(newProviderRecord->DriverObject);", rendered)
        self.assertNotIn("ObfReferenceObject(newProviderRecord->DriverObject);", rendered)
        self.assertIn("ExAcquireResourceExclusiveLite(&ExpFirmwareTableResource, TRUE);", rendered)
        self.assertIn(
            "newProviderRecord = ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'));",
            rendered,
        )
        self.assertIn("ExFreePoolWithTag(providerRecord, POOL_TAG('A', 'R', 'F', 'T'));", rendered)
        self.assertNotIn("providerRecord = (_DWORD *)(*(_QWORD *)providerLink - 24LL)", rendered)
        self.assertNotIn("CONTAINING_RECORD(providerLink->Flink", rendered)
        self.assertNotIn("qword_140EFEDD8 = (__int64)newProviderLink", rendered)
        self.assertNotIn("previousLink = (_QWORD *)", rendered)
        self.assertNotIn("PSEUDOFORGE_FIRMWARE_TABLE_PROVIDER_RECORD", rendered)
        self.assertNotIn("ExAllocatePool2(0x100uLL", rendered)
        self.assertIn("LABEL_19 -> CorruptListEntry: failfast_corrupt_list_entry", rendered)
        self.assertIn("LABEL_21 -> InvalidParameter: set_error_status_and_cleanup", rendered)
        self.assertIn("LABEL_22 -> Cleanup: release_resource_and_leave_critical_region", rendered)
        self.assertRegex(rendered, r"(?m)^CorruptListEntry:$")
        self.assertRegex(rendered, r"(?m)^InvalidParameter:$")
        self.assertRegex(rendered, r"(?m)^Cleanup:$")
        self.assertRegex(
            rendered,
            r"(?ms)^Cleanup:\n"
            r"  // PseudoForge: release_resource_and_leave_critical_region[^\n]*\n"
            r"  ExReleaseResourceLite\(&ExpFirmwareTableResource\);\n"
            r"  KeLeaveCriticalRegion\(\);\n"
            r"  return status;\n"
            r"InvalidParameter:",
        )
        self.assertRegex(
            rendered,
            r"(?m)^InvalidParameter:\n"
            r"  // PseudoForge: set_error_status_and_cleanup[^\n]*\n"
            r"  status = STATUS_INVALID_PARAMETER;\n"
            r"  goto Cleanup;",
        )
        self.assertRegex(
            rendered,
            r"(?m)^CorruptListEntry:\n"
            r"  // PseudoForge: failfast_corrupt_list_entry[^\n]*\n"
            r"  __fastfail\(3u\);",
        )
        self.assertNotRegex(rendered, r"(?m)^CorruptListEntry:\n[^\n]*\n\s{8,}__fastfail")
        self.assertNotRegex(rendered, r"(?m)^InvalidParameter:\n[^\n]*\n\s{4,}status = STATUS_INVALID_PARAMETER;")
        self.assertNotIn("  goto Cleanup;\nInvalidParameter:", rendered)
        self.assertIn("PsReferenceSiloContext is likely a bad import/name recovery", rendered)
        self.assertIn("Potential bad call target PsReferenceSiloContext", rendered)
        self.assertIn("Potential bad call target BadReferenceName", rendered)
        self.assertNotIn("{'message':", rendered)
        self.assertNotIn('{"old":', rendered)
        self.assertIn("if ( !pTableHandler->Register )\n  {\n    goto InvalidParameter;\n  }", rendered)


if __name__ == "__main__":
    unittest.main()
