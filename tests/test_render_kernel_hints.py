from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render_kernel_hints import (
    annotate_kernel_hints,
    rewrite_critical_region_entry,
)


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


if __name__ == "__main__":
    unittest.main()
