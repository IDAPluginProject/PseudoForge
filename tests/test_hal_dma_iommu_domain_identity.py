from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class HalDmaIommuDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_dma_and_iommu_profiles_correct_weak_hexrays_parameter_types(self) -> None:
        samples = [
            (
                """
void __fastcall HalpDmaMapScatterTransferV3(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4, unsigned int *a5, char a6, char a7, unsigned __int64 *a8)
{
  *a5 = *(_DWORD *)(a1 + 520) + (unsigned int)a4;
  *a8 = *(_QWORD *)(a1 + 144) + *(_QWORD *)(a2 + 32) + *(_QWORD *)(a3 + 56);
  if ( *(_BYTE *)(a1 + 445) || *(_BYTE *)(a3 + 64) )
  {
    *a8 += a6 + a7;
  }
}
""",
                "windows.hal_dma_iommu.dma_map_scatter_transfer_v3",
                [
                    "PHALP_DMA_ADAPTER dmaAdapter",
                    "PHALP_DMA_TRANSFER_CONTEXT transferContext",
                    "PSCATTER_GATHER_LIST scatterGatherList",
                    "SIZE_T transferLength",
                    "PULONG mapRegisterCount",
                    "BOOLEAN writeToDevice",
                    "BOOLEAN mapComplete",
                    "PULONG_PTR logicalAddressOutput",
                ],
            ),
            (
                """
__int64 __fastcall HalpDmaAllocateMapRegistersAtHighLevel(__int64 a1, int *a2)
{
  *a2 = *(_DWORD *)(a1 + 120);
  return STATUS_SUCCESS;
}
""",
                "windows.hal_dma_iommu.dma_allocate_map_registers_high_level",
                [
                    "PHALP_DMA_ADAPTER dmaAdapter",
                    "PULONG mapRegisterCount",
                ],
            ),
            (
                """
__int64 __fastcall HalpIommuDomainGetLogicalAddressRange(__int64 a1, _QWORD *a2, int a3, int a4, __int64 a5, _QWORD *a6)
{
  *a2 = a5;
  *a6 = a5 + a3 + a4;
  return STATUS_SUCCESS;
}
""",
                "windows.hal_dma_iommu.iommu_domain_get_logical_address_range",
                [
                    "PHALP_IOMMU_DOMAIN domain",
                    "PULONG_PTR logicalAddressBase",
                    "ULONG pageCount",
                    "ULONG flags",
                    "ULONG_PTR boundaryAddress",
                    "PULONG_PTR logicalAddressLimit",
                ],
            ),
            (
                """
__int64 __fastcall HalpDmaAllocateEmergencyResources(__int64 a1)
{
  if ( !HalpMmAllocCtxAlloc(a1, 56) )
  {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  return MmAllocateMappingAddress(0x1000, 0x446C6148) != 0 ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
""",
                "windows.hal_dma_iommu.dma_allocate_emergency_resources",
                [
                    "PHALP_MM_ALLOC_CONTEXT allocationContext",
                ],
            ),
            (
                """
char __fastcall HalpPciAccessIoConfigSpace(__int16 a1, unsigned __int8 a2, char a3, __int64 a4, unsigned int a5, int a6, int a7)
{
  int Address;
  Address = 8 * (a3 & 0xE0 | ((a3 & 0x1F | (32 * (a2 | 0xFFFF8000))) << 8));
  HalpPCIPerformConfigAccess((__int64)HalpPCIConfigReadHandlers, (__int64)&Address, a4, a5, a6);
  return a7 == 0;
}
""",
                "windows.hal_dma_iommu.pci_access_io_config_space",
                [
                    "USHORT segment",
                    "UCHAR bus",
                    "UCHAR deviceFunction",
                    "PVOID buffer",
                    "ULONG offset",
                    "ULONG length",
                    "BOOLEAN writeAccess",
                ],
            ),
            (
                """
__int64 __fastcall HalpIommuDomainMapLogicalRange(ULONG_PTR a1, __int64 a2, unsigned __int64 a3, __int64 a4, ULONG_PTR a5)
{
  if ( *(_BYTE *)(a1 + 52) )
  {
    return IommupHvMapDeviceLogicalRange(a1, a2, a3, a4, a5);
  }
  HalpIommuMapLogicalRange(0, *(_QWORD *)(a1 + 40), a2, a3, a4, a5);
  return IommupHvMapDeviceLogicalRange(a1, a2, a3, a4, a5);
}
""",
                "windows.hal_dma_iommu.iommu_domain_map_logical_range",
                [
                    "PHALP_IOMMU_DOMAIN domain",
                    "ULONG_PTR logicalAddress",
                    "SIZE_T byteCount",
                    "ULONG_PTR mapFlags",
                    "ULONG_PTR mapContext",
                ],
            ),
        ]
        expected_signatures = {
            "windows.hal_dma_iommu.dma_map_scatter_transfer_v3": "void __fastcall HalpDmaMapScatterTransferV3(",
            "windows.hal_dma_iommu.dma_allocate_map_registers_high_level": "NTSTATUS __fastcall HalpDmaAllocateMapRegistersAtHighLevel(",
            "windows.hal_dma_iommu.iommu_domain_get_logical_address_range": "NTSTATUS __fastcall HalpIommuDomainGetLogicalAddressRange(",
            "windows.hal_dma_iommu.dma_allocate_emergency_resources": "NTSTATUS __fastcall HalpDmaAllocateEmergencyResources(",
            "windows.hal_dma_iommu.pci_access_io_config_space": "BOOLEAN __fastcall HalpPciAccessIoConfigSpace(",
            "windows.hal_dma_iommu.iommu_domain_map_logical_range": "NTSTATUS __fastcall HalpIommuDomainMapLogicalRange(",
        }

        for text, profile_id, expected_fragments in samples:
            with self.subTest(profile_id=profile_id):
                capture = capture_from_pseudocode(text, source_path=SOURCE_PATH)
                plan = build_clean_plan(capture)
                rendered = render_cleaned_pseudocode(capture, plan)
                corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
                identities = self._profile_identities(plan, profile_id)

                self.assertEqual(len(expected_fragments), len(corrections))
                self.assertTrue(all(item.apply_to_preview for item in corrections))
                self.assertTrue(all(not item.apply_to_idb for item in corrections))
                if profile_id == "windows.hal_dma_iommu.dma_allocate_map_registers_high_level":
                    dma_identity = [
                        item for item in identities if item.get("trusted_role") == "dmaAdapter"
                    ]
                    self.assertEqual(1, len(dma_identity))
                    self.assertEqual("canonical-rewrite-eligible", dma_identity[0]["effective_mode"])
                    self.assertTrue(
                        any(
                            field.get("name") == "field_78" and field.get("offset") == 0x78
                            for field in dma_identity[0]["fields"]
                        )
                    )
                    self.assertEqual(1, len(plan.corrected_parameter_map))
                    self.assertEqual("dmaAdapter", plan.corrected_parameter_map[0].new_name)
                    self.assertEqual("HALP_DMA_ADAPTER", plan.corrected_parameter_map[0].structure)
                    self.assertEqual(9, len(plan.corrected_parameter_map[0].fields))
                else:
                    self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                    self.assertEqual([], plan.corrected_parameter_map)
                    if profile_id == "windows.hal_dma_iommu.dma_map_scatter_transfer_v3":
                        dma_identity = self._identity_by_role(identities, "dmaAdapter")
                        sg_identity = self._identity_by_role(identities, "scatterGatherList")
                        self.assertEqual({0x90, 0x1BD, 0x208}, self._field_offsets(dma_identity))
                        self.assertEqual({0x38, 0x40}, self._field_offsets(sg_identity))
                    if profile_id == "windows.hal_dma_iommu.iommu_domain_map_logical_range":
                        domain_identity = self._identity_by_role(identities, "iommuDomain")
                        self.assertEqual({0x28, 0x34}, self._field_offsets(domain_identity))
                self.assertIn(expected_signatures[profile_id], rendered)
                for fragment in expected_fragments:
                    self.assertIn(fragment, rendered)

    def test_dma_allocate_map_registers_uses_validated_layout_rewrite(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall HalpDmaAllocateMapRegistersAtHighLevel(__int64 a1, int *a2)
{
  __int64 total;

  total = *(_QWORD *)(a1 + 48)
        + *(_QWORD *)(a1 + 56)
        + *(_QWORD *)(a1 + 96)
        + *(unsigned int *)(a1 + 104);
  total += *(_QWORD *)(a1 + 112)
        + *(unsigned int *)(a1 + 120)
        + *(_QWORD *)(a1 + 160)
        + *(unsigned __int8 *)(a1 + 345);
  if ( *(unsigned __int8 *)(a1 + 442) )
  {
    total += *(unsigned __int8 *)(a1 + 442);
  }
  total += *(_QWORD *)(a1 + 112)
        + *(unsigned int *)(a1 + 120)
        + *(unsigned __int8 *)(a1 + 442);
  *a2 = (unsigned int)total;
  return STATUS_SUCCESS;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        ready = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_ready"
            and item.get("base") == "dmaAdapter"
        ]
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "dmaAdapter"
        ]

        self.assertEqual(1, len(plan.corrected_parameter_map))
        self.assertEqual([], blockers)
        self.assertEqual(1, len(ready))
        self.assertEqual("domain_identity", ready[0]["source_provenance"])
        self.assertEqual(
            "windows.hal_dma_iommu.dma_allocate_map_registers_high_level",
            ready[0]["domain_profile_id"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_interactive",
                apply_validated_layout_rewrites=True,
            )
            preview = Path(artifacts["layout_rewrite_preview"]).read_text(encoding="utf-8")
            metadata = json.loads(
                Path(artifacts["layout_rewrite_preview_metadata"]).read_text(encoding="utf-8")
            )

        self.assertEqual("applied", metadata["canonical_rewrite_status"])
        self.assertEqual(["dmaAdapter"], metadata["rewritten_bases"])
        self.assertEqual(13, metadata["rewritten_accesses"])
        self.assertIn("dmaAdapter->field_30", preview)
        self.assertIn("dmaAdapter->field_1BA", preview)
        self.assertNotIn("*(unsigned __int8 *)(dmaAdapter + 442)", preview)

    def test_hal_dma_iommu_build_mismatch_blocks_type_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall HalpIommuDomainGetLogicalAddressRange(__int64 a1, _QWORD *a2, int a3, int a4, __int64 a5, _QWORD *a6)
{
  *a2 = a5;
  *a6 = a5;
  return STATUS_SUCCESS;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        corrections = [
            item
            for item in plan.type_corrections
            if item.profile_id == "windows.hal_dma_iommu.iommu_domain_get_logical_address_range"
        ]

        self.assertEqual(6, len(corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in corrections))
        self.assertTrue(all(not item.apply_to_preview for item in corrections))
        self.assertIn("__int64 __fastcall HalpIommuDomainGetLogicalAddressRange(", rendered)
        self.assertNotIn("NTSTATUS __fastcall HalpIommuDomainGetLogicalAddressRange(", rendered)

    def test_timer_measure_worker_context_fields_are_report_only(self) -> None:
        plan = self._plan(
            """
ULONG_PTR __fastcall HalpTimerMeasureProcessorsWorker(ULONG_PTR Argument)
{
  int timerId;

  timerId = *(_DWORD *)(Argument + 16);
  HalpFindTimer(timerId, 0, 0, 0, 1);
  _InterlockedExchangeAdd((volatile signed __int32 *)Argument, -1);
  _InterlockedIncrement((volatile signed __int32 *)(Argument + 4));
  _InterlockedIncrement((volatile signed __int32 *)(Argument + 8));
  *(_DWORD *)(Argument + 12) = 1;
  HalpTimerReadTimerPairWithLatencyLimit(0, 0, 0, 0, 0);
  return 0;
}
"""
        )

        identity = self._identity_by_role(
            self._profile_identities(
                plan,
                "windows.hal_dma_iommu.timer_measure_processors_worker",
            ),
            "timerMeasureContext",
        )
        blockers = [
            item
            for item in plan.comments
            if item.get("kind") == "inferred_offset_rewrite_blockers"
            and item.get("base") == "timerMeasureContext"
        ]

        self.assertEqual("HALP_TIMER_MEASURE_CONTEXT", identity["structure_name"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertTrue({0xC, 0x10}.issubset(self._field_offsets(identity)))
        self.assertTrue(any("domain identity profile is report-only" in item["blockers"] for item in blockers))
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_ready"
                and item.get("base") == "timerMeasureContext"
                for item in plan.comments
            )
        )

    def test_hal_dma_iommu_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall HalpDmaAllocateMapRegistersAtHighLevel(__int64 a1, int *a2)
{
  *a2 = *(_DWORD *)(a1 + 120);
  return STATUS_SUCCESS;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/hal_dma_iommu.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _profile_identities(self, plan, profile_id: str) -> list[dict[str, object]]:
        return [item for item in self._identities(plan) if item.get("profile_id") == profile_id]

    def _identity_by_role(
        self,
        identities: list[dict[str, object]],
        role: str,
    ) -> dict[str, object]:
        matches = [item for item in identities if item.get("trusted_role") == role]
        self.assertEqual(1, len(matches))
        return matches[0]

    def _field_offsets(self, identity: dict[str, object]) -> set[int]:
        return {
            int(field.get("offset", -1))
            for field in identity.get("fields", []) or []
            if isinstance(field, dict)
        }
