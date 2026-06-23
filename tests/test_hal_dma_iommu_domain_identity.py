from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
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
  *a5 = (unsigned int)a4;
  *a8 = a4 + a6 + a7 + a1 + a2 + a3;
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
        ]

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
                self.assertTrue(all(item["effective_mode"] == "report-only" for item in identities))
                self.assertEqual([], plan.corrected_parameter_map)
                for fragment in expected_fragments:
                    self.assertIn(fragment, rendered)

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
        corrections = [
            item
            for item in plan.type_corrections
            if item.profile_id == "windows.hal_dma_iommu.iommu_domain_get_logical_address_range"
        ]

        self.assertEqual(6, len(corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in corrections))
        self.assertTrue(all(not item.apply_to_preview for item in corrections))

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
