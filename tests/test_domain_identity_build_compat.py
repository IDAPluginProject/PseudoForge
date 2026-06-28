from __future__ import annotations

import unittest

from ida_pseudoforge.core import domain_identity
from ida_pseudoforge.profiles import loader as profile_loader


COMPATIBLE_26100_PROFILE_IDS = {
    "windows.alpc_port.allocate_message_internal",
    "windows.alpc_port.nt_create_port_section",
    "windows.alpc_port.nt_impersonate_client_of_port",
    "windows.compression_xpress.xp10_read_and_decode_huffman_tables",
    "windows.etw_wmi_telemetry.cov_samp_stack_hash_check",
    "windows.hal_dma_iommu.dma_map_scatter_transfer_v3",
    "windows.hal_dma_iommu.iommu_domain_get_logical_address_range",
    "windows.hal_dma_iommu.iommu_domain_map_logical_range",
    "windows.hal_dma_iommu.timer_measure_processors_worker",
    "windows.memory_manager.change_slab_entry_identity",
    "windows.memory_manager.convert_large_active_page_to_chain",
    "windows.memory_manager.create_pfn_template",
    "windows.memory_manager.create_slab_entry",
    "windows.memory_manager.delete_empty_page_table_commit",
    "windows.memory_manager.lock_page_list_and_last_page",
    "windows.memory_manager.make_system_address_valid",
    "windows.memory_manager.prefetch_virtual_memory",
    "windows.memory_manager.unlink_bad_pages",
    "windows.memory_manager.validate_add_physical_memory_parameters",
    "windows.memory_manager.vmp_fill_gpn_ranges",
    "windows.memory_manager.vmp_fill_slat",
    "windows.memory_manager.vmp_split_memory_range",
    "windows.memory_manager.wsle_free",
    "windows.object_manager.free_object",
    "windows.pnp_power.popfx_query_current_component_perf_state",
    "windows.process_thread.psp_convert_silo_to_server_silo",
    "windows.process_thread_notify.ps_remove_create_thread_notify",
    "windows.registry_config.cm_save_key_to_buffer",
    "windows.registry_config.cmp_free_key_control_block",
    "windows.registry_config.cmp_find_value_by_name",
    "windows.registry_config.cmp_hive_cache_populate_hive_entry_thread",
    "windows.registry_config.cmp_insert_security_cell_list",
    "windows.registry_config.cmp_set_security_descriptor_info",
    "windows.registry_config.cmp_trans_search_add_trans",
    "windows.registry_config.hv_reallocate_cell",
    "windows.token_security.query_security_attributes_token",
    "windows.trap_processor_state.ki_retire_dpc_list",
    "windows.executive_async.exp_get_next_callback",
}


CANONICAL_REWRITE_26100_PROFILE_IDS = {
    "windows.memory_manager.create_shared_zero_pages",
    "windows.memory_manager.free_pages_from_mdl",
    "windows.memory_manager.pf_allocate_mdls",
    "windows.memory_manager.store_work_item_process",
}


class DomainIdentityBuildCompatTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_26100_compatible_profiles_keep_rewrite_closed(self) -> None:
        profiles = self._profiles_by_id()
        missing = sorted(COMPATIBLE_26100_PROFILE_IDS.difference(profiles))

        self.assertEqual([], missing)
        for profile_id in sorted(COMPATIBLE_26100_PROFILE_IDS):
            with self.subTest(profile_id=profile_id):
                profile = profiles[profile_id]
                blockers = domain_identity._profile_context_blockers(
                    profile,
                    {"image": "ntoskrnl.exe", "arch": "x64", "build": "26100.8457"},
                )
                mismatch_blockers = domain_identity._profile_context_blockers(
                    profile,
                    {"image": "ntoskrnl.exe", "arch": "x64", "build": "99999.1"},
                )
                rewrite_policy = domain_identity._profile_rewrite_policy(profile)

                self.assertNotIn("build_mismatch", blockers)
                self.assertIn("build_mismatch", mismatch_blockers)
                self.assertFalse(rewrite_policy["body_canonical_rewrite"])
                self.assertFalse(rewrite_policy["apply_to_idb_default"])
                self.assertTrue(
                    all(
                        str(parameter.get("mode", "report-only")) == "report-only"
                        for parameter in profile.get("parameters", [])
                        if isinstance(parameter, dict)
                    )
                )
                prototype = profile.get("prototype", {})
                if isinstance(prototype, dict):
                    self.assertTrue(
                        all(
                            not bool(parameter.get("apply_to_idb", False))
                            for parameter in prototype.get("parameters", [])
                            if isinstance(parameter, dict)
                        )
                    )

    def test_26100_canonical_rewrite_profiles_keep_idb_mutation_closed(self) -> None:
        profiles = self._profiles_by_id()
        missing = sorted(CANONICAL_REWRITE_26100_PROFILE_IDS.difference(profiles))

        self.assertEqual([], missing)
        for profile_id in sorted(CANONICAL_REWRITE_26100_PROFILE_IDS):
            with self.subTest(profile_id=profile_id):
                profile = profiles[profile_id]
                blockers = domain_identity._profile_context_blockers(
                    profile,
                    {"image": "ntoskrnl.exe", "arch": "x64", "build": "26100.8457"},
                )
                mismatch_blockers = domain_identity._profile_context_blockers(
                    profile,
                    {"image": "ntoskrnl.exe", "arch": "x64", "build": "99999.1"},
                )
                rewrite_policy = domain_identity._profile_rewrite_policy(profile)

                self.assertNotIn("build_mismatch", blockers)
                self.assertIn("build_mismatch", mismatch_blockers)
                self.assertTrue(rewrite_policy["body_canonical_rewrite"])
                self.assertFalse(rewrite_policy["apply_to_idb_default"])
                self.assertTrue(
                    any(
                        str(parameter.get("mode", "")) == "canonical-rewrite-eligible"
                        for parameter in profile.get("parameters", [])
                        if isinstance(parameter, dict)
                    )
                )
                prototype = profile.get("prototype", {})
                if isinstance(prototype, dict):
                    self.assertTrue(
                        all(
                            not bool(parameter.get("apply_to_idb", False))
                            for parameter in prototype.get("parameters", [])
                            if isinstance(parameter, dict)
                        )
                    )

    def _profiles_by_id(self) -> dict[str, dict[str, object]]:
        return {
            str(profile.get("id", "")): profile
            for profile in domain_identity._domain_identity_profiles()
            if isinstance(profile, dict) and str(profile.get("id", ""))
        }
