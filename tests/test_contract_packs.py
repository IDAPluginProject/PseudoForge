from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.contract_packs import (
    contract_pack_comments,
    contract_pack_summary,
    contract_profile_names_for_target,
    load_contract_pack,
)
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.free.service import analyze_text
from ida_pseudoforge.profiles import loader as profile_loader


WIN_USER_SAMPLE = r"""
__int64 __fastcall WinUserContractSample()
{
  HANDLE hFile;
  void *region;

  hFile = CreateFileW(L"C:\\temp\\input.bin", 0x80000000, 1u, 0i64, 3u, 0x80u, 0i64);
  region = VirtualAlloc(0i64, 0x1000ui64, 0x3000u, 4u);
  CloseHandle(hFile);
  return region != 0;
}
"""


LINUX_USER_SAMPLE = r"""
int __fastcall LinuxUserContractSample(void *ctx)
{
  int fd;
  void *buffer;

  buffer = malloc(64);
  pthread_mutex_lock(ctx);
  fd = socket(2, 1, 0);
  send(fd, buffer, 64, 0);
  close(fd);
  pthread_mutex_unlock(ctx);
  free(buffer);
  return 0;
}
"""


CXX_RUNTIME_SAMPLE = r"""
void *__fastcall CxxRuntimeObjectLifetime(unsigned __int64 size)
{
  void *object;

  object = _Znwm(size);
  __CxxFrameHandler4(0i64, 0i64, 0i64, 0i64);
  _ZdlPv(object);
  return object;
}
"""


UEFI_SAMPLE = r"""
EFI_STATUS __fastcall FirmwareUefiBootServices(void *gBS, void *guid)
{
  void *buffer;
  void *protocol;
  EFI_STATUS status;

  status = AllocatePool(0, 0x200, &buffer);
  if ( !status )
    LocateProtocol(guid, 0i64, &protocol);
  FreePool(buffer);
  return status;
}
"""


MACOS_SAMPLE = r"""
void __fastcall MacosObjcDispatch(void *queue, void *object, void *block)
{
  void *retained;

  retained = objc_retain(object);
  dispatch_async(queue, block);
  objc_release(retained);
}
"""


class ContractPackTests(unittest.TestCase):
    def tearDown(self) -> None:
        profile_loader.clear_profile_caches()

    def test_contract_profiles_are_report_only_runtime_inventory(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

        win_profile = load_contract_pack("contracts/win_user_api_contracts.json")
        linux_profile = load_contract_pack("contracts/linux_user_api_contracts.json")
        cxx_profile = load_contract_pack("contracts/cxx_runtime_contracts.json")
        uefi_profile = load_contract_pack("contracts/uefi_api_contracts.json")
        macos_profile = load_contract_pack("contracts/macos_macho_api_contracts.json")

        self.assertEqual("pseudoforge_contract_pack_v1", win_profile["schema"])
        self.assertEqual("report-only", win_profile["mode"])
        self.assertEqual("win_user_pe", win_profile["domain_pack_id"])
        self.assertEqual(6, len(win_profile["contracts"]))
        self.assertEqual("linux_elf_user", linux_profile["domain_pack_id"])
        self.assertEqual(9, len(linux_profile["contracts"]))
        self.assertEqual("cxx_runtime", cxx_profile["domain_pack_id"])
        self.assertEqual(3, len(cxx_profile["contracts"]))
        self.assertEqual("firmware_uefi", uefi_profile["domain_pack_id"])
        self.assertEqual(3, len(uefi_profile["contracts"]))
        self.assertEqual("macos_macho_user", macos_profile["domain_pack_id"])
        self.assertEqual(3, len(macos_profile["contracts"]))
        self.assertEqual([], profile_loader.profile_load_warnings())

    def test_windows_user_contracts_emit_comments_and_summary(self) -> None:
        capture = capture_from_pseudocode(
            WIN_USER_SAMPLE,
            source_path=r"C:\bin\client.exe",
            profile_context={
                "format": "pe",
                "platform": "windows",
                "privilege_domain": "user",
                "imports": ["CreateFileW", "VirtualAlloc", "CloseHandle"],
            },
        )
        plan = build_clean_plan(capture)
        comments = [
            item
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        ]
        symbols = {str(item.get("contract_symbol", "")) for item in comments}
        summary = contract_pack_summary(capture, plan)

        self.assertEqual(["contracts/win_user_api_contracts.json"], contract_profile_names_for_target(capture.target_context))
        self.assertIn("CreateFileW", symbols)
        self.assertIn("VirtualAlloc", symbols)
        self.assertIn("CloseHandle", symbols)
        self.assertTrue(any(item.get("ownership") == "returns_handle" for item in comments))
        self.assertEqual(["contracts/win_user_api_contracts.json"], summary["profiles"])
        self.assertEqual(["contracts/win_user_api_contracts.json"], summary["matched_profiles"])
        self.assertIn("CreateFileW", summary["matched_symbols"])
        self.assertEqual(3, summary["matched_contracts"])
        self.assertEqual({"windows_user_mode": 3}, summary["matched_by_domain"])

    def test_windows_user_contracts_do_not_activate_for_kernel_target(self) -> None:
        capture = capture_from_pseudocode(
            WIN_USER_SAMPLE,
            source_path=r"C:\drivers\client.sys",
            profile_context={
                "format": "pe",
                "platform": "windows",
                "privilege_domain": "kernel",
                "imports": ["CreateFileW", "CloseHandle"],
            },
        )
        plan = build_clean_plan(capture)

        self.assertEqual("windows_kernel", capture.target_context.target_family)
        self.assertEqual([], contract_profile_names_for_target(capture.target_context))
        self.assertEqual([], contract_pack_comments(capture))
        self.assertFalse(
            any(
                isinstance(item, dict) and item.get("kind") == "contract_pack_api"
                for item in plan.comments
            )
        )

    def test_linux_user_contracts_emit_comments_without_windows_contracts(self) -> None:
        capture = capture_from_pseudocode(
            LINUX_USER_SAMPLE,
            source_path="/tmp/server.elf",
            profile_context={
                "format": "elf",
                "platform": "linux",
                "imports": ["malloc", "free", "pthread_mutex_lock", "socket", "send", "close"],
                "sections": [".text", ".rodata", ".eh_frame"],
            },
        )
        plan = build_clean_plan(capture)
        comments = [
            item
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        ]
        symbols = {str(item.get("contract_symbol", "")) for item in comments}
        summary = contract_pack_summary(capture, plan)

        self.assertEqual("linux_elf_user", capture.target_context.target_family)
        self.assertIn("linux_elf_user", capture.target_context.eligible_domain_packs)
        self.assertIn("win_user_pe", capture.target_context.rejected_domain_packs)
        self.assertEqual(["contracts/linux_user_api_contracts.json"], contract_profile_names_for_target(capture.target_context))
        self.assertIn("malloc", symbols)
        self.assertIn("pthread_mutex_lock", symbols)
        self.assertIn("socket", symbols)
        self.assertIn("send", symbols)
        self.assertIn("close", symbols)
        self.assertNotIn("CreateFileW", symbols)
        self.assertEqual(["contracts/linux_user_api_contracts.json"], summary["profiles"])
        self.assertEqual({"linux_userland": len(comments)}, summary["matched_by_domain"])

    def test_cxx_runtime_contracts_emit_on_runtime_pack_without_becoming_os_family(self) -> None:
        capture = capture_from_pseudocode(
            CXX_RUNTIME_SAMPLE,
            source_path=r"C:\bin\game_client.exe",
            profile_context={
                "format": "pe",
                "platform": "windows",
                "privilege_domain": "user",
                "imports": ["operator new", "operator delete", "__CxxFrameHandler4"],
                "compiler_family": "msvc",
                "abi": "msvc",
                "language_runtime": "cxx",
            },
        )
        plan = build_clean_plan(capture)
        comments = [
            item
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        ]
        symbols = {str(item.get("contract_symbol", "")) for item in comments}

        self.assertEqual("windows_user_pe", capture.target_context.target_family)
        self.assertIn("cxx_runtime", capture.target_context.eligible_domain_packs)
        self.assertIn("win_user_pe", capture.target_context.eligible_domain_packs)
        self.assertIn("contracts/cxx_runtime_contracts.json", contract_profile_names_for_target(capture.target_context))
        self.assertIn("operator new", symbols)
        self.assertIn("operator delete", symbols)
        self.assertIn("__CxxFrameHandler4", symbols)

    def test_uefi_contracts_emit_without_windows_user_or_linux_bleedthrough(self) -> None:
        capture = capture_from_pseudocode(
            UEFI_SAMPLE,
            source_path=r"X:\firmware\Driver.efi",
            profile_context={
                "format": "pe",
                "platform": "uefi",
                "privilege_domain": "firmware",
                "imports": ["AllocatePool", "FreePool", "LocateProtocol"],
            },
        )
        plan = build_clean_plan(capture)
        comments = [
            item
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        ]
        symbols = {str(item.get("contract_symbol", "")) for item in comments}

        self.assertEqual("firmware_uefi", capture.target_context.target_family)
        self.assertIn("firmware_uefi", capture.target_context.eligible_domain_packs)
        self.assertIn("win_user_pe", capture.target_context.rejected_domain_packs)
        self.assertIn("linux_elf_user", capture.target_context.rejected_domain_packs)
        self.assertEqual(["contracts/uefi_api_contracts.json"], contract_profile_names_for_target(capture.target_context))
        self.assertEqual({"AllocatePool", "FreePool", "LocateProtocol"}, symbols)

    def test_macos_macho_contracts_emit_without_windows_or_uefi_bleedthrough(self) -> None:
        capture = capture_from_pseudocode(
            MACOS_SAMPLE,
            source_path="/tmp/AppKitClient.macho",
            profile_context={
                "format": "macho",
                "platform": "macos",
                "privilege_domain": "user",
                "imports": ["dispatch_async", "objc_retain", "objc_release"],
            },
        )
        plan = build_clean_plan(capture)
        comments = [
            item
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        ]
        symbols = {str(item.get("contract_symbol", "")) for item in comments}

        self.assertEqual("macos_macho_user", capture.target_context.target_family)
        self.assertIn("macos_macho_user", capture.target_context.eligible_domain_packs)
        self.assertIn("win_user_pe", capture.target_context.rejected_domain_packs)
        self.assertIn("firmware_uefi", capture.target_context.rejected_domain_packs)
        self.assertEqual(["contracts/macos_macho_api_contracts.json"], contract_profile_names_for_target(capture.target_context))
        self.assertEqual({"dispatch_async", "objc_retain", "objc_release"}, symbols)

    def test_export_and_free_summary_include_contract_pack_summary(self) -> None:
        capture = capture_from_pseudocode(
            WIN_USER_SAMPLE,
            source_path=r"C:\bin\client.exe",
            profile_context={
                "format": "pe",
                "platform": "windows",
                "privilege_domain": "user",
            },
        )
        plan = build_clean_plan(capture)

        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts = write_export_bundle(temp_dir, capture, plan)
            export_summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            free_result = analyze_text(
                WIN_USER_SAMPLE,
                output_dir=Path(temp_dir) / "free",
                input_label="client.exe.cpp",
                source_path=r"C:\bin\client.exe",
            )

        self.assertEqual(
            ["contracts/win_user_api_contracts.json"],
            export_summary["contract_pack_summary"]["matched_profiles"],
        )
        self.assertIn("CreateFileW", export_summary["contract_pack_summary"]["matched_symbols"])
        self.assertEqual(
            export_summary["contract_pack_summary"]["matched_symbols"],
            free_result.payload["contract_pack_summary"]["matched_symbols"],
        )


if __name__ == "__main__":
    unittest.main()
