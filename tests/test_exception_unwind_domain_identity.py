from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class ExceptionUnwindDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_rtlpx_virtual_unwind_identifies_control_pc(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall RtlpxVirtualUnwind(
        int argument0,
        __int64 argument1,
        unsigned __int64 a3,
        unsigned __int64 argument3,
        __int64 argument4,
        _BYTE *argument5,
        _QWORD *argument6,
        unsigned __int64 *argument7,
        _QWORD *argument8,
        __int64 argument9)
{
  __int64 unwindInfo;
  unsigned int offsetInFunction;

  unwindInfo = argument1 + *(unsigned int *)(argument3 + 8);
  offsetInFunction = a3 - argument1 - *(_DWORD *)argument3;
  if ( *(_BYTE *)unwindInfo && *(_BYTE *)a3 == 72 )
  {
    offsetInFunction += RtlpUnwindOpSlots();
  }
  return offsetInFunction;
}
"""
        )

        identity = self._single_identity(
            plan,
            "windows.exception_unwind.rtlpx_virtual_unwind",
            role="controlPc",
        )
        rename = self._rename(plan, "a3")

        self.assertEqual("controlPc", rename["new"])
        self.assertEqual("domain-profile", rename["source"])
        self.assertEqual("VIRTUAL_ADDRESS", identity["structure_name"])
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("profile_report_only", identity["blockers"])
        self.assertEqual([], identity["fields"])
        self.assertEqual("26200.8457", identity["profile_metadata"]["build"])
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_layout"
                and item.get("base") == "controlPc"
                for item in plan.comments
            )
        )
        self.assertFalse(
            any(
                item.get("kind") == "inferred_offset_rewrite_blockers"
                and item.get("base") == "controlPc"
                for item in plan.comments
            )
        )

    def test_rtlpx_virtual_unwind_requires_unwind_callee_hint(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall RtlpxVirtualUnwind(
        int argument0,
        __int64 argument1,
        unsigned __int64 a3,
        unsigned __int64 argument3,
        __int64 argument4,
        _BYTE *argument5,
        _QWORD *argument6,
        unsigned __int64 *argument7,
        _QWORD *argument8,
        __int64 argument9)
{
  return a3 - argument1 - *(_DWORD *)argument3;
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.exception_unwind.rtlpx_virtual_unwind"
                for item in self._identities(plan)
            )
        )
        self.assertFalse(any(item["new"] == "controlPc" for item in self._renames(plan)))

    def test_build_mismatch_does_not_promote_control_pc_rename(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall RtlpxVirtualUnwind(
        int argument0,
        __int64 argument1,
        unsigned __int64 a3,
        unsigned __int64 argument3,
        __int64 argument4,
        _BYTE *argument5,
        _QWORD *argument6,
        unsigned __int64 *argument7,
        _QWORD *argument8,
        __int64 argument9)
{
  if ( *(_BYTE *)a3 == 72 )
  {
    return RtlpUnwindOpSlots();
  }
  return 0;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )

        identity = self._single_identity(
            plan,
            "windows.exception_unwind.rtlpx_virtual_unwind",
            role="controlPc",
        )

        self.assertNotIn("controlPc", {item["new"] for item in self._renames(plan)})
        self.assertEqual("report-only", identity["effective_mode"])
        self.assertIn("build_mismatch", identity["forced_report_only_reasons"])
        self.assertIn("build_mismatch", identity["blockers"])

    def test_accepted_type_guard_blocks_wrong_control_pc_type(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall RtlpxVirtualUnwind(
        int argument0,
        __int64 argument1,
        int a3,
        unsigned __int64 argument3,
        __int64 argument4,
        _BYTE *argument5,
        _QWORD *argument6,
        unsigned __int64 *argument7,
        _QWORD *argument8,
        __int64 argument9)
{
  if ( *(_BYTE *)a3 == 72 )
  {
    return RtlpUnwindOpSlots();
  }
  return 0;
}
"""
        )

        self.assertFalse(
            any(
                item.get("profile_id") == "windows.exception_unwind.rtlpx_virtual_unwind"
                for item in self._identities(plan)
            )
        )
        self.assertFalse(any(item["new"] == "controlPc" for item in self._renames(plan)))

    def test_exception_unwind_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall RtlpxVirtualUnwind(
        int argument0,
        __int64 argument1,
        unsigned __int64 a3,
        unsigned __int64 argument3,
        __int64 argument4,
        _BYTE *argument5,
        _QWORD *argument6,
        unsigned __int64 *argument7,
        _QWORD *argument8,
        __int64 argument9)
{
  return RtlpUnwindOpSlots() + a3;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/exception_unwind.json" for item in manifests)
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)

    def _identities(self, plan) -> list[dict[str, object]]:
        return [item for item in plan.comments if item.get("kind") == "domain_structure_identity"]

    def _renames(self, plan) -> list[dict[str, object]]:
        return [
            {
                "old": item.old,
                "new": item.new,
                "confidence": item.confidence,
                "source": item.source,
                "evidence": item.evidence,
                "apply": item.apply,
            }
            for item in plan.renames
        ]

    def _rename(self, plan, old: str) -> dict[str, object]:
        matches = [item for item in self._renames(plan) if item["old"] == old]
        self.assertEqual(1, len(matches))
        return matches[0]

    def _single_identity(
        self,
        plan,
        profile_id: str,
        role: str = "",
    ) -> dict[str, object]:
        identities = [
            item
            for item in self._identities(plan)
            if item.get("profile_id") == profile_id
        ]
        if role:
            identities = [item for item in identities if item.get("trusted_role") == role]
        self.assertEqual(1, len(identities))
        return identities[0]
