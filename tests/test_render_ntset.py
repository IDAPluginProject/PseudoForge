from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_ntset import normalize_ntset_system_information_body


NTSET_REUSED_M128_ALIAS_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  void *Buf1[2];
  __m128i v148;

  v4 = a2;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = a2->m128i_i32[0];
  if ( (_DWORD)a3 )
    a1 = &a2->m128i_i8[(unsigned int)a3];
  v4 = (__m128i *)Buf1;
  updated += v4->m128i_i32[0];
  v4 = &v148;
  updated += a2[1].m128i_i32[0];
  return updated;
}
"""


NTSET_PRENORMALIZED_REUSED_M128_ALIAS_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        ULONG systemInformationLength)
{
  __m128i *systemInfo128 = (__m128i *)systemInformation;
  NTSTATUS status;
  __m128i capturedBlock0;

  status = systemInfo128->m128i_i32[0];
  systemInfo128 = &capturedBlock0;
  status += systemInfo128->m128i_i32[0];
  return status;
}
"""


class RenderNtSetTests(unittest.TestCase):
    def test_normalize_ntset_body_uses_stable_m128_alias_for_typed_access(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128;",
                "  KPROCESSOR_MODE previousMode;",
                "  NTSTATUS status;",
                "",
                "  systemInfo128 = systemInformation;",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "  status = systemInformation->m128i_i32[0];",
                "  status += systemInformation[1].m128i_i32[0];",
                "  capturedBlock0 = *systemInformation;",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertIn("PVOID userProbeEnd;", rendered)
        self.assertIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)
        self.assertIn("status = systemInfo128->m128i_i32[0];", rendered)
        self.assertIn("status += systemInfo128[1].m128i_i32[0];", rendered)
        self.assertIn("capturedBlock0 = *systemInfo128;", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("systemInformationClass = &", rendered)

    def test_normalize_ntset_body_splits_reused_m128_alias(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128 = (__m128i *)systemInformation;",
                "  KPROCESSOR_MODE previousMode;",
                "  NTSTATUS status;",
                "",
                "  systemInfo128 = (__m128i *)Buf1;",
                "  status = systemInformation->m128i_i32[0];",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertIn("__m128i *systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("__m128i *infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("infoBuffer128 = (__m128i *)Buf1;", rendered)
        self.assertIn("status = systemInformation128->m128i_i32[0];", rendered)
        self.assertIn(
            "userProbeEnd = &systemInformation128->m128i_i8[(unsigned int)systemInformationLength];",
            rendered,
        )
        self.assertNotIn("systemInfo128", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)

    def test_normalize_ntset_body_keeps_existing_user_probe_end_declaration(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128;",
                "  KPROCESSOR_MODE previousMode;",
                "  PVOID userProbeEnd;",
                "",
                "  systemInfo128 = systemInformation;",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertEqual(rendered.count("PVOID userProbeEnd;"), 1)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)

    def test_reused_m128_alias_splits_original_view_from_mutable_alias(self) -> None:
        capture = capture_from_pseudocode(NTSET_REUSED_M128_ALIAS_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v4"], "infoBuffer128")
        self.assertIn("__m128i *infoBuffer128;", rendered)
        self.assertIn("__m128i *systemInformation128;", rendered)
        self.assertIn("systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("infoBuffer128 = (__m128i *)Buf1;", rendered)
        self.assertIn("infoBuffer128 = &v148;", rendered)
        self.assertIn("status = systemInformation128->m128i_i32[0];", rendered)
        self.assertIn(
            "userProbeEnd = &systemInformation128->m128i_i8[(unsigned int)systemInformationLength];",
            rendered,
        )
        self.assertIn("status += systemInformation128[1].m128i_i32[0];", rendered)
        self.assertNotIn("__m128i *systemInfo128;", rendered)
        self.assertNotIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("((__m128i *)systemInformation)->", rendered)

    def test_prenormalized_reused_m128_alias_is_neutralized(self) -> None:
        capture = capture_from_pseudocode(NTSET_PRENORMALIZED_REUSED_M128_ALIAS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("__m128i *systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("__m128i *infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("status = infoBuffer128->m128i_i32[0];", rendered)
        self.assertIn("infoBuffer128 = &capturedBlock0;", rendered)
        self.assertNotIn("systemInfo128", rendered)


if __name__ == "__main__":
    unittest.main()
