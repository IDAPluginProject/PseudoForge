from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles import loader as profile_loader


SOURCE_PATH = r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"
MISMATCH_SOURCE_PATH = r"D:\bin\os\99999.1\ntoskrnl.exe.i64"


class CompressionXpressDomainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def tearDown(self) -> None:
        profile_loader.configure_profile_dir(profile_loader.DEFAULT_PROFILE_DIR)

    def test_xp10_huffman_decode_corrects_generic_signature_preview(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall Xp10ReadAndDecodeHuffmanTables(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, unsigned int a7, __int64 *a8)
{
  unsigned int scratch;
  scratch = 0;
  if ( *(_QWORD *)a5 )
  {
    Xp10ScatteredReadBytes(a5 + 24, &scratch, 4LL);
    Xp10SortHuffmanSymbols((int)a1 + 24, (int)a1 + 728, 33, 4, 8);
    *a8 = Xp10BuildHuffmanDecodeTable(a1 + 24, a1 + 2136, (_WORD *)(a1 + 728), 1, 8u, 4, a1 + 37464, 0, a6);
  }
  return STATUS_BAD_COMPRESSION_BUFFER;
}
""",
            source_path=SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.compression_xpress.xp10_read_and_decode_huffman_tables"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]
        identities = [
            item
            for item in plan.comments
            if item.get("kind") == "domain_structure_identity"
            and item.get("profile_id") == profile_id
        ]

        self.assertEqual(5, len(corrections))
        self.assertTrue(all(item.apply_to_preview for item in corrections))
        self.assertTrue(all(not item.apply_to_idb for item in corrections))
        self.assertIn(
            "NTSTATUS __fastcall Xp10ReadAndDecodeHuffmanTables("
            "PXP10_DECODE_CONTEXT decodeContext, ULONG symbolCount, __int64 argument2, "
            "__int64 argument3, PXP10_BIT_READER bitReader, __int64 argument5, "
            "ULONG argument6, PVOID * decodeTableOutput)",
            rendered,
        )
        self.assertNotIn("__int64 decodeContext", rendered)
        self.assertNotIn("__int64 bitReader", rendered)
        self.assertEqual(
            {
                "decodeContext": "XP10_DECODE_CONTEXT",
                "symbolCount": "XP10_SYMBOL_COUNT",
                "bitReader": "XP10_BIT_READER",
                "decodeTableOutput": "XP10_DECODE_TABLE_OUTPUT",
            },
            {item["trusted_role"]: item["structure_name"] for item in identities},
        )
        self.assertTrue(
            all(
                item.get("profile_metadata", {}).get("subsystem") == "Compression/Xpress"
                for item in identities
            )
        )
        self.assertTrue(all(item.get("effective_mode") == "report-only" for item in identities))
        self.assertFalse(any(item.get("kind") == "inferred_offset_rewrite_ready" for item in plan.comments))

    def test_xp10_huffman_decode_requires_xp10_callees(self) -> None:
        plan = self._plan(
            """
__int64 __fastcall Xp10ReadAndDecodeHuffmanTables(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, unsigned int a7, __int64 *a8)
{
  *a8 = a6;
  return 0;
}
"""
        )

        self.assertFalse(
            any(
                item.profile_id == "windows.compression_xpress.xp10_read_and_decode_huffman_tables"
                for item in plan.type_corrections
            )
        )

    def test_xp10_huffman_decode_build_mismatch_is_diagnostic_only(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall Xp10ReadAndDecodeHuffmanTables(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, unsigned int a7, __int64 *a8)
{
  unsigned int scratch;
  scratch = 0;
  Xp10ScatteredReadBytes(a5 + 24, &scratch, 4LL);
  Xp10SortHuffmanSymbols((int)a1 + 24, (int)a1 + 728, 33, 4, 8);
  *a8 = Xp10BuildHuffmanDecodeTable(a1 + 24, a1 + 2136, (_WORD *)(a1 + 728), 1, 8u, 4, a1 + 37464, 0, a6);
  return 0;
}
""",
            source_path=MISMATCH_SOURCE_PATH,
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        profile_id = "windows.compression_xpress.xp10_read_and_decode_huffman_tables"
        corrections = [item for item in plan.type_corrections if item.profile_id == profile_id]

        self.assertEqual(5, len(corrections))
        self.assertTrue(all("build_mismatch" in item.blockers for item in corrections))
        self.assertFalse(any(item.apply_to_preview for item in corrections))
        self.assertIn("__int64 __fastcall Xp10ReadAndDecodeHuffmanTables(", rendered)
        self.assertIn("Parameter type corrections: 0 applied, 5 blocked.", rendered)
        self.assertIn("build_mismatch=5", rendered)

    def test_compression_xpress_manifest_is_reported_when_pack_is_used(self) -> None:
        self._plan(
            """
__int64 __fastcall Xp10ReadAndDecodeHuffmanTables(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, unsigned int a7, __int64 *a8)
{
  unsigned int scratch;
  scratch = 0;
  Xp10ScatteredReadBytes(a5 + 24, &scratch, 4LL);
  Xp10SortHuffmanSymbols((int)a1 + 24, (int)a1 + 728, 33, 4, 8);
  *a8 = Xp10BuildHuffmanDecodeTable(a1 + 24, a1 + 2136, (_WORD *)(a1 + 728), 1, 8u, 4, a1 + 37464, 0, a6);
  return 0;
}
"""
        )

        manifests = profile_loader.active_profile_manifests()

        self.assertTrue(
            any(item.get("name") == "domain_identity/compression_xpress.json" for item in manifests)
        )

    def test_compression_xpress_subsystem_index_maps_profile(self) -> None:
        metadata = profile_loader.subsystem_identity_metadata(
            "windows.compression_xpress.xp10_read_and_decode_huffman_tables"
        )

        self.assertEqual("Compression/Xpress", metadata.get("subsystem"))
        self.assertEqual(
            "Xpress bitstream, Huffman table, and decode context roles",
            metadata.get("role_group"),
        )

    def _plan(self, text: str, source_path: str = SOURCE_PATH):
        capture = capture_from_pseudocode(text, source_path=source_path)
        return build_clean_plan(capture)


if __name__ == "__main__":
    unittest.main()
