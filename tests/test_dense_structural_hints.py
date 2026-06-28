from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode


KI_SYNCH_NUMA_COUNTER_BLOCK_SAMPLE = r"""
NTSTATUS __fastcall KiSynchNumaCounterSetCallback(int a1, __int64 a2)
{
  _DWORD *v17; // rbx
  int v27; // [rsp+98h] [rbp-70h] BYREF
  int v28; // [rsp+9Ch] [rbp-6Ch]
  int v29; // [rsp+A0h] [rbp-68h]
  int v30; // [rsp+A4h] [rbp-64h]
  int v31; // [rsp+A8h] [rbp-60h]
  int v32; // [rsp+ACh] [rbp-5Ch]
  int v33; // [rsp+B0h] [rbp-58h]
  int v34; // [rsp+B4h] [rbp-54h]
  int v35; // [rsp+B8h] [rbp-50h]
  int v36; // [rsp+BCh] [rbp-4Ch]
  int v37; // [rsp+C0h] [rbp-48h]
  int v38; // [rsp+C4h] [rbp-44h]
  int v69; // [rsp+158h] [rbp+50h] BYREF
  int v70; // [rsp+15Ch] [rbp+54h]
  int v71; // [rsp+160h] [rbp+58h]
  int v72; // [rsp+164h] [rbp+5Ch]
  int v73; // [rsp+168h] [rbp+60h]
  int v74; // [rsp+16Ch] [rbp+64h]
  int v75; // [rsp+170h] [rbp+68h]
  int v76; // [rsp+174h] [rbp+6Ch]
  int v77; // [rsp+178h] [rbp+70h]
  int v78; // [rsp+17Ch] [rbp+74h]
  int v79; // [rsp+180h] [rbp+78h]
  int v80; // [rsp+184h] [rbp+7Ch]

  memset_0(&v27, 0, 0x30uLL);
  memset_0(&v69, 0, 0x30uLL);
  v17 = (_DWORD *)(a2 + 36544);
  v27 += *v17;
  v28 += v17[1];
  v29 += v17[2];
  v30 += v17[3];
  v31 += v17[4];
  v32 += v17[5];
  v33 += v17[6];
  v34 += v17[7];
  v35 += v17[8];
  v36 += v17[9];
  v37 += v17[10];
  v38 += v17[11];
  v69 += *v17;
  v70 += v17[1];
  v71 += v17[2];
  v72 += v17[3];
  v73 += v17[4];
  v74 += v17[5];
  v75 += v17[6];
  v76 += v17[7];
  v77 += v17[8];
  v78 += v17[9];
  v79 += v17[10];
  v80 += v17[11];
  return 0;
}
"""


RASP_SCAN_CONVERT_STACK_ARRAY_SAMPLE = r"""
__int64 __fastcall RaspScanConvert(__int64 a1, __int64 a2, unsigned int a3)
{
  unsigned int v24; // r9d
  unsigned int v25; // r8d
  int v62; // [rsp+30h] [rbp-30h] BYREF
  int v63; // [rsp+34h] [rbp-2Ch]
  int v64; // [rsp+38h] [rbp-28h]
  _DWORD v65[4]; // [rsp+40h] [rbp-20h] BYREF
  int v66; // [rsp+50h] [rbp-10h]
  __int64 v67; // [rsp+58h] [rbp-8h] BYREF

  v24 = a3;
  v25 = a3 + 1;
  v62 = *(_DWORD *)(17LL * v24 + a2 + 8);
  v63 = *(_DWORD *)(17LL * v24 + a2);
  v64 = *(_DWORD *)(17LL * v25 + a2 + 4);
  v66 = *(_DWORD *)(17LL * v25 + a2 + 8);
  v65[0] = v62 + v63;
  v65[1] = v64 + v66;
  v65[2] = v65[0] + v65[1];
  v65[3] = v65[2] + *(_DWORD *)(17LL * v25 + a2);
  return v65[3] + v67;
}
"""


ENUM_STACK_ARRAY_SAMPLE = r"""
__int64 __fastcall EnumArraySample(int a1)
{
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel[4]; // [rsp+C0h] [rbp-F8h]

  ImpersonationLevel[0] = 0;
  ImpersonationLevel[1] = a1;
  return ImpersonationLevel[2] + ImpersonationLevel[1];
}
"""


class DenseStructuralHintTests(unittest.TestCase):
    def test_ki_synch_numa_counter_dense_accumulators_are_reported(self) -> None:
        capture = capture_from_pseudocode(KI_SYNCH_NUMA_COUNTER_BLOCK_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        stack_regions = [item for item in plan.comments if item.get("kind") == "dense_stack_local_region"]
        accumulators = [item for item in plan.comments if item.get("kind") == "dense_accumulator_block"]
        synthetic = [item for item in plan.comments if item.get("kind") == "synthetic_local_aggregate"]

        self.assertGreaterEqual(len(stack_regions), 2)
        self.assertGreaterEqual(len(accumulators), 2)
        self.assertGreaterEqual(len(synthetic), 2)
        self.assertTrue(any(item.get("synthetic_name") == "PF_INFERRED_LOCAL_AGGREGATE_0" for item in synthetic))
        self.assertTrue(any("v27..v38" in item["text"] for item in accumulators))
        self.assertTrue(any("memset_0(&v27, 0, 0x30)" in item["text"] for item in stack_regions))
        self.assertIn("dense_accumulator_block", rendered)
        self.assertIn("dense_stack_local_region", rendered)
        self.assertIn("synthetic_local_aggregate", rendered)
        self.assertIn("v28 += v17[1]; // PseudoForge review-only: v27Aggregate.field_04", rendered)
        self.assertNotIn("v27Aggregate->field_04", rendered)
        self.assertIn("Review-only", rendered)

    def test_rasp_scan_convert_stack_array_and_strided_record_are_reported_only(self) -> None:
        capture = capture_from_pseudocode(RASP_SCAN_CONVERT_STACK_ARRAY_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        stack_regions = [item for item in plan.comments if item.get("kind") == "dense_stack_local_region"]
        struct_candidates = [item for item in plan.comments if item.get("kind") == "review_only_struct_candidate"]
        synthetic = [item for item in plan.comments if item.get("kind") == "synthetic_local_aggregate"]

        self.assertTrue(any("v65[4]" in item["text"] for item in stack_regions))
        self.assertEqual(1, len(struct_candidates))
        self.assertEqual(2, len(synthetic))
        self.assertIn("stride 0x11", struct_candidates[0]["text"])
        self.assertIn("+0x8", struct_candidates[0]["text"])
        self.assertIn("review_only_struct_candidate", rendered)
        self.assertIn("synthetic_local_aggregate", rendered)
        self.assertNotIn("review_only_struct_candidate", body)
        self.assertIn(
            "*(_DWORD *)(17LL * v25 + argument1 + 8); // PseudoForge review-only: argument1Aggregate.field_08",
            body,
        )
        self.assertIn("v65[1] = v64 + v66; // PseudoForge review-only: v65Aggregate.field_04", body)
        self.assertNotIn("argument1Aggregate->field_08", body)

    def test_stack_array_typedef_scalars_use_word_sized_offsets(self) -> None:
        capture = capture_from_pseudocode(ENUM_STACK_ARRAY_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertIn("ImpersonationLevelAggregate.field_04", body)
        self.assertIn("ImpersonationLevelAggregate.field_08", body)
        self.assertNotIn("ImpersonationLevelAggregate.field_01", body)
        self.assertNotIn("ImpersonationLevelAggregate.field_02", body)


if __name__ == "__main__":
    unittest.main()
