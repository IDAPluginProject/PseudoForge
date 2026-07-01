from __future__ import annotations

import unittest

from ida_pseudoforge.core.helper_depth import (
    DEFAULT_HELPER_DEPTH,
    helper_capture_limit_for_depth,
    parse_helper_depth,
)


class HelperDepthTests(unittest.TestCase):
    def test_parse_helper_depth_accepts_two_through_four(self) -> None:
        self.assertEqual(2, parse_helper_depth("2"))
        self.assertEqual(3, parse_helper_depth("3"))
        self.assertEqual(4, parse_helper_depth("4"))

    def test_parse_helper_depth_rejects_values_outside_menu_range(self) -> None:
        self.assertIsNone(parse_helper_depth("1"))
        self.assertIsNone(parse_helper_depth("5"))
        self.assertIsNone(parse_helper_depth("x"))

    def test_capture_limit_scales_with_depth(self) -> None:
        self.assertEqual(12, helper_capture_limit_for_depth(DEFAULT_HELPER_DEPTH))
        self.assertEqual(32, helper_capture_limit_for_depth(3))
        self.assertEqual(64, helper_capture_limit_for_depth(4))


if __name__ == "__main__":
    unittest.main()
