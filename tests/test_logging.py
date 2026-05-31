from __future__ import annotations

import os
import tempfile
import unittest

from ida_pseudoforge.logging import append_bounded_log_line


class LoggingTests(unittest.TestCase):
    def test_bounded_log_line_rotates_at_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "pseudoforge_trace.log")
            for index in range(20):
                append_bounded_log_line(log_path, "line-%02d-%s" % (index, "X" * 20), max_bytes=160)

            rotated_path = log_path + ".1"

            self.assertTrue(os.path.exists(log_path))
            self.assertTrue(os.path.exists(rotated_path))
            self.assertLessEqual(os.path.getsize(log_path), 160)
            self.assertLessEqual(os.path.getsize(rotated_path), 160)
            with open(log_path, "r", encoding="utf-8") as file:
                current_text = file.read()
            self.assertIn("line-19", current_text)


if __name__ == "__main__":
    unittest.main()
