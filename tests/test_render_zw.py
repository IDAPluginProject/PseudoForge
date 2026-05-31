from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_zw import normalize_zw_api_probe_body


class RenderZwTests(unittest.TestCase):
    def test_normalize_zw_api_probe_body_rewrites_object_attributes_and_handles(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Length = 48;",
                "objectAttributes.Attributes = 576;",
                "createEventStatus = ZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, 0);",
                "if ( createEventStatus >= 0 )",
                "  ZwSetEvent(eventHandle, 0LL);",
                "ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &tokenHandle);",
                "ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &tokenHandle);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("if ( NT_SUCCESS(createEventStatus) )", rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwOpenThreadTokenEx(NtCurrentThread(), 8u, 1u, 0x200u, &tokenHandle);", rendered)

    def test_normalize_zw_api_probe_body_rewrites_only_used_object_attributes(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Length = 0x30u;",
                "objectAttributes.Attributes = 0x200u;",
                "otherHeader.Length = 48;",
                "ZwOpenKey(&eventHandle, 0x20019u, &objectAttributes);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("otherHeader.Length = 48;", rendered)

    def test_normalize_zw_api_probe_body_preserves_unknown_object_attribute_bits(self) -> None:
        text = "\n".join(
            [
                "objectAttributes.Attributes = 0x2402u;",
                "ZwCreateKey(&eventHandle, 0xF003Fu, &objectAttributes, 0, 0LL, 0, 0LL);",
            ]
        )

        rendered = normalize_zw_api_probe_body(text)

        self.assertIn(
            "objectAttributes.Attributes = OBJ_INHERIT | OBJ_FORCE_ACCESS_CHECK | 0x2000;",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
