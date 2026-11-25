"""Boneh–Franklin with explicit binary-safe integer conversion.

Only the byte codec is overridden; pairing and encryption operations remain
in Charm. Keep a nonzero prefix to preserve original byte length.
"""
from charm.core.math.integer import integer
from charm.schemes.ibenc.ibenc_bf01 import IBE_BonehFranklin


class BinarySafeBonehFranklin(IBE_BonehFranklin):
    def encodeToZn(self, message):
        if not isinstance(message, bytes) or not message:
            raise ValueError("Expected nonempty bytes")
        return integer(int.from_bytes(message, "big"))

    def decodeFromZn(self, element):
        value = int(element)
        if value < 0:
            raise ValueError("Invalid negative message integer")
        return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
