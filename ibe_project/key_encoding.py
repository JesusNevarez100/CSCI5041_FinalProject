"""Fixed-width AES-256 key encoding for Charm integer conversion.

The prefix preserves leading zeros; it is not an authentication mechanism.
"""

KEY_BYTES = 32
PREFIX = b"\x01"


def encode_key(key: bytes) -> bytes:
    """Encode exactly one AES-256 key as 33 bytes."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("Expected a 32-byte AES key")
    return PREFIX + key


def decode_key(encoded: bytes) -> bytes:
    """Reject failed decryption, wrong lengths and unknown prefixes."""
    if (not isinstance(encoded, bytes)
            or len(encoded) != KEY_BYTES + 1
            or encoded[:1] != PREFIX):
        raise ValueError("Invalid recovered key encoding")
    return encoded[1:]
