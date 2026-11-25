"""Run with: python -m examples.ibe_smoke_test"""

import platform
import secrets
import sys
from importlib.metadata import version

from ibe_project.boneh_franklin import BinarySafeBonehFranklin
from charm.toolbox.pairinggroup import PairingGroup

from ibe_project.identity import ibe_identity
from ibe_project.key_encoding import encode_key, decode_key


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    print(f"Python: {sys.version.split()[0]}; architecture: {platform.machine()}")
    print(f"Charm: {version('charm-crypto-framework')}")
    group = PairingGroup("MNT224", secparam=1024)
    ibe = BinarySafeBonehFranklin(group)
    public, master = ibe.setup()
    alice = ibe_identity("alice@EXAMPLE.COM")
    message = b"Project demo"

    # No recipient key exists at encryption time.
    ciphertext = ibe.encrypt(public, alice, message)
    require(ciphertext is not None, "IBE encryption failed")
    alice_key = ibe.extract(master, alice)
    require(ibe.decrypt(public, alice_key, ciphertext) == message,
            "Message round trip failed")
    print("PASS: encrypt first, issue recipient key later, decrypt")

    # Exercise the actual Charm round trip, not only the encoding functions.
    keys = [
        b"\x00" * 32,
        b"\x00" + b"\xff" * 31,
        b"\x00" * 8 + b"\xff" * 24,
        b"\xff" * 32,
    ] + [secrets.token_bytes(32) for _ in range(20)]
    for key in keys:
        ct = ibe.encrypt(public, alice, encode_key(key))
        require(ct is not None, "Charm rejected the 33-byte encoded key")
        recovered = ibe.decrypt(public, alice_key, ct)
        require(decode_key(recovered) == key, "AES key round trip failed")
    print(f"PASS: {len(keys)} encoded AES-256 keys recovered exactly")

    malformed = [None, "not bytes", b"", b"\x01" + b"\x00" * 31,
                 b"\x01" + b"\x00" * 33, b"\x02" + b"\x00" * 32]
    for value in malformed:
        try:
            decode_key(value)
        except ValueError:
            continue
        raise RuntimeError("Malformed recovered key was accepted")
    for value in [None, "not bytes", b"", b"\x00" * 31, b"\x00" * 33]:
        try:
            encode_key(value)
        except ValueError:
            continue
        raise RuntimeError("Invalid AES key was accepted")
    print("PASS: invalid input and malformed key encodings rejected")
    print("Smoke test complete; no security-level or attack-resistance claim")


if __name__ == "__main__":
    main()
