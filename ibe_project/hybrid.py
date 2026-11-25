"""In-memory Boneh–Franklin key transport with AES-256-GCM payloads.

Trusted local key issuance only. This does not authenticate the sender,
prevent replay, or verify ownership of an email address.
"""
from dataclasses import dataclass
import json
import secrets

import base64
from charm.toolbox.pairinggroup import PairingGroup
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .boneh_franklin import BinarySafeBonehFranklin
from .identity import ibe_identity
from .key_encoding import encode_key, decode_key

SCHEME = "BF01-AES256GCM-v1"


class DecryptionError(ValueError):
    """The envelope is invalid or cannot be decrypted with this key."""


@dataclass(frozen=True)
class Envelope:
    scheme: str
    identity: str
    wrapped_key: dict
    nonce: bytes
    ciphertext: bytes  # Includes the 16-byte GCM authentication tag.


class IBEWorkflow:
    def __init__(self):
        # Reproduce the existing example; this is not a security-level claim.
        self.group = PairingGroup("MNT224", secparam=1024)
        self.ibe = BinarySafeBonehFranklin(self.group)

    def setup(self):
        return self.ibe.setup()

    def issue_key(self, master_secret, email):
        # Caller is responsible for authorizing this trusted local operation.
        return self.ibe.extract(master_secret, ibe_identity(email))

    def _aad(self, scheme, identity, wrapped_key):
        # Pairing elements and Charm integer elements need different codecs.
        # Canonical JSON binds all three BF ciphertext components into GCM.
        header = {
            "scheme": scheme, "identity": identity,
            "wrapped_key": {
                "U": base64.b64encode(self.group.serialize(wrapped_key["U"])).decode("ascii"),
                "V": format(int(wrapped_key["V"]), "x"),
                "W": format(int(wrapped_key["W"]), "x"),
            },
        }
        return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def encrypt(self, public, email, plaintext):
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        identity = ibe_identity(email)
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        wrapped = self.ibe.encrypt(public, identity, encode_key(key))
        if wrapped is None:
            raise ValueError("IBE could not encode the session key")
        aad = self._aad(SCHEME, identity, wrapped)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return Envelope(SCHEME, identity, wrapped, nonce, ciphertext)

    def decrypt(self, public, private_key, envelope):
        try:
            if not isinstance(envelope, Envelope):
                raise ValueError("Invalid envelope type")
            if envelope.scheme != SCHEME:
                raise ValueError("Unsupported envelope scheme")
            if envelope.identity != private_key["IDstr"]:
                raise ValueError("Recipient identity mismatch")
            if not isinstance(envelope.nonce, bytes) or len(envelope.nonce) != 12:
                raise ValueError("Invalid nonce")
            if not isinstance(envelope.ciphertext, bytes) or len(envelope.ciphertext) < 16:
                raise ValueError("Invalid payload")
            recovered = self.ibe.decrypt(public, private_key, envelope.wrapped_key)
            key = decode_key(recovered)
            aad = self._aad(envelope.scheme, envelope.identity, envelope.wrapped_key)
            return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, aad)
        except (InvalidTag, ValueError, TypeError, KeyError, AttributeError,
                OverflowError, AssertionError) as exc:
            raise DecryptionError("Invalid ciphertext or recipient key") from exc
