"""Versioned UTF-8 JSON for public certificate-baseline envelopes only.

No certificates, plaintext keys or CA secrets are embedded. The fingerprint
identifies a certificate; it neither supplies nor validates that certificate.
"""
import base64
import binascii
import json
from pathlib import Path
import re

from .certificate_baseline import CertificateEnvelope, SCHEME
from .identity import canonical_email

FORMAT = "email-certificate-envelope-v1"
MAX_FILE_BYTES = 16 * 1024 * 1024
FIELDS = {"format", "scheme", "email", "certificate_fingerprint", "wrapped_key", "nonce", "ciphertext"}


class SerializationError(ValueError):
    """Unsupported or malformed certificate envelope."""


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _unb64(value):
    if not isinstance(value, str):
        raise SerializationError("Expected Base64 text")
    decoded = base64.b64decode(value, validate=True)
    if _b64(decoded) != value:
        raise SerializationError("Noncanonical Base64")
    return decoded


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SerializationError("Duplicate JSON field")
        result[key] = value
    return result


def loads(data):
    """Check structure and decode. Successful parsing is not authentication."""
    try:
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise SerializationError("Expected JSON bytes within the 16 MiB limit")
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(obj, dict) or set(obj) != FIELDS:
            raise SerializationError("Unexpected envelope fields")
        if obj["format"] != FORMAT or obj["scheme"] != SCHEME:
            raise SerializationError("Unsupported format or scheme")
        email = obj["email"]
        if not isinstance(email, str) or canonical_email(email) != email:
            raise SerializationError("Invalid canonical email")
        fingerprint = obj["certificate_fingerprint"]
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise SerializationError("Invalid SHA-256 certificate fingerprint")
        wrapped, nonce, ciphertext = (_unb64(obj[name]) for name in ("wrapped_key", "nonce", "ciphertext"))
        if len(wrapped) != 256 or len(nonce) != 12 or len(ciphertext) < 16:
            raise SerializationError("Invalid wrapped-key, nonce or payload length")
        return CertificateEnvelope(SCHEME, email, fingerprint, wrapped, nonce, ciphertext)
    except SerializationError:
        raise
    except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError) as exc:
        raise SerializationError("Malformed certificate envelope") from exc


def dumps(envelope):
    """Return deterministic JSON bytes; len(result) measures total wire size."""
    try:
        if not isinstance(envelope, CertificateEnvelope):
            raise SerializationError("Expected a certificate envelope")
        obj = {"format": FORMAT, "scheme": envelope.scheme, "email": envelope.email,
               "certificate_fingerprint": envelope.certificate_fingerprint,
               "wrapped_key": _b64(envelope.wrapped_key), "nonce": _b64(envelope.nonce),
               "ciphertext": _b64(envelope.ciphertext)}
        data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        loads(data)  # Enforce the reader's constraints before writing.
        return data
    except SerializationError:
        raise
    except (ValueError, TypeError, AttributeError) as exc:
        raise SerializationError("Cannot serialize certificate envelope") from exc


def save(envelope, path):
    """Create a new file and return its byte size; never overwrite."""
    data = dumps(envelope)
    with Path(path).open("xb") as stream:
        stream.write(data)
    return len(data)


def load(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    return loads(data)
