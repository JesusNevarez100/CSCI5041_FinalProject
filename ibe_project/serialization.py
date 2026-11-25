"""Versioned JSON for public encrypted envelopes only; no pickle loading."""
import base64
import binascii
import json
from pathlib import Path
import re

from charm.core.math.integer import integer
from charm.toolbox.pairinggroup import G2
from .hybrid import Envelope, SCHEME
from .identity import PREFIX, ibe_identity

FORMAT = "email-ibe-envelope-v1"
PARAMETERS = "MNT224-secparam1024"
MAX_FILE_BYTES = 16 * 1024 * 1024
FIELDS = {"format", "parameters", "scheme", "identity", "wrapped_key", "nonce", "ciphertext"}


class SerializationError(ValueError):
    """Unsupported or malformed encrypted-envelope format."""


def _b64(data):
    return base64.b64encode(data).decode("ascii")


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


def _hex(value, max_digits):
    if (not isinstance(value, str) or len(value) > max_digits
            or re.fullmatch(r"0|[1-9a-f][0-9a-f]*", value) is None):
        raise SerializationError("Invalid ciphertext integer")
    return integer(int(value, 16))


def loads(group, data):
    """Parse bytes using the workflow's fixed pairing parameters.

    Parsing validates structure, not authenticity. Call decrypt afterward.
    """
    try:
        if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
            raise SerializationError("Expected JSON bytes within the 16 MiB limit")
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(obj, dict) or set(obj) != FIELDS:
            raise SerializationError("Unexpected envelope fields")
        if (obj["format"] != FORMAT or obj["parameters"] != PARAMETERS
                or obj["scheme"] != SCHEME):
            raise SerializationError("Unsupported format, parameters or scheme")
        identity = obj["identity"]
        if (not isinstance(identity, str) or not identity.startswith(PREFIX)
                or ibe_identity(identity[len(PREFIX):]) != identity):
            raise SerializationError("Invalid canonical identity")
        wrapped = obj["wrapped_key"]
        if not isinstance(wrapped, dict) or set(wrapped) != {"U", "V", "W"}:
            raise SerializationError("Invalid wrapped-key fields")
        raw_u = _unb64(wrapped["U"])
        if len(raw_u) > 4096:
            raise SerializationError("Oversized group element")
        u = group.deserialize(raw_u)
        # Charm 0.62/MNT224 reports False for ismember() even on its own
        # generated G2 points. Do not claim subgroup validation here.
        if (u.type != G2 or group.serialize(u) != raw_u):
            raise SerializationError("Invalid or noncanonical G2 element")
        # V contains the 1024-bit random seed mask; W contains a 33-byte value.
        key = {"U": u, "V": _hex(wrapped["V"], 256), "W": _hex(wrapped["W"], 66)}
        nonce, ciphertext = _unb64(obj["nonce"]), _unb64(obj["ciphertext"])
        if len(nonce) != 12 or len(ciphertext) < 16:
            raise SerializationError("Invalid nonce or payload length")
        return Envelope(SCHEME, identity, key, nonce, ciphertext)
    except SerializationError:
        raise
    except Exception as exc:
        # Native Charm decoders can raise extension-specific exceptions.
        raise SerializationError("Malformed encrypted envelope") from exc


def dumps(group, envelope):
    """Return deterministic UTF-8 JSON bytes; length is the wire size."""
    try:
        obj = {
            "format": FORMAT, "parameters": PARAMETERS,
            "scheme": envelope.scheme, "identity": envelope.identity,
            "wrapped_key": {
                "U": _b64(group.serialize(envelope.wrapped_key["U"])),
                "V": format(int(envelope.wrapped_key["V"]), "x"),
                "W": format(int(envelope.wrapped_key["W"]), "x"),
            },
            "nonce": _b64(envelope.nonce), "ciphertext": _b64(envelope.ciphertext),
        }
        data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        loads(group, data)  # Apply the same constraints when writing.
        return data
    except SerializationError:
        raise
    except Exception as exc:
        raise SerializationError("Cannot serialize encrypted envelope") from exc


def save(group, envelope, path):
    """Create a new file, refusing to overwrite an existing one."""
    data = dumps(group, envelope)
    with Path(path).open("xb") as stream:
        stream.write(data)
    return len(data)


def load(group, path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    return loads(group, data)
