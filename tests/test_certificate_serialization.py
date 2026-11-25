import base64
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ibe_project.certificate_baseline import CertificateBaseline, BaselineDecryptionError
from ibe_project import certificate_serialization as codec


class CertificateSerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = CertificateBaseline()
        cls.ca = cls.b.setup()
        cls.key = cls.b.generate_recipient_key()
        cls.cert = cls.b.issue_certificate(cls.ca, "alice@example.com", cls.key.public_key())

    def envelope(self, message=b"saved"):
        return self.b.encrypt(self.ca.certificate, self.cert, "alice@example.com", message)

    def test_byte_roundtrips(self):
        for message in (b"", bytes(range(256)), b"x" * 100000):
            with self.subTest(length=len(message)):
                envelope = self.envelope(message)
                data = codec.dumps(envelope)
                restored = codec.loads(data)
                self.assertEqual(restored, envelope)
                self.assertEqual(codec.dumps(restored), data)
                self.assertEqual(self.b.decrypt(self.key, restored), message)

    def test_files_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "encrypted.json"
            envelope = self.envelope()
            size = codec.save(envelope, path)
            self.assertEqual(size, path.stat().st_size)
            self.assertEqual(codec.load(path), envelope)
            with self.assertRaises(FileExistsError):
                codec.save(self.envelope(b"different"), path)
            self.assertEqual(codec.load(path), envelope)

    def test_invalid_fields(self):
        obj = json.loads(codec.dumps(self.envelope()))
        changes = {
            "format": "unknown", "scheme": "unknown", "email": "alice@EXAMPLE.COM",
            "certificate_fingerprint": "z" * 64, "nonce": "!invalid!",
            "wrapped_key": base64.b64encode(b"x" * 255).decode(),
            "ciphertext": base64.b64encode(b"x" * 15).decode(),
        }
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(codec.SerializationError):
                codec.loads(json.dumps(dict(obj, **{field: value})).encode())
        for obj2 in (dict(obj, extra="unexpected"), {k: v for k, v in obj.items() if k != "nonce"}):
            with self.assertRaises(codec.SerializationError):
                codec.loads(json.dumps(obj2).encode())
        for data in (b"[]", b"{", b"\xff", b'{"format":1,"format":2}'):
            with self.assertRaises(codec.SerializationError):
                codec.loads(data)
        with self.assertRaises(codec.SerializationError):
            codec.dumps(replace(self.envelope(), nonce=b"short"))

    def test_file_size_limit(self):
        data = codec.dumps(self.envelope())
        with patch.object(codec, "MAX_FILE_BYTES", len(data) - 1):
            with self.assertRaises(codec.SerializationError):
                codec.loads(data)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "oversized.json"
                path.write_bytes(data)
                with self.assertRaises(codec.SerializationError):
                    codec.load(path)

    def test_parsing_is_not_authentication(self):
        obj = json.loads(codec.dumps(self.envelope()))
        payload = bytearray(base64.b64decode(obj["ciphertext"]))
        payload[0] ^= 1
        obj["ciphertext"] = base64.b64encode(payload).decode()
        restored = codec.loads(json.dumps(obj).encode())
        with self.assertRaises(BaselineDecryptionError):
            self.b.decrypt(self.key, restored)
