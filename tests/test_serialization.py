import json
from pathlib import Path
import tempfile
import unittest
from ibe_project.hybrid import IBEWorkflow, DecryptionError
from ibe_project.serialization import dumps, loads, save, load, SerializationError


class SerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = IBEWorkflow()
        cls.public, cls.master = cls.w.setup()
        cls.key = cls.w.issue_key(cls.master, "alice@example.com")

    def test_byte_roundtrips(self):
        for msg in (b"", bytes(range(256)), b"x" * 100000):
            with self.subTest(length=len(msg)):
                env = self.w.encrypt(self.public, "alice@example.com", msg)
                data = dumps(self.w.group, env)
                restored = loads(self.w.group, data)
                self.assertEqual(self.w.decrypt(self.public, self.key, restored), msg)
                self.assertEqual(dumps(self.w.group, restored), data)

    def test_file_and_no_overwrite(self):
        env = self.w.encrypt(self.public, "alice@example.com", b"saved")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            size = save(self.w.group, env, path)
            self.assertEqual(size, path.stat().st_size)
            self.assertEqual(self.w.decrypt(self.public, self.key, load(self.w.group, path)), b"saved")
            with self.assertRaises(FileExistsError):
                save(self.w.group, env, path)

    def test_malformed(self):
        env = self.w.encrypt(self.public, "alice@example.com", b"saved")
        obj = json.loads(dumps(self.w.group, env))
        mutations = []
        for field, value in (("format", "unknown"), ("parameters", "unknown"),
                             ("nonce", "!bad!"), ("identity", "alice@example.com")):
            mutations.append(dict(obj, **{field: value}))
        mutations.append(dict(obj, extra="unexpected"))
        for field, value in (("U", "!bad!"), ("V", "-1"), ("W", "f" * 67)):
            mutations.append(dict(obj, wrapped_key=dict(obj["wrapped_key"], **{field: value})))
        for altered in mutations:
            with self.assertRaises(SerializationError):
                loads(self.w.group, json.dumps(altered).encode())
        for data in (b"{", b"[]", b'{"format":1,"format":2}', b"\xff"):
            with self.assertRaises(SerializationError):
                loads(self.w.group, data)

    def test_valid_structure_does_not_imply_authenticity(self):
        env = self.w.encrypt(self.public, "alice@example.com", b"saved")
        obj = json.loads(dumps(self.w.group, env))
        obj["wrapped_key"]["W"] = format(int(obj["wrapped_key"]["W"], 16) ^ 1, "x")
        restored = loads(self.w.group, json.dumps(obj).encode())
        with self.assertRaises(DecryptionError):
            self.w.decrypt(self.public, self.key, restored)
