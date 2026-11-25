import unittest
from charm.core.math.integer import integer
from dataclasses import replace
from ibe_project.hybrid import IBEWorkflow, DecryptionError


class HybridTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = IBEWorkflow()
        cls.public, cls.master = cls.workflow.setup()
        cls.alice = cls.workflow.issue_key(cls.master, "alice@example.com")
        cls.bob = cls.workflow.issue_key(cls.master, "bob@example.com")

    def test_message_shapes(self):
        for message in (b"", b"hello", bytes(range(256)), b"x" * 100_000):
            with self.subTest(length=len(message)):
                ct = self.workflow.encrypt(self.public, "alice@example.com", message)
                self.assertEqual(self.workflow.decrypt(self.public, self.alice, ct), message)
                self.assertEqual(len(ct.ciphertext), len(message) + 16)

    def test_deferred_enrollment(self):
        ct = self.workflow.encrypt(self.public, "later@example.com", b"before enrollment")
        key = self.workflow.issue_key(self.master, "later@example.com")
        self.assertEqual(self.workflow.decrypt(self.public, key, ct), b"before enrollment")

    def test_wrong_recipient(self):
        ct = self.workflow.encrypt(self.public, "alice@example.com", b"secret")
        with self.assertRaises(DecryptionError):
            self.workflow.decrypt(self.public, self.bob, ct)

    def test_tampering(self):
        ct = self.workflow.encrypt(self.public, "alice@example.com", b"secret")
        wrapped = dict(ct.wrapped_key)
        wrapped["W"] = wrapped["W"] ^ integer(1)
        mutations = [replace(ct, scheme="unknown"),
                     replace(ct, identity="different@example.com"),
                     replace(ct, nonce=bytes([ct.nonce[0] ^ 1]) + ct.nonce[1:]),
                     replace(ct, ciphertext=ct.ciphertext[:-1]),
                     replace(ct, wrapped_key=wrapped),
                     replace(ct, wrapped_key={})]
        for modified in mutations:
            with self.subTest(modified=modified.scheme, nonce=modified.nonce):
                with self.assertRaises(DecryptionError):
                    self.workflow.decrypt(self.public, self.alice, modified)

    def test_fresh_encryptions(self):
        a = self.workflow.encrypt(self.public, "alice@example.com", b"same")
        b = self.workflow.encrypt(self.public, "alice@example.com", b"same")
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.ciphertext, b.ciphertext)


if __name__ == "__main__":
    unittest.main()
