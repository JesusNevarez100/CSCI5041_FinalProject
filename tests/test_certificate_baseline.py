import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from ibe_project.certificate_baseline import (
    CertificateBaseline, CertificateValidationError, BaselineDecryptionError,
)


class BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = CertificateBaseline()
        cls.now = datetime(2026, 11, 24, tzinfo=timezone.utc)
        cls.ca = cls.b.setup(now=cls.now)
        cls.key = cls.b.generate_recipient_key()
        cls.other_key = cls.b.generate_recipient_key()
        cls.cert = cls.b.issue_certificate(cls.ca, "Alice@EXAMPLE.COM", cls.key.public_key(), now=cls.now)

    def test_roundtrip(self):
        for message in (b"", bytes(range(256)), b"x" * 100000):
            with self.subTest(length=len(message)):
                env = self.b.encrypt(self.ca.certificate, self.cert, "Alice@example.com", message, now=self.now)
                self.assertEqual(self.b.decrypt(self.key, env), message)
                self.assertEqual(len(env.wrapped_key), 256)
                self.assertEqual(len(env.ciphertext), len(message) + 16)
        validated = self.b.validate_certificate(self.ca.certificate, self.cert, "Alice@example.com", now=self.now)
        env = self.b.encrypt_prevalidated(validated, b"benchmark")
        self.assertEqual(self.b.decrypt(self.key, env), b"benchmark")

    def test_wrong_email(self):
        for email in ("bob@example.com", "alice@example.com"):
            with self.assertRaises(CertificateValidationError):
                self.b.encrypt(self.ca.certificate, self.cert, email, b"x", now=self.now)

    def test_untrusted_ca(self):
        other = self.b.setup(now=self.now)  # Same subject name, different key.
        forged = self.b.issue_certificate(other, "Alice@example.com", self.key.public_key(), now=self.now)
        with self.assertRaises(CertificateValidationError):
            self.b.validate_certificate(self.ca.certificate, forged, "Alice@example.com", now=self.now)

    def test_validity_intervals(self):
        for when in (self.now - timedelta(days=1), self.now + timedelta(days=31), self.now + timedelta(days=366)):
            with self.assertRaises(CertificateValidationError):
                self.b.validate_certificate(self.ca.certificate, self.cert, "Alice@example.com", now=when)

    def test_modified_certificate(self):
        data = self.cert.public_bytes(serialization.Encoding.DER)
        modified = x509.load_der_x509_certificate(data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaises(CertificateValidationError):
            self.b.validate_certificate(self.ca.certificate, modified, "Alice@example.com", now=self.now)

    def test_wrong_key_and_tampering(self):
        env = self.b.encrypt(self.ca.certificate, self.cert, "Alice@example.com", b"secret", now=self.now)
        with self.assertRaises(BaselineDecryptionError):
            self.b.decrypt(self.other_key, env)
        for modified in (
            replace(env, scheme="unknown"), replace(env, email="bob@example.com"),
            replace(env, certificate_fingerprint="00" * 32),
            replace(env, nonce=bytes([env.nonce[0] ^ 1]) + env.nonce[1:]),
            replace(env, ciphertext=env.ciphertext[:-1]),
            replace(env, wrapped_key=bytes([env.wrapped_key[0] ^ 1]) + env.wrapped_key[1:]),
        ):
            with self.assertRaises(BaselineDecryptionError):
                self.b.decrypt(self.key, modified)

    def test_invalid_certificate_profiles(self):
        # CA-signed certificates must still satisfy purpose and usage checks.
        for profile in ("ca", "usage", "purpose", "critical"):
            builder = (x509.CertificateBuilder().subject_name(self.cert.subject)
                .issuer_name(self.ca.certificate.subject).public_key(self.key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(self.now - timedelta(minutes=1))
                .not_valid_after(self.now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=profile == "ca", path_length=None), True)
                .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                    key_encipherment=profile != "usage", data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if profile == "purpose"
                    else ExtendedKeyUsageOID.EMAIL_PROTECTION]), False)
                .add_extension(x509.SubjectAlternativeName([x509.RFC822Name("Alice@example.com")]), False))
            if profile == "critical":
                builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"test"), True)
            certificate = builder.sign(self.ca.private_key, hashes.SHA256())
            with self.subTest(profile=profile):
                with self.assertRaises(CertificateValidationError):
                    self.b.validate_certificate(self.ca.certificate, certificate, "Alice@example.com", now=self.now)

    def test_fresh_encryption(self):
        args = (self.ca.certificate, self.cert, "Alice@example.com", b"same")
        a, b = self.b.encrypt(*args, now=self.now), self.b.encrypt(*args, now=self.now)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.wrapped_key, b.wrapped_key)
        self.assertNotEqual(a.ciphertext, b.ciphertext)
