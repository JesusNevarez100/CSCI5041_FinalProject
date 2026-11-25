# Demonstrate the security tradeoffs between IBE and 
# certificate-based RSA, particularly replay, key escrow,
# authority compromise, and certificate expiration


# Tests simulate possession of trusted secrets; they do not
# demonstrate how those secrets were obtained

import unittest
from datetime import datetime, timedelta, timezone

from ibe_project.hybrid import IBEWorkflow
from ibe_project.certificate_baseline import (
    CertificateBaseline,
    BaselineDecryptionError,
    CertificateValidationError,
)


EMAIL = "bob@example.com"
MESSAGE = b"Confidential test message"

class SecurityEvaluationTests(unittest.TestCase):
    def setUp(self):
        # Initialize IBE
        self.ibe = IBEWorkflow()
        self.public, self.master = self.ibe.setup()

        # Initialize RSA certificate baseline
        self.rsa = CertificateBaseline()
        self.ca = self.rsa.setup()

        self.rsa_key = self.rsa.generate_recipient_key()

        self.cert = self.rsa.issue_certificate(
            self.ca, 
            EMAIL,
            self.rsa_key.public_key(),
        )


    def test_ibe_replay(self):
        """IBE does not prevent replay"""

        envelope = self.ibe.encrypt(
            self.public, EMAIL, MESSAGE
        )

        key = self.ibe.issue_key(self.master, EMAIL)

        first = self.ibe.decrypt(
            self.public, key, envelope
        )

        second = self.ibe.decrypt(
            self.public, key, envelope
        )

        self.assertEqual(first, MESSAGE)
        self.assertEqual(second, MESSAGE)


    def test_rsa_replay(self):
        """RSA baseline does not prevent replay"""

        envelope = self.rsa.encrypt(
            self.ca.certificate,
            self.cert,
            EMAIL,
            MESSAGE,
        )

        first = self.rsa.decrypt(self.rsa_key, envelope)
        second = self.rsa.decrypt(self.rsa_key, envelope)

        self.assertEqual(first, MESSAGE)
        self.assertEqual(second, MESSAGE)


    def test_pkg_master_secret_compromise(self):
        """A compromised PKG can derive recipient keys."""

        envelope = self.ibe.encrypt(
            self.public, EMAIL, MESSAGE
        )

        # Simulate possession of the PKG master secret
        compromised_master = self.master

        recovered_key = self.ibe.issue_key(
            compromised_master, EMAIL
        )

        recovered_message = self.ibe.decrypt(
            self.public, recovered_key, envelope
        )

        self.assertEqual(recovered_message, MESSAGE)


    def test_ca_compromise_forged_certificate(self):
        """A compromised CA can authorize a false binding."""

        attacker_key = self.rsa.generate_recipient_key()

        # Simulate unauthorized issuance by a compromised CA
        forged_cert = self.rsa.issue_certificate(
            self.ca,
            EMAIL,
            attacker_key.public_key(),
        )

        envelope = self.rsa.encrypt(
            self.ca.certificate,
            forged_cert,
            EMAIL,
            MESSAGE,
        )

        recovered = self.rsa.decrypt(
            attacker_key, envelope
        )

        self.assertEqual(recovered, MESSAGE)

        # Bob's genuine private key cannot decrypt it
        with self.assertRaises(BaselineDecryptionError):
            self.rsa.decrypt(self.rsa_key, envelope)


    def test_ibe_recipient_key_compromise(self):
        """Possession of Bob's key permits decryption."""

        key = self.ibe.issue_key(self.master, EMAIL)

        envelope = self.ibe.encrypt(
            self.public, EMAIL, MESSAGE
        )

        compromised_key = key 

        recovered = self.ibe.decrypt(
            self.public, compromised_key, envelope
        )

        self.assertEqual(recovered, MESSAGE)


    def test_rsa_recipient_key_compromise(self):
        """Possession of Bob's RSA key permits decryption."""

        envelope = self.rsa.encrypt(
            self.ca.certificate,
            self.cert,
            EMAIL,
            MESSAGE,
        )

        compromised_key = self.rsa_key

        recovered = self.rsa.decrypt(
            compromised_key, envelope
        )

        self.assertEqual(recovered, MESSAGE)


    def test_large_payload(self):
        """Both systems recover a 1 MiB message."""

        message = b"x" * (1024 * 1024)

        ibe_key = self.ibe.issue_key(
            self.master, EMAIL
        )

        ibe_envelope = self.ibe.encrypt(
            self.public, EMAIL, message
        )

        rsa_envelope = self.rsa.encrypt(
            self.ca.certificate,
            self.cert,
            EMAIL, 
            message,
        )

        self.assertEqual(
            self.ibe.decrypt(
                self.public, ibe_key, ibe_envelope
            ),
            message,
        )

        self.assertEqual(
            self.rsa.decrypt(self.rsa_key, rsa_envelope),
            message,
        )


    def test_decryption_after_certificate_expiration(self):
        """Expiration prevents new encryption, not old decryption."""

        now = datetime.now(timezone.utc)

        cert = self.rsa.issue_certificate(
            self.ca,
            EMAIL,
            self.rsa_key.public_key(),
            now=now,
            valid_days=1,
        )

        # Encrypt while the certificate is valid
        envelope = self.rsa.encrypt(
            self.ca.certificate,
            cert,
            EMAIL,
            MESSAGE,
            now=now,
        )

        # Simulate a time after expiration
        future = now + timedelta(days=2)

        # New encryption should be rejected
        with self.assertRaises(CertificateValidationError):
            self.rsa.encrypt(
                self.ca.certificate,
                cert,
                EMAIL,
                MESSAGE,
                now=future,
            )

        # Previously encrypted messages remain decryptable
        recovered = self.rsa.decrypt(
            self.rsa_key, envelope
        )

        self.assertEqual(recovered, MESSAGE)


    def test_ca_compromise_historical_ciphertext(self):
        """A CA signing key cannot directly decrypt old messages."""

        # encrypt using Bob's legitimate certificate
        envelope = self.rsa.encrypt(
            self.ca.certificate,
            self.cert,
            EMAIL,
            MESSAGE,
        )

        # Simulate compromise of the CA signing key
        compromised_ca_key = self.ca.private_key

        # The CA key should not decrypt Bob's message
        with self.assertRaises(BaselineDecryptionError):
            self.rsa.decrypt(
                compromised_ca_key, envelope
            )

        # Generate an attacker controlled key
        attacker_key = self.rsa.generate_recipient_key()

        # Issue a fraudulate certificate for Bob
        forged_cert = self.rsa.issue_certificate(
            self.ca,
            EMAIL,
            attacker_key.public_key(),
        )

        # The fraudulent certificate is still trusted
        self.rsa.validate_certificate(
            self.ca.certificate,
            forged_cert,
            EMAIL,
        )

        # The attacker's key still cannot decrypt old messages
        with self.assertRaises(BaselineDecryptionError):
            self.rsa.decrypt(attacker_key, envelope)

        # Bob's original key still works
        self.assertEqual(
            self.rsa.decrypt(self.rsa_key, envelope),
            MESSAGE,
        )


if __name__ == "__main__":
    unittest.main()