import unittest
from unittest.mock import Mock, patch
from ibe_project.email_verification import VerifiedPKG, SMTPMailer, VerificationError


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.workflow = Mock()
        self.mailer = Mock()
        self.pkg = VerifiedPKG(self.workflow, object(), self.mailer, clock=lambda: self.now)

    def request(self, email="Alice@EXAMPLE.COM"):
        challenge = self.pkg.request(email)
        code = self.mailer.send_code.call_args.args[1]
        return challenge, code

    def test_bound_identity_and_single_use(self):
        challenge, code = self.request()
        self.workflow.issue_key.assert_not_called()
        key = self.pkg.issue_verified_key(challenge, code)
        self.assertIs(key, self.workflow.issue_key.return_value)
        self.assertEqual(self.workflow.issue_key.call_args.args[1], "Alice@example.com")
        with self.assertRaises(VerificationError):
            self.pkg.issue_verified_key(challenge, code)
        self.workflow.issue_key.assert_called_once()

    def test_expiry(self):
        challenge, code = self.request()
        self.now = 600
        with self.assertRaises(VerificationError):
            self.pkg.issue_verified_key(challenge, code)
        self.workflow.issue_key.assert_not_called()

    def test_attempt_limit(self):
        challenge, code = self.request()
        for _ in range(5):
            with self.assertRaises(VerificationError):
                self.pkg.issue_verified_key(challenge, "invalid")
        with self.assertRaises(VerificationError):
            self.pkg.issue_verified_key(challenge, code)
        self.workflow.issue_key.assert_not_called()

    def test_rate_limit_and_replacement(self):
        old, code = self.request()
        with self.assertRaises(VerificationError):
            self.request()
        self.now = 60
        new, new_code = self.request()
        with self.assertRaises(VerificationError):
            self.pkg.issue_verified_key(old, code)
        self.pkg.issue_verified_key(new, new_code)

    def test_failed_delivery_cannot_issue(self):
        self.mailer.send_code.side_effect = OSError("SMTP down")
        with self.assertRaises(VerificationError):
            self.pkg.request("alice@example.com")
        self.assertFalse(self.pkg._challenges)
        self.workflow.issue_key.assert_not_called()

    def test_cross_challenge_code(self):
        a, code = self.request()
        b, _ = self.request("bob@example.com")
        # Compute an intentionally incorrect code even if random codes collide.
        b_code = self.mailer.send_code.call_args.args[1]
        wrong = "00000000" if b_code != "00000000" else "11111111"
        with self.assertRaises(VerificationError):
            self.pkg.issue_verified_key(b, wrong)
        self.pkg.issue_verified_key(a, code)

    @patch("ibe_project.email_verification.smtplib.SMTP")
    def test_smtp_requires_tls_before_login(self, factory):
        smtp = factory.return_value.__enter__.return_value
        smtp.send_message.return_value = {}
        mailer = SMTPMailer("smtp.example.com", 587, "user", "secret", "sender@example.com")
        mailer.send_code("alice@example.com", "12345678")
        names = [call[0] for call in smtp.method_calls]
        self.assertLess(names.index("starttls"), names.index("login"))
        smtp.starttls.side_effect = OSError("TLS unavailable")
        smtp.reset_mock()
        with self.assertRaises(OSError):
            mailer.send_code("alice@example.com", "12345678")
        smtp.login.assert_not_called()


class VerifiedWorkflowIntegration(unittest.TestCase):
    def test_challenge_then_decrypt(self):
        from ibe_project.hybrid import IBEWorkflow
        workflow = IBEWorkflow()
        public, master = workflow.setup()
        envelope = workflow.encrypt(public, "alice@example.com", b"verified enrollment")
        mailer = Mock()
        pkg = VerifiedPKG(workflow, master, mailer)
        challenge = pkg.request("alice@example.com")
        code = mailer.send_code.call_args.args[1]
        key = pkg.issue_verified_key(challenge, code)
        self.assertEqual(workflow.decrypt(public, key, envelope), b"verified enrollment")
