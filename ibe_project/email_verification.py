"""Local PKG mailbox challenge. State is deliberately process-local."""
from dataclasses import dataclass, field
from email.message import EmailMessage
import hashlib
import hmac
import os
import secrets
import smtplib
import ssl
import threading
import time

from .identity import canonical_email


class VerificationError(ValueError):
    pass


@dataclass(frozen=True)
class SMTPMailer:
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    sender: str = ""
    mode: str = "starttls"

    def __post_init__(self):
        if self.mode not in {"ssl", "starttls"}:
            raise ValueError("SMTP mode must be ssl or starttls")
        canonical_email(self.sender)
        if not self.host or not self.username or not self.password:
            raise ValueError("SMTP host and credentials are required")

    @classmethod
    def from_env(cls):
        return cls(os.environ["IBE_SMTP_HOST"], int(os.environ.get("IBE_SMTP_PORT", "587")),
                   os.environ["IBE_SMTP_USERNAME"], os.environ["IBE_SMTP_PASSWORD"],
                   os.environ["IBE_SMTP_FROM"], os.environ.get("IBE_SMTP_MODE", "starttls"))

    def send_code(self, email, code):
        email = canonical_email(email)
        msg = EmailMessage()
        msg["From"], msg["To"] = self.sender, email
        msg["Subject"] = "IBE project: verify your email for private-key issuance"
        msg.set_content(f"Your IBE verification code is: {code}\n\n"
                        "It expires in 10 minutes and can be used once.\n"
                        "Enter it only in the IBE project session you started.\n"
                        "If you did not request a private key, ignore this email.\n")
        context = ssl.create_default_context()
        if self.mode == "ssl":
            connection = smtplib.SMTP_SSL(self.host, self.port, timeout=20, context=context)
        else:
            connection = smtplib.SMTP(self.host, self.port, timeout=20)
        with connection as smtp:
            if self.mode == "starttls":
                smtp.ehlo()
                smtp.starttls(context=context)  # No plaintext fallback.
                smtp.ehlo()
            smtp.login(self.username, self.password)
            if smtp.send_message(msg):
                raise VerificationError("Verification delivery failed")


@dataclass
class _Challenge:
    email: str
    digest: bytes
    expires: float
    attempts: int = 0


class VerifiedPKG:
    """Keep this object, its master secret and workflow inside the trusted PKG.

    Clients receive only a challenge ID and, after successful verification,
    their private key. Never expose the raw workflow issue_key as a client API.
    """
    def __init__(self, workflow, master_secret, mailer, *, clock=time.monotonic):
        self._workflow, self._master, self._mailer = workflow, master_secret, mailer
        self._clock = clock
        self._secret = secrets.token_bytes(32)
        self._challenges = {}
        self._last_request = {}
        self._recent = []
        self._lock = threading.Lock()

    def _digest(self, challenge_id, code):
        return hmac.digest(self._secret, (challenge_id + ":" + code).encode(), hashlib.sha256)

    def request(self, email):
        email = canonical_email(email)
        with self._lock:
            now = self._clock()
            self._challenges = {k: v for k, v in self._challenges.items() if v.expires > now}
            self._last_request = {k: v for k, v in self._last_request.items() if now - v < 60}
            self._recent = [t for t in self._recent if now - t < 3600]
            if email in self._last_request or len(self._recent) >= 30:
                raise VerificationError("Verification request rate limit reached")
            if len(self._challenges) >= 100:
                raise VerificationError("Too many pending requests")
            # A new request invalidates the old code for this exact identity.
            self._challenges = {k: v for k, v in self._challenges.items() if v.email != email}
            challenge_id = secrets.token_urlsafe(32)
            code = f"{secrets.randbelow(100_000_000):08d}"
            self._challenges[challenge_id] = _Challenge(email, self._digest(challenge_id, code), now + 600)
            self._last_request[email] = now
            self._recent.append(now)
        try:
            self._mailer.send_code(email, code)
        except Exception:
            with self._lock:
                self._challenges.pop(challenge_id, None)
            raise VerificationError("Could not deliver verification email") from None
        return challenge_id

    def issue_verified_key(self, challenge_id, code):
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise VerificationError("Invalid or expired verification")
            if self._clock() >= challenge.expires:
                del self._challenges[challenge_id]
                raise VerificationError("Invalid or expired verification")
            challenge.attempts += 1
            valid = (isinstance(code, str) and len(code) == 8 and code.isascii()
                     and code.isdigit()
                     and hmac.compare_digest(challenge.digest, self._digest(challenge_id, code)))
            if valid or challenge.attempts >= 5:
                del self._challenges[challenge_id]
            if not valid:
                raise VerificationError("Invalid or expired verification")
            # Consume before extraction: the code cannot issue another key.
            return self._workflow.issue_key(self._master, challenge.email)
