"""Restricted local-CA profile: RSA-2048/OAEP-SHA256 + AES-256-GCM.

One pinned root and directly signed email certificates; not a general-purpose
X.509 path validator. Issuance is a trusted internal operation.
"""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

from .identity import canonical_email

SCHEME = "RSA2048-OAEP-SHA256-AES256GCM-v1"


class CertificateValidationError(ValueError):
    pass


class BaselineDecryptionError(ValueError):
    pass


@dataclass(frozen=True)
class LocalCA:
    private_key: rsa.RSAPrivateKey = field(repr=False)
    certificate: x509.Certificate


@dataclass(frozen=True)
class ValidatedRecipient:
    """Result of validation for immediate benchmark use, not a trust token."""
    email: str
    public_key: rsa.RSAPublicKey
    certificate_fingerprint: str


@dataclass(frozen=True)
class CertificateEnvelope:
    scheme: str
    email: str
    certificate_fingerprint: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


def _now(value=None):
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("Time must include a timezone")
    return value.astimezone(timezone.utc)


def _rsa_key(key):
    if (not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048
            or key.public_numbers().e != 65537):
        raise ValueError("Expected RSA-2048 public key with exponent 65537")
    return key


def _usage(ca):
    return x509.KeyUsage(digital_signature=ca, content_commitment=False,
                         key_encipherment=not ca, data_encipherment=False,
                         key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                         encipher_only=False, decipher_only=False)


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=SCHEME.encode("ascii"))


def _aad(scheme, email, fingerprint, wrapped):
    return json.dumps({"scheme": scheme, "email": email,
                       "certificate_fingerprint": fingerprint,
                       "wrapped_key": base64.b64encode(wrapped).decode("ascii")},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


class CertificateBaseline:
    def setup(self, *, now=None):
        now = _now(now)
        key = self.generate_recipient_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CSCI4041 Local Demo CA")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(_usage(True), critical=True)
                .sign(key, hashes.SHA256()))
        return LocalCA(key, cert)

    def generate_recipient_key(self):
        # Recipient owns this key; the CA receives only its public key.
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def issue_certificate(self, ca, email, public_key, *, now=None, valid_days=30):
        """Trusted issuance; caller must authorize the email/public-key binding."""
        now, email = _now(now), canonical_email(email)
        _rsa_key(public_key)
        if not 1 <= valid_days <= 365:
            raise ValueError("Certificate lifetime must be 1–365 days")
        if not ca.certificate.not_valid_before_utc <= now < ca.certificate.not_valid_after_utc:
            raise ValueError("CA is not currently valid")
        return (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)]))
                .issuer_name(ca.certificate.subject).public_key(public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(max(now - timedelta(minutes=1), ca.certificate.not_valid_before_utc))
                .not_valid_after(min(now + timedelta(days=valid_days), ca.certificate.not_valid_after_utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(_usage(False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
                .sign(ca.private_key, hashes.SHA256()))

    def validate_certificate(self, trusted_root, certificate, email, *, now=None):
        """trusted_root must be pinned out of band, never supplied by the sender."""
        try:
            now, email = _now(now), canonical_email(email)
            root_key = _rsa_key(trusted_root.public_key())
            recipient_key = _rsa_key(certificate.public_key())
            if trusted_root.subject != trusted_root.issuer or certificate.issuer != trusted_root.subject:
                raise ValueError("Issuer mismatch")
            for cert in (trusted_root, certificate):
                if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                    raise ValueError("Certificate is outside its validity interval")
                if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
                    raise ValueError("Unsupported certificate signature algorithm")
                root_key.verify(cert.signature, cert.tbs_certificate_bytes,
                                padding.PKCS1v15(), hashes.SHA256())
                for ext in cert.extensions:
                    if ext.critical and ext.oid not in {
                        x509.ExtensionOID.BASIC_CONSTRAINTS, x509.ExtensionOID.KEY_USAGE,
                        x509.ExtensionOID.EXTENDED_KEY_USAGE, x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    }:
                        raise ValueError("Unsupported critical extension")
            root_constraints = trusted_root.extensions.get_extension_for_class(x509.BasicConstraints).value
            root_usage = trusted_root.extensions.get_extension_for_class(x509.KeyUsage).value
            if not root_constraints.ca or not root_usage.key_cert_sign:
                raise ValueError("Root is not authorized to sign certificates")
            if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Expected an end-entity certificate")
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.key_encipherment or usage.key_cert_sign or usage.crl_sign:
                raise ValueError("Certificate is not authorized for key transport")
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if set(eku) != {ExtendedKeyUsageOID.EMAIL_PROTECTION}:
                raise ValueError("Expected email-protection purpose")
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if len(san) != 1 or san.get_values_for_type(x509.RFC822Name) != [email]:
                raise ValueError("Recipient email does not match certificate SAN")
            return ValidatedRecipient(email, recipient_key, certificate.fingerprint(hashes.SHA256()).hex())
        except (ValueError, TypeError, AttributeError, InvalidSignature, x509.ExtensionNotFound) as exc:
            raise CertificateValidationError("Untrusted or invalid recipient certificate") from exc

    def encrypt(self, trusted_root, certificate, email, plaintext, *, now=None):
        recipient = self.validate_certificate(trusted_root, certificate, email, now=now)
        return self.encrypt_prevalidated(recipient, plaintext)

    def encrypt_prevalidated(self, recipient, plaintext):
        """Benchmark primitive only: caller must just have validated the certificate.

        Does not check trust or expiry; never expose as an unvalidated sender API.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
        wrapped = _rsa_key(recipient.public_key).encrypt(key, _oaep())
        aad = _aad(SCHEME, recipient.email, recipient.certificate_fingerprint, wrapped)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return CertificateEnvelope(SCHEME, recipient.email,
                                   recipient.certificate_fingerprint, wrapped, nonce, ciphertext)

    def decrypt(self, private_key, envelope):
        try:
            if not isinstance(envelope, CertificateEnvelope) or envelope.scheme != SCHEME:
                raise ValueError("Unsupported envelope")
            if canonical_email(envelope.email) != envelope.email:
                raise ValueError("Invalid recipient identity")
            if len(envelope.wrapped_key) != 256 or len(envelope.nonce) != 12 or len(envelope.ciphertext) < 16:
                raise ValueError("Invalid ciphertext lengths")
            key = private_key.decrypt(envelope.wrapped_key, _oaep())
            if len(key) != 32:
                raise ValueError("Invalid session key")
            return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext,
                _aad(envelope.scheme, envelope.email, envelope.certificate_fingerprint, envelope.wrapped_key))
        except (ValueError, TypeError, AttributeError, InvalidTag) as exc:
            raise BaselineDecryptionError("Invalid ciphertext or recipient key") from exc
