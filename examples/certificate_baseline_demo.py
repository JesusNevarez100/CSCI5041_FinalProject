"""Run: python -m examples.certificate_baseline_demo"""
from dataclasses import replace
from ibe_project.certificate_baseline import (
    CertificateBaseline, CertificateValidationError, BaselineDecryptionError,
)


def main():
    baseline = CertificateBaseline()
    ca = baseline.setup()
    key = baseline.generate_recipient_key()
    cert = baseline.issue_certificate(ca, "alice@example.com", key.public_key())
    print("1. Local CA created; recipient generated a key and received a certificate.")
    message = b"Certificate-based hybrid encryption baseline."
    envelope = baseline.encrypt(ca.certificate, cert, "alice@example.com", message)
    print("2. Sender validated the certificate and encrypted the message.")
    recovered = baseline.decrypt(key, envelope)
    if recovered != message:
        raise RuntimeError("Message mismatch")
    print("3. Recovered:", recovered.decode())
    try:
        baseline.encrypt(ca.certificate, cert, "bob@example.com", message)
    except CertificateValidationError:
        print("PASS: certificate for the wrong email rejected")
    else:
        raise RuntimeError("Wrong identity accepted")
    altered = replace(envelope, ciphertext=envelope.ciphertext[:-1])
    try:
        baseline.decrypt(key, altered)
    except BaselineDecryptionError:
        print("PASS: modified payload rejected")
    else:
        raise RuntimeError("Tampering accepted")
    print("Issuance is trusted/simulated; no mailbox verification or public PKI lookup.")


if __name__ == "__main__":
    main()
