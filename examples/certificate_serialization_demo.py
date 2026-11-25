"""Run: python -m examples.certificate_serialization_demo [new-file.json]"""
import sys
from pathlib import Path
from ibe_project.certificate_baseline import CertificateBaseline
from ibe_project.certificate_serialization import save, load


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/certificate-message.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    baseline = CertificateBaseline()
    ca = baseline.setup()
    key = baseline.generate_recipient_key()
    certificate = baseline.issue_certificate(ca, "alice@example.com", key.public_key())
    message = b"Certificate file round trip: \x00\xff"
    envelope = baseline.encrypt(ca.certificate, certificate, "alice@example.com", message)
    size = save(envelope, path)
    restored = load(path)
    if baseline.decrypt(key, restored) != message:
        raise RuntimeError("File round trip failed")
    print(f"PASS: saved, loaded and decrypted {path} ({size} JSON bytes)")
    print("Size includes JSON encoding and metadata; certificate distribution is separate.")
    print("Keys remain in memory; the saved file alone cannot recreate them after exit.")


if __name__ == "__main__":
    main()
