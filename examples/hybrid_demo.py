"""Run with: python -m examples.hybrid_demo"""
from dataclasses import replace
from ibe_project.hybrid import IBEWorkflow, DecryptionError


def main():
    workflow = IBEWorkflow()
    public, master = workflow.setup()
    message = b"Hello Alice! This message was encrypted before you enrolled."
    envelope = workflow.encrypt(public, "alice@example.com", message)
    print("Encrypted message before recipient enrollment")
    key = workflow.issue_key(master, "alice@example.com")
    recovered = workflow.decrypt(public, key, envelope)
    if recovered != message:
        raise RuntimeError("Message recovery failed")
    print("Recovered:", recovered.decode("utf-8"))
    altered = replace(envelope, ciphertext=bytes([envelope.ciphertext[0] ^ 1])
                      + envelope.ciphertext[1:])
    try:
        workflow.decrypt(public, key, altered)
    except DecryptionError:
        print("PASS: tampered payload rejected")
    else:
        raise RuntimeError("Tampered payload was accepted")


if __name__ == "__main__":
    main()
