"""Interactive simulation: python -m examples.simulated_authorization_demo.

The simulated inbox is deliberately confined to this example module.
"""
from ibe_project.email_verification import VerifiedPKG, VerificationError
from ibe_project.hybrid import IBEWorkflow
from ibe_project.identity import canonical_email


class SimulatedInbox:
    def send_code(self, email, code):
        print("\n--- SIMULATED INBOX: no email was sent ---")
        print(f"To: {email}")
        print(f"Verification code: {code}")
        print("Expires in 10 minutes; maximum five attempts; single use.")
        print("--- End simulated inbox ---\n")


def main():
    print("SIMULATION: demonstrates the authorization gate, not mailbox ownership.")
    print("No SMTP service, credentials or network access are required.")
    try:
        email = canonical_email(input("Recipient email [alice@example.com]: ").strip()
                                or "alice@example.com")
    except ValueError as exc:
        raise SystemExit(f"Invalid recipient: {exc}") from None
    workflow = IBEWorkflow()
    public, master = workflow.setup()
    message = b"This message was encrypted before simulated authorized enrollment."
    envelope = workflow.encrypt(public, email, message)
    print("1. Encrypted message before issuing the recipient key.")
    pkg = VerifiedPKG(workflow, master, SimulatedInbox())
    challenge = pkg.request(email)
    print("2. Key issuance is gated on the code. Try a wrong code first if desired.")
    for attempt in range(5):
        code = input("Enter the simulated inbox code: ").strip()
        try:
            key = pkg.issue_verified_key(challenge, code)
        except VerificationError:
            print(f"DENIED: verification failed. Attempts remaining: {4 - attempt}.")
            continue
        print("3. ACCEPTED: authorization challenge passed; recipient key issued.")
        recovered = workflow.decrypt(public, key, envelope)
        if recovered != message:
            raise RuntimeError("Message recovery failed")
        print("4. Decrypted:", recovered.decode())
        try:
            pkg.issue_verified_key(challenge, code)
        except VerificationError:
            print("5. PASS: reusing the code was denied.")
        else:
            raise RuntimeError("Verification code was reused")
        print("Delivery was simulated; real mailbox control was not verified.")
        return
    raise SystemExit("DENIED: no recipient key was issued. Restart for a new challenge.")


if __name__ == "__main__":
    main()
