"""Real SMTP delivery: python -m examples.email_verification_demo"""
import os
from getpass import getpass
from ibe_project.email_verification import SMTPMailer, VerifiedPKG, VerificationError
from ibe_project.hybrid import IBEWorkflow
from ibe_project.identity import canonical_email


def main():
    if not os.environ.get("IBE_SMTP_PASSWORD"):
        os.environ["IBE_SMTP_PASSWORD"] = getpass("SMTP password/app password: ")
    mailer = SMTPMailer.from_env()
    email = canonical_email(input("Your recipient email: "))
    workflow = IBEWorkflow()
    public, master = workflow.setup()
    envelope = workflow.encrypt(public, email, b"Encrypted before verified enrollment.")
    pkg = VerifiedPKG(workflow, master, mailer)
    challenge = pkg.request(email)
    print("Verification email submitted to SMTP. Check your inbox and spam folder.")
    for _ in range(5):
        code = getpass("8-digit code from your email: ").strip()
        try:
            private_key = pkg.issue_verified_key(challenge, code)
        except VerificationError:
            print("Verification failed; check the code and expiry.")
            continue
        print("PASS: mailbox challenge accepted; recipient key issued")
        print(workflow.decrypt(public, private_key, envelope).decode())
        return
    raise SystemExit("Verification failed. No private key issued.")


if __name__ == "__main__":
    main()
