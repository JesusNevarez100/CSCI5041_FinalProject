# Mailbox verification for local PKG issuance

## Configure real email delivery

Use your SMTP provider's host, port, authenticated username and permitted
sender address. Do not commit credentials or paste them into chat. In the
activated project environment:

```sh
export IBE_SMTP_HOST="your-provider-smtp-host"
export IBE_SMTP_PORT="587"
export IBE_SMTP_MODE="starttls"
export IBE_SMTP_USERNAME="your-smtp-username"
export IBE_SMTP_FROM="your-authorized-sender@example.com"
python -m examples.email_verification_demo
```

The demo prompts for the SMTP password without echoing it. Use an SMTP/app
password if required by the provider; OAuth-only accounts need a different
transport integration. For implicit TLS use mode `ssl` and the provider's
port (commonly 465). No plaintext SMTP fallback exists. `.env` files are
ignored by Git but are not automatically loaded.

The demo asks for a recipient address, encrypts before enrollment, sends a
real verification email, and prompts for the received code. Only successful
verification issues the recipient key and decrypts the message. No code or
private key is printed. Re-run to start a fresh demo; keys and challenges
are process-local and not persisted.

## What verification establishes

It demonstrates access to the addressed mailbox at verification time, not
legal identity, permanent ownership, MFA, sender authentication or resistance
to mailbox compromise/phishing. The SMTP provider can observe the code.

`VerifiedPKG.request(email)` returns an unpredictable challenge identifier;
retain it in the requesting session. `issue_verified_key(challenge_id, code)`
uses the identity stored with that challenge, not a caller-selected email.
Codes have eight random decimal digits, a ten-minute lifetime, five attempts,
and one successful use. Only keyed code digests are stored. Resending after
the 60-second cooldown invalidates the previous challenge. A process-wide
30-request/hour cap and 100-pending cap bound email and state usage. These
limits are process-local and reset on restart, not distributed abuse control.

Keep the workflow and master secret inside the trusted PKG. The low-level
`IBEWorkflow.issue_key()` remains for internal use/tests and bypasses mailbox
verification. It must never be exposed as an unauthenticated client endpoint.
The local Python demo is the trusted PKG and recipient in one process;
remote clients would additionally need an authenticated TLS service and
secure private-key delivery. This implementation does not deploy that service.

## Verification status

Automated tests mock SMTP; they check expiration, attempt limits, identity
binding, replay prevention, replacement, failed delivery and TLS before login.
Real provider delivery is not verified until the configured demo succeeds.

Reference: https://docs.python.org/3.11/library/smtplib.html

## Presentation simulation

When SMTP configuration is unavailable, run
`python -m examples.simulated_authorization_demo`. Only email delivery is
replaced with a labeled console inbox. The same expiry, attempt limits and
single-use issuance logic run. This proves the demonstrated authorization
flow, not access to a real mailbox. The SMTP implementation remains separate.
