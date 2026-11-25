# Interface agreement for implementation and evaluation

Implemented workflow interfaces: IBEWorkflow in hybrid.py and
CertificateBaseline in certificate_baseline.py. See CERTIFICATE_BASELINE.md
for validation and benchmark boundaries.

## IBE

```python
public, master = ibe.setup()
envelope = ibe.encrypt(public, email, plaintext_bytes)
recipient_key = ibe.issue_key(master, email)
plaintext_bytes = ibe.decrypt(public, recipient_key, envelope)
```

Setup and issuance are outside encryption/decryption timing. The deferred
enrollment demonstration must call encrypt before issue_key.

## Certificate baseline

```python
ca = baseline.setup()
recipient_key = baseline.generate_recipient_key()
certificate = baseline.issue_certificate(ca, email, recipient_key.public_key())
baseline.validate_certificate(ca.certificate, certificate, email)
envelope = baseline.encrypt(ca.certificate, certificate, email, plaintext_bytes)
plaintext_bytes = baseline.decrypt(recipient_key, envelope)
```

Encryption must validate the recipient certificate. Also expose a separately
named operation accepting an already validated recipient key, allowing the
benchmark to measure cryptography separately from validation without silently
omitting validation from the end-to-end workflow.

The recipient generates its own private key. The CA signs the public-key
binding; it does not receive or derive recipient private keys.

## Shared behavior

- Message input and decrypted output: exact bytes, including empty and binary messages.
- AES-GCM payload encryption with a fresh nonce and fresh key per message.
- Versioned envelope; bind scheme, canonical recipient and version through
  authenticated metadata. Specify serialization before measuring sizes.
- Documented validation/decryption exceptions. Never return partial plaintext.
- No secrets in logs or benchmark output.

## Teammate's measurements

Record setup, recipient key generation/issuance, certificate validation,
encryption and decryption separately; report end-to-end timings as well.
Exclude fixture construction, printing, disk I/O and environment startup
from primitive timings. State warmup, repetition count, message sizes and
summary statistics. Use the same host for each paired IBE/baseline comparison.

Test wrong identity/key, altered ciphertext and metadata, invalid/expired/
untrusted certificate, and deferred enrollment. Replay and compromise should
be documented as threat-model experiments: accepting an authentic replay or
decrypting with a deliberately compromised key is not automatically an
implementation defect.

The IBE parameter strength must not be assumed equal to the RSA baseline.
Report the actual settings; timings alone do not establish equivalent security.
