# Local-CA certificate baseline

```sh
python -m examples.certificate_baseline_demo
python -m unittest discover -s tests -p 'test_certificate_baseline.py' -v
```

## Workflow

```python
from ibe_project.certificate_baseline import CertificateBaseline

baseline = CertificateBaseline()
ca = baseline.setup()
key = baseline.generate_recipient_key()
cert = baseline.issue_certificate(ca, "alice@example.com", key.public_key())
envelope = baseline.encrypt(ca.certificate, cert, "alice@example.com", b"hello")
message = baseline.decrypt(key, envelope)
```

The recipient generates and retains its private key. Certificate issuance
receives only the public key. The CA has its own RSA signing key; possessing
that CA key does not derive already issued recipient private keys. CA
compromise can nevertheless enable fraudulent certificates and impersonation.

A sender must already trust the root certificate through an out-of-band
mechanism. Pass that pinned root to encrypt; do not trust a root obtained
from an untrusted message. Validation checks direct root signatures, root
signing authority, both validity periods, RSA/SHA256 signature profile,
RSA-2048 key/exponent policy, leaf non-CA status, key encipherment usage,
email-protection purpose, exact canonical email SAN, and unsupported critical
extensions. This is a restricted one-root/direct-leaf profile, not a full
X.509 path-building implementation. No intermediates, revocation lookup,
certificate discovery, or real ownership verification are implemented.
Issuance is trusted/simulated and must be gated before remote exposure.

## Encryption and comparison

RSA-2048 OAEP with SHA-256 and MGF1-SHA256 wraps a fresh random 32-byte AES
key. AES-256-GCM uses a fresh 12-byte nonce, just as the IBE workflow does.
The scheme identifier, email, certificate SHA-256 fingerprint and wrapped
key are authenticated as associated data. The payload contains its 16-byte
GCM tag; the RSA wrapped key is 256 bytes. No sender signature or replay
prevention is provided. Certificate expiry prevents new encryption through
validation; it does not erase access to old messages with a retained key.

Both workflows use in-memory keys. The certificate envelope now has a versioned JSON serializer in
`certificate_serialization.py`. For later size measurements distinguish raw ciphertext
components, encoded wire size, and certificate distribution overhead. Do not
compare the IBE JSON size directly with only the RSA raw ciphertext size.

## Benchmark interface

`validate_certificate` returns a ValidatedRecipient. `encrypt` always performs
validation. For separate cryptographic timings:

```python
recipient = baseline.validate_certificate(ca.certificate, cert, "alice@example.com")
envelope = baseline.encrypt_prevalidated(recipient, b"hello")
```

`encrypt_prevalidated` deliberately skips validation and expiry checks. Its
argument is an internal result, not an unforgeable authorization token. Use
it immediately after validation for benchmarks only; report validation and
end-to-end encryption separately. Time setup, recipient key generation,
issuance, validation, encryption and decryption independently. No benchmark
numbers have been collected. RSA-2048 and MNT224 are not asserted to provide
equal security strength.

Errors: CertificateValidationError for invalid certificate/identity and
BaselineDecryptionError for the checked invalid key/ciphertext cases.
The integration tests are not a cryptographic audit.

## References

- https://cryptography.io/en/latest/x509/tutorial/
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

## Envelope file serialization

```sh
python -m examples.certificate_serialization_demo
# Choose another new destination on subsequent runs:
python -m examples.certificate_serialization_demo artifacts/certificate-message-2.json
```

The default is `artifacts/certificate-message.json`. Existing files are not
overwritten. JSON stores version, scheme, canonical email, SHA-256 certificate
fingerprint, wrapped key, nonce and encrypted payload/tag. Binary fields use
Base64. The certificate and private keys are not embedded. The fingerprint
is a reference, not proof that a certificate is trusted.

```python
from ibe_project import certificate_serialization as cert_codec
from ibe_project import serialization as ibe_codec

certificate_json_size = len(cert_codec.dumps(certificate_envelope))
ibe_json_size = len(ibe_codec.dumps(workflow.group, ibe_envelope))
```

Use the same message and recipient when comparing sizes. Both measurements
include their respective format metadata and encoding overhead. Measure
certificate distribution and IBE public parameters separately. Raw RSA
components total `256 + 12 + len(envelope.ciphertext)` bytes; report this
separately from JSON size.

API: `dumps(envelope)`, `loads(json_bytes)`, `save(envelope, path)` and
`load(path)`. Parsing rejects unknown/duplicate/missing fields, unsupported
versions, noncanonical Base64, invalid fingerprints, wrong field lengths,
and JSON files over 16 MiB. Valid structure does not establish authenticity;
call decrypt to check the RSA-wrapped key and GCM tag. Keys remain in memory,
so this demo does not implement decryption after program restart. Cross-host
compatibility remains untested.
