# Email-Based Identity-Based Encryption

Python research prototype comparing Charm Boneh–Franklin IBE with a
certificate-based hybrid encryption baseline. Due December 1, 2026.

## Responsibilities

- Implementation: IBE workflow and certificate-based baseline.
- Teammate: security tests and benchmarks for both workflows.
- Both: integration, interpretation, presentation and rehearsal.

## First milestone: reproduce the IBE smoke test

Use Python 3.11 on both machines. Create a separate environment on each
architecture; do not copy `.venv` between machines.

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m examples.ibe_smoke_test
```

Charm requires native GMP, PBC and OpenSSL libraries. If pip cannot build it,
follow https://github.com/JHUISI/charm#installation for your platform.
The current distribution name is `charm-crypto-framework`, not the old
`charm-crypto` package. Installation status is recorded in SETUP_STATUS.md.

The smoke test demonstrates encryption before key issuance and exact
decryption. Its additional byte probes check compatibility with later
session-key wrapping. They are not attack tests.

`MNT224` and `secparam=1024` reproduce the upstream example, not a claim of
modern or 1024-bit security. Parameter choice and security comparability
must be documented before interpreting benchmark results.

## Implementation sequence

1. Reproduce the smoke test on ARM64 and x86_64.
2. Build the IBE hybrid workflow with AES-GCM payload encryption. Use
   `ibe_project/key_encoding.py` to preserve all 32 bytes of each AES key.
3. Build a local-CA certificate baseline with RSA-OAEP key wrapping and the
   same AES-GCM payload encryption. Validate certificate signature, trust,
   validity, email identity, and intended key usage before encryption.
4. Expose separate setup, issuance, encryption, validation and decryption
   operations so the teammate can test and time them independently.
5. Measure both implementations on the same host. Report hardware and
   parameter differences; do not assume their security strengths match.

The IBE and local-CA certificate hybrid workflows are implemented. The full
security evaluation and benchmark harness remain pending. Local key issuance will be a trusted demo
operation, not proof of email ownership or an authentication service.

## Identity policy

`ibe_project/identity.py` accepts a restricted ASCII email format, removes
surrounding whitespace, lowercases the domain and preserves local-part
case, dots and tags. It prefixes the result with `csci4041:email-ibe:v1:`.
Use the same resulting string for encryption and extraction. Let Charm
perform its scheme-specific group hash; do not pre-hash the identity.

## Sources

- https://github.com/JHUISI/charm
- https://github.com/JHUISI/charm/blob/dev/charm/schemes/ibenc/ibenc_bf01.py

This repository is a course prototype. No experimental results have been
collected yet.

## AES key encoding

Encode AES-256 keys as `0x01 || key` before IBE encryption. After IBE
decryption, require the prefix and exact 33-byte length before extracting
the key. This preserves leading zeros; integrity comes from the cryptographic
construction, not the prefix. The smoke test checks real Charm round trips.

Use `BinarySafeBonehFranklin` from `ibe_project/boneh_franklin.py`: it replaces
Charm's byte codec with explicit big-endian integer conversion to avoid
embedded-NUL truncation observed in this build. The prefix and this adapter
are both required. Pairing and encryption operations remain in Charm.

## Hybrid message encryption

```sh
python -m examples.hybrid_demo
python -m unittest discover -s tests -v
```

`ibe_project/hybrid.py` provides `IBEWorkflow.setup`, `issue_key`, `encrypt`,
and `decrypt`. Encrypt before calling `issue_key` to demonstrate deferred
enrollment. Each message gets a new AES-256 key and 12-byte nonce. The key
is prefix-encoded and protected with the binary-safe Boneh–Franklin adapter;
AES-GCM protects the message. The version, identity and all three wrapped-key
components are authenticated as associated data. Decryption returns bytes or
raises `DecryptionError` for the checked invalid-envelope cases.

The envelope can now be saved and loaded as versioned JSON using
`ibe_project/serialization.py`. Cross-architecture compatibility is untested. Run one workflow/group configuration per
process because upstream Charm stores its group in module globals. Existing
parameter choices and encoding fixes do not establish a security level or
constitute an audit. This prototype does not authenticate senders, verify
email ownership, prevent replay or implement expiry.

Local integration checks cover deferred enrollment, empty/binary/100 KB
payloads, fresh encryptions, wrong recipient, and altered payload, nonce,
identity, scheme and wrapped key. They complement the teammate's security
suite; no performance benchmarks have been collected.

## Encrypted-envelope serialization

```sh
python -m examples.serialization_demo
# Or choose a new destination:
python -m examples.serialization_demo artifacts/another-message.json
```

This saves, reloads and decrypts an encrypted message. Existing files are
not overwritten. The default destination is `artifacts/message.json`.
Public parameters and private keys remain in memory: this demonstration does
not yet provide decryption across program restarts or distribute PKG keys.
Never include the master secret or plaintext session key in the envelope.

API: `dumps(group, envelope)` / `loads(group, bytes)` and
`save(group, envelope, path)` / `load(group, path)`. The JSON format identifies
its version and fixed MNT224/secparam1024 configuration. Group elements,
nonce and payload use Base64; ciphertext integers use hexadecimal. Measure
`len(dumps(group, envelope))` for total JSON wire size, including encoding
and metadata overhead. This differs from raw cryptographic ciphertext size.

Parsing rejects unknown versions/fields, duplicate fields, invalid encodings,
wrong nonce length and oversized files (16 MiB maximum). A parsed envelope
still requires authenticated decryption; parsing does not authenticate it.
Charm's native group decoder processes the serialized point. In this local
Charm 0.62/MNT224 build, `ismember` returns False even for generated G2
points. The parser checks type and exact reserialization but cannot claim
subgroup validation or safe processing of arbitrary hostile point encodings.
The teammate should include this limitation in the security evaluation.

## Mailbox verification

The SMTP-backed local PKG flow is implemented. See EMAIL_VERIFICATION.md for
configuration and run `python -m examples.email_verification_demo`. This is
separate from the earlier trusted-issuance demos. The verified flow gates
issuance on a single-use emailed code; the underlying `issue_key` operation
remains internal. Real delivery requires SMTP credentials and has not yet
been tested. This adds mailbox access verification, not a deployed remote
PKG or secure remote key-delivery service.

## Simulated authorization demonstration (no SMTP)

```sh
python -m examples.simulated_authorization_demo
```

Accept the example recipient or enter an address. Copy the code displayed in
the clearly labeled simulated inbox into the prompt. You may first enter a
wrong code to demonstrate denial. Correct verification issues the recipient
key, decrypts the earlier message, and demonstrates code-reuse rejection.
Five failed attempts stop issuance. The example uses the same VerifiedPKG
logic as SMTP delivery, with only its mail transport replaced.

Presentation wording: "Email delivery is simulated. The prototype implements
and tests the authorization gate, but this demonstration does not establish
control of a real mailbox." The simulated inbox prints its code intentionally;
this example must not be used as a real authorization mechanism.

## Local-CA certificate baseline

Run `python -m examples.certificate_baseline_demo`. See
CERTIFICATE_BASELINE.md for the interface, trust model, validation checks and
benchmark boundaries. The baseline uses RSA-2048/OAEP-SHA256 key transport
and AES-256-GCM payload encryption. Certificate issuance is trusted/simulated;
certificate validation runs on every normal encryption call.

## Certificate-envelope serialization

Run `python -m examples.certificate_serialization_demo` to create, load and
decrypt `artifacts/certificate-message.json`. Use a new output path on repeat
runs; existing files are protected from overwrite. Both workflows now provide
JSON wire-size measurements; see CERTIFICATE_BASELINE.md for equivalent
measurement calls and separate certificate/public-parameter overhead.

## Teammate handoff

Start with TEAMMATE_HANDOFF.md for x86_64 setup, acceptance commands, security
experiments, benchmark boundaries, size accounting and result deliverables.
The repository source still needs to be committed/pushed or otherwise shared;
the handoff document does not publish it automatically.
