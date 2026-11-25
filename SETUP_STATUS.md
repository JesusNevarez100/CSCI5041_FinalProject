# Setup status — November 23, 2026

Verified locally:

- macOS ARM64, Python 3.11.14, isolated `.venv`.
- Charm distribution: charm-crypto-framework 0.62.
- Native prerequisites installed through Homebrew: GMP, PBC, OpenSSL 3.
- IBE example: encrypt before recipient-key extraction, then decrypt: PASS.
- 16-byte and 32-byte samples without leading zero: exact recovery PASS.
- 16-byte sample beginning with zero: exact recovery FALSE.
- Identity canonicalization basic checks and Python syntax checks: PASS.

Adopted `ibe_project/key_encoding.py`: encode exactly 32 AES key bytes as
`0x01 || key` and require exactly 33 bytes plus the expected prefix when
decoding. The prefix prevents integer conversion from dropping leading zeros;
it is not authentication. Run the smoke test to verify actual Charm recovery
for all-zero, leading-zero, all-0xff and random keys, plus malformed-input
rejection. AES-GCM integration was completed on November 24.

The x86_64 environment has not been tested. No full attack suite, certificate
baseline or benchmarks have run yet.

## macOS installation detail

The old `charm-crypto` distribution failed with inconsistent version
metadata. The current `charm-crypto-framework` package built after installing
the native prerequisites. OpenSSL 4 is linked globally on this computer;
OpenSSL 3 was selected for this build without changing the global link:

```sh
CPPFLAGS='-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/include' \
LDFLAGS='-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/lib' \
PKG_CONFIG_PATH='/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/lib/pkgconfig' \
python -m pip install -r requirements.txt
```

These paths are specific to ARM64 Homebrew. Use platform-specific paths on
other machines. `requirements-local-arm64.txt` records the working Python
dependency versions; it does not capture native library versions.

## Binary-safe adapter

The adoption checks additionally found that the installed Charm byte-to-integer
codec truncates at embedded NUL bytes. The prefix alone is insufficient.
`BinarySafeBonehFranklin` overrides only encodeToZn/decodeFromZn using explicit
big-endian integer conversion. Use this adapter together with the fixed prefix;
do not use raw IBE_BonehFranklin for arbitrary binary key material. The smoke
test exercises the adapter with 24 keys, including all-zero, leading-zero,
all-0xff and random values. This is an encoding fix, not a security audit or
proof of the upstream cryptographic implementation.

## November 24: hybrid integration

The in-memory IBE/AES-256-GCM workflow and demo pass locally. All five
integration tests pass, including binary and empty payloads, deferred
enrollment, wrong recipient and tampering rejection. The original 24-key
encoding smoke test also passes. Encrypted-envelope JSON serialization is now implemented; the certificate
baseline remains pending.

## November 24: serialization

All nine integration tests pass locally. Saved/loaded/decrypted a binary
message through a real JSON file. Empty, binary and 100 KB payloads round-trip;
malformed files and overwriting are rejected. Structurally valid ciphertext
modification is rejected during decryption. Exact wire-byte round trips pass.
Cross-architecture and cross-process key persistence are not tested or
implemented, respectively. Native G2 membership checking returned False for
both freshly generated and deserialized valid points: subgroup validation
is an unresolved upstream/backend limitation, documented in README.md.

## Mailbox challenge implementation

Added SMTP TLS delivery, expiring/attempt-limited single-use challenges and
VerifiedPKG issuance. Automated verification uses mocked delivery, including
integration with real Charm decryption. Live SMTP delivery awaits provider
configuration. See EMAIL_VERIFICATION.md for trust boundaries and limitations.

## Local-CA baseline completed

Added RSA-2048 local CA and recipient key generation, directly signed email
certificates, restricted-profile validation, OAEP-SHA256 session-key wrapping
and AES-256-GCM payload encryption. Demo and all 25 tests pass locally.
Certificate trust/expiry/identity/usage and ciphertext modification checks
are covered. No revocation, certificate discovery or certificate-envelope
file serialization is implemented. No benchmarks collected.

## Certificate-envelope serialization completed

Added versioned deterministic JSON bytes and file helpers, 16 MiB input cap,
strict field/encoding validation, and overwrite protection. All 30 tests pass.
A real temporary-file round trip recovered binary plaintext successfully.
Keys and certificates are not embedded, and cross-host interoperability has
not been verified. The earlier certificate serializer limitation is resolved.
