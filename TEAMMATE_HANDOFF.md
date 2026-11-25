# Teammate handoff: security tests and benchmarks

Presentation deadline: Tuesday, December 1, 2026.

Implementation owner: Jesus — IBE and local-CA certificate baseline.
Evaluation owner: teammate — security experiments, benchmark harness and results.
Both: reproduce results, explain trust assumptions and prepare the presentation.

## 1. Receive a complete source snapshot

Repository: https://github.com/JesusNevarez100/CSCI5041_FinalProject

These instructions do not mean the implementation has been committed or pushed.
Jesus must commit/push the intended files or provide a complete source archive.
Do not transfer `.venv`, credentials, private keys or generated artifacts.
After receiving the source, record `git rev-parse HEAD` and `git status --short`.
If files are modified/untracked, identify the exact snapshot used for results.
Do not publish results from different source snapshots as if they were one run.

## 2. Create your own x86_64 environment

Use Python 3.11 and install GMP, PBC and OpenSSL prerequisites using the
instructions for your OS: https://github.com/JHUISI/charm#installation

Linux/macOS shell:

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-local-arm64.txt
python -c "import platform, sys; print(sys.version); print(platform.platform()); print(platform.machine())"
python -m pip freeze
```

Despite its name, `requirements-local-arm64.txt` contains Python package
version pins, not ARM binaries. Build/install them for your own architecture.
Native dependency versions are not captured by that file. Windows users may
prefer an x86_64 Linux environment if native Charm installation is difficult;
record WSL/container/VM use and benchmark both schemes in that same environment.
The minimal direct dependencies are also listed in `requirements.txt`.

The ARM64 build needed OpenSSL 3 selected explicitly; see SETUP_STATUS.md.
Do not copy its `/opt/homebrew` paths blindly to x86_64. If installation fails,
share the command and relevant compiler error with secrets removed.

## 3. Acceptance checklist before evaluation

Run from the repository root with the environment activated:

```sh
python -m examples.ibe_smoke_test
python -m examples.hybrid_demo
python -m examples.certificate_baseline_demo
python -m examples.simulated_authorization_demo
python -m examples.serialization_demo
python -m examples.certificate_serialization_demo
python -m unittest discover -s tests -v
```

As of this handoff, the local ARM64 suite has 30 passing tests. Test count may
change as evaluation adds coverage. Require successful commands, not a fixed
count. For the simulated-inbox demo, try a wrong code, then the displayed code;
confirm denial, successful decryption and code-reuse rejection. No SMTP is
needed. Serialization demos refuse to overwrite files: use a new path on repeat
runs, e.g. `python -m examples.serialization_demo artifacts/ibe-run2.json`.

Only local ARM64 execution is verified so far. Do not claim cross-host
interoperability based on each host generating and decrypting its own envelope.
That would require shared public parameters/certificates and matching private
keys. Key persistence/distribution is not implemented.

## 4. API entry points

IBE: `ibe_project.hybrid.IBEWorkflow`

```python
from ibe_project.hybrid import IBEWorkflow

ibe = IBEWorkflow()
public, master = ibe.setup()
envelope = ibe.encrypt(public, "alice@example.com", b"message")
key = ibe.issue_key(master, "alice@example.com")
assert ibe.decrypt(public, key, envelope) == b"message"
```

The order above demonstrates encryption before enrollment. Direct issue_key
is a trusted internal operation; it bypasses the verification gate by design.
Use `VerifiedPKG` in `email_verification.py` for authorization tests. See
EMAIL_VERIFICATION.md. Simulation verifies the gate, not real mailbox control.

Certificate baseline: `ibe_project.certificate_baseline.CertificateBaseline`

```python
from ibe_project.certificate_baseline import CertificateBaseline

baseline = CertificateBaseline()
ca = baseline.setup()
key = baseline.generate_recipient_key()
cert = baseline.issue_certificate(ca, "alice@example.com", key.public_key())
envelope = baseline.encrypt(ca.certificate, cert, "alice@example.com", b"message")
assert baseline.decrypt(key, envelope) == b"message"
```

Pin `ca.certificate` independently of untrusted inputs. The recipient generates
its own key; the CA signs only the public-key/email binding. Issuance is trusted
and does not verify mailbox ownership. No general PKI directory, intermediate
chain, revocation or network certificate lookup is implemented.

Expected errors:

| Component | Error |
|---|---|
| IBE decryption | `hybrid.DecryptionError` |
| Certificate validation | `certificate_baseline.CertificateValidationError` |
| Certificate decryption | `certificate_baseline.BaselineDecryptionError` |
| Verification gate | `email_verification.VerificationError` |
| IBE JSON parsing | `serialization.SerializationError` |
| Certificate JSON parsing | `certificate_serialization.SerializationError` |

Malformed native Charm objects may expose extension-specific exceptions beyond
these checked cases. Record them as findings; do not silently classify crashes
as successful rejection.

## 5. Security evaluation matrix

Record test setup, expected behavior, observed behavior and evidence separately.
Existing tests are starting coverage, not a complete security evaluation.

| Experiment | Expected result / interpretation |
|---|---|
| Correct recipient; empty/binary/large message | Exact plaintext recovery |
| IBE encryption before key extraction | Later matching key decrypts |
| Wrong recipient key | No plaintext recovery |
| Changed payload, nonce, identity or wrapped key | Decryption rejected |
| Untrusted or modified certificate | Normal baseline encryption rejected |
| Wrong certificate email/local-part case | Rejected under documented identity policy |
| Expired/not-yet-valid certificate or CA | Validation rejected; use injected `now`, not clock changes |
| Leaf marked CA, wrong usage/purpose, unknown critical extension | Validation rejected |
| Malformed JSON/Base64, missing/duplicate fields, oversized files | Parsing rejected |
| Wrong verification code, expired code, exhausted attempts | No recipient key issued |
| Reuse successful verification code | No second issuance |
| Resend/cooldown/request cap | Document actual in-process limit behavior |
| Replay unchanged valid envelope | Currently accepted; no replay prevention claimed |
| Retained key after certificate expiry | Old ciphertext remains decryptable; expiry is not erasure |
| Recipient-key compromise | That key permits intended-recipient decryption |
| PKG master-secret compromise | Derive a matching key and decrypt existing IBE ciphertext |
| CA signing-key compromise | Can forge new bindings, but CA key alone does not decrypt past RSA envelopes |

Use `dataclasses.replace` to modify envelopes. Tests show construction patterns.
For altered signatures, modify certificate DER and reload it. For certificate
policy failures, create CA-signed test certificates with the relevant extension.
Run experiments only on generated local fixtures; no live-account attacks.

Priority investigation: inspect the exact upstream Boneh–Franklin mask/hash
behavior and its output length versus the 33-byte encoded AES key. Functional
round trips alone do not establish that every key bit is hidden. Document any
exposed structure or security mismatch rather than interpreting GCM success
as proof of IBE security. Also investigate the G2 membership-check limitation
below. These are open review questions, not passed security guarantees.

## 6. Benchmark protocol

Run BOTH schemes on your x86_64 computer in the same environment. Jesus's
ARM64 numbers, if collected, are a separate comparison. Avoid comparing IBE
on one machine against RSA on another. Keep the laptop plugged in and record
power mode, CPU, RAM, OS, architecture and any virtualization.

Use `time.perf_counter_ns()` around only the named operation. Prepare fixtures
and message bytes before timing. Warm up five times; use 100 timed repetitions
for encrypt/decrypt/validation/issuance and at least 20 for expensive setup/key
generation if feasible. Record actual counts and any deviations. Use repeated
batches or alternate scheme order to reduce order/thermal bias. Verify outputs
outside the timed interval. Save raw samples, median and 25th/75th percentiles;
avoid conclusions based on one run. Do not subtract different workloads and
label the difference an isolated operation.

Suggested payload sizes: 0, 128, 1024, 16384 and 1048576 bytes. Use identical
messages and the same canonical recipient for both schemes. Every encryption
must generate its normal fresh key/nonce; do not optimize away randomness.

| Measurement | Operation being timed |
|---|---|
| IBE authority setup | `ibe.setup()` |
| IBE recipient issuance | `ibe.issue_key(master, email)` |
| IBE encryption | `ibe.encrypt(public, email, message)` |
| IBE decryption | `ibe.decrypt(public, key, envelope)` |
| CA setup | `baseline.setup()` (includes root RSA generation and self-signing) |
| RSA recipient key generation | `baseline.generate_recipient_key()` |
| Certificate issuance | `baseline.issue_certificate(ca, email, public_key)` |
| Certificate validation | `baseline.validate_certificate(root, cert, email)` |
| Baseline normal encryption | `baseline.encrypt(root, cert, email, message)` (includes validation) |
| Baseline crypto-only encryption | `baseline.encrypt_prevalidated(validated, message)` |
| Baseline decryption | `baseline.decrypt(key, envelope)` |

Create `validated` immediately before the crypto-only measurement batch.
`encrypt_prevalidated` deliberately skips certificate trust/expiry checks; do
not present it as the complete sender workflow. Also present normal encryption.
IBE issuance and RSA key generation plus certificate issuance represent
different enrollment work; do not label either cost-free.

Exclude SMTP/human input, imports, object construction, printing, disk I/O,
serialization and fixture generation from primitive timings. If measuring
an end-to-end or serialization path, name the included operations explicitly.
Multi-recipient evaluation means encrypting separately for N identities in
these implementations, not a native broadcast algorithm. State whether keys
are pre-issued and report total versus per-recipient time.

## 7. Size measurements

```python
from ibe_project import serialization as ibe_json
from ibe_project import certificate_serialization as cert_json

ibe_wire_bytes = len(ibe_json.dumps(ibe.group, ibe_envelope))
certificate_wire_bytes = len(cert_json.dumps(certificate_envelope))
```

Both include their format metadata and encoding overhead. Measure the same
message and identity. Report plaintext bytes, total JSON bytes and overhead
(total minus plaintext). Raw ciphertext bytes are a separate metric.

- RSA raw envelope crypto components: 256-byte wrapped key + 12-byte nonce +
  payload length including its 16-byte GCM tag.
- IBE raw components: serialized U, minimally encoded unsigned V/W, nonce and
  payload/tag. State that representation explicitly; Python object memory
  size (`sys.getsizeof`) is not a ciphertext size.
- Certificate and root: `cert.public_bytes(Encoding.DER)` / root equivalent.
- RSA public/private keys: SPKI DER / unencrypted PKCS8 DER byte length measured
  in memory only. Do not write private key material into results.
- IBE parameters/private key: define a deterministic representation for each
  component. The pairing serializer cannot directly encode Charm integer
  elements; follow the integer conversion pattern in serialization.py.
  Include the curve/configuration identifier when claiming portable size.

Certificate/root distribution and IBE public-parameter distribution must be
listed separately from per-message size. Neither file format currently
embeds that complete setup material.

## 8. Results to return

Suggested output files (create these during evaluation, not fabricated now):

- `results/environment.json`: source revision/state, hardware, OS, Python,
  package/native dependency versions, pairing/RSA settings, timing protocol.
- `results/timings.csv`: scheme, operation, message_bytes, batch, iteration,
  elapsed_ns and success. Add recipient_count where relevant.
- `results/sizes.csv`: scheme, message_bytes, metric, size_bytes and encoding.
- `results/security_findings.md`: expected/observed outcomes, reproduction
  commands, interpretation, failures and limitations.
- `results/summary.md`: measured conclusions and chart-ready aggregates.

Never include master secrets, private keys, SMTP credentials, verification
codes or personal plaintext in result files. Supply the harness source and
commands so both teammates can reproduce the experiments.

## 9. Limits to preserve in the report

- MNT224/secparam1024 is an example configuration, not 1024-bit security.
  RSA-2048 and this IBE configuration are not asserted to have equal strength.
- The binary-safe adapter fixes byte conversion only; it is not a security audit.
- Charm stores group/hash state in module globals. Use one IBE workflow/group
  configuration per process; avoid concurrent benchmark workers sharing it.
- Charm 0.62/MNT224 `ismember` returns False for valid generated G2 points.
  File parsing checks point type and canonical encoding, not subgroup validity.
  Native point parsing is not claimed safe for arbitrary hostile encodings.
- In-memory key/challenge state means no cross-restart enrollment or decryption.
- No replay prevention, remote key-delivery service or sender authentication.
- Email simulation proves flow control, not mailbox ownership. SMTP remains
  implemented but live delivery is unverified.

## 10. Suggested remaining schedule

- November 24–25: receive source, reproduce x86_64 setup and baseline tests.
- November 26–27: implement/run security experiments and benchmarks; return findings.
- November 28: integrate measured results into slides and select demo commands.
- November 29–30: independent reproduction, rehearsal and backup demo recording.
- December 1: presentation.

Report installation blockers or security findings as soon as found so Jesus
can address implementation issues while evaluation continues.
