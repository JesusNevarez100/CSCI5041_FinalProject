# Threat Model: Email-Based IBE vs Certificate-Based RSA

# 1. Scope

The goal of the project is to evaluate two hybrid encryption implementations:

Boneh-Franklin Identity-Based Encryption using Charm-Cryptop 0.62 and MNT224.

RSA-2048 with OAEP-SHAA256 and locally issued X.509 certificates.

These implementations use AES-256-GCM for message encryption.

The evaluation focuses on confidentiality, ciphertext integrity, recipient identity binding, authorization, and the consequences of key compromise. 

# 2. Protected Assets

Original message plaintext.
AES session keys.
Recipient private keys.
PKG master secret.
CA signing private key.
Email verification challenges.
Integrity of ciphertext and associated metadata.
Authenticity of public parameters and truster CA certificates.

# 3. Attacker Capabilities

The assumed adversary can:

Intercept and store encrypted messages.
Modify ciphertext, nonces, wrapped keys, and metadata.
Replay previously transmitted ciphertext.
Submit malformed serialized envelopes. 
Generate unrelated private keys and certificates.
Attempts to decrypt messages intended for another recipient.
Submit incorrect, expired, or previously used verification codes.

Authority and recipient-key compromise are evaluated separately.

# 4. Trust Assumptions

# Identity-Based Encryption

The sender trusts the authenticity of the PKG public parameters. The PKG is trusted to protect its master secret and issue private keys only to authorized recipients. The PKG inherently possesses the ability to derive recipient private keys. This introduces key escrow and centralized trust.

# Certificate-Based RSA

The sender independently trusts the local CA certificate and validates recipient certificates before encryption. Recipients generate their own RSA private keys. The CA signs the binding between a recipient's email identity and public key without needing to access the recipient's private key. The local certificate issuance process assumes trusted enrollment and does not independently verify mailbox ownership.

# 5. Security Objectives

Correct recipients recover the original plaintext.
Incorrect recipient keys do not recover plaintext.
Modified ciphertext and protected metadata rejected.
Invalid or untrusted certificates are rejected.
Unauthorized verification requests do not result in IBE private-key issuane through the verification gate.
IBE supportes encryption before recipient private-key issuance.

# 6. Key Compromise

# Recipient Private-Key Compromise

Compromise of a recipient's private key permits decryption of ciphertext intended for that key. Neither implementation provides forward secrecy.

# PKG Master-Secret Compormise

Compromise of the PKG master secret allows an adversary to derive identity-specific private keys and potentially decrypt previously captured messages under the attached public parameters.

# CA Signing-Key Compromise

Compromise of the SA signing key allows fraudulent certificates to be issued for recipient identities. This may compromise future encryption if senders accept the fraudulent certificates. Possession of the CA signing key alone does not provide the RSA private keys necessary to decrypt previously encrypted recipient messages.

# 7. Known Limitations

No replay prevention.
No cryptographic sender authentication.
No forward secrecy.
No certificate revocation infrastructure.
No production key persistence or distribution infrastructure.
No general PKI directory or intermediate certificate-chain support.
Simulates email verification does not establish real mailbox ownership. 
Certificate expiration does not erase existing recipient keys or prevent decryption of previously encrypted messages.
Message etadata is not necessarily confidential.

# 8. Open Cryptographic Questions

The following require additional investigation:

1. Whether the Boneh-Franklin masking operation protects the entire 33-byte encoded AES key.

2. Whether the current G2 element validation provides sufficient protection against malformed or invalid subgroup elements.

3. Whether the selected IBE and RSA configurations provide comparable security strengths.

# 9. Initial Experiment Evidence

The existing implementation was independently tested on macOS x86_64 using Python 3.11.15, Charm-Crypto 0.62, PBC 1.0.0, and Cryptography 50.0.2. 

All 30 existing automated tests passed in 2.621 seconds. The IBE smoke test also passed, including deferred enrollment and exact recovery of 24 encoded AES keys. These results establish functional correctness for the tested cases. Additional security experiments and performance measurements remain necessary. 