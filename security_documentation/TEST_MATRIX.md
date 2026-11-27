# Security and Functional Test Matrix

# Environment

Architecture: x86_64
Operating system: macOS
Python: 3.11.15
Charm-Crypto: 0.62
Cryptography: 50.0.2
PBC: 1.0.0

# Existing Test Suite

| Category | Passed | Total | Status |
| --- | --- | --- | --- | 
| RSA certificate baseline | 8 | 8 | Pass |
| RSA serialization | 5 | 5 | Pass |
| Email verification | 8 | 8 | Pass |
| IBE hybrid encryption | 5 | 5 | Pass |
| IBE serialization | 4 | 4 | Pass |
| Total | 30 | 30 | Pass | 

Initial test suite runtime: 2.621 seconds. 

All accenptance demos completed successfully. 

# Additional Security Experiments 

| ID | Experiment | Expected Outcome | Observed Outcome |
| --- | --- | --- | --- |
| SEC-01 | IBE replay | Accepted | Expected behavior confirmed |
| SEC-02 | RSA replay | Accepted | Expected behavior confirmed |
| SEC-03 | PKG compromise | Plaintext recovered | Expected behavior confirmed | 
| SEC-04 | CA compromise | Fraudulent binding accepted | Expected behavior confirmed |
| SEC-05 | IBE recipient-key compromise | Plaintext recovered | Expected behavior confirmed |
| SEC-06 | RSA recipient-key compromise | Plaintext recovered | Expected behavior confirmed |
| SEC-07 | Large payload | exact recovery | Passed |
| SEC-08 | Certificate expiration | Previously encrypted message remains decrypted | Expected behavior confirmed |
| SEC-09 | CA key against historical ciphertext | Decryption rejected | Expected behavior confirmed |
| SEC-10 | IBE masking coverage | Requires investigation | Pending |
| SEC-11 | G2 subgroup membership | Requires investigation | Pending |

# Interpretation 

Passing functional tests establishes correctness for the tested inputs. Security experiments may show known limitations instead of successful attack prevention. These results do not establish formal cryptographic security or equivalent security strengths between the selected IBE and RSA configurations. 