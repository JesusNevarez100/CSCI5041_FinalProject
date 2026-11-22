# Email-Based Identity-Based Encryption: Work Plan

Deadline: Tuesday, December 1, 2026.
Source: CSCI 4041 Final Project Proposal.docx supplied by the project team.
Status: Starting from the proposal; no implementation or experimental results verified yet.

## Concrete Question
What convenience does IBE provide, and what performance and true costs come with it?

## Minimum deliverable

A local command-line demonstration of hybrid identity-based encryption, supported by a documented threat model, functional tests, measurements, and presentation slides. Select and verify an existing IBE implementation before committing to a language or library. Do not implement pairing arithmetic from scratch or substitute ordinary public-key encryption and label it IBE.

The demonstration should:

1. Generate PKG master secret and public parameters.
2. Encrypt a short message for an email identity using only public parameters, before issuing that identity's private key.
3. Issue the recipient's private key through a local, explicitly trusted demonstration step.
4. Decrypt successfully with the matching identity key.
5. Reject use of a different identity's key and modification of protected ciphertext or metadata.

The prototype does not need a mail server, browser interface, or deployed authentication service. Explain that real email ownership verification and secure private-key delivery are deployment requirements, not features demonstrated by the local issuance command.

## Decisions to settle first

- Course requirements: presentation duration, rubric, report/code requirements, permitted dependencies, and whether an experimental certificate-based baseline is mandatory.
- Both teammates' operating systems and ability to use a shared reproducible environment.
- Available IBE implementations: installation feasibility, exact scheme variant, supported security properties, licensing, and examples that run correctly.
- Identity encoding: document a deterministic rule; do not silently lowercase the whole address without defining the intended identity semantics.
- Construction details: distinguish the selected IBE variant's guarantees from authenticated symmetric encryption. Do not claim hybrid authenticated encryption alone proves chosen-ciphertext security for an arbitrary IBE scheme.

| Component | What you would build in Python |
|---|---|
| IBE workflow | Setup, email identity handling, key issuance, encryption, and decryption using an IBE library |
| Certificate-based baseline | A local certificate authority, recipient certificates, certificate validation, and hybrid encryption using cryptographic libraries |
| Security tests | Wrong-recipient keys, modified ciphertexts, invalid certificates, replay, and simulated key compromise |
| Benchmarks | Repeated measurements of execution time, ciphertext size, and key/certificate sizes |
| Demo | Commands that run both workflows and display their results |

## Proposed division of work

| Owner | Primary responsibility | Review responsibility |
|---|---|---|
| You | PKG setup, key extraction, encryption/decryption demo, reproducible run instructions | Review security claims and explain implementation in rehearsal |
| Teammate | Primary-source research, threat model, test matrix, benchmark harness, initial slide outline | Run the demo independently and review failure cases |
| Both | Choose dependencies, interpret measurements, finalize slides, rehearse | Be able to explain the full workflow |

Swap ownership if your skills favor the reverse.

## Schedule

| Date | Required outcome |
|---|---|
| Nov 21–22 | Confirm requirements, select a feasible IBE dependency, run its example, agree on scope |
| Nov 23–24 | Complete setup → encrypt → issue key → decrypt workflow |
| Nov 25 | Add wrong-identity and tampering tests; document issuance and trust boundaries |
| Nov 26–27 | Collect timings and size measurements; complete security analysis and comparison |
| Nov 28 | Draft slides using actual results and prepare a short repeatable demonstration |
| Nov 29 | Review accuracy, reproduce demo on a second environment, rehearse together |
| Nov 30 | Freeze implementation, finish slides, record a backup demo, rehearse within time limit |
| Dec 1 | Present |

## Evaluation evidence

Record environment, dependency versions, exact scheme, repetitions, message sizes, and timing method. Keep setup, key extraction, encryption, and decryption measurements separate. Report actual results, not expected outcomes. Measure ciphertext overhead and key/parameter sizes if serialization is available.

Minimum cases: correct identity, encryption before key issuance, wrong identity, modified encrypted payload, modified protected identity/metadata. Discuss replay, expiration, recipient-key compromise, and PKG compromise; implement mechanisms only where supported and within scope. Replaying a valid ciphertext is not automatically prevented by authenticated encryption. Expiration labels do not invalidate already-held keys or erase access to old messages.

For a certificate-based comparison, distinguish measured cryptographic operations from conceptual certificate discovery, validation, and enrollment costs. Do not claim an experimental PKI comparison if only a conceptual analysis was performed.

## Presentation outline

1. Problem and research question: encrypt to an email identity before enrollment.
2. IBE workflow and PKG trust boundary.
3. Chosen construction and hybrid encryption design.
4. Prototype demonstration: encrypt first, issue key later, decrypt.
5. Functional and attack-test results.
6. Measured performance and storage overhead.
7. Comparison with certificate-based encryption.
8. Limitations and conclusion: convenience in exchange for centralized trust and key escrow.

Adjust the slide count to the required presentation duration. Leave experimental findings blank until measured.
