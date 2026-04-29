# Assignment 2 — DLT Inventory Web Application

crypto_utils.py file: RSA operations sign, verify, encrypt, decrypt
harn_multisig.py file: multi-signature implementation
dlt_system.py file: integrates all tasks
app.py file: API endpoints
index.html file: frontend UI

Task 1 — Digital Signature Authentication

This task ensures that new inventory records are authentic and tamper-proof.

A node creates a record and signs it using RSA:

S = H(m)^d mod n
Implemented using:
rsa_sign() — generates signature
rsa_verify() — verifies signature across all nodes
All nodes independently verify the signature using the sender’s public key.


Task 2 — Consensus Protocol (PBFT)

This task ensures that all nodes agree before storing a record.

Uses a simplified PBFT (Practical Byzantine Fault Tolerance) approach:
Each node verifies the signature
Votes ACCEPT / REJECT
Requires ≥75% agreement
Implemented using:
task2_consensus() — handles voting and decision logic
If consensus is reached, the record is stored on all nodes.


Task 1 + 2 — Full Record Lifecycle

Combines signing and consensus into one process:

Record is signed (Task 1)
Signature is verified by all nodes
Consensus is reached (Task 2)
Record is stored in all node JSON files
Implemented using:
task1and2() (or equivalent combined function)


Task 3 — Multi-Signature Query & Secure Delivery

This task enables secure retrieval of inventory data.

All nodes jointly sign a query result using the Harn multi-signature scheme:

Partial signature:

sig_i = (H(m) * r_i + s_i) mod n

Aggregated signature:

S = Σ sig_i mod n
Implemented using:
generate_partial_signature()
aggregate_signatures()
verify_aggregate_signature()
The result is then:
Encrypted using RSA (rsa_encrypt())
Decrypted by the requester (rsa_decrypt())