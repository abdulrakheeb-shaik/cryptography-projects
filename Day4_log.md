Day 4 – PQC Messaging Simulation
Goal

*Move beyond simple key generation/encryption tests.

*Simulate a secure message exchange between two parties (Party A & Party B) using Kyber512 for key encapsulation.

*Capture all encrypted/decrypted communication in a log file.

Steps Taken

Setup & Imports

*Used the kyber-py repo in Ubuntu environment.

*Imported Kyber and DEFAULT_PARAMETERS to configure Kyber512.

Key Generation

*Party A generated a key pair (public_key, secret_key).

*Public key shared with Party B.

Encapsulation / Shared Secret

*Party B used Party A’s public key to encapsulate → got (ciphertext, shared_secret_B).

*Ciphertext sent to Party A.

Decapsulation / Shared Secret Validation

*Party A used its secret key to decapsulate ciphertext → got shared_secret_A.

*Confirmed shared_secret_A == shared_secret_B.

Secure Messaging Simulation

*Party B sent three messages encrypted with the shared secret.

*Party A decrypted each one successfully.

Logging

*All communication written into day4_pqc_messaging.log.

Each entry recorded:

*Encrypted ciphertext (hex).

*Decrypted plaintext message.