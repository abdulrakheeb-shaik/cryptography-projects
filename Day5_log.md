Day 5 Log – Bi-directional PQC Messaging

Environment: Ubuntu, Python 3.12, pqc_env

Goal:

Extend key exchange to bi-directional (A↔B) using Kyber512

Encrypt/decrypt larger messages with AES using shared secrets

Print decrypted messages

Steps Completed:

Initialized Kyber512 for User A and User B.

A → B: Encapsulated shared secret, encrypted a large message with AES, decrypted and printed it.

B → A: Encapsulated shared secret, encrypted a large message with AES, decrypted and printed it.

Verified shared secrets match in both directions.

Challenges:

Kyber methods from previous code (enc, dec) not available → switched to encaps() and decaps().

Needed to handle larger payloads → integrated AES-GCM.

Output:

Shared secret established A -> B
Decrypted A -> B message: This is a large test message from A to B...
Shared secret established B -> A
Decrypted B -> A message: This is a large test message from B to A...


Result:

Bi-directional secure messaging working correctly.

AES encryption/decryption verified with large messages.