# Day 2 Log – Sep 24, 2025

## Goals
- Implement classical AES messaging as baseline.
- Test encryption & decryption workflow.

## Results
- Built AES secure messaging system.
- Successfully encrypted & decrypted test message.

## Next Step
- Research and integrate post-quantum cryptography libraries (PyPQCrypto or Open Quantum Safe).
- Replace AES-only with hybrid PQC + AES.

## Code Line to line explanation

from Crypto.Cipher import AES → imports the AES cipher module from PyCryptodome (the library we installed). AES is a symmetric encryption algorithm.

from Crypto.Random import get_random_bytes → allows us to create secure random keys/nonces, which are critical for strong encryption.

import base64 → we use Base64 encoding to convert binary data (ciphertext, nonce, tags) into text, so it’s easier to display or send over a network.

key = get_random_bytes(32)
Generated a 256-bit key (32 bytes).

AES supports 128/192/256-bit keys → 256 bits chosen for maximum strength.

Randomness ensures security against brute force.

def encrypt_message(message, key): → defines a function to encrypt a text message.

cipher = AES.new(key, AES.MODE_EAX) → creates a new AES cipher object in EAX mode.

EAX mode provides both confidentiality (encryption) and integrity (authentication).

ciphertext, tag = cipher.encrypt_and_digest(message.encode())

message.encode() converts the message from text → bytes.

encrypt_and_digest returns:

ciphertext = encrypted version of the message.

tag = an authentication code to ensure message wasn’t tampered with.

return (...) → we return three things:

nonce: unique random value used in encryption (like a one-time random salt).

ciphertext: encrypted message.

tag: authentication code.

All three are encoded with base64.b64encode(...).decode() so they can be stored or sent as normal text.

def decrypt_message(...) → defines a function to reverse encryption.

nonce = base64.b64decode(nonce) → decode text values back into raw bytes.

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) → recreate the cipher using the same key and nonce as encryption.

plaintext = cipher.decrypt_and_verify(ciphertext, tag) →

decrypt recovers the original message.

verify checks the tag → if message was modified, decryption fails.

return plaintext.decode() → converts decrypted bytes back into a readable string.

if __name__ == "__main__": → ensures this block only runs if we execute the script directly.

msg = "Hello PQC World from Day 2!" → sample test message.

nonce, ciphertext, tag = encrypt_message(msg, key) → call the encryption function.

print(f"Encrypted: {ciphertext}") → show the encrypted version (random gibberish in Base64).

decrypted = decrypt_message(...) → call the decryption function to recover the original.

print(f"Decrypted: {decrypted}") → verify it matches the original message.