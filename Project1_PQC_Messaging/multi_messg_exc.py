from messaging import PQCMessenger

# Initialize
messenger = PQCMessenger()

# Party A generates keypair
pk_A, sk_A = messenger.generate_keys()

# Party B encapsulates shared key
shared_key_B, ciphertext = messenger.encapsulate(pk_A)

# Party A decapsulates
shared_key_A = messenger.decapsulate(sk_A, ciphertext)
assert shared_key_A == shared_key_B
print("Shared key established.")

# Exchange multiple messages
messages = [
    b"Message 1: Init handshake",
    b"Message 2: Sending encrypted payload",
    b"Message 3: Final confirmation"
]

for i, msg in enumerate(messages, 1):
    ct, iv = messenger.aes_encrypt(shared_key_B, msg)
    decrypted = messenger.aes_decrypt(shared_key_A, ct, iv)
    print(f"\n Exchange {i}")
    print("Sent:", msg)
    print("Decrypted:", decrypted)
