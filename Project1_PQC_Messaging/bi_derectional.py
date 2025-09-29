# bi-directional messaging with large payloads

from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS
from Crypto.Cipher import AES

# =========================
# Initialize Kyber for both users
# =========================
kyber = Kyber(DEFAULT_PARAMETERS["kyber_512"])
pk_A, sk_A = kyber.keygen()
pk_B, sk_B = kyber.keygen()

# =========================
# A -> B: encapsulate secret
# =========================
shared_A, ct_A = kyber.encaps(pk_B)        # encapsulate using B's public key
shared_B = kyber.decaps(sk_B, ct_A)        # decapsulate using B's secret key

assert shared_A == shared_B
print("✅ Shared secret established A -> B")

# AES encryption for A -> B message
message_A2B = b"This is a large test message from A to B" * 10
key_A2B = shared_A[:32]  # AES-256 key

cipher_A2B = AES.new(key_A2B, AES.MODE_GCM)
ciphertext_A2B, tag_A2B = cipher_A2B.encrypt_and_digest(message_A2B)

# Decrypt at B
decipher_A2B = AES.new(key_A2B, AES.MODE_GCM, nonce=cipher_A2B.nonce)
plaintext_A2B = decipher_A2B.decrypt_and_verify(ciphertext_A2B, tag_A2B)

assert plaintext_A2B == message_A2B
print("A -> B message successfully encrypted/decrypted")
print("Decrypted A -> B message:", plaintext_A2B.decode())

# =========================
# B -> A: encapsulate secret
# =========================
shared_BA, ct_B = kyber.encaps(pk_A)       # encapsulate using A's public key
shared_A_rev = kyber.decaps(sk_A, ct_B)    # decapsulate using A's secret key

assert shared_BA == shared_A_rev
print("Shared secret established B -> A")

# AES encryption for B -> A message
message_B2A = b"This is a large test message from B to A" * 10
key_B2A = shared_BA[:32]  # AES-256 key

cipher_B2A = AES.new(key_B2A, AES.MODE_GCM)
ciphertext_B2A, tag_B2A = cipher_B2A.encrypt_and_digest(message_B2A)

# Decrypt at A
decipher_B2A = AES.new(key_B2A, AES.MODE_GCM, nonce=cipher_B2A.nonce)
plaintext_B2A = decipher_B2A.decrypt_and_verify(ciphertext_B2A, tag_B2A)

assert plaintext_B2A == message_B2A
print("B -> A message successfully encrypted/decrypted")
print("Decrypted B -> A message:", plaintext_B2A.decode())
