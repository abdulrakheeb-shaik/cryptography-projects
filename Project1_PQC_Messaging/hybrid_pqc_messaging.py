# ==========Defining Messaging Function============

from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Initialize Kyber512
kyber = Kyber(DEFAULT_PARAMETERS['kyber_512'])

# Key generation function
def generate_keys():
    pk, sk = kyber.keygen()
    return pk, sk

# Encapsulation for sender
def encapsulate_key(pk):
    shared_key, ciphertext = kyber.encaps(pk)
    return shared_key, ciphertext

# Decapsulation for receiver
def decapsulate_key(sk, ciphertext):
    shared_key = kyber.decaps(sk, ciphertext)
    return shared_key

# AES encryption
def aes_encrypt(key, plaintext):
    aes_key = key[:32]
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return ct_bytes, cipher.iv

# AES decryption
def aes_decrypt(key, ciphertext, iv):
    aes_key = key[:32]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# =========Simulate Two party communication==========

# Party A generates keypair
pk_A, sk_A = generate_keys()

# Party B encapsulates key using Party A's public key
shared_key_B, ciphertext = encapsulate_key(pk_A)

# Party A decapsulates to recover the same key
shared_key_A = decapsulate_key(sk_A, ciphertext)

# Verify shared key agreement
assert shared_key_A == shared_key_B
print("Shared key agreement successful.")

# Party B sends a secret message using AES
message = b"Hello Party A, this is a secret!"
ct_bytes, iv = aes_encrypt(shared_key_B, message)

# Party A decrypts the message
decrypted_message = aes_decrypt(shared_key_A, ct_bytes, iv)
print("Original message:", message)
print("Decrypted message:", decrypted_message)
