import sys
sys.path.insert(0, '/home/rakhib_shaik/pyky/kyber-py/src')

# Initialize kyber512 
from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS

# Initialize Kyber512 with default parameters
kyber = Kyber(DEFAULT_PARAMETERS['kyber_512'])

# ======== Key Encapsulation (KEM) phase =========
# Generate public/private keypair
pk, sk = kyber.keygen()

# Sender encapsulates a shared AES key
shared_key_enc, ciphertext = kyber.encaps(pk)

# Receiver decapsulates to recover the same AES key
shared_key_dec = kyber.decaps(sk, ciphertext)

# Verify shared key matches
assert shared_key_enc == shared_key_dec
print("Kyber512 KEM successful. Shared key established.")

# ======== AES Encryption/Decryption phase =========

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Use the shared key for AES encryption (truncate to 32 bytes)
aes_key = shared_key_enc[:32]

# Encrypt a message
message = b"Hello, this is a secret message!"
cipher = AES.new(aes_key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(message, AES.block_size))
iv = cipher.iv

# Decrypt the message
cipher_dec = AES.new(aes_key, AES.MODE_CBC, iv=iv)
decrypted = unpad(cipher_dec.decrypt(ct_bytes), AES.block_size)

# Verify decryption
print("Original message:", message)
print("Decrypted message:", decrypted)
