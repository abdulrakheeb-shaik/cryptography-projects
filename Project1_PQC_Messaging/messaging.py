from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate random AES key (256-bit)
key = get_random_bytes(32)

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return (base64.b64encode(cipher.nonce).decode(),
            base64.b64encode(ciphertext).decode(),
            base64.b64encode(tag).decode())

def decrypt_message(nonce, ciphertext, tag, key):
    nonce = base64.b64decode(nonce)
    ciphertext = base64.b64decode(ciphertext)
    tag = base64.b64decode(tag)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Test
if __name__ == "__main__":
    msg = "Testing messaging encryption and decryption"
    nonce, ciphertext, tag = encrypt_message(msg, key)
    print(f"Encrypted: {ciphertext}")

    decrypted = decrypt_message(nonce, ciphertext, tag, key)
    print(f"Decrypted: {decrypted}")
