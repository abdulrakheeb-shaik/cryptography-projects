import logging
from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Setup logging
logging.basicConfig(
    filename="day4_pqc_messaging.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_message(direction, message, encrypted=False):
    tag = "Encrypted" if encrypted else "Decrypted"
    logging.info(f"{direction} | {tag}: {message}")

class PQCMessenger:
    def __init__(self, parameter_set="kyber_512"):
        self.kyber = Kyber(DEFAULT_PARAMETERS[parameter_set])

    def generate_keys(self):
        return self.kyber.keygen()

    def encapsulate(self, pk):
        return self.kyber.encaps(pk)

    def decapsulate(self, sk, ciphertext):
        return self.kyber.decaps(sk, ciphertext)

    def aes_encrypt(self, key, plaintext: bytes):
        aes_key = key[:32]
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
        return ct_bytes, cipher.iv

    def aes_decrypt(self, key, ciphertext: bytes, iv: bytes):
        aes_key = key[:32]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

if __name__ == "__main__":
    # Initialize messenger (Kyber512 by default)
    messenger = PQCMessenger(parameter_set="kyber_512")

    # Step 1: Party A generates keys
    pk_A, sk_A = messenger.generate_keys()

    # Step 2: Party B encapsulates key using A's public key
    shared_key_B, ciphertext = messenger.encapsulate(pk_A)

    # Step 3: Party A decapsulates to recover shared key
    shared_key_A = messenger.decapsulate(sk_A, ciphertext)
    assert shared_key_A == shared_key_B
    print("Shared key established.")

    # Step 4: Multi-message exchange
    messages = [
        b"Message 1: Init handshake",
        b"Message 2: Sending encrypted payload",
        b"Message 3: Final confirmation"
    ]

    for i, msg in enumerate(messages, 1):
        # Encrypt with shared key
        ct, iv = messenger.aes_encrypt(shared_key_B, msg)
        log_message("Party B -> Party A", ct.hex(), encrypted=True)

        # Decrypt with shared key
        decrypted = messenger.aes_decrypt(shared_key_A, ct, iv)
        log_message("Party A <- Party B", decrypted, encrypted=False)

        print(f"\n📩 Exchange {i}")
        print("Sent:", msg)
        print("Decrypted:", decrypted)
