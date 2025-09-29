# messaging.py
from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
