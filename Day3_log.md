Day 3 – Hybrid PQC + AES Messaging (Complete Log)

Goal: Implement a working Kyber512 KEM + AES encryption/decryption prototype for secure messaging.

Transition from Windows CMD → Ubuntu Environment

Reason for transition:

On Windows CMD, installation of PQC libraries (pyoqs, python-pqcrypto) failed repeatedly due to:

Missing binaries for Windows.

Virtual environment conflicts.

Incompatibility with pip install options (--break-system-packages).

Action taken:

Switched to Ubuntu 22.04 LTS, which has better support for Python cryptography and PQC libraries.

Created a dedicated Python virtual environment:

python3 -m venv pqc_env
source pqc_env/bin/activate


Installed dependencies for Kyber/PQC experiments:

pip install pycryptodome

Challenges Faced and Resolutions
Challenge	Resolution
pyoqs and python-pqcrypto not available via pip on Windows	Switched to Ubuntu, where Linux wheels are available.
Externally-managed Python environment (PEP 668)	Created virtual environment (pqc_env) to isolate dependencies.
GitHub repo clone failed due to authentication errors	Cloned public forked repo GiacomoPope/kyber-py successfully.
Module import errors (kyber512 not found)	Explored repo structure, used correct import path: from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS.
Parameter mismatch (Kyber512 vs kyber_512)	Corrected key initialization: Kyber(DEFAULT_PARAMETERS['kyber_512']).
Step-by-Step Implementation (Day 3)

Step 1 – Initialize Kyber512

from kyber_py.kyber.kyber import Kyber
from kyber_py.kyber.default_parameters import DEFAULT_PARAMETERS

# Initialize Kyber512 with default parameters
kyber = Kyber(DEFAULT_PARAMETERS['kyber_512'])


Step 2 – Key Encapsulation (KEM)

# Generate keypair
pk, sk = kyber.keygen()

# Sender encapsulates a shared AES key
shared_key_enc, ciphertext = kyber.encaps(pk)

# Receiver decapsulates to recover the AES key
shared_key_dec = kyber.decaps(sk, ciphertext)

# Verify the keys match
assert shared_key_enc == shared_key_dec
print("Kyber512 KEM successful. Shared key established.")


Step 3 – AES Encryption/Decryption

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Use shared key for AES (truncate to 32 bytes)
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

Outcome

Kyber512 KEM works: keypairs generated and shared secret established. 

AES encryption/decryption works with the shared key. 

End-to-end hybrid PQC + AES messaging verified. 

Lessons Learned

Ubuntu provides a more stable environment for PQC experiments than Windows CMD.

Virtual environments are essential when dealing with system-managed Python installations.

Reading the repository structure carefully is critical to avoid import errors.

Transitioning from KEM testing to a full hybrid encryption system requires both correct parameter usage and careful key handling.