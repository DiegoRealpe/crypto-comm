from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def load_key_from_file(filename, is_private=True):
    # Load a key from a file
    with open(filename, 'rb') as f:
        pem = f.read()
    if is_private:
        return serialization.load_pem_private_key(pem, password=None)
    else:
        return serialization.load_pem_public_key(pem)

def derive_aes_key(private_key, public_key):
    # Derive a shared secret using ECDH
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    # Derive a 128-bit AES key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def encrypt_file(aes_key, plaintext_file, ciphertext_file):
    # Generate a random IV
    iv = os.urandom(16)
    # Encrypt the plaintext using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    with open(plaintext_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Write IV and ciphertext to the output file
    with open(ciphertext_file, 'wb') as f:
        f.write(iv + ciphertext)
    print(f"Plaintext length: {len(plaintext)}")
    print(f"Ciphertext length: {len(ciphertext)}")

if __name__ == "__main__":
    sender_private_key = load_key_from_file("AlicePriKey.pem", is_private=True)
    receiver_public_key = load_key_from_file("BobPubKey.pem", is_private=False)
    aes_key = derive_aes_key(sender_private_key, receiver_public_key)
    encrypt_file(aes_key, "plaintext.txt", "ciphertext.data")