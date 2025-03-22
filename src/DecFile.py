from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_file(aes_key, ciphertext_file):
    # Read IV and ciphertext from the file
    with open(ciphertext_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    # Decrypt the ciphertext using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print(f"Decrypted plaintext: {plaintext.decode()}")
    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Plaintext length: {len(plaintext)}")

if __name__ == "__main__":
    receiver_private_key = load_key_from_file("BobPriKey.pem", is_private=True)
    sender_public_key = load_key_from_file("AlicePubKey.pem", is_private=False)
    aes_key = derive_aes_key(receiver_private_key, sender_public_key)
    decrypt_file(aes_key, "ciphertext.data")