import argparse
import subprocess
import sys
from ECCKeyGen import generate_ecc_key_pair, save_key_to_file
from EncFile import encrypt_file, load_key_from_file, derive_aes_key
from DecFile import decrypt_file
from client import send_file
from server import receive_file

def generate_keys():
    print("Generating ECC key pairs...")
    private_key, public_key = generate_ecc_key_pair()
    save_key_to_file(private_key, "AlicePriKey.pem", is_private=True)
    save_key_to_file(public_key, "AlicePubKey.pem", is_private=False)
    print("ECC key pairs saved to AlicePriKey.pem and AlicePubKey.pem.")

def encrypt():
    print("Encrypting file...")
    sender_private_key = load_key_from_file("AlicePriKey.pem", is_private=True)
    receiver_public_key = load_key_from_file("BobPubKey.pem", is_private=False)
    aes_key = derive_aes_key(sender_private_key, receiver_public_key)
    encrypt_file(aes_key, "plaintext.txt", "ciphertext.data")
    print("File encrypted and saved to ciphertext.data.")

def decrypt():
    print("Decrypting file...")
    receiver_private_key = load_key_from_file("BobPriKey.pem", is_private=True)
    sender_public_key = load_key_from_file("AlicePubKey.pem", is_private=False)
    aes_key = derive_aes_key(receiver_private_key, sender_public_key)
    decrypt_file(aes_key, "ciphertext.data")
    print("File decrypted.")

def run_server():
    print("Starting server...")
    receive_file("received_ciphertext.data")
    print("Server stopped.")

def run_client():
    print("Sending file to server...")
    send_file("ciphertext.data")
    print("File sent to server.")

def main():
    parser = argparse.ArgumentParser(description="Client-Server Application with Asymmetric Encryption")
    parser.add_argument("--generate-keys", action="store_true", help="Generate ECC key pairs")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt a file")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt a file")
    parser.add_argument("--server", action="store_true", help="Run the server")
    parser.add_argument("--client", action="store_true", help="Run the client")
    args = parser.parse_args()

    if args.generate_keys:
        generate_keys()
    elif args.encrypt:
        encrypt()
    elif args.decrypt:
        decrypt()
    elif args.server:
        run_server()
    elif args.client:
        run_client()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()