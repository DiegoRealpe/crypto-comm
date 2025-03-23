"""main.py: Client-Server Application with Asymmetric Encryption."""
from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, cast

from DecFile import decrypt_file
from ECG import generate_ecc_key_pair, save_key_to_file
from EncFile import derive_aes_key, encrypt_file, load_key_from_file
from ProjectLogging import logger

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )


def generate_keys(private_key_path: str, public_key_path: str) -> None:
    """Generate ECC key pairs and save them to specified files."""
    logger.info("Generating ECC key pair...")
    private_key, public_key = generate_ecc_key_pair()
    save_key_to_file(private_key, private_key_path, is_private=True)
    save_key_to_file(public_key, public_key_path, is_private=False)
    logger.info("Keys saved: %s & %s", private_key_path, public_key_path)


def encrypt(sender_private_key: str, receiver_public_key: str, input_file: str, output_file: str) -> None:
    """Encrypt a file using ECC-derived AES key."""
    logger.info("Encrypting file...")
    sender_key: EllipticCurvePrivateKey = cast("EllipticCurvePrivateKey", load_key_from_file(sender_private_key, is_private=True))
    receiver_key: EllipticCurvePublicKey = cast("EllipticCurvePublicKey", load_key_from_file(receiver_public_key, is_private=False))
    aes_key = derive_aes_key(sender_key, receiver_key)
    encrypt_file(aes_key, input_file, output_file)
    logger.info("File encrypted and saved to %s.", output_file)


def decrypt(receiver_private_key: str, sender_public_key: str, input_file: str) -> None:
    """Decrypt a file using ECC-derived AES key."""
    logger.info("Decrypting file...")
    receiver_key: EllipticCurvePrivateKey = cast("EllipticCurvePrivateKey", load_key_from_file(receiver_private_key, is_private=True))
    sender_key: EllipticCurvePublicKey = cast("EllipticCurvePublicKey", load_key_from_file(sender_public_key, is_private=False))
    aes_key = derive_aes_key(receiver_key, sender_key)
    decrypt_file(aes_key, input_file)
    logger.info("Decryption complete.")


def main() -> None:
    """Command-line interface for encryption, decryption, and key generation."""
    parser = argparse.ArgumentParser(description="Client-Server Application with Asymmetric Encryption")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Key generation
    keygen_parser = subparsers.add_parser("generate-keys", help="Generate ECC key pairs")
    keygen_parser.add_argument("private_key", help="Path to save the private key file")
    keygen_parser.add_argument("public_key", help="Path to save the public key file")

    # Encryption
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("sender_private_key", help="Path to the sender's private key")
    encrypt_parser.add_argument("receiver_public_key", help="Path to the receiver's public key")
    encrypt_parser.add_argument("input_file", help="Path to the plaintext input file")
    encrypt_parser.add_argument("output_file", help="Path to save the encrypted output file")

    # Decryption
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("receiver_private_key", help="Path to the receiver's private key")
    decrypt_parser.add_argument("sender_public_key", help="Path to the sender's public key")
    decrypt_parser.add_argument("input_file", help="Path to the encrypted input file")

    args = parser.parse_args()

    try:
        if args.command == "generate-keys":
            generate_keys(args.private_key, args.public_key)
        elif args.command == "encrypt":
            encrypt(args.sender_private_key, args.receiver_public_key, args.input_file, args.output_file)
        elif args.command == "decrypt":
            decrypt(args.receiver_private_key, args.sender_public_key, args.input_file)
        else:
            parser.print_help()
    except Exception:
        logger.exception("Unexpected error occurred.")
        sys.exit(1)


if __name__ == "__main__":
    main()
