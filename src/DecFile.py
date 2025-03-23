"""DecFile.py: Decrypt a file using AES with a shared secret derived from ECDH."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ProjectLogging import logger


def load_key_from_file(filename: str, is_private: bool) -> EllipticCurvePrivateKey | EllipticCurvePublicKey:
    """Load a public or private ECC key from a file."""
    if not Path(filename).exists():
        logger.error("File '%s' does not exist.", filename)
        sys.exit(1)
    try:
        with Path(filename).open("rb") as f:
            pem: bytes = f.read()
        if is_private:
            return cast("EllipticCurvePrivateKey", serialization.load_pem_private_key(pem, None))
        return cast("EllipticCurvePublicKey", serialization.load_pem_public_key(pem))
    except ValueError as _e:
        logger.exception("Error loading key from '%s'.", filename)
        sys.exit(1)


def derive_aes_key(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey) -> bytes:
    """Derive an AES key using ECDH."""
    try:
        shared_key: bytes = private_key.exchange(ECDH(), public_key)
        derived_key: bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)
    except Exception as _e:
        logger.exception("Error deriving AES key.")
        sys.exit(1)
    else:
        return derived_key


def decrypt_file(aes_key: bytes, ciphertext_file: str) -> None:
    """Decrypt a file using AES in CBC mode."""
    if not Path(ciphertext_file).exists():
        logger.error("File '%s' does not exist.", ciphertext_file)
        sys.exit(1)
    try:
        with Path(ciphertext_file).open("rb") as f:
            iv: bytes = f.read(16)
            ciphertext: bytes = f.read()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext: bytes = decryptor.update(ciphertext) + decryptor.finalize()

        logger.info("Decryption successful.")
        logger.info("Ciphertext length: %d", len(ciphertext))
        logger.info("Plaintext length: %d", len(plaintext))

        print(f"Decrypted plaintext:\n{plaintext.decode(errors='ignore')}")  # Handle potential decoding issues  # noqa: T201

    except Exception as _e:
        logger.exception("Error decrypting file.")
        sys.exit(1)


def main() -> None:
    """Handle command-line arguments and perform decryption."""
    parser = argparse.ArgumentParser(description="Decrypt a file using AES with a shared secret derived from ECDH.")
    parser.add_argument("receiver_private_key", help="Path to the receiver's private key file.")
    parser.add_argument("sender_public_key", help="Path to the sender's public key file.")
    parser.add_argument("ciphertext_file", help="Path to the ciphertext file.")
    args = parser.parse_args()

    # Load keys
    receiver_private_key: EllipticCurvePrivateKey = cast(
        "EllipticCurvePrivateKey", load_key_from_file(args.receiver_private_key, is_private=True),
    )
    sender_public_key: EllipticCurvePublicKey = cast(
        "EllipticCurvePublicKey", load_key_from_file(args.sender_public_key, is_private=False),
    )

    # Derive AES key
    aes_key: bytes = derive_aes_key(receiver_private_key, sender_public_key)

    # Decrypt the file
    decrypt_file(aes_key, args.ciphertext_file)


if __name__ == "__main__":
    main()
