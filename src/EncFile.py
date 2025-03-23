"""EncFile.py: A Python script to encrypt files using AES with a shared secret derived from ECDH."""
from __future__ import annotations

import os
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
    """Load a public or private key from a file."""
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


def derive_aes_key(private_key: EllipticCurvePrivateKey , public_key: EllipticCurvePublicKey ) -> bytes:
    """Derive a shared secret using ECDH."""
    try:
        shared_key: bytes = private_key.exchange(ECDH(), public_key)
        # Derive a 128-bit AES key using HKDF
        derived_key: bytes = HKDF(
            algorithm=hashes.SHA256(),  # algorithm
            length=16,  # length
            salt=None,  # salt
            info=b"handshake data",  # info
        ).derive(shared_key)
    except Exception as _e:
        logger.exception("Error deriving AES key.")
        sys.exit(1)
    else:
        return derived_key


def encrypt_file(aes_key: bytes, plaintext_file: str, ciphertext_file: str) -> None:
    """Encrypt a file using AES in CBC mode."""
    if not Path(plaintext_file).exists():
        logger.error("File '%s' does not exist.", plaintext_file)
        sys.exit(1)
    try:
        # Generate a random IV
        iv: bytes = os.urandom(16)
        # Encrypt the plaintext using AES in CBC mode
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        with Path(plaintext_file).open("rb") as f:
            plaintext: bytes = f.read()
        ciphertext: bytes = encryptor.update(plaintext) + encryptor.finalize()
        # Write IV and ciphertext to the output file
        with Path(ciphertext_file).open("wb") as f:
            f.write(iv + ciphertext)
        logger.info("Plaintext length: %d", len(plaintext))
        logger.info("Ciphertext length: %d", len(ciphertext))
    except Exception as _e:
        logger.exception("Error encrypting file.")
        sys.exit(1)


def main() -> None:
    """Handle command-line arguments and perform encryption."""
    if len(sys.argv) != 4:
        logger.error(
            "Usage: python EncFile.py <sender_private_key> <receiver_public_key> <plaintext_file>",
        )
        sys.exit(1)

    sender_private_key_file: str = sys.argv[1]
    receiver_public_key_file: str = sys.argv[2]
    plaintext_file: str = sys.argv[3]
    ciphertext_file: str = "ciphertext.data"  # Default output file name

    # Load keys
    sender_private_key: EllipticCurvePrivateKey = cast("EllipticCurvePrivateKey", load_key_from_file(sender_private_key_file, is_private=True))
    receiver_public_key: EllipticCurvePublicKey = cast("EllipticCurvePublicKey", load_key_from_file(receiver_public_key_file, is_private=False))

    # Derive AES key
    aes_key: bytes = derive_aes_key(sender_private_key, receiver_public_key)

    # Encrypt the file
    encrypt_file(aes_key, plaintext_file, ciphertext_file)
    logger.info("Encryption complete. Ciphertext saved to '%s'.", ciphertext_file)


if __name__ == "__main__":
    main()
