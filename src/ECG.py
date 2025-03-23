"""ECG.py: Generate an Elliptic Curve key pair and save to PEM files."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ProjectLogging import logger

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )


def generate_ecc_key_pair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECC key pair using the SECP256R1 curve."""
    try:
        private_key: EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
        public_key: EllipticCurvePublicKey = private_key.public_key()
    except Exception as e:
        logger.exception("Error generating ECC key pair: (%s)", e)
        sys.exit(1)
    else:
        return private_key, public_key


def save_key_to_file(key: EllipticCurvePrivateKey | EllipticCurvePublicKey, filename: str, is_private: bool) -> None:
    """Serialize and save a key to a PEM file."""
    try:
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists

        if is_private:
            pem: bytes = cast("EllipticCurvePrivateKey", key).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with path.open("wb") as f:
                f.write(pem)
        else:
            pub: bytes = cast("EllipticCurvePublicKey", key).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with path.open("wb") as f:
                f.write(pub)

    except Exception as _e:
        logger.exception("Error saving key to %s", filename)
        sys.exit(1)


def main() -> None:
    """Handle command-line arguments and generate ECC key pair."""
    parser = argparse.ArgumentParser(description="Generate an ECC key pair and save the keys to files.")
    parser.add_argument("private_key_output", type=str, help="Path to save the private key file.")
    parser.add_argument("public_key_output", type=str, help="Path to save the public key file.")
    args = parser.parse_args()

    # Generate ECC key pair
    private_key, public_key = generate_ecc_key_pair()

    # Save keys to files
    save_key_to_file(private_key, args.private_key_output, is_private=True)
    save_key_to_file(public_key, args.public_key_output, is_private=False)

    logger.debug("ECC key pair saved to:\n  Private: %s\n  Public:  %s", args.private_key_output, args.public_key_output)


if __name__ == "__main__":
    main()
