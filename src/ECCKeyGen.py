from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ecc_key_pair():
    # Generate an ECC key pair using the SECP256R1 curve
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename, is_private=True):
    # Serialize and save the key to a file
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, 'wb') as f:
        f.write(pem)

if __name__ == "__main__":
    private_key, public_key = generate_ecc_key_pair()
    save_key_to_file(private_key, "AlicePriKey.pem", is_private=True)
    save_key_to_file(public_key, "AlicePubKey.pem", is_private=False)
    print("ECC key pair generated and saved to files.")