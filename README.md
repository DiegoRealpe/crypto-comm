# Crypto Communications

This project is a cybersecurity exercise for ComS 559. It implements a client-server application that uses asymmetric encryption (ECC and AES) to securely share files between a sender (Alice) and a receiver (Bob).

## Installation

```bash
pip install .
```
OR

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate ECC Key Pairs
Run the following command to generate ECC key pairs:

```bash
crypto-generate-keys <private_key_path> <public_key_path>
```

### 2. Encrypt a File
Run the following command to encrypt a plaintext file:
```bash
crypto-encrypt <sender_private_key> <receiver_public_key> <plaintext_file> <ciphertext_path>
```

### 3. Decrypt a File
Run the following command to decrypt a ciphertext file:
```bash
crypto-decrypt <receiver_private_key> <sender_public_key> <ciphertext_file>
```

