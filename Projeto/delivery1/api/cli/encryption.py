import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend


# Generate a random AES key
def generate_aes_key(key_size=32):  # 32 bytes = 256 bits
    return os.urandom(key_size)


# Encrypt the AES key using a public RSA key
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key


# Compute a cryptographic hash of the file contents (file handle)
def compute_file_handle(file_path, hash_algorithm=hashes.SHA256()):
    digest = hashes.Hash(hash_algorithm, backend=default_backend())
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            digest.update(chunk)
    return digest.finalize()


# Encrypt the file using AES (CBC mode with PKCS7 padding)
def encrypt_file(file_path, aes_key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    encryptor = cipher.encryptor()

    encrypted_file_path = f"{file_path}.enc"
    with open(file_path, "rb") as infile, open(encrypted_file_path, "wb") as outfile:
        outfile.write(iv)  # Store IV at the beginning of the encrypted file
        while chunk := infile.read(4096):
            padded_data = padder.update(chunk)
            outfile.write(encryptor.update(padded_data))
        outfile.write(encryptor.update(padder.finalize()) + encryptor.finalize())

    return encrypted_file_path, iv


# Generate HMAC for integrity control
def generate_integrity_control(aes_key, file_path):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    return hmac.finalize()


# Generate metadata and save as JSON
def generate_metadata(file_handle, iv, integrity_control):
    metadata = {
        "alg": {
            "encryption": {
                "algorithm": "AES",
                "mode": "CBC",
                "Padder": "PKCS7",
                "iv": iv.hex(),
            },
            "integrity_control": {
                "method": "HMAC",
                "hash_algorithm": "SHA256",
                "MAC": integrity_control.hex(),
            },
        },
        "file_handle": file_handle.hex(),
        "aes_key": aes_key.hex(),
    }
    with open("metadata.json", "w") as json_file:
        json.dump(metadata, json_file, indent=4)
    return metadata


# Decrypt the file using AES (CBC mode with PKCS7 unpadding).
def decrypt_file(encrypted_file_path, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(encrypted_file_path, "rb") as infile, open(
        decrypted_file_path, "wb"
    ) as outfile:
        iv_in_file = infile.read(16)
        if iv_in_file != iv:
            raise ValueError("IV in file does not match metadata IV.")

        while chunk := infile.read(4096):
            decrypted_data = decryptor.update(chunk)
            outfile.write(unpadder.update(decrypted_data))
        outfile.write(unpadder.update(decryptor.finalize()))
        outfile.write(unpadder.finalize())

    return decrypted_file_path


# Verify the integrity of a file using HMAC
def verify_integrity(aes_key, file_path, expected_mac):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    hmac.verify(bytes.fromhex(expected_mac))


# Test the encryption and decryption functions locally
if __name__ == "__main__":
    original_file_path = "document.txt"

    # Encrypt
    aes_key = generate_aes_key()
    encrypted_file_path, iv = encrypt_file(original_file_path, aes_key)
    file_handle = compute_file_handle(original_file_path)
    integrity_control = generate_integrity_control(aes_key, original_file_path)
    metadata = generate_metadata(file_handle, iv, integrity_control)

    print("Encrypted file saved to:", encrypted_file_path)
    print("Metadata saved to: metadata.json")
    print("Metadata content:", json.dumps(metadata, indent=4))

    # Decrypt
    with open("metadata.json", "r") as json_file:
        metadata = json.load(json_file)

    file_handle = bytes.fromhex(metadata["file_handle"])
    aes_key = bytes.fromhex(metadata["aes_key"])  # Retrieve the AES key
    iv = bytes.fromhex(metadata["alg"]["encryption"]["iv"])
    expected_mac = metadata["alg"]["integrity_control"]["MAC"]

    encrypted_file_path = "document.txt.enc"

    decrypted_file_path = decrypt_file(encrypted_file_path, aes_key, iv)
    print("Decrypted file saved to:", decrypted_file_path)

    try:
        verify_integrity(aes_key, decrypted_file_path, expected_mac)
        print("Integrity verification succeeded. File is authentic.")
    except Exception as e:
        print("Integrity verification failed:", str(e))
