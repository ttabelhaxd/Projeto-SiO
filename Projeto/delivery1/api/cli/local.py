import argparse
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, _serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding as sym_padding

def decrypt_file_aux(encrypted_file_path, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()
    
    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(encrypted_file_path, 'rb') as infile, open(decrypted_file_path, 'wb') as outfile:
        iv_in_file = infile.read(16)  # Read the IV stored in the encrypted file
        if iv_in_file != iv:
            raise ValueError("IV in file does not match metadata IV.")
        
        while chunk := infile.read(4096):
            decrypted_data = decryptor.update(chunk)
            outfile.write(unpadder.update(decrypted_data))
        
        outfile.write(unpadder.update(decryptor.finalize()))
        outfile.write(unpadder.finalize())
    
    return decrypted_file_path


def verify_integrity(aes_key, file_path, expected_mac):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    hmac.verify(bytes.fromhex(expected_mac))

# Função para o comando `rep_decrypt_file`
def decrypt_file(encrypted_file_path, metadata_file):
    with open(metadata_file, "r") as json_file:
        metadata = json.load(json_file)

    iv = bytes.fromhex(metadata["alg"]["encryption"]["iv"])
    expected_mac = metadata["alg"]["integrity_control"]["MAC"]
    aes_key = bytes.fromhex(metadata["aes_key"])

    decrypted_file_path = decrypt_file_aux(encrypted_file_path, aes_key, iv)
    print("Decrypted file saved to:", decrypted_file_path)

    try:
        verify_integrity(aes_key, decrypted_file_path, expected_mac)
        print("Integrity verification succeeded. File is authentic.")
    except Exception as e:
        print("Integrity verification failed:", str(e))


# Função para o comando `rep_subject_credentials`
def create_key_pair(password, credentials_file):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(credentials_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        )
    print(f"Private key saved to {credentials_file}")
        
    public_key = private_key.public_key()
    with open(f"{credentials_file}.pub", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"Public key saved to {credentials_file}.pub")
    print("Key pair generated successfully.")

def main():
    parser = argparse.ArgumentParser(description="CLI for Local Commands")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Comando `rep_decrypt_file`
    parser_decrypt_file = subparsers.add_parser("rep_decrypt_file", help="Decrypt an encrypted file using metadata")
    parser_decrypt_file.add_argument("encrypted_file", help="Path to the encrypted file")
    parser_decrypt_file.add_argument("metadata_file", help="Path to the metadata file")

    # Comando `rep_subject_credentials`
    parser_subject_credentials = subparsers.add_parser("rep_subject_credentials", help="Creates subject credentials")
    parser_subject_credentials.add_argument("password", help="Password to protect the private key")
    parser_subject_credentials.add_argument("credentials_file", help="Path to save the private key file")

    args = parser.parse_args()

    if args.command == "rep_decrypt_file":
        return decrypt_file(args.encrypted_file, args.metadata_file)
    elif args.command == "rep_subject_credentials":
        return create_key_pair(args.password, args.credentials_file)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    exit(main())