# delivery 1: rep_subject_credentials, rep_create_org, rep_create_session and rep_get_file

import requests, argparse, os, getpass, re
from utils_encryptions import encrypt_data
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64, re

BASE_URL = "http://localhost:5000/api/anonymous"
REPO_PUB_KEY = "../api/keys/repositoryKeys/RepoKey.pem.pub"

def decrypt_and_verify(file_content, metadata, output_file=None):
    try:
        encrypted_data = base64.b64decode(file_content)
        aes_key = bytes.fromhex(metadata["aes_key"])
        iv = bytes.fromhex(metadata["iv"])
        expected_mac = metadata["expected_mac"]

        hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
        hmac.update(encrypted_data)
        calculated_mac = hmac.finalize().hex()

        if calculated_mac != expected_mac:
            raise ValueError("Integrity check failed: Calculated MAC does not match the expected MAC.")

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        readable_content = re.sub(r'[^\x20-\x7E\n]', '', decrypted_data.decode("utf-8", errors="ignore")).strip()

        print("Decrypted File Content:")
        print(readable_content)

        if output_file:
            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            print(f"\nFile also saved to {output_file}.")

        return True
    except Exception as e:
        print(f"Error in decrypt_and_verify: {e}")
        return False

# delivery 1

# Create Organization
def create_org(organization, username, name, email, public_key_file):
    if not os.path.exists(public_key_file):
        print(f"Error: Public key file '{public_key_file}' not found.")
        return 1

    with open(public_key_file, 'r') as f:
        public_key = f.read()

    public_key_path = os.path.basename(public_key_file)
    password = getpass.getpass("Enter password for the new organization creator: ")
    if not password:
        print("Error: Password cannot be empty.")
        return 1
    if len(password) > 128:
        print("Error: Password cannot be longer than 128 characters.")
        return 1
    if len(password) < 12 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Error: Password must be at least 12 characters long and include uppercase, lowercase, digit, and special character.")
        return 1

    data = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
        "public_key_path": public_key_path,
        "password": password,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/organization/create", json=encrypted_data)
        try:
            response_data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(f"Error: Invalid response from server: {response.text}")
            return 1

        if response.status_code == 201:
            print(f"Organization '{organization}' created successfully.")
            return 0
        else:
            print(f"Error creating organization: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1

# List Organizations
def list_orgs():
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.get(f"{BASE_URL}/organizations", params={"encrypted_data": encrypted_data})
        if response.status_code == 200:
            organizations = response.json()
            if not organizations:
                print("No organizations found.")
                return 0
            for org in organizations:
                print(f"Name: {org['name']}, Creator: {org['creator_name']}, Created At: {org['create_date']}")
            return 0
        else:
            print(f"Error listing organizations: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Create Session
def create_session(organization, username, password, credentials_file, session_file):
    if not os.path.exists(credentials_file):
        print(f"Error: Credentials file '{credentials_file}' not found.")
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    data = {
        "organization": organization,
        "username": username,
        "password": password,
        "timestamp": timestamp
    }

    data_encrypted = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/session/create", json=data_encrypted)
        if response.status_code == 201:
            session_id = response.json().get("session_id")
            with open(session_file, 'w') as f:
                f.write(session_id)
            print(f"Session created successfully. Session ID saved to {session_file}.")
            return 0
        else:
            print(f"Error creating session: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1
    

# Download File
def get_file(file_handle, output_file=None):
    timestamp = datetime.now(timezone.utc).isoformat()

    data = {
        "file_handle": file_handle,
        "timestamp": timestamp
    }

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.get(
            f"{BASE_URL}/file/download",
            params={"encrypted_data": encrypted_data}
        )
        if response.status_code == 200:
            response_data = response.json()
            file_content = response_data["file_content"]
            metadata = response_data["metadata"]

            if not decrypt_and_verify(file_content, metadata, output_file):
                print("File integrity failed. File not saved.")
                return 1

            return 0
        else:
            try:
                error_message = response.json().get("error", "Unknown error")
            except ValueError:
                error_message = f"Unexpected response: {response.text}"
            print(f"Error downloading file: {error_message}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Main parser function
def main():
    parser = argparse.ArgumentParser(description="CLI for Repository API Anonymous Commands")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Command rep_create_org
    parser_create_org = subparsers.add_parser("rep_create_org", help="Create a new organization")
    parser_create_org.add_argument("organization", help="Organization name")
    parser_create_org.add_argument("username", help="Username of the creator")
    parser_create_org.add_argument("name", help="Full name of the creator")
    parser_create_org.add_argument("email", help="Email of the creator")
    parser_create_org.add_argument("public_key_file", help="Path to the public key file")

    # Command rep_list_orgs
    parser_list_orgs = subparsers.add_parser("rep_list_orgs", help="List all organizations")

    # Command rep_create_session
    parser_create_session = subparsers.add_parser("rep_create_session", help="Create a session for a user")
    parser_create_session.add_argument("organization", help="Organization name")
    parser_create_session.add_argument("username", help="Username")
    parser_create_session.add_argument("password", help="Password")
    parser_create_session.add_argument("credentials_file", help="Path to the private key (credentials file)")
    parser_create_session.add_argument("session_file", help="Path to save the session ID")

    # Command rep_get_file
    parser_get_file = subparsers.add_parser("rep_get_file", help="Download a file by its handle")
    parser_get_file.add_argument("file_handle", help="File handle to download")
    parser_get_file.add_argument("output_file", nargs="?", help="Optional output file to save the content")

    args = parser.parse_args()

    # Executes the correct function based on the command
    if args.command == "rep_create_org":
        return create_org(args.organization, args.username, args.name, args.email, args.public_key_file)
    elif args.command == "rep_list_orgs":
        return list_orgs()
    elif args.command == "rep_create_session":
        return create_session(args.organization, args.username, args.password, args.credentials_file, args.session_file)
    elif args.command == "rep_get_file":
        return get_file(args.file_handle, args.output_file)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    exit(main())
