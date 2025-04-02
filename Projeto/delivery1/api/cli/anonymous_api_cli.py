# rep_subject_credentials, rep_create_org, rep_create_session and rep_get_file

import requests
import argparse
import json
import os

BASE_URL = "http://localhost:5000/api/anonymous"

# Create Organization
def create_org(organization, username, name, email, public_key_file):
    if not os.path.exists(public_key_file):
        print(f"Error: Public key file '{public_key_file}' not found.")
        return 1

    with open(public_key_file, 'r') as f:
        public_key = f.read()

    data = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key
    }

    try:
        response = requests.post(f"{BASE_URL}/organization/create", json=data)
        try:
            response_data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(f"Error: Invalid response from server: {response.text}")
            return 1

        if response.status_code == 201:
            print(f"Organization '{organization}' created successfully.")
            print(f"Password: {response_data.get('password')}")
            return 0
        else:
            print(f"Error creating organization: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1

# List Organizations
def list_orgs():
    try:
        response = requests.get(f"{BASE_URL}/organizations")
        if response.status_code == 200:
            organizations = response.json()
            if not organizations:
                print("No organizations found.")
                return 0
            for org in organizations:
                print(f"Name: {org['name']}, Creator: {org['creator_id']}, Created At: {org['create_date']}")
            return 0
        else:
            print(f"Error listing organizations: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Create Session
def create_session(organization, username, password, credentials_file, session_file):
    # Certifique-se de que a chave privada existe
    if not os.path.exists(credentials_file):
        print(f"Error: Credentials file '{credentials_file}' not found.")
        return 1

    with open(credentials_file, 'r') as f:
        private_key = f.read()  

    data = {
        "organization": organization,
        "username": username,
        "password": password
    }

    try:
        response = requests.post(f"{BASE_URL}/session/create", json=data)
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
    try:
        response = requests.get(f"{BASE_URL}/file/download/{file_handle}")
        if response.status_code == 200:
            file_content = response.json().get("file_content")
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(file_content)
                print(f"File downloaded successfully and saved to {output_file}.")
            else:
                print(file_content)
            return 0
        else:
            print(f"Error downloading file: {response.json().get('error', 'Unknown error')}")
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
