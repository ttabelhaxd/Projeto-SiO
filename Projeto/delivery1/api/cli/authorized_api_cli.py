#  rep_add_subject, rep_suspend_subject, rep_activate_subject, rep_add_doc, rep_get_doc_metadata, e rep_delete_doc
import requests
import argparse
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

BASE_URL = "http://localhost:5000/api/authorized" 

# Helper function to load the session_id
def load_session(session_file):
    try:
        with open(session_file, 'r') as f:
            session_id = f.read().strip()
        return session_id
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return None

# Function for command `rep_add_subject`
def add_subject(session_file, username, name, email, credentials_file):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    with open(credentials_file, 'r') as f:
        public_key = f.read()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key
    }

    try:
        response = requests.post(f"{BASE_URL}/subjects", headers=headers, json=data)
        try:
            response_data = response.json()
        except requests.exceptions.JSONDecodeError:
            print(f"Error: Invalid response from server: {response.text}")
            return 1

        if response.status_code == 201:
            print(f"Password: {response_data.get('password')}")
            return 0
        else:
            print(f"Error adding a new subject: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1
    
# Function for commands `rep_suspend_subject` and `rep_activate_subject`
def change_subject_status(session_file, username, action):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}
    endpoint = "suspend" if action == "suspend" else "activate"

    data = {"status": "suspended" if action == "suspend" else "active"}
    response = requests.patch(f"{BASE_URL}/subjects/{username}/status", headers=headers, json=data)

    if response.status_code == 200:
        print(response.json().get("message"))
        return 0
    else:
        print(f"Error changing subject status: {response.json().get('error', 'Unknown error')}")
        return 1

# Function for command `rep_add_doc`
def add_doc(session_file, document_name, file_path):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}
    with open(file_path, 'r') as f:
        file_content = f.read()

    data = {
        "document_name": document_name,
        "file_content": file_content
    }

    try:
        response = requests.post(f"{BASE_URL}/documents", headers=headers, json=data)
        if response.status_code == 201:
            metadata = response.json()
            print("Document uploaded successfully. Metadata:")
            print(json.dumps(metadata, indent=4))
            return 0
        else:
            print(f"Error uploading document: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1

# Function for command `rep_get_doc_metadata`
def get_doc_metadata(session_file, document_name):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}

    response = requests.get(f"{BASE_URL}/documents/{document_name}/metadata", headers=headers)
    
    if response.status_code == 200:
        metadata = response.json()
        print(json.dumps(metadata, indent=4))
        return 0
    else:
        print(f"Error fetching document metadata: {response.json().get('error', 'Unknown error')}")
        return 1

# Function for command `rep_get_doc_file`
def get_doc_file(session_file, document_name, output_file):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}

    response = requests.get(f"{BASE_URL}/documents/{document_name}/content", headers=headers)
    
    if response.status_code == 200:
        try:
            file_content = response.json().get("file_content")
        except ValueError:
            print(f"Error: Response is not valid JSON. Raw response: {response.text}")
            return 1

        if not output_file:
            print(file_content)
            return 0
        with open(output_file, 'w') as f:
            f.write(file_content)
        print(f"File content saved to {output_file}.")
        return 0
    else:
        try:
            error_message = response.json().get('error', 'Unknown error')
        except ValueError:
            error_message = f"Unexpected response: {response.text}"
        print(f"Error fetching document file: {error_message}")
        return 1

# Function for command `rep_delete_doc`
def delete_doc(session_file, document_name):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}
    response = requests.delete(f"{BASE_URL}/documents/{document_name}", headers=headers)

    try:
        if response.status_code == 200:
            print(response.json().get("message", "Document deleted successfully"))
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error deleting document: {error_message}")
            return 1
    except Exception as e:
        print(f"Unexpected response: {response.text}")
        return 1
        
# Main parser function
def main():
    parser = argparse.ArgumentParser(description="CLI for Repository API Authorized Commands")
    
    subparsers = parser.add_subparsers(dest="command")

    # Command `rep_add_subject`
    parser_add_subject = subparsers.add_parser("rep_add_subject", help="Add a new subject")
    parser_add_subject.add_argument("session_file", help="Session file path")
    parser_add_subject.add_argument("username", help="Username of the new subject")
    parser_add_subject.add_argument("name", help="Full name of the new subject")
    parser_add_subject.add_argument("email", help="Email of the new subject")
    parser_add_subject.add_argument("credentials_file", help="Public key file for the new subject")

    # Commands `rep_suspend_subject` and `rep_activate_subject`
    parser_suspend_subject = subparsers.add_parser("rep_suspend_subject", help="Suspend a subject")
    parser_suspend_subject.add_argument("session_file", help="Session file path")
    parser_suspend_subject.add_argument("username", help="Username of the subject to suspend")

    parser_activate_subject = subparsers.add_parser("rep_activate_subject", help="Activate a subject")
    parser_activate_subject.add_argument("session_file", help="Session file path")
    parser_activate_subject.add_argument("username", help="Username of the subject to activate")

    # Command `rep_add_doc`
    parser_add_doc = subparsers.add_parser("rep_add_doc", help="Add a new document")
    parser_add_doc.add_argument("session_file", help="Session file path")
    parser_add_doc.add_argument("document_name", help="Name of the document")
    parser_add_doc.add_argument("file_path", help="Path to the file to upload")

    # Command `rep_get_doc_metadata`
    parser_get_doc_metadata = subparsers.add_parser("rep_get_doc_metadata", help="Get document metadata")
    parser_get_doc_metadata.add_argument("session_file", help="Session file path")
    parser_get_doc_metadata.add_argument("document_name", help="Name of the document")

    # Command `rep_get_doc_file`
    parser_get_doc_file = subparsers.add_parser("rep_get_doc_file", help="Get document file")
    parser_get_doc_file.add_argument("session_file", help="Session file path")
    parser_get_doc_file.add_argument("document_name", help="Name of the document")
    parser_get_doc_file.add_argument("output_file", nargs="?", help="Optional path to save the file")

    # Command `rep_delete_doc`
    parser_delete_doc = subparsers.add_parser("rep_delete_doc", help="Delete a document")
    parser_delete_doc.add_argument("session_file", help="Session file path")
    parser_delete_doc.add_argument("document_name", help="Name of the document to delete")

    args = parser.parse_args()

    # Executes the correct function based on the command
    if args.command == "rep_add_subject":
        return add_subject(args.session_file, args.username, args.name, args.email, args.credentials_file)
    elif args.command == "rep_suspend_subject":
        return change_subject_status(args.session_file, args.username, "suspend")
    elif args.command == "rep_activate_subject":
        return change_subject_status(args.session_file, args.username, "activate")
    elif args.command == "rep_add_doc":
        return add_doc(args.session_file, args.document_name, args.file_path)
    elif args.command == "rep_get_doc_metadata":
        return get_doc_metadata(args.session_file, args.document_name)
    elif args.command == "rep_get_doc_file":
        return get_doc_file(args.session_file, args.document_name, args.output_file)
    elif args.command == "rep_delete_doc":
        return delete_doc(args.session_file, args.document_name)
    else:
        parser.print_help()
        return 1
    
if __name__ == "__main__":
    exit(main())