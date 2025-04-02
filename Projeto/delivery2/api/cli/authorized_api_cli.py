# delivery 1: rep_add_subject, rep_suspend_subject, rep_activate_subject, rep_add_doc, rep_get_doc_metadata, and rep_delete_doc
# delivery 2: rep_add_role, rep_suspend_role, rep_reactivate_role, rep_add_permission, rep_remove_permission, and rep_acl_doc

import requests, argparse, json, getpass, re, base64, os
from utils_encryptions import encrypt_data, decrypt_response
from datetime import datetime, timezone

BASE_URL = "http://localhost:5000/api/authorized"
REPO_PUB_KEY = "../api/keys/repositoryKeys/RepoKey.pem.pub"

# Helper function to load the session_id
def load_session(session_file):
    try:
        with open(session_file, "r") as f:
            session_id = f.read().strip()
        if not session_id:
            print(f"Error: Session file '{session_file}' is empty. Please log in to create a session.")
            return None
        return session_id
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found. Please log in to create a session.")
        return None


# delivery 1


# Function for command `rep_add_subject`
def add_subject(session_file, username, name, email, credentials_file):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    if not os.path.exists(credentials_file):
        print(f"Error: Public key file '{credentials_file}' not found.")
        return 1

    with open(credentials_file, "r") as f:
        public_key = f.read()

    public_key_path = os.path.basename(credentials_file)
    password = getpass.getpass(f"Enter password for user '{username}': ")
    if not password:
        print("Error: Password cannot be empty.")
        return 1
    if len(password) > 128:
        print("Error: Password cannot be longer than 128 characters.")
        return 1
    if len(password) < 12 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Error: Password must be at least 12 characters long and include uppercase, lowercase, digit, and special character.")
        return 1

    PERMISSIONS = [
        "DOC_READ", "DOC_DELETE", "DOC_ACL",
        "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
        "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
    ]

    if username in PERMISSIONS:
        print(f"Error: Username '{username}' cannot be the same as a system permission name.")
        return 1

    try:
        roles_response = requests.get(f"{BASE_URL}/roles", headers={"Authorization": f"Bearer {session_id}"})
        if roles_response.status_code == 200:
            existing_roles = [role["name"] for role in roles_response.json()]
            if username in existing_roles:
                print(f"Error: Username '{username}' conflicts with an existing role name. Please choose a different username.")
                return 1
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the roles API. Username validation could not be completed. Exception: {str(e)}")
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {"Authorization": f"Bearer {session_id}"}
    data = {
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
        "public_key_path": public_key_path,
        "password": password,
        "timestamp": timestamp
    }

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/subjects", headers=headers, json=encrypted_data)
        if response.status_code == 201:
            print(f"Subject '{username}' added successfully.")
            return 0
        elif response.status_code == 409:
            response_data = response.json()
            print(f"Error: {response_data.get('error', 'Conflict occurred while adding subject.')}")
            return 1
        elif response.status_code == 500:
            print("Error: An internal server error occurred on the backend. "
                  "This may be due to a misconfiguration or unexpected issue. "
                  "Please contact the administrator or try again later.")
            return 1
        else:
            response_data = response.json()
            print(f"Error adding subject: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Function for commands `rep_suspend_subject` and `rep_activate_subject`
def change_subject_status(session_file, username, action):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    status = "suspended" if action == "suspend" else "active"
    data = {"username": username, "status": status, "timestamp": timestamp}

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.patch(
            f"{BASE_URL}/subjects/status",
            headers=headers,
            json={"encrypted_data": encrypted_data}
        )

        if response.status_code == 200:
            print(response.json().get("message", "Subject status updated successfully"))
            return 0
        else:
            print(f"Error changing subject status: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return 1


# Function for command `rep_add_doc`
def add_doc(session_file, document_name, file_path):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    with open(file_path, "rb") as f:
        file_content = f.read()

    encoded_content = base64.b64encode(file_content).decode("utf-8")
    decoded_content = base64.b64decode(encoded_content)
    if file_content != decoded_content:
        raise ValueError("Problema na codificação/decodificação Base64 no cliente.")

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {
        "document_name": document_name,
        "file_content": encoded_content,
        "timestamp": timestamp,
    }

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/documents", headers=headers, json=encrypted_data)
        if response.status_code == 201:
            response_json = response.json()
            encrypted_data = response_json.get("encrypted_data")
            key_path = response_json.get("key_path")

            if not encrypted_data or not key_path:
                print("Missing encrypted data or key path in response.")
                return 1        

            decrypted_data = decrypt_response(encrypted_data, key_path)
            if not decrypted_data:
                return 1
            print("Document uploaded successfully. Metadata:")
            print(json.dumps(decrypted_data, indent=4))
            return 0
        else:
            print(
                f"Error uploading document: {response.json().get('error', 'Unknown error')}"
            )
            return 1
    except requests.exceptions.ConnectionError:
        print(
            "Error: Unable to connect to the server. Ensure the API is running and accessible."
        )
        return 1


# Function for command `rep_get_doc_metadata`
def get_doc_metadata(session_file, document_name):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"document_name": document_name, "timestamp": timestamp}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.get(f"{BASE_URL}/documents/metadata", headers=headers, json={"encrypted_data": encrypted_data})
        if response.status_code == 200:
            response_json = response.json()
            encrypted_data = response_json.get("encrypted_data")
            key_path = response_json.get("key_path")

            if not encrypted_data or not key_path:
                print("Missing encrypted data or key path in response.")
                return 1        

            decrypted_data = decrypt_response(encrypted_data, key_path)
            if not decrypted_data:
                return 1
            print(json.dumps(decrypted_data, indent=4))
            return 0
        else:
            print(f"Error fetching document metadata: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return 1


# Function for command `rep_get_doc_file`
def get_doc_file(session_file, document_name, output_file):
    """Obtém o conteúdo de um documento e o salva em um arquivo ou exibe no console."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"document_name": document_name, "timestamp": timestamp}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.get(f"{BASE_URL}/documents/content", headers=headers, json={"encrypted_data": encrypted_data})

        if response.status_code == 200:
            response_json = response.json()
            encrypted_data = response_json.get("encrypted_data")
            key_path = response_json.get("key_path")

            if not encrypted_data or not key_path:
                print("Missing encrypted data or key path in response.")
                return 1        

            decrypted_data = decrypt_response(encrypted_data, key_path)
            if not decrypted_data:
                print("Error: Unable to decrypt the data.")
                return 1
            
            # Decodifica o conteúdo Base64
            file_content_base64 = decrypted_data.get("file_content")
            if not file_content_base64:
                print("Error: Missing file content in the decrypted data.")
                return 1

            file_content = base64.b64decode(file_content_base64)

            if not output_file:
                print(file_content.decode("utf-8"))  
                return 0

            with open(output_file, "wb") as f:
                f.write(file_content)

            print(f"File content saved to {output_file}.")
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error fetching document file: {error_message}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the server. Exception: {str(e)}")
        return 1





# Function for command `rep_delete_doc`
def delete_doc(session_file, document_name):
    """Deleta um documento especificado."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"document_name": document_name, "timestamp": timestamp}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.delete(f"{BASE_URL}/documents/delete", headers=headers, json={"encrypted_data": encrypted_data})

        if response.status_code == 200:
            print(response.json().get("message", "Document deleted successfully"))
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error deleting document: {error_message}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the server. Exception: {str(e)}")
        return 1


# delivery 2

# Function for command `rep_add_role`
def add_role(session_file, role):
    """Adiciona uma nova role ao sistema."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"role_name": role, "timestamp": timestamp}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/roles", headers=headers, json=encrypted_data)

        if response.status_code == 201:
            print(response.json().get("message", "Role added successfully"))
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error adding role: {error_message}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Function for command `rep_suspend_role`
def suspend_role(session_file, role):
    """Suspende uma role especificada."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"role_name": role, "status": "suspended", "timestamp": timestamp}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.patch(f"{BASE_URL}/roles/status", headers=headers, json={"encrypted_data": encrypted_data})

        if response.status_code == 200:
            print(response.json().get("message", "Role suspended successfully"))
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error suspending role: {error_message}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return 1


# Function for command `rep_reactivate_role`
def reactivate_role(session_file, role):
    """Reativa uma role específica."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    data = {"role_name": role, "status": "active", "timestamp": timestamp}
    encrypted_data = {"encrypted_data": encrypt_data(data, REPO_PUB_KEY)}

    try:
        response = requests.patch(
            f"{BASE_URL}/roles/status", headers=headers, json=encrypted_data
        )
        response_data = response.json()

        if response.status_code == 200:
            print(response_data.get("message", "Role reactivated successfully"))
            return 0
        else:
            print(
                f"Error reactivating role: {response_data.get('error', 'Unknown error')}"
            )
            return 1
    except ValueError:
        print("Error: Response is not a valid JSON.")
        print("Response Content:", response.text)
        return 1


# Function for command `rep_add_permission`
def add_permission(session_file, role_name, target):
    """Adiciona uma permissão a uma role ou associa uma role a um usuário."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    PERMISSIONS = [
        "DOC_READ", "DOC_DELETE", "DOC_ACL",
        "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
        "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
    ]

    if target in PERMISSIONS:
        print(f"Adding permission '{target}' to role '{role_name}'...")
        data = {"role_name": role_name, "permission": target, "timestamp": timestamp}
    else:
        print(f"Assigning role '{role_name}' to user '{target}'...")
        data = {"role_name": role_name, "username": target, "timestamp": timestamp}

    encrypted_data = {"encrypted_data": encrypt_data(data, REPO_PUB_KEY)}

    try:
        response = requests.post(
            f"{BASE_URL}/roles/manage",
            headers=headers,
            json=encrypted_data
        )
        response_data = response.json()

        if response.status_code == 200:
            print(response_data.get("message", "Operation successful"))
            return 0
        else:
            print(f"Error: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return 1


# Function for command `rep_remove_permission`
def remove_permission(session_file, role_name, target):
    """Remove uma permissão de uma role ou desassocia uma role de um usuário."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}
    PERMISSIONS = [
        "DOC_READ", "DOC_DELETE", "DOC_ACL",
        "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
        "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
    ]

    if target in PERMISSIONS:
        print(f"Removing permission '{target}' from role '{role_name}'...")
        data = {"role_name": role_name, "permission": target, "timestamp": timestamp}
    else:
        print(f"Removing role '{role_name}' from user '{target}'...")
        data = {"role_name": role_name, "username": target, "timestamp": timestamp}

    encrypted_data = {"encrypted_data": encrypt_data(data, REPO_PUB_KEY)}

    try:
        response = requests.delete(
            f"{BASE_URL}/roles/manage",
            headers=headers,
            json=encrypted_data
        )
        response_data = response.json()

        if response.status_code == 200:
            print(response_data.get("message", "Operation successful"))
            return 0
        else:
            print(f"Error: {response_data.get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {str(e)}")
        return 1


# Function for command `rep_acl_doc`
def acl_doc(session_file, document_name, action, role, permission):
    """Gera o ACL de um documento: adiciona ou remove permissões."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    # Adiciona timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}"}

    data = {
        "document_name": document_name,
        "role_id": role,
        "permission": permission,
        "action": action,
        "timestamp": timestamp
    }

    encrypted_data = {"encrypted_data": encrypt_data(data, REPO_PUB_KEY)}

    try:
        response = requests.patch(f"{BASE_URL}/documents/acl", headers=headers, json=encrypted_data)

        if response.status_code == 200:
            print(response.json().get("message"))
            return 0
        else:
            print(f"Error managing ACL: {response.json().get('error', 'Unknown error')}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1


# Main parser function
def main():
    parser = argparse.ArgumentParser(
        description="CLI for Repository API Authorized Commands"
    )

    subparsers = parser.add_subparsers(dest="command")

    # Command `rep_add_subject`
    parser_add_subject = subparsers.add_parser(
        "rep_add_subject", help="Add a new subject"
    )
    parser_add_subject.add_argument("session_file", help="Session file path")
    parser_add_subject.add_argument("username", help="Username of the new subject")
    parser_add_subject.add_argument("name", help="Full name of the new subject")
    parser_add_subject.add_argument("email", help="Email of the new subject")
    parser_add_subject.add_argument(
        "credentials_file", help="Public key file for the new subject"
    )

    # Commands `rep_suspend_subject` and `rep_activate_subject`
    parser_suspend_subject = subparsers.add_parser(
        "rep_suspend_subject", help="Suspend a subject"
    )
    parser_suspend_subject.add_argument("session_file", help="Session file path")
    parser_suspend_subject.add_argument(
        "username", help="Username of the subject to suspend"
    )

    parser_activate_subject = subparsers.add_parser(
        "rep_activate_subject", help="Activate a subject"
    )
    parser_activate_subject.add_argument("session_file", help="Session file path")
    parser_activate_subject.add_argument(
        "username", help="Username of the subject to activate"
    )

    # Command `rep_add_doc`
    parser_add_doc = subparsers.add_parser("rep_add_doc", help="Add a new document")
    parser_add_doc.add_argument("session_file", help="Session file path")
    parser_add_doc.add_argument("document_name", help="Name of the document")
    parser_add_doc.add_argument("file_path", help="Path to the file to upload")

    # Command `rep_get_doc_metadata`
    parser_get_doc_metadata = subparsers.add_parser(
        "rep_get_doc_metadata", help="Get document metadata"
    )
    parser_get_doc_metadata.add_argument("session_file", help="Session file path")
    parser_get_doc_metadata.add_argument("document_name", help="Name of the document")

    # Command `rep_get_doc_file`
    parser_get_doc_file = subparsers.add_parser(
        "rep_get_doc_file", help="Get document file"
    )
    parser_get_doc_file.add_argument("session_file", help="Session file path")
    parser_get_doc_file.add_argument("document_name", help="Name of the document")
    parser_get_doc_file.add_argument(
        "output_file", nargs="?", help="Optional path to save the file"
    )

    # Command `rep_delete_doc`
    parser_delete_doc = subparsers.add_parser(
        "rep_delete_doc", help="Delete a document"
    )
    parser_delete_doc.add_argument("session_file", help="Session file path")
    parser_delete_doc.add_argument(
        "document_name", help="Name of the document to delete"
    )

    # Command `rep_add_role`
    parser_add_role = subparsers.add_parser("rep_add_role", help="Add a new role")
    parser_add_role.add_argument("session_file", help="Session file path")
    parser_add_role.add_argument("role", help="Name of the role")

    # Command `rep_suspend_role`
    parser_suspend_role = subparsers.add_parser(
        "rep_suspend_role", help="Suspend a role"
    )
    parser_suspend_role.add_argument("session_file", help="Session file path")
    parser_suspend_role.add_argument("role", help="Name of the role to suspend")

    # Command `rep_reactivate_role`
    parser_reactivate_role = subparsers.add_parser(
        "rep_reactivate_role", help="Reactivate a role"
    )
    parser_reactivate_role.add_argument("session_file", help="Session file path")
    parser_reactivate_role.add_argument("role", help="Name of the role to reactivate")

    # Command `rep_add_permission`
    parser_add_permission = subparsers.add_parser(
    "rep_add_permission", help="Add a permission to a role or assign a role to a user"
    )
    parser_add_permission.add_argument("session_file", help="Session file path")
    parser_add_permission.add_argument("role", help="Role name")
    parser_add_permission.add_argument("target", help="Permission to add OR username to assign role")

    # Command `rep_remove_permission`
    parser_remove_permission = subparsers.add_parser(
    "rep_remove_permission", help="Remove a permission from a role or unassign a role from a user"
    )
    parser_remove_permission.add_argument("session_file", help="Session file path")
    parser_remove_permission.add_argument("role", help="Role name")
    parser_remove_permission.add_argument("target", help="Permission to remove OR username to unassign role")

    # Command `rep_acl_doc`
    parser_acl_doc = subparsers.add_parser("rep_acl_doc", help="Manage document ACL")
    parser_acl_doc.add_argument("session_file", help="Session file path")
    parser_acl_doc.add_argument("document_name", help="Name of the document")
    parser_acl_doc.add_argument("action", choices=["+", "-"], help="Action to perform")
    parser_acl_doc.add_argument("role", help="Role to add or remove")
    parser_acl_doc.add_argument("permission", help="Permission to add or remove")

    args = parser.parse_args()

    # Executes the correct function based on the command
    if args.command == "rep_add_subject":
        return add_subject(
            args.session_file,
            args.username,
            args.name,
            args.email,
            args.credentials_file,
        )
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
    elif args.command == "rep_add_role":
        return add_role(args.session_file, args.role)
    elif args.command == "rep_suspend_role":
        return suspend_role(args.session_file, args.role)
    elif args.command == "rep_reactivate_role":
        return reactivate_role(args.session_file, args.role)
    elif args.command == "rep_add_permission":
        return add_permission(args.session_file, args.role, args.target)
    elif args.command == "rep_remove_permission":
        return remove_permission(args.session_file, args.role, args.target)
    elif args.command == "rep_acl_doc":
        return acl_doc(
            args.session_file,
            args.document_name,
            args.action,
            args.role,
            args.permission,
        )
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    exit(main())
