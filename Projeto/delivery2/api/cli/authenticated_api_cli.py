# delivery 1: rep_list_subjects and rep_list_docs
# delivery 2: rep_assume_role, rep_drop_role, rep_list_roles, rep_list_role_subjects, rep_list_subject_roles, rep_list_role_permissions and rep_list_permission_roles

import requests, argparse
from utils_encryptions import encrypt_data, decrypt_response
from urllib.parse import quote
from datetime import datetime, timezone


BASE_URL = "http://localhost:5000/api/authenticated" 
REPO_PUB_KEY = "../api/keys/repositoryKeys/RepoKey.pem.pub"
    
# Helper function to load the session_id
def load_session(session_file):
    try:
        with open(session_file, 'r') as f:
            session_id = f.read().strip()
        return session_id
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return None

# delivery 1

# Function for command `rep_list_subjects`
def list_subjects(session_file, username=None):
    """Lista todos os subjects (usuários), com possibilidade de filtro por username."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}", "Timestamp": timestamp}

    params = {}
    if username:
        params['username'] = username

    try:
        response = requests.get(f"{BASE_URL}/subjects", headers=headers, params=params)
        response_data = response.json()

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
            
            if "message" in decrypted_data:
                print(decrypted_data["message"])
                return 0
            for subject in decrypted_data:
                print(f"Username: {subject['username']}")
                print(f"  Full Name: {subject['full_name']}")
                print(f"  Email: {subject['email']}")
                print(f"  Status: {subject['status']}\n")
            return 0
        else:
            error_message = response_data.get("error", "Unknown error")
            additional_info = response_data.get("additional_info", "")
            print(f"Error listing subjects: {error_message}")
            if additional_info:
                print(f"Additional Info: {additional_info}")
            return 1

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {str(e)}")
        return 1

    except ValueError:
        print(f"Unexpected response: {response.text}")
        return 1


# Function for command `rep_list_docs`
def list_docs(session_file, username=None, date=None, filter=None):
    """Lista documentos com filtros opcionais para username, date, e filter."""
    session_id = open(session_file).read().strip()
    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": f"Bearer {session_id}", "Timestamp": timestamp}
    params = {"timestamp": timestamp}

    if username:
        params["username"] = username
    if date:
        params["date"] = date
    if filter:
        params["filter"] = filter

    response = requests.get(f"{BASE_URL}/documents", headers=headers, params=params)
    if response.status_code == 200:
        response_json = response.json()
        encrypted_data = response_json.get("encrypted_data")
        key_path = response_json.get("key_path")

        if not encrypted_data:
            print("No docs found.")
            return 1        

        decrypted_data = decrypt_response(encrypted_data, key_path)
        if not decrypted_data:
            return 1

        if "message" in decrypted_data:
            print(decrypted_data["message"])
            return 0 

        for doc in decrypted_data:
            print(f"Document Name: {doc['name']}, Created By: {doc['creator']}, Created At: {doc['create_date']}")
        return 0
    else:
        print(f"Error listing documents: {response.json().get('error', 'Unknown error')}")
        return 1

    
# delivery 2

# Function for command `rep_assume_role`
def assume_role(session_file, role):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }

    data = {"role": role}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    try:
        response = requests.post(f"{BASE_URL}/session/assume_role", headers=headers, json=encrypted_data)

        if response.status_code == 200:
            print(f"Role {role} assumed successfully.")
            return 0
        else:
            error_message = response.json().get("error", "Unknown error")
            print(f"Error assuming role: {error_message}")
            return 1
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the server. Ensure the API is running and accessible.")
        return 1

# Function for command `rep_drop_role`
def drop_role(session_file, role):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()

    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp 
    }

    data = {
        "role": role
    }

    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    response = requests.post(f"{BASE_URL}/session/release_role", headers=headers, json=encrypted_data)

    if response.status_code == 200:
        print(f"Role {role} released successfully.")
        return 0
    else:
        try:
            error_message = response.json().get('error', 'Unknown error')
        except requests.exceptions.JSONDecodeError:
            error_message = "Invalid JSON response from server."
        print(f"Error releasing role: {error_message}")
        return 1

# Function for command `rep_list_roles`
def list_roles(session_file):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }

    response = requests.get(f"{BASE_URL}/roles", headers=headers)

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
        for role in decrypted_data:
            print(f"Role Name: {role['name']} ({role['status']})")
            print("  Subjects:")
            for subject in role["subjects"]:
                print(f"    - Username: {subject['username']}")
        return 0
    else:
        print(f"Error listing roles: {response.json().get('error', 'Unknown error')}")
        return 1


# Function for command `rep_list_role_subjects`
def list_role_subjects(session_file, role_name):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }
    
    data = {"role_name": role_name}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    response = requests.get(
        f"{BASE_URL}/roles/subjects",
        headers=headers,
        params={"encrypted_data": encrypted_data}
    )

    try:
        response_json = response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"Unexpected response from /roles/subjects: {response.text}")
        return 1

    if response.status_code == 200:
        encrypted_data = response_json.get("encrypted_data")
        key_path = response_json.get("key_path")

        if not encrypted_data or not key_path:
            print("Missing encrypted data or key path in response.")
            return 1        

        decrypted_data = decrypt_response(encrypted_data, key_path)
        if not decrypted_data:
            return 1
        if "subjects" in decrypted_data:
            print(f"Subjects in Role '{role_name}':")
            for subject in decrypted_data:
                print(
                    f"- Username: {subject['username']}, Full Name: {subject['full_name']}, "
                    f"Email: {subject['email']}, Status: {subject['status']}"
                )
        else:
            print(decrypted_data.get("message", f"No subjects found in role '{role_name}'."))
        return 0
    else:
        error_message = response_json.get("error", "Unknown error")
        print(f"Error listing subjects for role '{role_name}': {error_message}")
        return 1


# Function for command `rep_list_subject_roles`
def list_subject_roles(session_file, username):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }

    encrypted_username = encrypt_data({"username": username}, REPO_PUB_KEY)[0]
    encoded_username = quote(encrypted_username)
    response = requests.get(
        f"{BASE_URL}/subjects/roles?encrypted_username={encoded_username}", headers=headers
    )

    try:
        response_json = response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"Unexpected response: {response.text}")
        return 1

    if response.status_code == 200:
        encrypted_data = response_json.get("encrypted_data")
        key_path = response_json.get("key_path")

        if not encrypted_data or not key_path:
            print("Missing encrypted data or key path in response.")
            return 1        

        decrypted_data = decrypt_response(encrypted_data, key_path)
        if not decrypted_data:
            return 1
        for role in decrypted_data:
            print(f"Role Name: {role['name']}, Role ID: {role['id']}")
        return 0
    else:
        print(f"Error listing roles for subject {username}: {response_json.get('error', 'Unknown error')}")
        return 1



# Function for command `rep_list_role_permissions`
def list_role_permissions(session_file, role_name):
    """Lista as permissões de uma role com nome diretamente."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }

    data = {"role_name": role_name}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    response = requests.get(
        f"{BASE_URL}/roles/permissions", 
        headers=headers, 
        params={"encrypted_data": encrypted_data}
    )

    try:
        response_json = response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"Error: Invalid JSON response. Raw response: {response.text}")
        return 1

    if response.status_code == 200:
        if isinstance(response_json, list):
            if not response_json:
                print(f"No permissions found for role '{role_name}'.")
                return 0
            else:
                print(f"Unexpected response format: {response_json}")
                return 1

        encrypted_data = response_json.get("encrypted_data")
        key_path = response_json.get("key_path")

        if not encrypted_data or not key_path:
            print("Missing encrypted data or key path in response.")
            return 1        

        decrypted_data = decrypt_response(encrypted_data, key_path)
        if not decrypted_data:
            print(f"No permissions found for role '{role_name}'.")
            return 1

        print(f"Permissions for role '{role_name}':")
        for permission in decrypted_data:
            print(f"- Permission Type: {permission['type']}")
        return 0
    else:
        error_message = response_json.get("error", "Unknown error")
        print(f"Error listing permissions for role '{role_name}': {error_message}")
        return 1


# Function for command `rep_list_permission_roles`
def list_permission_roles(session_file, permission):
    """Lista roles associadas a uma permissão específica."""
    session_id = load_session(session_file)
    if not session_id:
        return 1

    timestamp = datetime.now(timezone.utc).isoformat()
    headers = {
        "Authorization": f"Bearer {session_id}",
        "Timestamp": timestamp
    }

    data = {"permission": permission}
    encrypted_data = encrypt_data(data, REPO_PUB_KEY)

    response = requests.get(
        f"{BASE_URL}/permissions/roles",
        headers=headers,
        params={"encrypted_data": encrypted_data}
    )

    try:
        response_json = response.json()
    except requests.exceptions.JSONDecodeError:
        print("Error: Response is not valid JSON.")
        return 1

    if response.status_code == 200:
        encrypted_data = response_json.get("encrypted_data")
        key_path = response_json.get("key_path")

        if not encrypted_data or not key_path:
            print("Missing encrypted data or key path in response.")
            return 1        

        decrypted_data = decrypt_response(encrypted_data, key_path)
        if not decrypted_data:
            print(f"No roles found with permission '{permission}'.")
            return 1

        print(f"Roles with permission '{permission}':")
        for role in decrypted_data:
            print(f"- Role Name: {role['name']}")
        return 0
    else:
        error_message = response_json.get("error", "Unknown error")
        print(f"Error listing roles for permission '{permission}': {error_message}")
        return 1


# Main parser function
def main():
    parser = argparse.ArgumentParser(description="CLI for Repository API Authenticated Commands")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Command `rep_list_subjects`
    parser_list_subjects = subparsers.add_parser("rep_list_subjects", help="List subjects")
    parser_list_subjects.add_argument("session_file", help="Session file path")
    parser_list_subjects.add_argument("username", nargs="?", help="Optional username to filter")

    # Command `rep_list_docs`
    parser_list_docs = subparsers.add_parser("rep_list_docs", help="List documents")
    parser_list_docs.add_argument("session_file", help="Session file path")
    parser_list_docs.add_argument("-s", "--username", help="Filter by creator username")
    parser_list_docs.add_argument("-d", "--date", help="Filter by date (DD-MM-YYYY)")
    parser_list_docs.add_argument("-f", "--filter", choices=["nt", "ot", "et"], help="Date filter type")

    # Command `rep_assume_role`
    parser_assume_role = subparsers.add_parser("rep_assume_role", help="Assume a role")
    parser_assume_role.add_argument("session_file", help="Session file path")
    parser_assume_role.add_argument("role", help="Role to assume")

    # Command `rep_drop_role`
    parser_drop_role = subparsers.add_parser("rep_drop_role", help="Drop a role")
    parser_drop_role.add_argument("session_file", help="Session file path")
    parser_drop_role.add_argument("role", help="Role to drop")

    # Command `rep_list_roles`
    parser_list_roles = subparsers.add_parser("rep_list_roles", help="List roles")
    parser_list_roles.add_argument("session_file", help="Session file path")

    # Command `rep_list_role_subjects`
    parser_list_role_subjects = subparsers.add_parser("rep_list_role_subjects", help="List subjects in a role")
    parser_list_role_subjects.add_argument("session_file", help="Session file path")
    parser_list_role_subjects.add_argument("role", help="Role name")

    # Command `rep_list_subject_roles`
    parser_list_subject_roles = subparsers.add_parser("rep_list_subject_roles", help="List roles of a subject")
    parser_list_subject_roles.add_argument("session_file", help="Session file path")
    parser_list_subject_roles.add_argument("username", help="Subject username")

    # Command `rep_list_role_permissions`
    parser_list_role_permissions = subparsers.add_parser("rep_list_role_permissions", help="List permissions in a role")
    parser_list_role_permissions.add_argument("session_file", help="Session file path")
    parser_list_role_permissions.add_argument("role", help="Role name")

    # Command `rep_list_permission_roles`
    parser_list_permission_roles = subparsers.add_parser("rep_list_permission_roles", help="List roles with a permission")
    parser_list_permission_roles.add_argument("session_file", help="Session file path")
    parser_list_permission_roles.add_argument("permission", help="Permission name")

    args = parser.parse_args()

    # Executes the correct function based on the command
    if args.command == "rep_list_subjects":
        return list_subjects(args.session_file, args.username)
    elif args.command == "rep_list_docs":
        return list_docs(args.session_file, args.username, args.date, args.filter)
    elif args.command == "rep_assume_role":
        return assume_role(args.session_file, args.role)
    elif args.command == "rep_drop_role":
        return drop_role(args.session_file, args.role)
    elif args.command == "rep_list_roles":
        return list_roles(args.session_file)
    elif args.command == "rep_list_role_subjects":
        return list_role_subjects(args.session_file, args.role)
    elif args.command == "rep_list_subject_roles":
        return list_subject_roles(args.session_file, args.username)
    elif args.command == "rep_list_role_permissions":
        return list_role_permissions(args.session_file, args.role)
    elif args.command == "rep_list_permission_roles":
        return list_permission_roles(args.session_file, args.permission)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    exit(main())
