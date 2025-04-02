import os, json, base64, traceback
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.security import generate_password_hash
from models import Subject, Role, Document, ACL, Session, OrganizationSubject, SubjectRole
from init_db import db
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone
from tempfile import NamedTemporaryFile
from routes.error_handler import handle_error
from functools import wraps

authorized_bp = Blueprint("authorized", __name__)

# ------------------------------------------------------------------------------------
# encrypt functions


# Generate a random AES key
def generate_aes_key(key_size=32):  # 32 bytes = 256 bits
    return os.urandom(key_size)


# Encrypt the file using AES (CBC mode with PKCS7 padding)
def encrypt_file(file_path, aes_key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    encryptor = cipher.encryptor()

    encrypted_file_path = f"{file_path}.enc"
    with open(file_path, "rb") as infile, open(encrypted_file_path, "wb") as outfile:
        outfile.write(iv)  # Escreve o IV no início do arquivo
        while chunk := infile.read(4096):
            padded_data = padder.update(chunk)
            outfile.write(encryptor.update(padded_data))
        outfile.write(encryptor.update(padder.finalize()) + encryptor.finalize())

    return encrypted_file_path, iv


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


# Generate HMAC for integrity control
def generate_integrity_control(aes_key, encrypted_file_path):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    with open(encrypted_file_path, "rb") as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    mac = hmac.finalize()  # Retorna diretamente o valor em bytes
    print(f"HMAC (Upload): {mac.hex()}")
    return mac  # Retorna bytes em vez de string hexadecimal



# Generate metadata and save as JSON
def generate_metadata(file_handle, iv, integrity_control, aes_key):
    if (
        not isinstance(iv, bytes)
        or not isinstance(aes_key, bytes)
        or not isinstance(file_handle, bytes)
    ):
        raise ValueError("iv, aes_key, and file_handle must be bytes")
    if not isinstance(integrity_control, bytes):
        raise ValueError("integrity_control must be bytes")

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
    return metadata


# ------------------------------------------------------------------------------------

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_response(data, public_key_content):
    """Encripta a resposta usando o conteúdo da chave pública."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_content.encode("utf-8"),
            backend=default_backend()
        )
        json_data = json.dumps(data).encode("utf-8")
        max_chunk_size = public_key.key_size // 8 - 66

        chunks = [
            json_data[i : i + max_chunk_size]
            for i in range(0, len(json_data), max_chunk_size)
        ]

        encrypted_chunks = [
            base64.b64encode(public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )).decode("utf-8")
            for chunk in chunks
        ]
        return encrypted_chunks
    except Exception as e:
        raise ValueError(f"Error encrypting response: {e}")

def decrypt_data(encrypted_data, private_key):
    try:
        if not isinstance(encrypted_data, list):
            raise ValueError("Invalid encrypted data format: expected list")
        
        decoded_data = [base64.b64decode(chunk) for chunk in encrypted_data]
        decrypted_data = b"".join(
            [
                private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                for chunk in decoded_data
            ]
        )

        return json.loads(decrypted_data)
    except Exception as e:
        traceback.print_exc()
        return {}

def verify_session():
    try:
        session_id = request.headers.get("Authorization")
        if not session_id:
            return None, handle_error("Missing session ID in headers", 401)

        if session_id.startswith("Bearer "):
            session_id = session_id[7:]

        session = Session.query.filter_by(session_id=session_id).first()
        if not session:
            return None, handle_error("Session not found", 401)
        if session.expires_at < datetime.utcnow():
            return None, handle_error("Session expired", 401)

        return session, None
    except Exception as e:
        return None, handle_error("Internal server error", 500, str(e))


def requires_permission(*permissions):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session, error_response = verify_session()
            if error_response:
                return jsonify(error_response), error_response[1]

            if not any(has_permission(session, perm) for perm in permissions):
                return handle_error("Permission denied", 403)

            kwargs["session"] = session
            return func(*args, **kwargs)

        return wrapper
    return decorator



def has_document_permission(session, document_id, required_permission):
    acl_entries = ACL.query.filter_by(document_id=document_id).all()
    for entry in acl_entries:
        if entry.role_id in [role.id for role in session.roles]:
            permissions = json.loads(entry.permissions)
            if required_permission in permissions:
                return True
    return False


def has_permission(session, required_permission):
    """Verifica se a sessão possui a permissão necessária através das roles atribuídas."""
    roles = session.roles
    for role in roles:
        permissions = json.loads(role.permissions)
        if required_permission in permissions:
            return True
    return False

def validate_timestamp(timestamp):
    try:
        request_time = datetime.fromisoformat(timestamp)
        current_time = datetime.now(timezone.utc)
        max_time_difference = timedelta(seconds=1)

        if abs(current_time - request_time) > max_time_difference:
            raise ValueError("Timestamp is outside the acceptable range.")
    except Exception as e:
        return False, f"Invalid timestamp: {str(e)}"
    return True, "Valid timestamp"

# first delivery
@authorized_bp.route("/subjects", methods=["POST"])
@requires_permission("SUBJECT_NEW")
def add_subject(session):
    try:
        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        username = data.get("username")
        name = data.get("name")
        email = data.get("email")
        public_key = data.get("public_key")
        public_key_path = data.get("public_key_path")
        password = data.get("password")

        if not all([username, name, email, public_key, password]):
            return handle_error("Missing fields", 400)

        existing_role = Role.query.filter_by(name=username, organization_id=session.organization_id).first()
        if existing_role:
            return handle_error(f"Username '{username}' conflicts with an existing role name. Please choose a different username.", 409)

        PERMISSIONS = [
            "DOC_READ", "DOC_DELETE", "DOC_ACL",
            "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
            "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
        ]
        if username in PERMISSIONS:
            return handle_error(f"Username '{username}' conflicts with a system permission name. Please choose a different username.", 409)

        if Subject.query.filter_by(username=username).first():
            return handle_error(f"Subject '{username}' already exists", 409)

        password_hash = generate_password_hash(password)

        new_subject = Subject(
            username=username,
            full_name=name,
            email=email,
            public_key=public_key,
            public_key_path=public_key_path,
            status="active",
            password_hash=password_hash,
        )
        db.session.add(new_subject)
        db.session.flush()

        organization_subject = OrganizationSubject(
            organization_id=session.organization_id,
            subject_id=new_subject.id
        )
        db.session.add(organization_subject)

        guest_role = Role.query.filter_by(
            name="guest", organization_id=session.organization_id
        ).first()

        if not guest_role:
            guest_role = Role(
                name="guest",
                permissions=json.dumps(["DOC_READ"]),
                organization_id=session.organization_id,
            )
            db.session.add(guest_role)
            db.session.flush()

        subject_role = SubjectRole(subject_id=new_subject.id, role_id=guest_role.id)
        db.session.add(subject_role)
        db.session.commit()

        return jsonify({"message": f"Subject '{username}' added successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return handle_error("Internal server error", 500, str(e))


# first delivery
@authorized_bp.route("/subjects/status", methods=["PATCH"])
@requires_permission("SUBJECT_UP", "SUBJECT_DOWN")
def change_subject_status(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        username = data.get("username")
        new_status = data.get("status")

        if not all([username, new_status]):
            return handle_error("Missing fields", 400)

        if new_status == "suspended" and not has_permission(session, "SUBJECT_DOWN"):
            return handle_error("Permission denied", 403)
        if new_status == "active" and not has_permission(session, "SUBJECT_UP"):
            return handle_error("Permission denied", 403)

        subject = Subject.query.filter_by(username=username).first()
        if not subject:
            return handle_error("Subject not found", 404)

        subject.status = new_status
        db.session.commit()

        return jsonify({"message": f"Subject '{username}' status changed to '{new_status}'"}), 200

    except Exception as e:
        return handle_error("Internal server error", 500, str(e))


# second delivery
@authorized_bp.route("/roles", methods=["POST"])
@requires_permission("ROLE_NEW")
def add_role(session):
    try:
        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        role_name = data.get("role_name")
        permissions = data.get("permissions", [])

        if not role_name:
            return handle_error("Role name is required", 400)

        existing_role = Role.query.filter_by(
            name=role_name, organization_id=session.organization_id
        ).first()
        if existing_role:
            return handle_error(f"Role '{role_name}' already exists", 409)

        new_role = Role(
            name=role_name,
            permissions=json.dumps(permissions),
            organization_id=session.organization_id,
            status="active",
        )
        db.session.add(new_role)
        db.session.commit()

        return jsonify({"message": f"Role '{role_name}' added successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return handle_error(f"Internal server error in add_role: {str(e)}", 500)


# second delivery
@authorized_bp.route("/roles/status", methods=["PATCH"])
@requires_permission("ROLE_UP", "ROLE_DOWN")
def change_role_status(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        role_name = data.get("role_name")
        new_status = data.get("status")

        if not all([role_name, new_status]) or new_status not in ["active", "suspended"]:
            return handle_error("Invalid or missing fields. Use 'role_name' and 'status' as 'active' or 'suspended'", 400)

        role = Role.query.filter(
            Role.name == role_name,
            Role.organization_id == session.organization_id
        ).first()

        if not role:
            return handle_error("Role not found", 404)

        if role.name == "manager" and new_status == "suspended":
            return handle_error("The 'manager' role cannot be suspended", 403)

        role.status = new_status
        db.session.commit()

        return jsonify({"message": f"Role '{role.name}' status changed to '{new_status}'"}), 200

    except Exception as e:
        return handle_error(f"Internal server error in change_role_status: {str(e)}", 500)


# second delivery
@authorized_bp.route("/roles/subjects/manage", methods=["POST", "DELETE"])
@requires_permission("ROLE_MOD")
def manage_subjects_in_role(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        role_id = data.get("role_id")
        subject_id = data.get("subject_id")

        if not all([role_id, subject_id]):
            return handle_error("Missing fields: 'role_id' and 'subject_id' are required", 400)

        role = Role.query.filter_by(
            id=role_id, organization_id=session.organization_id
        ).first()
        if not role:
            return handle_error("Role not found", 404)

        if request.method == "POST":
            organization_subject = OrganizationSubject.query.filter_by(
                organization_id=session.organization_id, subject_id=subject_id
            ).first()
            if not organization_subject:
                return handle_error("Subject not found in organization", 404)

            role.subjects.append(organization_subject)
            db.session.commit()
            return jsonify({"message": f"Subject added to role '{role.name}'"}), 200

        elif request.method == "DELETE":
            role.subjects = [s for s in role.subjects if s.subject_id != subject_id]
            db.session.commit()
            return jsonify({"message": f"Subject removed from role '{role.name}'"}), 200

    except Exception as e:
        return handle_error("Internal server error", 500, str(e))


# second delivery
@authorized_bp.route("/roles/manage", methods=["POST"])
@requires_permission("ROLE_MOD")
def manage_role_permissions_or_assignments(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        role_name = data.get("role_name")
        permission = data.get("permission")
        username = data.get("username")

        if not role_name:
            return handle_error("Missing 'role_name'", 400)

        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return handle_error("Role not found", 404)

        if permission:
            current_permissions = json.loads(role.permissions)
            if permission in current_permissions:
                return handle_error("Permission already exists", 409)

            current_permissions.append(permission)
            role.permissions = json.dumps(current_permissions)
            db.session.commit()
            return jsonify({"message": f"Permission '{permission}' added to role '{role_name}'"}), 200

        elif username:
            subject = Subject.query.filter_by(username=username).first()
            if not subject:
                return handle_error(f"User '{username}' not found", 404)

            existing_assignment = SubjectRole.query.filter_by(subject_id=subject.id, role_id=role.id).first()
            if existing_assignment:
                return handle_error(f"User '{username}' already has the role '{role_name}'", 409)

            new_assignment = SubjectRole(subject_id=subject.id, role_id=role.id)
            db.session.add(new_assignment)
            db.session.commit()

            return jsonify({"message": f"Role '{role_name}' assigned to user '{username}'"}), 200

        return handle_error("Either 'permission' or 'username' must be provided", 400)

    except Exception as e:
        db.session.rollback()
        return handle_error(f"Internal server error in manage_role: {str(e)}", 500)
    

# second delivery
@authorized_bp.route("/roles/manage", methods=["DELETE"])
@requires_permission("ROLE_MOD")
def manage_role_permissions_or_assignments_remove(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        role_name = data.get("role_name")
        permission = data.get("permission")
        username = data.get("username")

        if not role_name:
            return handle_error("Missing 'role_name'", 400)

        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return handle_error("Role not found", 404)

        if permission:
            current_permissions = json.loads(role.permissions)
            if permission not in current_permissions:
                return handle_error("Permission not found in role", 404)

            current_permissions.remove(permission)
            role.permissions = json.dumps(current_permissions)
            db.session.commit()
            return jsonify({"message": f"Permission '{permission}' removed from role '{role_name}'"}), 200

        elif username:
            subject = Subject.query.filter_by(username=username).first()
            if not subject:
                return handle_error(f"User '{username}' not found", 404)

            assignment = SubjectRole.query.filter_by(subject_id=subject.id, role_id=role.id).first()
            if not assignment:
                return handle_error(f"User '{username}' does not have the role '{role_name}'", 404)

            db.session.delete(assignment)
            db.session.commit()
            return jsonify({"message": f"Role '{role_name}' removed from user '{username}'"}), 200

        return handle_error("Either 'permission' or 'username' must be provided", 400)

    except Exception as e:
        db.session.rollback()
        return handle_error(f"Internal server error in manage_role_remove: {str(e)}", 500)


# first delivery
@authorized_bp.route("/documents", methods=["POST"])
@requires_permission("DOC_NEW")
def upload_document(session):
    try:
        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        document_name = data.get("document_name")
        file_content_encoded = data.get("file_content")
        if not all([document_name, file_content_encoded]):
            return handle_error("Missing fields", 400)

        file_content = base64.b64decode(file_content_encoded)
        encoded_content = base64.b64encode(file_content).decode("utf-8")
        if file_content_encoded != encoded_content:
            raise ValueError("Invalid base64 encoding")
        
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name

        aes_key = generate_aes_key()
        encrypted_file_path, iv = encrypt_file(temp_file_path, aes_key)

        integrity_control = generate_integrity_control(aes_key, encrypted_file_path)
        file_handle = compute_file_handle(temp_file_path)

        existing_doc = Document.query.filter_by(file_handle=file_handle.hex()).first()
        if existing_doc:
            os.remove(temp_file_path)
            return handle_error("Document with the same content already exists", 409)

        metadata = generate_metadata(file_handle, iv, integrity_control, aes_key)
        metadata_json = json.dumps(metadata)

        new_doc = Document(
            name=document_name,
            file_handle=file_handle.hex(),
            file_path=encrypted_file_path,
            file_metadata=metadata_json,
            creator_id=session.subject_id,
            organization_id=session.organization_id,
        )
        db.session.add(new_doc)
        db.session.commit()

        os.remove(temp_file_path)

        data = {
                "message": f"Document '{document_name}' uploaded successfully",
                "file_handle": file_handle.hex(),
                "file_path": encrypted_file_path,
        }

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(data, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 201
    
    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return handle_error("Internal server error", 500, str(e))


# first delivery
@authorized_bp.route("/documents/metadata", methods=["GET"])
@requires_permission("DOC_READ")
def download_document_metadata(session):
    data_encrypted = request.json.get("encrypted_data")
    if not data_encrypted:
        return handle_error("Missing encrypted data", 400)

    document_data = decrypt_data(data_encrypted, current_app.config["PRIVATE_KEY"])

    timestamp = document_data.get("timestamp")
    if not timestamp or not validate_timestamp(timestamp):
        return handle_error("Invalid or missing timestamp", 400)
    
    document_name = document_data.get("document_name")

    document = Document.query.filter_by(
        name=document_name, organization_id=session.organization_id
    ).first()
    if not document:
        return jsonify({"error": "Document not found"}), 404

    metadata = json.loads(document.file_metadata)

    # converter bytes para hex
    metadata["file_handle"] = (
        metadata["file_handle"]
        if isinstance(metadata["file_handle"], str)
        else bytes.fromhex(metadata["file_handle"]).hex()
    )
    metadata["alg"]["encryption"]["iv"] = (
        metadata["alg"]["encryption"]["iv"]
        if isinstance(metadata["alg"]["encryption"]["iv"], str)
        else bytes.fromhex(metadata["alg"]["encryption"]["iv"]).hex()
    )
    metadata["alg"]["integrity_control"]["MAC"] = (
        metadata["alg"]["integrity_control"]["MAC"]
        if isinstance(metadata["alg"]["integrity_control"]["MAC"], str)
        else bytes.fromhex(metadata["alg"]["integrity_control"]["MAC"]).hex()
    )
    metadata["aes_key"] = (
        metadata["aes_key"]
        if isinstance(metadata["aes_key"], str)
        else bytes.fromhex(metadata["aes_key"]).hex()
    )

    subject = Subject.query.get(session.subject_id)
    encrypted_data = encrypt_response(metadata, subject.public_key)
    key_path = subject.public_key_path

    return jsonify({
        "encrypted_data": encrypted_data,
        "key_path": key_path
    }), 200


# first delivery
@authorized_bp.route("/documents/content", methods=["GET"])
@requires_permission("DOC_READ")
def download_document_content(session):
    data_encrypted = request.json.get("encrypted_data")
    if not data_encrypted:
        return handle_error("Missing encrypted data", 400)

    document_data = decrypt_data(data_encrypted, current_app.config["PRIVATE_KEY"])
    document_name = document_data.get("document_name")

    timestamp = document_data.get("timestamp")
    if not timestamp or not validate_timestamp(timestamp):
        return handle_error("Invalid or missing timestamp", 400)

    document = Document.query.filter_by(
        name=document_name, organization_id=session.organization_id
    ).first()
    if not document:
        return jsonify({"error": "Document not found"}), 404

    try:
        encrypted_file_path = document.file_path
        if not os.path.exists(encrypted_file_path):
            return jsonify({"error": "Encrypted file not found on server"}), 404
        
        with open(encrypted_file_path, "rb") as f:
            file_content_base64 = base64.b64encode(f.read()).decode("utf-8")

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response({"file_content": file_content_base64}, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        print(f"Error in download_document_content: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# first delivery
@authorized_bp.route("/documents/delete", methods=["DELETE"])
@requires_permission("DOC_DELETE")
def delete_document(session):
    try:
        data_encrypted = request.json.get("encrypted_data")
        if not data_encrypted:
            return handle_error("Missing encrypted data", 400)

        document_data = decrypt_data(data_encrypted, current_app.config["PRIVATE_KEY"])
        timestamp = document_data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        document_name = document_data.get("document_name")
        document_name = document_data.get("document_name")
        if not document_name:
            return handle_error("Missing document name", 400)

        document = Document.query.filter_by(
            name=document_name, organization_id=session.organization_id
        ).first()

        if not document:
            return handle_error("Document not found", 404)

        db.session.delete(document)
        db.session.commit()

        return jsonify({"message": f"Document '{document_name}' deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return handle_error("Internal server error", 500, str(e))

# second delivery
@authorized_bp.route("/documents/acl", methods=["PATCH"])
@requires_permission("DOC_ACL")
def manage_document_acl(session):
    try:
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data", 400)

        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        if not timestamp or not validate_timestamp(timestamp):
            return handle_error("Invalid or missing timestamp", 400)

        document_name = data.get("document_name")
        document_name = data.get("document_name")
        role_id = data.get("role_id")
        permission = data.get("permission")
        action = data.get("action")

        if not all([document_name, role_id, permission, action]):
            return handle_error("Missing required fields", 400)

        if action not in ["+", "-"]:
            return handle_error("Invalid action. Use '+' to add or '-' to remove.", 400)

        document = Document.query.filter_by(
            name=document_name, organization_id=session.organization_id
        ).first()
        if not document:
            return handle_error("Document not found", 404)

        acl_entry = ACL.query.filter_by(document_id=document.id, role_id=role_id).first()

        if action == "+":
            if acl_entry:
                permissions = json.loads(acl_entry.permissions)
                if permission in permissions:
                    return handle_error("Permission already exists", 409)
                permissions.append(permission)
                acl_entry.permissions = json.dumps(permissions)
            else:
                acl_entry = ACL(
                    document_id=document.id,
                    role_id=role_id,
                    permissions=json.dumps([permission]),
                )
                db.session.add(acl_entry)

            db.session.commit()
            return jsonify({"message": f"Permission '{permission}' added to ACL"}), 200

        elif action == "-":
            if not acl_entry:
                return handle_error("Permission entry not found in ACL", 404)

            permissions = json.loads(acl_entry.permissions)
            if permission not in permissions:
                return handle_error("Permission not found in ACL", 404)

            permissions.remove(permission)
            if permissions:
                acl_entry.permissions = json.dumps(permissions)
            else:
                db.session.delete(acl_entry)

            db.session.commit()
            return jsonify({"message": f"Permission '{permission}' removed from ACL"}), 200

    except Exception as e:
        return handle_error(f"Internal server error: {str(e)}", 500)
