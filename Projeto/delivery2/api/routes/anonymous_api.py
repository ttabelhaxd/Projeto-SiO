from flask import Blueprint, request, jsonify, current_app
import uuid, traceback, os, json, base64
from datetime import datetime, timedelta, timezone
from init_db import db
from models import Organization, Subject, Role, Document, Session, OrganizationSubject, SubjectRole
from werkzeug.security import generate_password_hash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from routes.error_handler import handle_error

anonymous_bp = Blueprint("anonymous", __name__)

def decrypt_data(encrypted_data, private_key):
    try:
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
        return None

# ----------------------------------------------------------------------------------------
# Funções auxiliares para desencriptar arquivos e verificar integridade


def decrypt_file_aux(encrypted_file_path, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(encrypted_file_path, "rb") as infile, open(
        decrypted_file_path, "wb"
    ) as outfile:
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
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    hmac.verify(bytes.fromhex(expected_mac))


# ----------------------------------------------------------------------------------------

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


@anonymous_bp.route("/organization/create", methods=["POST"])
def create_organization():
    try:
        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        name = data.get("organization")
        username = data.get("username")
        full_name = data.get("name")
        email = data.get("email")
        public_key = data.get("public_key")
        public_key_path = data.get("public_key_path")
        password = data.get("password")

        if not all([name, username, full_name, email, public_key, password]):
            return handle_error("Missing fields", 400)

        if Organization.query.filter_by(name=name).first():
            return handle_error(f"Organization '{name}' already exists", 409)

        if Subject.query.filter_by(username=username).first():
            return handle_error(f"Username '{username}' already taken", 409)

        password_hash = generate_password_hash(password)

        creator = Subject(
            username=username,
            full_name=full_name,
            email=email,
            public_key=public_key,
            public_key_path=public_key_path,
            status="active",
            password_hash=password_hash,
        )
        db.session.add(creator)
        db.session.flush()

        new_org = Organization(name=name, creator_id=creator.id)
        db.session.add(new_org)
        db.session.flush()

        organization_subject = OrganizationSubject(
            organization_id=new_org.id,
            subject_id=creator.id,
        )
        db.session.add(organization_subject)

        manager_permissions = [
            "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP",
            "DOC_NEW", "DOC_READ", "DOC_DELETE", "DOC_ACL",
            "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
        ]
        
        manager_role = Role(
            name="manager",
            permissions=json.dumps(manager_permissions),
            organization_id=new_org.id,
        )
        db.session.add(manager_role)
        db.session.flush()

        manager_subject_role = SubjectRole(
            subject_id=creator.id,
            role_id=manager_role.id
        )
        db.session.add(manager_subject_role)
        db.session.commit()

        print(f"Creator '{username}' associated with 'manager' role")

        return (
            jsonify(
                {
                    "message": f"Organization '{name}' created successfully",
                    "organization_id": new_org.id,
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return handle_error("Internal server error", 500, str(e))


# List Organizations
@anonymous_bp.route("/organizations", methods=["GET"])
def list_organizations():
    try:
        encrypted_data = request.args.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data in request", 400)

        decrypted_data = decrypt_data([encrypted_data], current_app.config["PRIVATE_KEY"])
        if not decrypted_data:
            return handle_error("Decryption failed", 400)

        timestamp = decrypted_data.get("timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        organizations = Organization.query.all()
        organization_list = [
            {
                "id": org.id,
                "name": org.name,
                "creator_name": Subject.query.get(org.creator_id).full_name if org.creator_id else "Unknown",
                "create_date": org.create_date.strftime("%d-%m-%Y %H:%M:%S"),
            }
            for org in organizations
        ]
        return jsonify(organization_list), 200
    except Exception as e:
        traceback.print_exc()
        return handle_error("Internal server error", 500, str(e))


# Create Session
@anonymous_bp.route("/session/create", methods=["POST"])
def create_session():
    try:
        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        timestamp = data.get("timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        organization_name = data.get("organization")
        username = data.get("username")
        password = data.get("password")

        if not all([organization_name, username, password]):
            return handle_error("Missing fields", 400)

        organization = Organization.query.filter_by(name=organization_name).first()
        if not organization:
            return handle_error("Organization not found", 404)

        subject = Subject.query.filter_by(username=username, status="active").first()
        if not subject:
            return handle_error("User not found or inactive", 404)

        if not subject.check_password(password):
            return handle_error("Invalid credentials", 401)

        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=1)

        new_session = Session(
            session_id=session_id,
            subject_id=subject.id,
            organization_id=organization.id,
            expires_at=expires_at,
        )
        db.session.add(new_session)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Session created successfully",
                    "session_id": session_id,
                    "expires_at": expires_at.isoformat(),
                }
            ),
            201,
        )
    except Exception as e:
        traceback.print_exc()
        return handle_error("Internal server error", 500, str(e))


@anonymous_bp.route("/file/download", methods=["GET"])
def download_file():
    try:
        encrypted_data = request.args.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data in request", 400)

        decrypted_data = decrypt_data([encrypted_data], current_app.config["PRIVATE_KEY"])
        if not decrypted_data:
            return handle_error("Decryption failed", 400)

        timestamp = decrypted_data.get("timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        file_handle = decrypted_data.get("file_handle")
        if not file_handle:
            return handle_error("Missing file_handle in request", 400)

        document = Document.query.filter_by(file_handle=file_handle).first()
        if not document:
            return handle_error("File not found", 404)

        encrypted_file_path = document.file_path
        if not os.path.exists(encrypted_file_path):
            return handle_error("Encrypted file not found on server", 404)

        metadata = json.loads(document.file_metadata)
        expected_mac = metadata["alg"]["integrity_control"]["MAC"]

        response_data = {
            "file_content": base64.b64encode(open(encrypted_file_path, "rb").read()).decode("utf-8"),
            "metadata": {
                "iv": metadata["alg"]["encryption"]["iv"],
                "aes_key": metadata["aes_key"],
                "expected_mac": expected_mac
            }
        }

        return jsonify(response_data), 200
    except Exception as e:
        traceback.print_exc()
        return handle_error("Internal server error", 500, str(e))
