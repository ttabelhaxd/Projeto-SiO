from functools import wraps
from flask import Blueprint, request, jsonify, current_app
from models import Subject, Role, Document, Session, OrganizationSubject, SubjectRole
from init_db import db
from datetime import datetime, timedelta, timezone
from routes.error_handler import handle_error
import json, base64, traceback
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

authenticated_bp = Blueprint("authenticated", __name__)

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
        decoded_data = [base64.b64decode(chunk) for chunk in encrypted_data]
        print(f"Decoded Data: {decoded_data}")
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
        print(f"Decrypt error: {e}")
        traceback.print_exc()
        return None

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


def requires_session():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            session, error_response = verify_session()
            if error_response:
                return jsonify(error_response[0]), error_response[1]

            # Adiciona sessão nos argumentos
            kwargs["session"] = session
            return func(*args, **kwargs)

        return wrapper
    return decorator


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


# second delivery
@authenticated_bp.route("/session/assume_role", methods=["POST"])
@requires_session()
def assume_session_role(session):
    try:
        timestamp = request.headers.get("Timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])

        role_name = data.get("role")
        if not role_name:
            return handle_error("Role name is required", 400)

        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return handle_error("Role not found in your organization", 404)

        subject_role = SubjectRole.query.filter_by(subject_id=session.subject_id, role_id=role.id).first()
        if not subject_role:
            return handle_error("You do not have this role", 403)

        if role not in session.roles:
            session.roles.append(role)
            db.session.commit()

        return jsonify({"message": f"Role {role_name} assumed successfully"}), 200

    except Exception as e:
        return handle_error(f"Error in assume_session_role: {str(e)}", 500)

# second delivery
@authenticated_bp.route("/session/release_role", methods=["POST"])
@requires_session()
def release_session_role(session):
    try:
        timestamp = request.headers.get("Timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        encrypted_data = request.json
        data = decrypt_data(encrypted_data, current_app.config["PRIVATE_KEY"])
        
        role_name = data.get("role")
        if not role_name:
            return handle_error("Role name is required", 400)

        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return handle_error("Role not found in your organization", 404)

        if role.name == "manager":
            subject_count = SubjectRole.query.filter_by(role_id=role.id).count()
            if subject_count <= 1:
                return handle_error(
                    "Cannot release the 'manager' role. At least one subject must remain associated with it.",
                    403
                )

        subject_role = SubjectRole.query.filter_by(subject_id=session.subject_id, role_id=role.id).first()
        if not subject_role:
            return handle_error("Role not assumed in this session", 403)

        db.session.delete(subject_role)
        db.session.commit()

        remaining_roles = SubjectRole.query.filter_by(subject_id=session.subject_id).all()
        if not remaining_roles:
            guest_role = Role.query.filter_by(name="guest", organization_id=session.organization_id).first()
            if guest_role:
                new_assignment = SubjectRole(subject_id=session.subject_id, role_id=guest_role.id)
                db.session.add(new_assignment)
                db.session.commit()
                return jsonify({
                    "message": f"Role '{role_name}' released successfully. 'guest' role assumed automatically."
                }), 200
            else:
                return handle_error("Guest role not found. Contact admin.", 500)

        return jsonify({"message": f"Role '{role_name}' released successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return handle_error(f"Error in release_session_role: {str(e)}", 500)

# second delivery
@authenticated_bp.route("/session/list_roles", methods=["GET"])
@requires_session()
def list_session_roles(session):
    try:
        timestamp = request.headers.get("Timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        roles = session.roles
        if not roles:
            return jsonify({"message": "No roles assumed in this session"}), 200

        roles_list = [{"id": role.id, "name": role.name} for role in roles]
        
        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(roles_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_session_roles: {str(e)}", 500)

# first delivery
@authenticated_bp.route("/subjects", methods=["GET"])
@requires_session()
def list_subjects(session):
    try:
        timestamp = request.headers.get("Timestamp")
        is_valid, message = validate_timestamp(timestamp)
        if not is_valid:
            return handle_error(message, 400)

        assoc_query = OrganizationSubject.query.filter_by(organization_id=session.organization_id)
        subjects = [assoc.subject for assoc in assoc_query]

        username = request.args.get("username")
        if username:
            subjects = [s for s in subjects if s.username == username]

        if not subjects:
            message = f"No subjects found with username '{username}'" if username else "No subjects found in the organization"
            return jsonify({"message": message}), 404

        subject_list = [
            {
                "username": subject.username,
                "full_name": subject.full_name,
                "email": subject.email,
                "status": subject.status,
            }
            for subject in subjects
        ]

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(subject_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_subjects: {str(e)}", 500)

# second delivery
@authenticated_bp.route("/roles", methods=["GET"])
@requires_session()
def list_roles(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)
        
        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        roles = Role.query.filter_by(organization_id=session.organization_id).all()
        if not roles:
            return jsonify({"message": "No roles found in your organization"}), 200

        roles_list = []
        for role in roles:
            subjects = [
                {"username": subject_role.subject.username}
                for subject_role in role.subjects
            ]
            roles_list.append({
                "name": role.name,
                "status": role.status,
                "subjects": subjects,
            })

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(roles_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_roles: {str(e)}", 500)


# second delivery
@authenticated_bp.route("/roles/subjects", methods=["GET"])
@requires_session()
def list_subjects_in_role(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)
        
        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        encrypted_data = request.args.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data in request", 400)

        decrypted_data = decrypt_data([encrypted_data], current_app.config["PRIVATE_KEY"])
        role_name = decrypted_data.get("role_name")
        if not role_name:
            return handle_error("Decryption failed or role_name missing", 400)


        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()
        if not role:
            return handle_error("Role not found in your organization", 404)

        subjects = [subject_role.subject for subject_role in role.subjects]
        if not subjects:
            return jsonify({"message": f"No subjects found in role '{role.name}'"}), 200

        subject_list = [
            {
                "username": subject.username,
                "full_name": subject.full_name,
                "email": subject.email,
                "status": subject.status,
            }
            for subject in subjects
        ]

        data = {
            "role_name": role.name,
            "status": role.status,
            "subjects": subject_list
        }

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(data, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_subjects_in_role: {str(e)}", 500)


# second delivery
@authenticated_bp.route("/subjects/roles", methods=["GET"])
@requires_session()
def list_roles_of_subject(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)
        
        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        encrypted_username = request.args.get("encrypted_username")
        if not encrypted_username:
            return handle_error("Missing encrypted username in request", 400)

        print(f"Encrypted username received: {encrypted_username}")
        
        decrypted_data = decrypt_data([encrypted_username], current_app.config["PRIVATE_KEY"])

        print(f"Decrypted data: {decrypted_data}")

        username = decrypted_data.get("username")

        if not username:
            return handle_error("Decryption failed or username missing", 400)

        subject = Subject.query.filter_by(username=username).first()
        if not subject or subject not in [assoc.subject for assoc in session.organization.subjects_assoc]:
            return handle_error("Subject not found in your organization", 404)

        roles = [subject_role.role for subject_role in subject.roles]
        if not roles:
            return jsonify([]), 200

        roles_list = [{"id": role.id, "name": role.name} for role in roles]
        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(roles_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_roles_of_subject: {str(e)}", 500)


# second delivery
@authenticated_bp.route("/roles/permissions", methods=["GET"])
@requires_session()
def list_permissions_in_role(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)

        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        encrypted_data = request.args.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data in request", 400)

        decrypted_data = decrypt_data([encrypted_data], current_app.config["PRIVATE_KEY"])
        role_name = decrypted_data.get("role_name")

        if not role_name:
            return handle_error("Decryption failed or role_name missing", 400)

        role = Role.query.filter_by(name=role_name, organization_id=session.organization_id).first()

        if not role:
            return jsonify({"error": "Role not found in your organization"}), 404

        permissions = json.loads(role.permissions) if role.permissions else []

        if not permissions:
            return jsonify([]), 200

        permissions_list = [{"type": permission} for permission in permissions]
        
        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(permissions_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_permissions_in_role: {str(e)}", 500)

# second delivery
@authenticated_bp.route("/permissions/roles", methods=["GET"])
@requires_session()
def list_roles_with_permission(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)

        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        encrypted_data = request.args.get("encrypted_data")
        if not encrypted_data:
            return handle_error("Missing encrypted data in request", 400)

        decrypted_data = decrypt_data([encrypted_data], current_app.config["PRIVATE_KEY"])
        permission = decrypted_data.get("permission")

        valid_permissions = [
            "DOC_READ", "DOC_DELETE", "DOC_ACL",
            "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
            "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
        ]

        if permission not in valid_permissions:
            return handle_error("Invalid permission type", 400)

        roles = Role.query.filter(
            Role.organization_id == session.organization_id,
            Role.permissions.like(f"%{permission}%")
        ).all()

        if not roles:
            return jsonify({"message": "No roles found with this permission"}), 200

        roles_list = [{"name": r.name} for r in roles]

        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(roles_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200

    except Exception as e:
        return handle_error(f"Error in list_roles_with_permission: {str(e)}", 500)

# first delivery
@authenticated_bp.route("/documents", methods=["GET"])
@requires_session()
def list_documents(session):
    try:
        request_timestamp = request.headers.get("Timestamp")
        if not request_timestamp:
            return handle_error("Missing Timestamp in request", 400)

        is_valid, error_message = validate_timestamp(request_timestamp)
        if not is_valid:
            return handle_error(error_message, 400)

        query = Document.query.filter_by(organization_id=session.organization_id)
        
        username = request.args.get("username")
        if username:
            query = query.join(Subject).filter(Subject.username == username)
        
        date_filter = request.args.get("filter")
        date_value = request.args.get("date")
        if date_filter and date_value:
            try:
                date_obj = datetime.strptime(date_value, "%d-%m-%Y")
                if date_filter == "nt":  # newer than
                    query = query.filter(Document.create_date > date_obj)
                elif date_filter == "ot":  # older than
                    query = query.filter(Document.create_date < date_obj)
                elif date_filter == "et":  # equal to
                    query = query.filter(Document.create_date == date_obj)
                else:
                    return handle_error("Invalid filter type. Use 'nt', 'ot', or 'et'", 400)
            except ValueError:
                return handle_error("Invalid date format. Use DD-MM-YYYY", 400)
        
        documents = query.all()
        if not documents:
            return jsonify({"message": "No documents found"}), 200
        
        document_list = [
            {
                "name": doc.name,
                "file_handle": doc.file_handle,
                "create_date": doc.create_date.isoformat(),
                "creator": doc.creator.username if doc.creator else "Unknown"
            }
            for doc in documents
        ]
        
        subject = Subject.query.get(session.subject_id)
        encrypted_data = encrypt_response(document_list, subject.public_key)
        key_path = subject.public_key_path

        return jsonify({
            "encrypted_data": encrypted_data,
            "key_path": key_path
        }), 200
    
    except Exception as e:
        print(f"Error in list_documents: {str(e)}")
        return handle_error("Internal server error", 500)


