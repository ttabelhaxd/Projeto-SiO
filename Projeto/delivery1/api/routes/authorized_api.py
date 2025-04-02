import hashlib, secrets, string, os, json, uuid
from flask import Blueprint, request, jsonify, send_file
from werkzeug.security import generate_password_hash
from ..models import Subject, Role, Document, ACL, Session, Organization, OrganizationSubject
from ..init_db import db
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from tempfile import NamedTemporaryFile

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
    with open(file_path, 'rb') as infile, open(encrypted_file_path, 'wb') as outfile:
        outfile.write(iv)  # Store IV at the beginning of the encrypted file
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
            label=None
        )
    )
    return encrypted_key

# Compute a cryptographic hash of the file contents (file handle)
def compute_file_handle(file_path, hash_algorithm=hashes.SHA256()):
    digest = hashes.Hash(hash_algorithm, backend=default_backend())
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            digest.update(chunk)
    return digest.finalize()

# Generate HMAC for integrity control
def generate_integrity_control(aes_key, file_path):
    hmac = HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hmac.update(chunk)
    return hmac.finalize()

# Generate metadata and save as JSON
def generate_metadata(file_handle, iv, integrity_control, aes_key):
    if not isinstance(iv, bytes) or not isinstance(aes_key, bytes) or not isinstance(file_handle, bytes):
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

def verify_session():
    try:
        session_id = request.headers.get("Authorization")
        if not session_id:
            return None, {"error": "Missing session ID in headers"}

        if session_id.startswith("Bearer "):
            session_id = session_id[7:]

        session = Session.query.filter_by(session_id=session_id).first()
        if not session:
            return None, {"error": "Session not found"}
        if session.expires_at < datetime.utcnow():
            return None, {"error": "Session expired"}

        return session, None

    except Exception as e:
        print(f"Error in verify_session: {str(e)}")
        return None, {"error": "Internal server error"}

# first delivery
@authorized_bp.route("/subjects", methods=["POST"])
def add_subject():
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    try:
        data = request.json
        username = data.get("username")
        name = data.get("name")
        email = data.get("email")
        public_key = data.get("public_key")

        if not all([username, name, email, public_key]):
            return jsonify({"error": "Missing fields"}), 400

        if Subject.query.filter_by(username=username).first():
            return jsonify({"error": f"Subject '{username}' already exists"}), 409

        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        print(f"Generated password for {username}: {password}")

        new_subject = Subject(
            username=username,
            full_name=name,
            email=email,
            public_key=public_key,
            status="active",
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_subject)
        db.session.commit()
        print(f"Subject '{username}' created successfully with ID {new_subject.id}")

        organization_subject = OrganizationSubject(
            organization_id=session.organization_id,
            subject_id=new_subject.id
        )
        db.session.add(organization_subject)
        db.session.commit()
        print(f"Subject '{username}' linked to organization ID {session.organization_id}")

        return jsonify({
            "message": f"Subject '{username}' added successfully",
            "password": password
        }), 201

    except Exception as e:
        print(f"Error in add_subject: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

# first delivery
@authorized_bp.route("/subjects/<username>/status", methods=["PATCH"])
def change_subject_status(username):
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]
    
    try:
        data = request.json
        new_status = data.get("status")

        if not new_status:
            return jsonify({"error": "Missing fields"}), 400

        subject = Subject.query.filter_by(username=username).first()
        if not subject:
            return jsonify({"error": "Subject not found"}), 404

        subject.status = new_status
        db.session.commit()

        return jsonify({"message": f"Subject '{username}' status changed to '{new_status}'"}), 200
    
    except Exception as e:
        print(f"Error in change_subject_status: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    

@authorized_bp.route("/roles", methods=["POST"])
def add_role():
    #TODO Implementar lógica para adicionar um papel
    pass

@authorized_bp.route("/roles/<role_id>/status", methods=["PATCH"])
def change_role_status(role_id):
    #TODO Implementar lógica para mudar o status de um papel (suspender/ativar)
    pass

@authorized_bp.route("/roles/<role_id>/subjects", methods=["POST", "DELETE"])
def manage_subjects_in_role(role_id):
    #TODO Implementar lógica para adicionar/remover sujeitos a um papel
    pass

@authorized_bp.route("/roles/<role_id>/permissions", methods=["POST", "DELETE"])
def manage_permissions_in_role(role_id):
    #TODO Implementar lógica para adicionar/remover permissões a um papel
    pass

# first delivery
@authorized_bp.route("/documents", methods=["POST"])
def upload_document():
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    try:
        data = request.json
        document_name = data.get("document_name")
        file_content = data.get("file_content")

        if not all([document_name, file_content]):
            return jsonify({"error": "Missing fields"}), 400

        # Salvar o conteúdo do arquivo num arquivo temporário
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(file_content.encode())
            temp_file_path = temp_file.name

        aes_key = generate_aes_key()
        encrypted_file_path, iv = encrypt_file(temp_file_path, aes_key)
        file_handle = hashlib.sha256(file_content.encode()).digest()
        existing_doc = Document.query.filter_by(file_handle=file_handle.hex()).first()
        
        if existing_doc:
            return jsonify({"error": "Document with the same content already exists"}), 409

        integrity_control = generate_integrity_control(aes_key, temp_file_path)
        metadata = generate_metadata(file_handle, iv, integrity_control, aes_key)
        metadata_json = json.dumps(metadata)

        new_doc = Document(
            name=document_name,
            file_handle=file_handle.hex(),
            file_path=encrypted_file_path,
            file_metadata=metadata_json,
            creator_id=session.subject_id,
            organization_id=session.organization_id
        )
        db.session.add(new_doc)
        db.session.commit()

        # Remover o arquivo temporário
        os.remove(temp_file_path)

        return jsonify({
            "message": f"Document '{document_name}' uploaded successfully",
            "file_handle": file_handle.hex(),
            "file_path": encrypted_file_path
        }), 201

    except Exception as e:
        print(f"Error in upload_document: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

# first delivery
@authorized_bp.route("/documents/<document_name>/metadata", methods=["GET"])
def download_document_metadata(document_name):
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    document = Document.query.filter_by(name=document_name, organization_id=session.organization_id).first()
    if not document:
        return jsonify({"error": "Document not found"}), 404

    metadata = json.loads(document.file_metadata)

    # converter bytes para hex
    metadata["file_handle"] = metadata["file_handle"] if isinstance(metadata["file_handle"], str) else bytes.fromhex(metadata["file_handle"]).hex()
    metadata["alg"]["encryption"]["iv"] = metadata["alg"]["encryption"]["iv"] if isinstance(metadata["alg"]["encryption"]["iv"], str) else bytes.fromhex(metadata["alg"]["encryption"]["iv"]).hex()
    metadata["alg"]["integrity_control"]["MAC"] = metadata["alg"]["integrity_control"]["MAC"] if isinstance(metadata["alg"]["integrity_control"]["MAC"], str) else bytes.fromhex(metadata["alg"]["integrity_control"]["MAC"]).hex()
    metadata["aes_key"] = metadata["aes_key"] if isinstance(metadata["aes_key"], str) else bytes.fromhex(metadata["aes_key"]).hex()

    return jsonify(metadata), 200

# first delivery
@authorized_bp.route("/documents/<document_name>/content", methods=["GET"])
def download_document_content(document_name):
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    document = Document.query.filter_by(name=document_name, organization_id=session.organization_id).first()
    if not document:
        return jsonify({"error": "Document not found"}), 404

    try:
        encrypted_file_path = document.file_path

        if not os.path.exists(encrypted_file_path):
            return jsonify({"error": "Encrypted file not found on server"}), 404

        return send_file(
            encrypted_file_path,
            as_attachment=True,
            download_name=f"{document_name}.enc",
            mimetype="application/octet-stream",
        )

    except Exception as e:
        print(f"Error in download_document_content: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# first delivery
@authorized_bp.route("/documents/<document_name>", methods=["DELETE"])
def delete_document(document_name):
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    print(f"Attempting to delete document: {document_name}")

    document = Document.query.filter_by(name=document_name, organization_id=session.organization_id).first()
    if not document:
        return jsonify({"error": "Document not found"}), 404

    try:
        encrypted_file_path = document.file_path
        print(f"Encrypted file path: {encrypted_file_path}")

        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
            print(f"File deleted: {encrypted_file_path}")
        else:
            print(f"Warning: File not found for deletion: {encrypted_file_path}")

        db.session.delete(document)
        db.session.commit()

        return jsonify({"message": f"Document '{document_name}' deleted successfully"}), 200

    except Exception as e:
        print(f"Error in delete_document: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

@authorized_bp.route("/documents/<document_id>/acl", methods=["PATCH"])
def change_document_acl(document_id):
    #TODO Implementar lógica para mudar o ACL de um documento
    pass