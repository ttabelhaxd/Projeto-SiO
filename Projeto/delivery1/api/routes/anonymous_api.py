from flask import Blueprint, request, jsonify, send_file
import uuid, secrets, string, traceback, os, json
from datetime import datetime, timedelta
from ..models import Organization, Subject, Document, Session, OrganizationSubject
from werkzeug.security import generate_password_hash
from ..init_db import db
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

anonymous_bp = Blueprint("anonymous", __name__)

# ----------------------------------------------------------------------------------------
# Funções auxiliares para desencriptar arquivos e verificar integridade

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

# ----------------------------------------------------------------------------------------    

@anonymous_bp.route("/organization/create", methods=["POST"])
def create_organization():
    try:
        data = request.json
        print("Received data:", data)

        name = data.get("organization")
        username = data.get("username")
        full_name = data.get("name")
        email = data.get("email")
        public_key = data.get("public_key")

        if not all([name, username, full_name, email, public_key]):
            print("Error: Missing fields")
            return jsonify({"error": "Missing fields"}), 400

        existing_org = Organization.query.filter_by(name=name).first()
        if existing_org:
            print(f"Error: Organization '{name}' already exists")
            return jsonify({"error": "Organization already exists"}), 409

        existing_user = Subject.query.filter_by(username=username).first()
        if existing_user:
            print(f"Error: Username '{username}' already taken")
            return jsonify({"error": "Username already taken"}), 409

        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        print(f"Generated password for {username}: {password}")

        creator = Subject(
            username=username,
            full_name=full_name,
            email=email,
            public_key=public_key,
            status="active",
            password_hash=generate_password_hash(password)
        )
        db.session.add(creator)
        db.session.commit()
        print(f"Creator '{username}' created successfully with ID {creator.id}")

        new_org = Organization(name=name, creator_id=creator.id)
        db.session.add(new_org)
        db.session.commit()
        print(f"Organization '{name}' created successfully with ID {new_org.id}")

        organization_subject = OrganizationSubject(
            organization_id=new_org.id,
            subject_id=creator.id
        )
        db.session.add(organization_subject)
        db.session.commit()
        print(f"Creator '{username}' linked to organization '{name}' in OrganizationSubject table")

        return jsonify({
            "message": f"Organization '{name}' created successfully",
            "organization_id": new_org.id,
            "password": password
        }), 201

    except Exception as e:
        print("Error in create_organization:", str(e))
        traceback.print_exc()
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

# List Organizations
@anonymous_bp.route("/organizations", methods=["GET"])
def list_organizations():
    organizations = Organization.query.all()
    organization_list = [
        {
            "id": org.id,
            "name": org.name,
            "creator_id": org.creator_id,
            "create_date": org.create_date.isoformat()
        }
        for org in organizations
    ]
    return jsonify(organization_list), 200


# Create Session
@anonymous_bp.route("/session/create", methods=["POST"])
def create_session():
    try:
        data = request.json
        organization_name = data.get("organization")
        username = data.get("username")
        password = data.get("password")

        if not all([organization_name, username, password]):
            return jsonify({"error": "Missing fields"}), 400

        organization = Organization.query.filter_by(name=organization_name).first()
        if not organization:
            return jsonify({"error": "Organization not found"}), 404

        subject = Subject.query.filter_by(username=username, status="active").first()
        if not subject:
            return jsonify({"error": "User not found or inactive"}), 404

        if not subject.check_password(password):
            return jsonify({"error": "Invalid credentials"}), 401

        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=1)

        new_session = Session(
            session_id=session_id,
            subject_id=subject.id,
            organization_id=organization.id,
            expires_at=expires_at
        )
        db.session.add(new_session)
        db.session.commit()

        return jsonify({
            "message": "Session created successfully",
            "session_id": session_id,
            "expires_at": expires_at.isoformat()
        }), 201
    except Exception as e:
        print("Error in create_session:", str(e)) 
        return jsonify({"error": "Internal server error"}), 500

@anonymous_bp.route("/file/download/<file_handle>", methods=["GET"])
def download_file(file_handle):
    try:
        document = Document.query.filter_by(file_handle=file_handle).first()
        if not document:
            return jsonify({"error": "File not found"}), 404

        encrypted_file_path = document.file_path

        if not os.path.exists(encrypted_file_path):
            return jsonify({"error": "Encrypted file not found on server"}), 404

        metadata = json.loads(document.file_metadata)
        iv = bytes.fromhex(metadata["alg"]["encryption"]["iv"])
        aes_key = bytes.fromhex(metadata["aes_key"])
        expected_mac = metadata["alg"]["integrity_control"]["MAC"]

        decrypted_file_path = decrypt_file_aux(encrypted_file_path, aes_key, iv)

        try:
            verify_integrity(aes_key, decrypted_file_path, expected_mac)
        except Exception as e:
            os.remove(decrypted_file_path)
            return jsonify({"error": f"Integrity verification failed: {str(e)}"}), 400

        return send_file(
            decrypted_file_path,
            as_attachment=True,
            download_name=document.name,
            mimetype="application/octet-stream"
        )

    except Exception as e:
        print("Error in download_file:", str(e))
        return jsonify({"error": "Internal server error"}), 500
