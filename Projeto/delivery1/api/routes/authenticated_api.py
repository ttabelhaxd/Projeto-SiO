from flask import Blueprint, request, jsonify
from ..models import Subject, Role, Document, ACL, Session, Organization, OrganizationSubject
from ..init_db import db
from datetime import datetime

authenticated_bp = Blueprint("authenticated", __name__)

def verify_session():
    try:
        session_id = request.headers.get("Authorization")
        if not session_id:
            return None, ({"error": "Missing session ID in headers"}, 401)

        if session_id.startswith("Bearer "):
            session_id = session_id[7:]

        session = Session.query.filter_by(session_id=session_id).first()
        if not session:
            return None, ({"error": "Session not found"}, 404)
        if session.expires_at < datetime.utcnow():
            return None, ({"error": "Session expired"}, 401)

        return session, None

    except Exception as e:
        print(f"Error in verify_session: {str(e)}")
        return None, ({"error": "Internal server error"}, 500)

@authenticated_bp.route("/session/assume_role", methods=["POST"])
def assume_session_role():
    #TODO Implementar lógica para assumir um papel na sessão
    pass

@authenticated_bp.route("/session/release_role", methods=["POST"])
def release_session_role():
    #TODO Implementar lógica para liberar um papel na sessão
    pass

@authenticated_bp.route("/session/list_roles", methods=["GET"])
def list_session_roles():
    #TODO Implementar lógica para listar papéis na sessão
    pass

# first delivery
@authenticated_bp.route("/subjects", methods=["GET"])
def list_subjects():
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]

    try:
        assoc_query = OrganizationSubject.query.filter_by(organization_id=session.organization_id)
        subjects = [assoc.subject for assoc in assoc_query]

        username = request.args.get("username")
        if username:
            subjects = [s for s in subjects if s.username == username]

        if not subjects:
            return jsonify({"message": "No subjects found"}), 200

        subject_list = [
            {
                "id": subject.id,
                "username": subject.username,
                "full_name": subject.full_name,
                "email": subject.email,
                "status": subject.status,
            }
            for subject in subjects
        ]

        return jsonify(subject_list), 200

    except Exception as e:
        print(f"Error in list_subjects: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@authenticated_bp.route("/roles", methods=["GET"])
def list_roles():
    #TODO Implementar lógica para listar papéis da organização do usuário
    pass

@authenticated_bp.route("/roles/<role_id>/subjects", methods=["GET"])
def list_subjects_in_role(role_id):
    #TODO Implementar lógica para listar sujeitos em um papel específico da organização do usuário
    pass

@authenticated_bp.route("/subjects/<subject_id>/roles", methods=["GET"])
def list_roles_of_subject(subject_id):
    #TODO Implementar lógica para listar papéis de um sujeito específico da organização do usuário
    pass

@authenticated_bp.route("/roles/<role_id>/permissions", methods=["GET"])
def list_permissions_in_role(role_id):
    #TODO Implementar lógica para listar permissões em um papel específico da organização do usuário
    pass

@authenticated_bp.route("/permissions/<permission>/roles", methods=["GET"])
def list_roles_with_permission(permission):
    #TODO Implementar lógica para listar papéis que têm uma permissão específica
    pass

# first delivery
@authenticated_bp.route("/documents", methods=["GET"])
def list_documents():
    session, error_response = verify_session()
    if error_response:
        return jsonify(error_response), error_response[1]
    
    try:
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
                    return jsonify({"error": "Invalid filter type. Use 'nt', 'ot', or 'et'"}), 400
            except ValueError:
                return jsonify({"error": "Invalid date format. Use DD-MM-YYYY"}), 400
        
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
        return jsonify(document_list), 200
    
    except Exception as e:
        print(f"Error in list_documents: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
