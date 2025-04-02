from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from .init_db import db


class Organization(db.Model):
    __tablename__ = 'organization'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='SET NULL'), nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship("Subject", back_populates="organizations_created", foreign_keys=[creator_id])
    subjects_assoc = db.relationship("OrganizationSubject", back_populates="organization", cascade="all, delete-orphan")
    documents = db.relationship("Document", back_populates="organization", cascade="all, delete-orphan")
    roles = db.relationship("Role", back_populates="organization", cascade="all, delete-orphan")



class Subject(db.Model):
    __tablename__ = 'subject'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    status = db.Column(db.String, db.CheckConstraint("status IN ('active', 'suspended')"), default='active', nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    organizations_assoc = db.relationship("OrganizationSubject", back_populates="subject", cascade="all, delete-orphan")
    organizations_created = db.relationship("Organization", back_populates="creator")
    documents_created = db.relationship("Document", foreign_keys="Document.creator_id", back_populates="creator")
    acl_entries = db.relationship("ACL", back_populates="subject", cascade="all, delete-orphan")
    roles = db.relationship("SubjectRole", back_populates="subject", cascade="all, delete-orphan")
    sessions = db.relationship("Session", back_populates="subject")

    def set_password(self, password):
        """Gera o hash da senha e armazena"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Valida a senha"""
        return check_password_hash(self.password_hash, password)

    
class OrganizationSubject(db.Model):
    __tablename__ = 'organizations_subjects'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    organization = db.relationship("Organization", back_populates="subjects_assoc")
    subject = db.relationship("Subject", back_populates="organizations_assoc")
    

class Document(db.Model):
    __tablename__ = 'document'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False)
    file_handle = db.Column(db.String(150), unique=True, nullable=False)  # Mantém o file_handle como identificador único
    file_path = db.Column(db.String(255), nullable=False)
    file_metadata = db.Column(db.Text, nullable=False)  # Metadados como JSON
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)

    creator = db.relationship("Subject", back_populates="documents_created")
    organization = db.relationship("Organization", back_populates="documents")
    acl_entries = db.relationship("ACL", back_populates="document", cascade="all, delete-orphan")


class ACL(db.Model):
    __tablename__ = 'acl'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    permission_type = db.Column(
        db.String(20),
        db.CheckConstraint("permission_type IN ('DOC_READ', 'DOC_DELETE', 'DOC_ACL')"),
        nullable=False
    )
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False)

    document = db.relationship("Document", back_populates="acl_entries")
    subject = db.relationship("Subject", back_populates="acl_entries")


class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)

    __table_args__ = (db.UniqueConstraint('name', 'organization_id', name='unique_role_per_org'),)

    organization = db.relationship("Organization", back_populates="roles")
    subjects = db.relationship("SubjectRole", back_populates="role", cascade="all, delete-orphan")


class SubjectRole(db.Model):
    __tablename__ = 'subject_role'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)

    subject = db.relationship("Subject", back_populates="roles")
    role = db.relationship("Role", back_populates="subjects")


class Session(db.Model):
    __tablename__ = 'session'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(150), unique=True, nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id', ondelete='CASCADE'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    subject = db.relationship("Subject", back_populates="sessions")
    organization = db.relationship("Organization")
