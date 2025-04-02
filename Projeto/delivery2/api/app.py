from flask import Flask
from init_db import db
import getpass, traceback
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def create_app():
    """Cria a aplicação Flask com as configurações necessárias."""
    app = Flask(__name__)
    
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = True

    db.init_app(app)

    from routes.anonymous_api import anonymous_bp
    from routes.authenticated_api import authenticated_bp
    from routes.authorized_api import authorized_bp

    app.register_blueprint(anonymous_bp, url_prefix="/api/anonymous")
    app.register_blueprint(authenticated_bp, url_prefix="/api/authenticated")
    app.register_blueprint(authorized_bp, url_prefix="/api/authorized")

    with app.app_context():
        try:
            db.create_all()
            print("Database initialized successfully.")
        except Exception as e:
            print("Error initializing database:", str(e))
            traceback.print_exc()  


    return app

app = create_app()

if __name__ == "__main__":
    import logging

    try:
        with open("delivery2/api/keys/repositoryKeys/RepoKey.pem", "rb") as f:
            password = getpass.getpass("Enter the password for the repository private key: ")
            while password == "":
                password = getpass.getpass("Password cannot be empty. Enter the password for the repository private key: ")
            try:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode(),
                    backend=default_backend()
                )
                app.config["PRIVATE_KEY"] = private_key
                print("Private key loaded successfully.")
            except:
                print("Wrong credentials. Exiting.")
                exit(-1)
    except:
        print("Private key file not found. Ensure the file exists and is in the correct path and try again.")
        exit(-1)

    logging.basicConfig(level=logging.DEBUG)
    app.run(host="0.0.0.0", port=5000, debug=True)
