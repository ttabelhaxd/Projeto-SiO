from flask import Flask, request, jsonify
from .init_db import db

def create_app():
    """Cria a aplicação Flask com as configurações necessárias."""
    app = Flask(__name__)
    
    # Configurações do banco de dados
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////delivery1/instance/db.sqlite"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = True

    # Inicializa o banco de dados
    db.init_app(app)

    # Importa e registra os blueprints
    from .routes.anonymous_api import anonymous_bp
    from .routes.authenticated_api import authenticated_bp
    from .routes.authorized_api import authorized_bp

    app.register_blueprint(anonymous_bp, url_prefix="/api/anonymous")
    app.register_blueprint(authenticated_bp, url_prefix="/api/authenticated")
    app.register_blueprint(authorized_bp, url_prefix="/api/authorized")

    # Garante a criação das tabelas no banco de dados
    with app.app_context():
        try:
            db.create_all()
            print("Database initialized successfully.")
        except Exception as e:
            print("Error initializing database:", str(e))
            import traceback
            traceback.print_exc()  # Adiciona mais detalhes do erro


    return app

# Inicializa a aplicação
app = create_app()

if __name__ == "__main__":
    import logging

    # Configura logging para erros detalhados
    logging.basicConfig(level=logging.DEBUG)
    app.run(host="0.0.0.0", port=5000, debug=True)
