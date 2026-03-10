from flask import Flask, render_template
from config import Config
from extensions import db, login_manager, bcrypt, csrf
from sqlalchemy import inspect, text
import os

def ensure_schema_compatibility(app):
    # Lightweight runtime migration for existing SQLite DBs created before new columns were added.
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            if 'files' not in inspector.get_table_names():
                return

            existing_columns = {col['name'] for col in inspector.get_columns('files')}
            alter_statements = []

            if 'decryption_key_salt' not in existing_columns:
                alter_statements.append("ALTER TABLE files ADD COLUMN decryption_key_salt VARCHAR(64)")
            if 'decryption_key_hash' not in existing_columns:
                alter_statements.append("ALTER TABLE files ADD COLUMN decryption_key_hash VARCHAR(128)")

            for statement in alter_statements:
                db.session.execute(text(statement))

            if alter_statements:
                db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.warning("Schema compatibility check failed: %s", exc)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload directory exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)

    # Login configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Register Blueprints
    from routes.auth_routes import auth_bp
    from routes.file_routes import file_bp
    from routes.encryption_routes import encryption_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(encryption_bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('error.html', message="Page not found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('error.html', message="Internal server error"), 500

    ensure_schema_compatibility(app)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
