from app import create_app
from extensions import db
from models.user import User
from models.file import FileMetadata
from models.audit_log import AuditLog
from models.shared_file import SharedFile

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")
    app.run(debug=True, port=5050)
