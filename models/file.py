from datetime import datetime
from extensions import db

class FileMetadata(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_size = db.Column(db.Integer) # in bytes
    
    # Encryption Parameters
    encryption_algorithm = db.Column(db.String(50), nullable=False) # AES, ChaCha20, etc.
    cipher_mode = db.Column(db.String(20)) # CBC, GCM, etc.
    key_size = db.Column(db.Integer) # 128, 192, 256
    iv_nonce = db.Column(db.Text) # Base64 encoded
    salt = db.Column(db.String(64)) # For PBKDF2/Argon2 per file
    tag = db.Column(db.String(64)) # Auth tag for GCM/Poly1305
    decryption_key_salt = db.Column(db.String(64)) # Random salt used to hash generated decryption key
    decryption_key_hash = db.Column(db.String(128)) # Hash of generated decryption key (never store raw key)
    
    # Integrity
    hash_algorithm = db.Column(db.String(20), default='SHA256')
    file_hash = db.Column(db.String(128))
    
    is_encrypted = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_downloaded = db.Column(db.DateTime)

    def __repr__(self):
        return f'<File {self.original_filename}>'
