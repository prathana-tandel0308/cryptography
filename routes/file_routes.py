import io
import mimetypes
from pathlib import Path
from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for, current_app, session
from flask_login import login_required, current_user
from models.file import FileMetadata
from utils.file_handler import FileHandler
from extensions import db
import os

file_bp = Blueprint('file', __name__)

SUPPORTED_ALGORITHM_MODES = {
    'AES': ['CBC', 'GCM', 'CTR', 'CFB', 'OFB'],
    'CHACHA20': ['POLY1305'],
    'BLOWFISH': ['CBC'],
    '3DES': ['CBC'],
    'DES': ['CBC']
}

SUPPORTED_KEY_SIZES = {
    'AES': [128, 192, 256],
    'CHACHA20': [256],
    'BLOWFISH': [128, 192, 256, 448],
    '3DES': [128, 192],
    'DES': [56]
}

def _read_decryption_key():
    return (request.form.get('decryption_key') or '').strip()

@file_bp.route('/dashboard')
@file_bp.route('/decrypt')
@login_required
def decrypt_page():
    files = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).all()
    return render_template('decrypt.html', files=files)

@file_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        algorithm = (request.form.get('algorithm', 'AES') or 'AES').upper()
        mode = (request.form.get('mode', 'CBC') or 'CBC').upper()
        try:
            key_size = int(request.form.get('key_size', 256))
        except (TypeError, ValueError):
            key_size = 256

        if algorithm not in SUPPORTED_KEY_SIZES:
            flash('Unsupported encryption algorithm selected', 'danger')
            return redirect(request.url)

        allowed_modes = SUPPORTED_ALGORITHM_MODES.get(algorithm, ['CBC'])
        if mode not in allowed_modes:
            mode = allowed_modes[0]
            flash(f'Cipher mode was adjusted to {mode} for {algorithm}.', 'warning')

        allowed_key_sizes = SUPPORTED_KEY_SIZES[algorithm]
        if key_size not in allowed_key_sizes:
            key_size = max(allowed_key_sizes)
            flash(f'Key size was adjusted to {key_size}-bit for {algorithm}.', 'warning')
        
        try:
            metadata, generated_decryption_key = FileHandler.encrypt_and_save(file, current_user, algorithm, mode, key_size)
            session[f'generated_decryption_key_{metadata.id}'] = generated_decryption_key
            return redirect(url_for('file.result_page', operation='encryption', file_id=metadata.id))
        except Exception as e:
            flash(f'Error during encryption: {str(e)}', 'danger')
            
    files = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).all()
    return render_template('encrypt.html', files=files)

@file_bp.route('/decrypt/process/<int:file_id>', methods=['POST'])
@login_required
def process_decryption(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('file.decrypt_page'))

    decryption_key = _read_decryption_key()
    if file_metadata.decryption_key_hash and not decryption_key:
        flash('Decryption key is required for this file.', 'danger')
        return redirect(url_for('file.decrypt_page'))

    try:
        # Validate that decryption can be performed before showing result page.
        FileHandler.decrypt_and_get(file_metadata, current_user, decryption_key=decryption_key or None)
        return redirect(url_for('file.result_page', operation='decryption', file_id=file_metadata.id))
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('file.decrypt_page'))

@file_bp.route('/decrypt-upload', methods=['POST'])
@login_required
def decrypt_upload():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('file.decrypt_page'))

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        flash('No selected encrypted file', 'danger')
        return redirect(url_for('file.decrypt_page'))

    uploaded_ciphertext = uploaded_file.read()
    if not uploaded_ciphertext:
        flash('Uploaded encrypted file is empty', 'danger')
        return redirect(url_for('file.decrypt_page'))

    decryption_key = _read_decryption_key()

    file_metadata = None
    candidates = FileMetadata.query.filter_by(user_id=current_user.id).order_by(FileMetadata.created_at.desc()).all()
    for candidate in candidates:
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], candidate.encrypted_filename)
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'rb') as f:
            if f.read() == uploaded_ciphertext:
                file_metadata = candidate
                break

    if not file_metadata:
        flash('Uploaded encrypted file does not match your stored encrypted files.', 'danger')
        return redirect(url_for('file.decrypt_page'))

    if file_metadata.decryption_key_hash and not decryption_key:
        flash('Decryption key is required for this file.', 'danger')
        return redirect(url_for('file.decrypt_page'))

    try:
        FileHandler.decrypt_ciphertext(uploaded_ciphertext, file_metadata, current_user, decryption_key=decryption_key)
        return redirect(url_for('file.result_page', operation='decryption', file_id=file_metadata.id))
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('file.decrypt_page'))

@file_bp.route('/result/<string:operation>/<int:file_id>')
@login_required
def result_page(operation, file_id):
    operation = operation.lower()
    if operation not in ('encryption', 'decryption'):
        flash('Invalid operation type', 'danger')
        return redirect(url_for('file.upload'))

    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('file.upload'))

    generated_decryption_key = None
    if operation == 'encryption':
        generated_decryption_key = session.pop(f'generated_decryption_key_{file_id}', None)

    return render_template(
        'result.html',
        operation=operation,
        file=file_metadata,
        generated_decryption_key=generated_decryption_key
    )

@file_bp.route('/download-encrypted/<int:file_id>')
@login_required
def download_encrypted(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('file.upload'))

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_metadata.encrypted_filename)
    if not os.path.exists(filepath):
        flash('Encrypted file not found on disk', 'danger')
        return redirect(url_for('file.upload'))

    return send_file(
        filepath,
        as_attachment=True,
        download_name=f"{Path(file_metadata.original_filename).stem}_encrypted{Path(file_metadata.original_filename).suffix}",
        mimetype='application/octet-stream'
    )

@file_bp.route('/download/<int:file_id>', methods=['GET', 'POST'])
@file_bp.route('/download-decrypted/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_decrypted(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('file.decrypt_page'))

    decryption_key = ''
    if request.method == 'POST':
        decryption_key = _read_decryption_key()
    else:
        decryption_key = (request.args.get('decryption_key') or '').strip()

    if file_metadata.decryption_key_hash and not decryption_key:
        flash('Decryption key is required to download this file.', 'danger')
        return redirect(url_for('file.decrypt_page'))

    try:
        decrypted_data = FileHandler.decrypt_and_get(
            file_metadata,
            current_user,
            decryption_key=decryption_key or None
        )
        mimetype = mimetypes.guess_type(file_metadata.original_filename)[0] or 'application/octet-stream'
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file_metadata.original_filename,
            mimetype=mimetype
        )
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('file.decrypt_page'))

@file_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file_metadata = FileMetadata.query.get_or_404(file_id)
    if file_metadata.user_id != current_user.id:
        flash('Permission denied', 'danger')
        return redirect(url_for('file.decrypt_page'))
        
    # Delete encrypted file
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_metadata.encrypted_filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        
    db.session.delete(file_metadata)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('file.decrypt_page'))
