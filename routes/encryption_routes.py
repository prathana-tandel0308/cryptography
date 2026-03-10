from flask import Blueprint, jsonify, request
from encryption.cipher_factory import CipherFactory
import time

encryption_bp = Blueprint('encryption', __name__)

@encryption_bp.route('/api/algorithms')
def list_algorithms():
    algorithms = [
        {'name': 'AES', 'modes': ['CBC', 'GCM', 'CTR', 'CFB', 'OFB', 'ECB'], 'key_sizes': [128, 192, 256]},
        {'name': 'ChaCha20', 'modes': ['Poly1305'], 'key_sizes': [256]},
        {'name': 'DES', 'modes': ['CBC', 'ECB'], 'key_sizes': [56]},
        {'name': '3DES', 'modes': ['CBC', 'ECB'], 'key_sizes': [112, 168]},
        {'name': 'Blowfish', 'modes': ['CBC', 'ECB'], 'key_sizes': [128, 256, 448]}
    ]
    return jsonify(algorithms)

@encryption_bp.route('/api/encrypt/test', methods=['POST'])
def test_encryption():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '').encode()
    algorithm = data.get('algorithm', 'AES')
    mode = data.get('mode', 'CBC')
    key_size = int(data.get('key_size', 256))
    
    # Simple test key derived from something
    key = b'test-secret-key-32-bytes-long-!!'[:key_size//8]
    
    try:
        cipher = CipherFactory.get_cipher(algorithm, key, mode)
        start_time = time.perf_counter()
        result = cipher.encrypt(text)
        end_time = time.perf_counter()
        
        return jsonify({
            'success': True,
            'time': end_time - start_time,
            'ciphertext_len': len(result['ciphertext'])
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@encryption_bp.route('/api/decrypt/test', methods=['POST'])
def test_decryption():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '').encode()
    algorithm = data.get('algorithm', 'AES')
    mode = data.get('mode', 'CBC')
    key_size = int(data.get('key_size', 256))

    key = b'test-secret-key-32-bytes-long-!!'[:key_size//8]

    try:
        cipher = CipherFactory.get_cipher(algorithm, key, mode)

        encrypt_start = time.perf_counter()
        encrypted = cipher.encrypt(text)
        encrypt_end = time.perf_counter()

        decrypt_start = time.perf_counter()
        tag = encrypted.get('tag')
        if tag is not None:
            plaintext = cipher.decrypt(encrypted['ciphertext'], encrypted['iv'], tag)
        else:
            plaintext = cipher.decrypt(encrypted['ciphertext'], encrypted['iv'])
        decrypt_end = time.perf_counter()

        return jsonify({
            'success': True,
            'encrypt_time': encrypt_end - encrypt_start,
            'decrypt_time': decrypt_end - decrypt_start,
            'ciphertext_len': len(encrypted['ciphertext']),
            'matches': plaintext == text
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
