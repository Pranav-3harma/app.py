from flask import Flask, render_template, request, jsonify, send_file, session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
import os
import base64
import json
import tempfile
from werkzeug.utils import secure_filename
import uuid
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

# Ensure temp directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class PranavCrypt:
    """PranavCrypt - Multi-Algorithm Cryptographic Engine"""
    
    @staticmethod
    def generate_rsa_keys():
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': base64.b64encode(private_pem).decode('utf-8'),
            'public_key': base64.b64encode(public_pem).decode('utf-8')
        }
    
    @staticmethod
    def rsa_encrypt_file(file_data, public_key_b64):
        """RSA encryption for files"""
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            # For files, always use hybrid encryption (AES + RSA)
            # Generate AES key
            aes_key = os.urandom(32)
            # Encrypt data with AES
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad file data
            padded_data = file_data
            if len(padded_data) % 16 != 0:
                padded_data += b'\0' * (16 - len(padded_data) % 16)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine encrypted key, IV, and data
            result = encrypted_key + iv + encrypted_data
            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            raise ValueError(f"RSA encryption failed: {str(e)}")
    
    @staticmethod
    def rsa_decrypt_file(encrypted_data, private_key_b64):
        """RSA decryption for files"""
        try:
            private_key_bytes = base64.b64decode(private_key_b64)
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract encrypted key, IV, and data
            encrypted_key = encrypted_bytes[:256]
            iv = encrypted_bytes[256:272]
            encrypted_file_data = encrypted_bytes[272:]
            
            # Decrypt AES key
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = decrypted_data.rstrip(b'\0')
            return decrypted_data
        except Exception as e:
            raise ValueError(f"RSA decryption failed: {str(e)}")
    
    @staticmethod
    def aes_encrypt_file(file_data, key=None):
        """AES-256-CBC encryption for files"""
        try:
            if key is None:
                key = os.urandom(32)
            elif isinstance(key, str):
                key = base64.b64decode(key)
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad file data
            padded_data = file_data
            if len(padded_data) % 16 != 0:
                padded_data += b'\0' * (16 - len(padded_data) % 16)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            result = iv + encrypted_data
            return {
                'encrypted': base64.b64encode(result).decode('utf-8'),
                'key': base64.b64encode(key).decode('utf-8')
            }
        except Exception as e:
            raise ValueError(f"AES encryption failed: {str(e)}")
    
    @staticmethod
    def aes_decrypt_file(encrypted_data, key):
        """AES-256-CBC decryption for files"""
        try:
            if isinstance(key, str):
                key = base64.b64decode(key)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_bytes[:16]
            encrypted_file_data = encrypted_bytes[16:]
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = decrypted_data.rstrip(b'\0')
            return decrypted_data
        except Exception as e:
            raise ValueError(f"AES decryption failed: {str(e)}")
    
    @staticmethod
    def chacha20_encrypt_file(file_data, key=None):
        """ChaCha20 encryption for files"""
        try:
            if key is None:
                key = os.urandom(32)
            elif isinstance(key, str):
                key = base64.b64decode(key)
            
            nonce = os.urandom(12)

            
            # Use ChaCha20Poly1305 instead of ChaCha20 for better compatibility
            cipher = ChaCha20Poly1305(key)
            encrypted_data = cipher.encrypt(nonce, file_data, None)
            
            # Combine nonce and encrypted data
            result = nonce + encrypted_data
            return {
                'encrypted': base64.b64encode(result).decode('utf-8'),
                'key': base64.b64encode(key).decode('utf-8')
            }
        except Exception as e:
            raise ValueError(f"ChaCha20 encryption failed: {str(e)}")
    
    @staticmethod
    def chacha20_decrypt_file(encrypted_data, key):
        """ChaCha20 decryption for files"""
        try:
            if isinstance(key, str):
                key = base64.b64decode(key)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            nonce = encrypted_bytes[:12]
            encrypted_file_data = encrypted_bytes[12:]
            
            # Use ChaCha20Poly1305 instead of ChaCha20 for better compatibility
            cipher = ChaCha20Poly1305(key)
            decrypted_data = cipher.decrypt(nonce, encrypted_file_data, None)
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"ChaCha20 decryption failed: {str(e)}")
    
    @staticmethod
    def blowfish_generate_key():
        """Generate Blowfish key"""
        # Blowfish supports key sizes from 32 to 448 bits (4 to 56 bytes)
        # We'll use 448 bits (56 bytes) for maximum security
        key = os.urandom(56)
        return {
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    @staticmethod
    def blowfish_encrypt_file(file_data, key=None):
        """Blowfish encryption for files"""
        try:
            if key is None:
                key = os.urandom(56)
            elif isinstance(key, str):
                key = base64.b64decode(key)
            
            # Blowfish uses 64-bit blocks, so we need 8-byte IV
            iv = os.urandom(8)
            
            # Use Blowfish in CBC mode
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad file data to 8-byte blocks (Blowfish block size)
            padded_data = file_data
            if len(padded_data) % 8 != 0:
                padded_data += b'\0' * (8 - len(padded_data) % 8)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            result = iv + encrypted_data
            return {
                'encrypted': base64.b64encode(result).decode('utf-8'),
                'key': base64.b64encode(key).decode('utf-8')
            }
        except Exception as e:
            raise ValueError(f"Blowfish encryption failed: {str(e)}")
    
    @staticmethod
    def blowfish_decrypt_file(encrypted_data, key):
        """Blowfish decryption for files"""
        try:
            if isinstance(key, str):
                key = base64.b64decode(key)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_bytes[:8]
            encrypted_file_data = encrypted_bytes[8:]
            
            # Use Blowfish in CBC mode
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = decrypted_data.rstrip(b'\0')
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Blowfish decryption failed: {str(e)}")

@app.route('/')
def home():
    """Home page"""
    return render_template('home.html')

@app.route('/encrypt_decrypt')
def encrypt_decrypt():
    """Main encryption/decryption page"""
    return render_template('encrypt_decrypt.html')

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    """Generate keys for selected algorithm"""
    try:
        algorithm = request.json.get('algorithm')
        
        if algorithm == 'RSA':
            keys = PranavCrypt.generate_rsa_keys()
        elif algorithm == 'Blowfish':
            keys = PranavCrypt.blowfish_generate_key()
        else:
            return jsonify({'error': 'Key generation not needed for this algorithm'}), 400
        
        return jsonify({
            'success': True,
            'keys': keys
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """Encrypt file or text message"""
    try:
        print(f"Encrypt route called with algorithm: {request.form.get('algorithm')}")  # Debug print
        algorithm = request.form.get('algorithm')
        input_type = request.form.get('input_type', 'file')  # Default to file for backward compatibility
        
        if input_type == 'file':
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Read file data
            file_data = file.read()
            
            result = {}
            
            if algorithm == 'RSA':
                key = request.form.get('key')
                if not key:
                    return jsonify({'error': 'Public key is required for RSA'}), 400
                encrypted = PranavCrypt.rsa_encrypt_file(file_data, key)
                result = {'encrypted': encrypted}
            
            elif algorithm == 'AES':
                key = request.form.get('key')
                encryption_result = PranavCrypt.aes_encrypt_file(file_data, key)
                result = encryption_result
            
            elif algorithm == 'ChaCha20':
                key = request.form.get('key')
                print(f"ChaCha20 encryption - key provided: {bool(key)}")  # Debug print
                encryption_result = PranavCrypt.chacha20_encrypt_file(file_data, key)
                result = encryption_result
            
            elif algorithm == 'Blowfish':
                key = request.form.get('key')
                encryption_result = PranavCrypt.blowfish_encrypt_file(file_data, key)
                result = encryption_result
            
            else:
                return jsonify({'error': 'Invalid algorithm'}), 400
            
            return jsonify({
                'success': True,
                'result': result,
                'original_filename': file.filename,
                'file_size': len(file_data)
            })
        
        elif input_type == 'text':
            message = request.form.get('message')
            if not message:
                return jsonify({'error': 'No message provided'}), 400
            
            if len(message) > 10000:
                return jsonify({'error': 'Message too long. Maximum 10,000 characters allowed.'}), 400
            
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            result = {}
            
            if algorithm == 'RSA':
                key = request.form.get('key')
                if not key:
                    return jsonify({'error': 'Public key is required for RSA'}), 400
                encrypted = PranavCrypt.rsa_encrypt_file(message_bytes, key)
                result = {'encrypted': encrypted}
            
            elif algorithm == 'AES':
                key = request.form.get('key')
                encryption_result = PranavCrypt.aes_encrypt_file(message_bytes, key)
                result = encryption_result
            
            elif algorithm == 'ChaCha20':
                key = request.form.get('key')
                print(f"ChaCha20 text encryption - key provided: {bool(key)}")  # Debug print
                encryption_result = PranavCrypt.chacha20_encrypt_file(message_bytes, key)
                result = encryption_result
            
            elif algorithm == 'Blowfish':
                key = request.form.get('key')
                encryption_result = PranavCrypt.blowfish_encrypt_file(message_bytes, key)
                result = encryption_result
            
            else:
                return jsonify({'error': 'Invalid algorithm'}), 400
            
            return jsonify({
                'success': True,
                'result': result,
                'message_length': len(message)
            })
        
        else:
            return jsonify({'error': 'Invalid input type'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """Decrypt file or text message"""
    try:
        print(f"Decrypt route called with algorithm: {request.form.get('algorithm')}")  # Debug print
        algorithm = request.form.get('algorithm')
        input_type = request.form.get('input_type', 'file')  # Default to file for backward compatibility
        
        if not algorithm:
            return jsonify({'error': 'Algorithm is required'}), 400
        
        if input_type == 'file':
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Read encrypted file data
            encrypted_file_data = file.read()
            
            key = request.form.get('key')
            if not key:
                return jsonify({'error': 'Key is required for decryption'}), 400
            
            result = {}
            
            if algorithm == 'RSA':
                # The encrypted file contains Base64 text, so we need to decode it as UTF-8
                encrypted_base64 = encrypted_file_data.decode('utf-8')
                decrypted_data = PranavCrypt.rsa_decrypt_file(encrypted_base64, key)
                # Try to decode as UTF-8, if it fails, return as Base64 for binary files
                try:
                    text_content = decrypted_data.decode('utf-8')
                    result = {'decrypted_data': text_content}
                except UnicodeDecodeError:
                    # Binary file, return as Base64
                    result = {'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8'), 'is_binary': True}
            
            elif algorithm == 'AES':
                # The encrypted file contains Base64 text, so we need to decode it as UTF-8
                encrypted_base64 = encrypted_file_data.decode('utf-8')
                decrypted_data = PranavCrypt.aes_decrypt_file(encrypted_base64, key)
                # Try to decode as UTF-8, if it fails, return as Base64 for binary files
                try:
                    text_content = decrypted_data.decode('utf-8')
                    result = {'decrypted_data': text_content}
                except UnicodeDecodeError:
                    # Binary file, return as Base64
                    result = {'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8'), 'is_binary': True}
            
            elif algorithm == 'ChaCha20':
                # The encrypted file contains Base64 text, so we need to decode it as UTF-8
                encrypted_base64 = encrypted_file_data.decode('utf-8')
                decrypted_data = PranavCrypt.chacha20_decrypt_file(encrypted_base64, key)
                # Try to decode as UTF-8, if it fails, return as Base64 for binary files
                try:
                    text_content = decrypted_data.decode('utf-8')
                    result = {'decrypted_data': text_content}
                except UnicodeDecodeError:
                    # Binary file, return as Base64
                    result = {'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8'), 'is_binary': True}
            
            elif algorithm == 'Blowfish':
                # The encrypted file contains Base64 text, so we need to decode it as UTF-8
                encrypted_base64 = encrypted_file_data.decode('utf-8')
                decrypted_data = PranavCrypt.blowfish_decrypt_file(encrypted_base64, key)
                # Try to decode as UTF-8, if it fails, return as Base64 for binary files
                try:
                    text_content = decrypted_data.decode('utf-8')
                    result = {'decrypted_data': text_content}
                except UnicodeDecodeError:
                    # Binary file, return as Base64
                    result = {'decrypted_data': base64.b64encode(decrypted_data).decode('utf-8'), 'is_binary': True}
            
            else:
                return jsonify({'error': 'Invalid algorithm'}), 400
            
            return jsonify({
                'success': True,
                'result': result,
                'filename': file.filename
            })
        
        elif input_type == 'text':
            message = request.form.get('message')
            if not message:
                return jsonify({'error': 'No message provided'}), 400
            
            key = request.form.get('key')
            if not key:
                return jsonify({'error': 'Key is required for decryption'}), 400
            
            result = {}
            
            if algorithm == 'RSA':
                # For text messages, the encrypted data is already Base64
                decrypted_data = PranavCrypt.rsa_decrypt_file(message, key)
                # Text messages should always be UTF-8
                text_content = decrypted_data.decode('utf-8')
                result = {'decrypted_data': text_content}
            
            elif algorithm == 'AES':
                decrypted_data = PranavCrypt.aes_decrypt_file(message, key)
                text_content = decrypted_data.decode('utf-8')
                result = {'decrypted_data': text_content}
            
            elif algorithm == 'ChaCha20':
                decrypted_data = PranavCrypt.chacha20_decrypt_file(message, key)
                text_content = decrypted_data.decode('utf-8')
                result = {'decrypted_data': text_content}
            
            elif algorithm == 'Blowfish':
                decrypted_data = PranavCrypt.blowfish_decrypt_file(message, key)
                text_content = decrypted_data.decode('utf-8')
                result = {'decrypted_data': text_content}
            
            else:
                return jsonify({'error': 'Invalid algorithm'}), 400
            
            return jsonify({
                'success': True,
                'result': result,
                'message_length': len(message)
            })
        
        else:
            return jsonify({'error': 'Invalid input type'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download(filename):
    """Download file"""
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Development server configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Only run development server if not in production
    if os.environ.get('FLASK_ENV') != 'production':
        app.run(debug=debug, host='0.0.0.0', port=port)
    else:
        print("Production mode detected. Use Gunicorn to run the server:")
        print("gunicorn --config gunicorn.conf.py wsgi:app")
