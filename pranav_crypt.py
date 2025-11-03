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
from PIL import Image
import wave
from pydub import AudioSegment
import cv2
import fitz  # PyMuPDF
import io
import struct

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

class SteganographyEngine:
    """Multi-format Steganography Engine for hiding and extracting messages"""

    @staticmethod
    def validate_carrier_file(file_data, file_type):
        """Validate carrier file format and integrity"""
        try:
            if file_type.lower() in ['png', 'jpg', 'jpeg', 'bmp']:
                img = Image.open(io.BytesIO(file_data))
                img.verify()  # Verify image integrity
                return True
            elif file_type.lower() == 'wav':
                with wave.open(io.BytesIO(file_data), 'rb') as wav_file:
                    wav_file.getparams()
                return True
            elif file_type.lower() == 'mp4':
                # Basic MP4 validation using OpenCV
                cap = cv2.VideoCapture(io.BytesIO(file_data))
                if cap.isOpened():
                    ret, _ = cap.read()
                    cap.release()
                    return ret
                return False
            elif file_type.lower() == 'pdf':
                pdf_document = fitz.open(stream=file_data, filetype="pdf")
                if pdf_document.page_count > 0:
                    pdf_document.close()
                    return True
                return False
            else:
                return False
        except Exception:
            return False

    @staticmethod
    def calculate_capacity(file_data, file_type):
        """Calculate maximum message capacity for different file types"""
        try:
            if file_type.lower() in ['png', 'jpg', 'jpeg', 'bmp']:
                img = Image.open(io.BytesIO(file_data))
                width, height = img.size
                # LSB steganography: 1 bit per RGB channel per pixel = 3 bits per pixel
                max_bits = width * height * 3
                max_bytes = max_bits // 8
                return max_bytes
            elif file_type.lower() == 'wav':
                with wave.open(io.BytesIO(file_data), 'rb') as wav_file:
                    frames = wav_file.getnframes()
                    # LSB in audio samples: 1 bit per sample
                    max_bytes = frames // 8
                    return max_bytes
            elif file_type.lower() == 'mp4':
                cap = cv2.VideoCapture(io.BytesIO(file_data))
                frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                cap.release()
                # Use 10% of frames for steganography to avoid detection
                usable_frames = frame_count // 10
                max_bits = usable_frames * width * height * 3
                max_bytes = max_bits // 8
                return max_bytes
            elif file_type.lower() == 'pdf':
                pdf_document = fitz.open(stream=file_data, filetype="pdf")
                metadata = pdf_document.metadata
                pdf_document.close()
                # PDF metadata can typically store ~4KB
                return 4096
            else:
                return 0
        except Exception:
            return 0

    @staticmethod
    def hide_message_in_image(carrier_data, message):
        """Hide message in image using LSB steganography"""
        try:
            img = Image.open(io.BytesIO(carrier_data))

            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Add message delimiter
            message_with_delim = message + "<<<END>>>"
            message_bytes = message_with_delim.encode('utf-8')
            message_bits = ''.join(format(byte, '08b') for byte in message_bytes)

            width, height = img.size
            pixels = list(img.getdata())

            if len(message_bits) > len(pixels) * 3:
                raise ValueError("Message too long for image capacity")

            # Modify LSB of RGB values
            modified_pixels = []
            bit_index = 0

            for pixel in pixels:
                r, g, b = pixel
                if bit_index < len(message_bits):
                    # Modify red channel
                    r = (r & 0xFE) | int(message_bits[bit_index])
                    bit_index += 1
                if bit_index < len(message_bits):
                    # Modify green channel
                    g = (g & 0xFE) | int(message_bits[bit_index])
                    bit_index += 1
                if bit_index < len(message_bits):
                    # Modify blue channel
                    b = (b & 0xFE) | int(message_bits[bit_index])
                    bit_index += 1

                modified_pixels.append((r, g, b))

            # Create new image with modified pixels
            new_img = Image.new('RGB', (width, height))
            new_img.putdata(modified_pixels)

            # Save to bytes
            output = io.BytesIO()
            new_img.save(output, format='PNG')
            output.seek(0)

            return output.getvalue()
        except Exception as e:
            raise ValueError(f"Failed to hide message in image: {str(e)}")

    @staticmethod
    def extract_message_from_image(stego_data):
        """Extract hidden message from image using LSB steganography"""
        try:
            img = Image.open(io.BytesIO(stego_data))
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = list(img.getdata())
            message_bits = []

            for pixel in pixels:
                r, g, b = pixel
                message_bits.append(str(r & 1))
                message_bits.append(str(g & 1))
                message_bits.append(str(b & 1))

                # Check for end delimiter every 24 bits (3 bytes)
                if len(message_bits) >= 24:
                    chunk_bits = message_bits[-24:]
                    try:
                        chunk_bytes = ''.join([chr(int(''.join(chunk_bits[i:i+8]), 2))
                                              for i in range(0, len(chunk_bits), 8)])
                        if "<<<END>>>" in chunk_bytes:
                            message_bits = message_bits[:-24]  # Remove delimiter
                            break
                    except:
                        continue

            # Convert bits to bytes
            message_bytes = []
            for i in range(0, len(message_bits), 8):
                if i + 8 <= len(message_bits):
                    byte_bits = message_bits[i:i+8]
                    byte_value = int(''.join(byte_bits), 2)
                    message_bytes.append(byte_value)

            message = bytes(message_bytes).decode('utf-8', errors='ignore')
            return message
        except Exception as e:
            raise ValueError(f"Failed to extract message from image: {str(e)}")

    @staticmethod
    def hide_message_in_audio(carrier_data, message):
        """Hide message in WAV audio using LSB steganography"""
        try:
            with wave.open(io.BytesIO(carrier_data), 'rb') as wav_file:
                params = wav_file.getparams()
                frames = wav_file.readframes(-1)

            # Add message delimiter
            message_with_delim = message + "<<<END>>>"
            message_bytes = message_with_delim.encode('utf-8')
            message_bits = ''.join(format(byte, '08b') for byte in message_bytes)

            # Convert frames to list of integers
            frame_bytes = bytearray(frames)

            if len(message_bits) > len(frame_bytes):
                raise ValueError("Message too long for audio capacity")

            # Modify LSB of audio samples
            for i, bit in enumerate(message_bits):
                if i < len(frame_bytes):
                    frame_bytes[i] = (frame_bytes[i] & 0xFE) | int(bit)

            # Create new WAV file
            output = io.BytesIO()
            with wave.open(output, 'wb') as new_wav:
                new_wav.setparams(params)
                new_wav.writeframes(bytes(frame_bytes))

            output.seek(0)
            return output.getvalue()
        except Exception as e:
            raise ValueError(f"Failed to hide message in audio: {str(e)}")

    @staticmethod
    def extract_message_from_audio(stego_data):
        """Extract hidden message from WAV audio"""
        try:
            with wave.open(io.BytesIO(stego_data), 'rb') as wav_file:
                frames = wav_file.readframes(-1)

            frame_bytes = bytearray(frames)
            message_bits = [str(byte & 1) for byte in frame_bytes]

            # Convert bits to bytes and look for delimiter
            message_bytes = []
            for i in range(0, len(message_bits), 8):
                if i + 8 <= len(message_bits):
                    byte_bits = message_bits[i:i+8]
                    byte_value = int(''.join(byte_bits), 2)
                    message_bytes.append(byte_value)

                    # Check for delimiter
                    if len(message_bytes) >= 8:
                        try:
                            chunk = bytes(message_bytes[-8:]).decode('utf-8')
                            if "<<<END>>>" in chunk:
                                message_bytes = message_bytes[:-8]  # Remove delimiter
                                break
                        except:
                            continue

            message = bytes(message_bytes).decode('utf-8', errors='ignore')
            return message
        except Exception as e:
            raise ValueError(f"Failed to extract message from audio: {str(e)}")

    @staticmethod
    def hide_message_in_video(carrier_data, message):
        """Hide message in MP4 video using frame-based steganography"""
        try:
            # Save video to temporary file
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_input:
                temp_input.write(carrier_data)
                temp_input_path = temp_input.name

            cap = cv2.VideoCapture(temp_input_path)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

            # Add message delimiter
            message_with_delim = message + "<<<END>>>"
            message_bytes = message_with_delim.encode('utf-8')
            message_bits = ''.join(format(byte, '08b') for byte in message_bytes)

            # Calculate frames needed (use every 10th frame for stealth)
            frames_to_use = max(1, (len(message_bits) // (width * height * 3)) + 1)
            frame_interval = max(1, frame_count // frames_to_use)

            frames = []
            bit_index = 0

            for frame_num in range(0, frame_count, frame_interval):
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
                ret, frame = cap.read()
                if ret and bit_index < len(message_bits):
                    # Convert frame to RGB
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

                    # Flatten frame for easier manipulation
                    pixels = rgb_frame.reshape(-1, 3)

                    for pixel in pixels:
                        if bit_index < len(message_bits):
                            # Modify red channel
                            pixel[0] = (pixel[0] & 0xFE) | int(message_bits[bit_index])
                            bit_index += 1
                        if bit_index < len(message_bits):
                            # Modify green channel
                            pixel[1] = (pixel[1] & 0xFE) | int(message_bits[bit_index])
                            bit_index += 1
                        if bit_index < len(message_bits):
                            # Modify blue channel
                            pixel[2] = (pixel[2] & 0xFE) | int(message_bits[bit_index])
                            bit_index += 1
                        if bit_index >= len(message_bits):
                            break

                    # Convert back to BGR and add to frames
                    modified_frame = cv2.cvtColor(rgb_frame.reshape(height, width, 3), cv2.COLOR_RGB2BGR)
                    frames.append(modified_frame)
                elif ret:
                    frames.append(frame)

            cap.release()

            # Write modified video to temporary output file
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_output:
                temp_output_path = temp_output.name

            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(temp_output_path, fourcc, fps, (width, height))

            for frame in frames:
                out.write(frame)

            out.release()

            # Read output video
            with open(temp_output_path, 'rb') as f:
                output_data = f.read()

            # Clean up temporary files
            os.unlink(temp_input_path)
            os.unlink(temp_output_path)

            return output_data
        except Exception as e:
            raise ValueError(f"Failed to hide message in video: {str(e)}")

    @staticmethod
    def extract_message_from_video(stego_data):
        """Extract hidden message from MP4 video"""
        try:
            # Save video to temporary file
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_file:
                temp_file.write(stego_data)
                temp_file_path = temp_file.name

            cap = cv2.VideoCapture(temp_file_path)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

            message_bits = []

            # Read every 10th frame (consistent with hiding method)
            for frame_num in range(0, frame_count, 10):
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
                ret, frame = cap.read()
                if ret:
                    # Convert frame to RGB
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    pixels = rgb_frame.reshape(-1, 3)

                    for pixel in pixels:
                        r, g, b = pixel
                        message_bits.append(str(r & 1))
                        message_bits.append(str(g & 1))
                        message_bits.append(str(b & 1))

                        # Check for end delimiter every 24 bits
                        if len(message_bits) >= 24:
                            chunk_bits = message_bits[-24:]
                            try:
                                chunk_bytes = ''.join([chr(int(''.join(chunk_bits[i:i+8]), 2))
                                                      for i in range(0, len(chunk_bits), 8)])
                                if "<<<END>>>" in chunk_bytes:
                                    message_bits = message_bits[:-24]
                                    break
                            except:
                                continue
                    else:
                        continue
                    break

            cap.release()

            # Convert bits to bytes
            message_bytes = []
            for i in range(0, len(message_bits), 8):
                if i + 8 <= len(message_bits):
                    byte_bits = message_bits[i:i+8]
                    byte_value = int(''.join(byte_bits), 2)
                    message_bytes.append(byte_value)

            message = bytes(message_bytes).decode('utf-8', errors='ignore')

            # Clean up temporary file
            os.unlink(temp_file_path)

            return message
        except Exception as e:
            raise ValueError(f"Failed to extract message from video: {str(e)}")

    @staticmethod
    def hide_message_in_pdf(carrier_data, message):
        """Hide message in PDF metadata"""
        try:
            # Add message delimiter
            message_with_delim = message + "<<<END>>>"

            # Open PDF document
            pdf_document = fitz.open(stream=carrier_data, filetype="pdf")

            # Hide message in PDF metadata
            metadata = pdf_document.metadata
            if not metadata:
                metadata = {}

            # Encode message and hide in custom metadata fields
            encoded_message = base64.b64encode(message_with_delim.encode('utf-8')).decode('utf-8')

            # Split message into smaller parts to hide in multiple metadata fields
            chunk_size = 100
            for i in range(0, len(encoded_message), chunk_size):
                chunk = encoded_message[i:i+chunk_size]
                field_name = f"Custom{i:03d}"
                metadata[field_name] = chunk

            # Set modified metadata
            pdf_document.set_metadata(metadata)

            # Save to bytes
            output = io.BytesIO()
            pdf_document.save(output)
            output.seek(0)

            pdf_document.close()
            return output.getvalue()
        except Exception as e:
            raise ValueError(f"Failed to hide message in PDF: {str(e)}")

    @staticmethod
    def extract_message_from_pdf(stego_data):
        """Extract hidden message from PDF metadata"""
        try:
            pdf_document = fitz.open(stream=stego_data, filetype="pdf")
            metadata = pdf_document.metadata

            if not metadata:
                pdf_document.close()
                return ""

            # Reconstruct message from metadata fields
            encoded_chunks = []
            i = 0

            while True:
                field_name = f"Custom{i:03d}"
                if field_name in metadata:
                    encoded_chunks.append(metadata[field_name])
                    i += 1
                else:
                    break

            if not encoded_chunks:
                pdf_document.close()
                return ""

            encoded_message = ''.join(encoded_chunks)

            try:
                message_bytes = base64.b64decode(encoded_message)
                message = message_bytes.decode('utf-8')

                # Remove delimiter
                if "<<<END>>>" in message:
                    message = message.replace("<<<END>>>", "")

                pdf_document.close()
                return message
            except Exception:
                pdf_document.close()
                return ""
        except Exception as e:
            raise ValueError(f"Failed to extract message from PDF: {str(e)}")

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

@app.route('/api/steganography/hide', methods=['POST'])
def steganography_hide():
    """Hide message in carrier file using steganography"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No carrier file uploaded'}), 400

        carrier_file = request.files['file']
        if carrier_file.filename == '':
            return jsonify({'error': 'No carrier file selected'}), 400

        message = request.form.get('message', '')
        if not message:
            return jsonify({'error': 'No message provided'}), 400

        if len(message) > 50000:
            return jsonify({'error': 'Message too long. Maximum 50,000 characters allowed.'}), 400

        # Get file type from filename or form
        file_type = request.form.get('file_type')
        if not file_type:
            # Extract file extension from filename
            filename = carrier_file.filename.lower()
            if filename.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                file_type = filename.split('.')[-1]
            elif filename.endswith('.wav'):
                file_type = 'wav'
            elif filename.endswith('.mp4'):
                file_type = 'mp4'
            elif filename.endswith('.pdf'):
                file_type = 'pdf'
            else:
                return jsonify({'error': 'Unsupported file format for steganography'}), 400

        # Read carrier file data
        carrier_data = carrier_file.read()

        # Validate carrier file
        if not SteganographyEngine.validate_carrier_file(carrier_data, file_type):
            return jsonify({'error': 'Invalid or corrupted carrier file'}), 400

        # Check capacity
        capacity = SteganographyEngine.calculate_capacity(carrier_data, file_type)
        if len(message.encode('utf-8')) > capacity:
            return jsonify({
                'error': 'Message too long for carrier file capacity',
                'capacity': capacity,
                'required': len(message.encode('utf-8'))
            }), 400

        # Hide message based on file type
        if file_type.lower() in ['png', 'jpg', 'jpeg', 'bmp']:
            processed_data = SteganographyEngine.hide_message_in_image(carrier_data, message)
            output_filename = f"stego_{carrier_file.filename}"
            if not output_filename.lower().endswith('.png'):
                output_filename = output_filename.rsplit('.', 1)[0] + '.png'
        elif file_type.lower() == 'wav':
            processed_data = SteganographyEngine.hide_message_in_audio(carrier_data, message)
            output_filename = f"stego_{carrier_file.filename}"
        elif file_type.lower() == 'mp4':
            processed_data = SteganographyEngine.hide_message_in_video(carrier_data, message)
            output_filename = f"stego_{carrier_file.filename}"
        elif file_type.lower() == 'pdf':
            processed_data = SteganographyEngine.hide_message_in_pdf(carrier_data, message)
            output_filename = f"stego_{carrier_file.filename}"
        else:
            return jsonify({'error': 'Unsupported file format for steganography'}), 400

        # Save processed file temporarily
        temp_filename = str(uuid.uuid4()) + '_' + output_filename
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)

        with open(temp_path, 'wb') as f:
            f.write(processed_data)

        # Return success response with file info
        return jsonify({
            'success': True,
            'message': 'Message successfully hidden in file',
            'output_file': temp_filename,
            'original_filename': carrier_file.filename,
            'output_filename': output_filename,
            'file_size': len(processed_data),
            'capacity_used': len(message.encode('utf-8')),
            'capacity_remaining': max(0, capacity - len(message.encode('utf-8'))),
            'steganography_type': file_type
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/steganography/extract', methods=['POST'])
def steganography_extract():
    """Extract hidden message from steganography file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        stego_file = request.files['file']
        if stego_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Get file type from filename or form
        file_type = request.form.get('file_type')
        if not file_type:
            # Extract file extension from filename
            filename = stego_file.filename.lower()
            if filename.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                file_type = filename.split('.')[-1]
            elif filename.endswith('.wav'):
                file_type = 'wav'
            elif filename.endswith('.mp4'):
                file_type = 'mp4'
            elif filename.endswith('.pdf'):
                file_type = 'pdf'
            else:
                return jsonify({'error': 'Unsupported file format for steganography'}), 400

        # Read stego file data
        stego_data = stego_file.read()

        # Validate file
        if not SteganographyEngine.validate_carrier_file(stego_data, file_type):
            return jsonify({'error': 'Invalid or corrupted file'}), 400

        # Extract message based on file type
        if file_type.lower() in ['png', 'jpg', 'jpeg', 'bmp']:
            extracted_message = SteganographyEngine.extract_message_from_image(stego_data)
        elif file_type.lower() == 'wav':
            extracted_message = SteganographyEngine.extract_message_from_audio(stego_data)
        elif file_type.lower() == 'mp4':
            extracted_message = SteganographyEngine.extract_message_from_video(stego_data)
        elif file_type.lower() == 'pdf':
            extracted_message = SteganographyEngine.extract_message_from_pdf(stego_data)
        else:
            return jsonify({'error': 'Unsupported file format for steganography'}), 400

        if not extracted_message:
            return jsonify({
                'success': True,
                'message': 'No hidden message found in file',
                'extracted_message': '',
                'message_length': 0
            })

        return jsonify({
            'success': True,
            'message': 'Message successfully extracted from file',
            'extracted_message': extracted_message,
            'message_length': len(extracted_message),
            'steganography_type': file_type
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/steganography/analyze', methods=['POST'])
def steganography_analyze():
    """Analyze carrier file for steganography capacity and properties"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        analysis_file = request.files['file']
        if analysis_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Get file type from filename or form
        file_type = request.form.get('file_type')
        if not file_type:
            # Extract file extension from filename
            filename = analysis_file.filename.lower()
            if filename.endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                file_type = filename.split('.')[-1]
            elif filename.endswith('.wav'):
                file_type = 'wav'
            elif filename.endswith('.mp4'):
                file_type = 'mp4'
            elif filename.endswith('.pdf'):
                file_type = 'pdf'
            else:
                return jsonify({'error': 'Unsupported file format for steganography'}), 400

        # Read file data
        file_data = analysis_file.read()

        # Validate file
        if not SteganographyEngine.validate_carrier_file(file_data, file_type):
            return jsonify({'error': 'Invalid or corrupted file'}), 400

        # Calculate capacity and get file info
        capacity = SteganographyEngine.calculate_capacity(file_data, file_type)

        # Try to extract any existing message
        try:
            if file_type.lower() in ['png', 'jpg', 'jpeg', 'bmp']:
                existing_message = SteganographyEngine.extract_message_from_image(file_data)
            elif file_type.lower() == 'wav':
                existing_message = SteganographyEngine.extract_message_from_audio(file_data)
            elif file_type.lower() == 'mp4':
                existing_message = SteganographyEngine.extract_message_from_video(file_data)
            elif file_type.lower() == 'pdf':
                existing_message = SteganographyEngine.extract_message_from_pdf(file_data)
            else:
                existing_message = ""
        except:
            existing_message = ""

        has_hidden_message = bool(existing_message and existing_message.strip())

        return jsonify({
            'success': True,
            'analysis': {
                'file_type': file_type,
                'file_size': len(file_data),
                'maximum_capacity': capacity,
                'capacity_remaining': max(0, capacity - len(existing_message.encode('utf-8'))) if has_hidden_message else capacity,
                'supports_steganography': True,
                'has_hidden_message': has_hidden_message,
                'existing_message_length': len(existing_message) if has_hidden_message else 0
            }
        })

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
