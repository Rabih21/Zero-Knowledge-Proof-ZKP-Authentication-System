# app.py
import os
import base64
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Directory to store uploaded files temporarily
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from the password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_data: bytes, password: str) -> bytes:
    """Encrypt file data using AES-256-CBC"""
    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Pad the data to be compatible with block cipher
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return salt + IV + encrypted data
    return salt + iv + encrypted_data

def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt file data using AES-256-CBC"""
    # Extract salt, IV, and encrypted data
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    try:
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        return original_data
    except ValueError:
        raise ValueError("Invalid password or corrupted file")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not password:
        flash('Password is required')
        return redirect(url_for('index'))
    
    try:
        # Read file data
        file_data = file.read()
        
        # Encrypt the file
        encrypted_data = encrypt_file(file_data, password)
        
        # Create a BytesIO object for the encrypted data
        encrypted_io = io.BytesIO(encrypted_data)
        encrypted_io.seek(0)
        
        # Generate output filename
        original_name = secure_filename(file.filename)
        output_name = f"{original_name}.encrypted"
        
        return send_file(
            encrypted_io,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name
        )
    except Exception as e:
        flash(f'Encryption failed: {str(e)}')
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not password:
        flash('Password is required')
        return redirect(url_for('index'))
    
    try:
        # Read encrypted file data
        encrypted_data = file.read()
        
        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data, password)
        
        # Create a BytesIO object for the decrypted data
        decrypted_io = io.BytesIO(decrypted_data)
        decrypted_io.seek(0)
        
        # Generate output filename
        original_name = secure_filename(file.filename)
        if original_name.endswith('.encrypted'):
            output_name = original_name[:-10]  # Remove .encrypted extension
        else:
            output_name = f"decrypted_{original_name}"
        
        return send_file(
            decrypted_io,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name
        )
    except ValueError as e:
        flash('Decryption failed: Invalid password or corrupted file')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Decryption failed: {str(e)}')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)