from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import os
from io import BytesIO

app = Flask(__name__)

MAGIC = b"FILEENC2"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERS = 390000

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password)

def encrypt_file(password, file_data, filename):
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)

    original_name = filename.encode('utf-8')
    name_len = len(original_name)
    header_name = bytes([name_len]) + original_name

    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    encrypted = MAGIC + salt + nonce + header_name + ciphertext
    return BytesIO(encrypted), filename + ".enc"

def decrypt_file(password, file_data):
    content = file_data.read()
    if content[:len(MAGIC)] != MAGIC:
        raise ValueError("Invalid file")
    offset = len(MAGIC)
    salt = content[offset:offset+SALT_SIZE]; offset += SALT_SIZE
    nonce = content[offset:offset+NONCE_SIZE]; offset += NONCE_SIZE

    name_len = content[offset]; offset += 1
    original_name = content[offset:offset+name_len].decode('utf-8'); offset += name_len

    ciphertext = content[offset:]
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return BytesIO(plaintext), original_name

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files['file']
    password = request.form['password']
    encrypted_io, filename = encrypt_file(password, file.read(), file.filename)
    encrypted_io.seek(0)
    return send_file(encrypted_io, as_attachment=True, download_name=filename)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files['file']
    password = request.form['password']
    try:
        decrypted_io, filename = decrypt_file(password, file)
    except Exception as e:
        return f"Decryption failed: {str(e)}"
    decrypted_io.seek(0)
    return send_file(decrypted_io, as_attachment=True, download_name=filename)

if __name__ == "__main__":
    app.run(debug=True)
