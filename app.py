# hashing, password, keys, rsa, aes
from privacy.rsa.rsa import rsa
from privacy.aes.aes import aes
from privacy.file.file import file
from privacy.generate.generate import generate
# Steganography
from type.image.image import image
from type.audio.audio import audio
from type.text.text import text
from type.video.video import video
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from user_form import EmailFormMixin, PasswordFormMixin, SecurityQuestionFormMixin, RegistrationForm, LoginForm, PasswordResetForm
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
import ecdsa
import secrets
from io import BytesIO
from werkzeug.utils import secure_filename
from hashlib import sha256


app = Flask(__name__)

FILE_EXT = {'txt', 'pdf', 'png', 'docx', 'xlsx', 'pptx'}
app.secret_key = "hello"

MODES = {
    'Image': {
        'upload_folder': 'type/image/static',
        'cache_folder': 'type/image/__pycache__'
    },
    'Text': {
        'upload_folder': 'type/text/static',
        'cache_folder': 'type/text/__pycache__'
    },
    'Audio': {
        'upload_folder': 'type/audio/static',
        'cache_folder': 'type/audio/__pycache__'
    },
    'Video': {
        'upload_folder': 'type/video/static',
        'cache_folder': 'type/video/__pycache__'
    },
    'Generate': {
        'upload_folder': 'privacy/generate/static',
        'cache_folder': 'privacy/generate/__pycache__'
    },
    'RSA': {
        'upload_folder': 'privacy/rsa/static',
        'cache_folder': 'privacy/rsa/__pycache__'
    },
    'AES': {
        'upload_folder': 'privacy/aes/static',
        'cache_folder': 'privacy/aes/__pycache__'
    },
    'File': {
        'upload_folder': 'privacy/file/static',
        'cache_folder': 'privacy/file/__pycache__'
    }
}
for mode, folders in MODES.items():
    app.config['UPLOAD_' + mode.upper() + '_FOLDER'] = folders['upload_folder']
    app.config[mode.upper() + '_CACHE_FOLDER'] = folders['cache_folder']

app.register_blueprint(image, url_prefix="/image")
app.register_blueprint(audio, url_prefix="/audio")
app.register_blueprint(text, url_prefix="/text")
app.register_blueprint(video, url_prefix="/video")
app.register_blueprint(generate, url_prefix="/generate")
app.register_blueprint(file, url_prefix="/file")
app.register_blueprint(rsa, url_prefix="/rsa")
app.register_blueprint(aes, url_prefix="/aes")


# Database Setup SQLITE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)

# User Activity Management
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Schema


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)

    @staticmethod
    def generate_password_hash(password):
        hashed_password = generate_password_hash(password)
        return hashed_password

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


with app.app_context():
    db.create_all()

# Landing Page Home: User Home


@app.route("/")
def home():
    return render_template("home.html")

# User do Steganography, Hashing, Password, Keys, RSA, AES


@app.route("/steganography")
@login_required
def steganography():
    return render_template("steganography.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register Page


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        user.security_question = form.security_question.data
        user.security_answer = form.security_answer.data
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))
    print(form)
    return render_template('register.html', form=form)

# Login Page


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

# Logout Page


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Forgot Password Page


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.security_question == form.security_question.data and user.security_answer == form.security_answer.data:
            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password reset successful. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email, security question or security answer.', 'danger')
    return render_template('forgot_password.html', form=form)

# About: Secure App About Page


@app.route("/about")
def about():
    return render_template("about.html")


# Account: User Account Page: Similar to Wallet
@app.route("/account")
def account():
    return render_template("account.html")

# Account: User Account Page: Similar to Wallet


@app.route("/dashboard")
def dashboard():
    return render_template("template.html")


# 3-DES Encryption and Decryption
def des3_encrypt(plain_text, key, mode, iv=None):
    if mode in (DES3.MODE_CBC, DES3.MODE_CFB, DES3.MODE_OFB):
        cipher = DES3.new(key, mode, iv)
    else:
        cipher = DES3.new(key, mode)
    return cipher.encrypt(pad(plain_text, 8))


def des3_decrypt(cipher_text, key, mode, iv=None):
    if mode in (DES3.MODE_CBC, DES3.MODE_CFB, DES3.MODE_OFB):
        cipher = DES3.new(key, mode, iv)
    else:
        cipher = DES3.new(key, mode)
    return unpad(cipher.decrypt(cipher_text), 8)

# AES Encryption and Decryption


def aes_encrypt(plain_text, key, mode, iv=None):
    if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
        cipher = AES.new(key, mode, iv)
    else:
        cipher = AES.new(key, mode)
    return cipher.encrypt(pad(plain_text, 16))


def aes_decrypt(cipher_text, key, mode, iv=None):
    if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
        cipher = AES.new(key, mode, iv)
    else:
        cipher = AES.new(key, mode)
    return unpad(cipher.decrypt(cipher_text), 16)

# RSA Key Generation, Encryption, and Decryption


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(plain_text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(plain_text)


def rsa_decrypt(cipher_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(cipher_text)

# SHA-2 and SHA-3 Hashing


def sha2_hash(text, bit_size=256):
    if bit_size == 256:
        h = SHA256.new()
    elif bit_size == 512:
        h = SHA512.new()
    else:
        raise ValueError("Invalid bit size")
    h.update(text)
    return h.hexdigest()


def sha3_hash(text, bit_size=256):
    if bit_size == 256:
        h = SHA3_256.new()
    elif bit_size == 512:
        h = SHA3_512.new()
    else:
        raise ValueError("Invalid bit size")
    h.update(text)
    return h.hexdigest()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def genPassword(password_length):
    return secrets.token_hex(password_length)[:password_length]


def save_file(file):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


@app.route('/generate_password', methods=['GET', 'POST'])
@login_required
def generate_password():
    result = ""
    if request.method == "POST":
        password_length = int(request.form["length"])
        password = genPassword(password_length)
        result = f"Generated Password: {password}"
    return render_template("generatePassword.html", result=result)


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part"
        file = request.files['file']
        if file.filename == '':
            return "No selected file"
        if file and allowed_file(file.filename):
            filename = save_file(file)
            return "File uploaded and saved."
    return render_template("fileUploadDownload.html")


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt_file():
    # Implement the encryption logic based on user input
    # Get user input from the form and call the appropriate encryption function
    result = ""
    if request.method == "POST":
        file = request.files["file"]
        if not file or file.filename == "":
            flash("Forgot to upload file")
        else:
            plaintext = file.read()
            method = request.form["encryption_method"]
            key = request.form['key'].encode('utf-8')
            mode = int(request.form["mode"])
            iv = request.form["iv"].encode()

            if method == "3des":
                result = des3_encrypt(plaintext, key, mode, iv)
            elif method == "aes":
                result = aes_encrypt(plaintext, key, mode, iv)
            elif method == "rsa":
                # public_key = request.form["public_key"].encode()
                result = rsa_encrypt(plaintext, key)
            else:
                result = "Invalid encryption method selected"
                return render_template("encryptFile.html", result=result)

            return send_file(
                BytesIO(result),
                as_attachment=True,
                download_name=file.filename,
                mimetype="application/octet-stream",
            )

    return render_template("encryptFile.html", result=result)


@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt_file():
    # Implement the decryption logic based on user input
    # Get user input from the form and call the appropriate decryption function
    result = ""
    if request.method == "POST":
        print(request.files)
        file = request.files["file"]
        if not file or file.filename == "":
            flash("Forgot to upload file")
        else:
            ciphertext = file.read()
            method = request.form["decryption_method"]
            key = request.form["key"].encode()
            mode = int(request.form["mode"])
            iv = request.form["iv"].encode()

            if method == "3des":
                result = des3_decrypt(ciphertext, key, mode, iv)
            elif method == "aes":
                result = aes_decrypt(ciphertext, key, mode, iv)
            elif method == "rsa":
                # private_key = request.form["private_key"].encode()
                private_key = key
                result = rsa_decrypt(ciphertext, private_key)
            else:
                result = "Invalid decryption method selected"
                return render_template("decryptFile.html", result=result)

            return send_file(
                BytesIO(result),
                as_attachment=True,
                download_name=file.filename,
                mimetype="application/octet-stream",
            )

    return render_template("decryptFile.html", result=result)


@app.route("/hash", methods=["GET", "POST"])
@login_required
def hash_file():
    # Get the input text and selected hashing algorithm from the form
    result = ""
    if request.method == "POST":
        file = request.files["file"]
        if not file or file.filename == "":
            flash("Forgot to upload file")
        else:
            text_to_hash = file.read()  # request.form["text_to_hash"]
            selected_algorithm = request.form["selected_algorithm"]

            # Call the appropriate hashing function
            if selected_algorithm == "sha2_256":
                result = sha2_hash(text_to_hash, bit_size=256)
            elif selected_algorithm == "sha2_512":
                result = sha2_hash(text_to_hash, bit_size=512)
            elif selected_algorithm == "sha3_256":
                result = sha3_hash(text_to_hash, bit_size=256)
            elif selected_algorithm == "sha3_512":
                result = sha3_hash(text_to_hash, bit_size=512)
            else:
                result = "Error: Invalid hashing algorithm selected"
                return render_template("hashFile.html", result=result)

            result = "Hash: " + result

    return render_template("hashFile.html", result=result)


@app.route("/compare_hashes", methods=["GET", "POST"])
@login_required
def compare_hashes():
    result = ""
    if request.method == "POST":
        # Get the uploaded files
        file1 = request.files["file1"]
        file2 = request.files["file2"]

        # Check if the files are allowed
        if not file1 or not file2 or not allowed_file(file1.filename) or not allowed_file(file2.filename):
            flash("Please upload two files with allowed extensions", "error")
            return redirect(url_for("index"))

        # Save the files and compute their SHA-256 hashes
        # file1_name = save_file(file1)
        # file2_name = save_file(file2)
        # with open(os.path.join(app.config['UPLOAD_FOLDER'], file1_name), "rb") as f:
        hash1 = sha256(file1.read()).hexdigest()
        # with open(os.path.join(app.config['UPLOAD_FOLDER'], file2_name), "rb") as f:
        hash2 = sha256(file2.read()).hexdigest()

        # Compare the hashes and return the result
        if hash1 == hash2:
            result = "The two files have the same SHA-256 hash"
        else:
            result = "The two files have different SHA-256 hashes"

    return render_template("compareHashes.html", result=result)


def rsa_pss_sign(message, private_key):
    # Import the private key
    key = RSA.import_key(private_key)

    # Hash the message
    h = SHA256.new(message.encode())

    # Sign the hash using RSA-PSS
    signature = pkcs1_15.new(key).sign(h)

    return signature.hex()


def rsa_pss_verify(message, signature, public_key):
    # Import the public key
    key = RSA.import_key(public_key)

    # Hash the message
    h = SHA256.new(message.encode())

    # Verify the signature using RSA-PSS
    try:
        pkcs1_15.new(key).verify(h, bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def ecdsa_sign(message, private_key):
    # Import the private key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)

    # Sign the message using ECDSA
    signature = sk.sign(message.encode())

    return signature.hex()


def ecdsa_verify(message, signature, public_key):
    # Import the public key
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)

    # Verify the message using ECDSA
    try:
        return vk.verify(bytes.fromhex(signature), message.encode())
    except (ValueError, TypeError):
        return False


@app.route("/generate_key", methods=["GET", "POST"])
def generate_key():
    result = ""
    if request.method == "POST":
        # Call the appropriate key generation function based on user input
        method = request.form["key_generation_method"]

        if method == "rsa":
            private_key, public_key = generate_rsa_keys()
            result = f"Private Key:\n{private_key.decode()}\n\nPublic Key:\n{public_key.decode()}"
        else:
            result = "Invalid key generation method selected"
    return render_template("generatekey.html", result=result)


@app.route("/sign", methods=["POST"])
@login_required
def sign():
    # Implement the signing logic based on user input
    # Get user input from the form and call the appropriate signing function

    text_to_sign = request.form["text_to_sign"]
    private_key = request.form["private_key"].encode()
    signature_algorithm = request.form["signature_algorithm"]

    # Call the appropriate signing function based on the selected algorithm
    # (You will need to implement these functions)

    if signature_algorithm == "rsa_pss":
        result = rsa_pss_sign(text_to_sign, private_key)
    elif signature_algorithm == "ecdsa":
        result = ecdsa_sign(text_to_sign, private_key)
    else:
        result = "Invalid signing algorithm selected"

    return render_template("result.html", result=result)


@app.route("/verify", methods=["POST"])
def verify():
 # Implement the verification logic based on user input
    # Get user input from the form and call the appropriate verification function

    text_to_verify = request.form["text_to_verify"]
    public_key = request.form["public_key"].encode()
    signature = request.form["signature"].encode()
    verification_algorithm = request.form["verification_algorithm"]

    # Call the appropriate verification function based on the selected algorithm
    # (You will need to implement these functions)

    if verification_algorithm == "rsa_pss":
        result = rsa_pss_verify(text_to_verify, public_key, signature)
    elif verification_algorithm == "ecdsa":
        result = ecdsa_verify(text_to_verify, public_key, signature)
    else:
        result = "Invalid verification algorithm selected"

    return render_template("result.html", result=result)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
