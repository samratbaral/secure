# Steganography
from type.video.video import video
from type.text.text import text
from type.audio.audio import audio
from type.image.image import image

# hashing, password, keys, rsa, aes
# from privacy.file.file import file
# from privacy.aes.aes import aes
# from privacy.rsa.rsa import rsa
from privacy.generate.generate import generate

import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
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
        hashed_password = generate_password_hash(password, method='sha256')
        return hashed_password

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


with app.app_context():
    db.create_all()


app.register_blueprint(image, url_prefix="/image")
app.register_blueprint(audio, url_prefix="/audio")
app.register_blueprint(text, url_prefix="/text")
app.register_blueprint(video, url_prefix="/video")

# Landing Page



# Home: User Home: Let User do Steganography, Hashing, Password, Keys, RSA, AES
@app.route("/")
def home():
    return render_template("home.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# About: Secure App About Page

@app.route("/user")
def user():
    return render_template('user.html')

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






@app.route("/about")
def about():
    return render_template("about.html")


# Account: User Account Page: Similar to Wallet
@app.route("/account")
def account():
    return render_template("account.html")


if __name__ == "__main__":
    app.run(debug=True)
