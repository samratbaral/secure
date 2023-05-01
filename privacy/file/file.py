import random
import string
import os
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES3
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import stepic
import shutil
from datetime import timedelta
from flask import Flask, Blueprint, app, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
import ecdsa
import secrets
from io import BytesIO
from flask import send_from_directory
from werkzeug.utils import secure_filename
from hashlib import sha256

FILE_EXT = {'txt', 'pdf', 'png', 'docx', 'xlsx', 'pptx'}

file = Blueprint("file", __name__, static_folder="static",
                 template_folder="templates")
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
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in FILE_EXT


def save_file(file):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename

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
