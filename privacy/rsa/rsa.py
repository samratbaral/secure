import random
import string
from flask import Blueprint, app, render_template, current_app, url_for, redirect, request, session, flash
import os
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import stepic
import shutil
from datetime import timedelta
from werkzeug.utils import secure_filename

FILE_EXT = {'txt', 'pdf', 'png', 'docx', 'xlsx', 'pptx'}
rsa = Blueprint("rsa", __name__, static_folder="static",
                     template_folder="templates")
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


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in FILE_EXT


def save_file(file):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename
