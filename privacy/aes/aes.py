import random
import string
from flask import Blueprint, app, render_template, current_app, url_for, redirect, request, session, flash
import os
import rsa
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import stepic
import shutil
from datetime import timedelta
from werkzeug.utils import secure_filename

FILE_EXT = {'txt', 'pdf', 'png', 'docx', 'xlsx', 'pptx'}
aes = Blueprint("aes", __name__, static_folder="static",
                     template_folder="templates")


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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in FILE_EXT


def save_file(file):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename
