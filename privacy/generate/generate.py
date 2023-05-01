import random
import string
from flask import Blueprint, render_template, current_app, url_for, redirect, request, session, flash
import os
import rsa
from Crypto.PublicKey import RSA
from PIL import Image
import stepic
import shutil
from datetime import timedelta

generate = Blueprint("generate", __name__, static_folder="static",
                     template_folder="templates")


# @generate.route("/password")
# def generate_password():
#     if os.path.exists(current_app.config['GENERATE_CACHE_FOLDER']):
#         shutil.rmtree(
#             current_app.config['GENERATE_CACHE_FOLDER'], ignore_errors=False)
#     else:
#         print("Not Found")

#         if os.path.exists(os.path.join(current_app.config['UPLOAD_GENERATE__FOLDER'], "encrypted_generate_password.txt")):
#             # print("Found")
#             os.remove(os.path.join(
#                 current_app.config['UPLOAD_GENERATE__FOLDER'], "encrypted_generate_password.txt"))
#         else:
#             print("Not found")
#     return render_template("password-generate.html")


# @generate.route("/password-result", method=['POST', 'GET'])
# def generate_password():
#     if request.method == 'POST':
#         pass_length = int(request.form['password_length'])
#         password = generate_password(pass_length)
#         return render_template("password-result.html", password=password)


# @generate.route("/key", method=['POST'])
# def generate_key():
#     return render_template("key-generate.html")


# @generate.route("/key-result", method=['POST', 'GET'])
# def generate_password():
#     if request.method == 'POST':
#         rsa_key = generate_keys()
#         return render_template("key-result.html", rsa_key=rsa_key)


# def generate_password(length):
#     characters = string.ascii_letters + string.digits + string.punctuation
#     password = ''.join(random.choice(characters) for i in range(length))
#     return password


# def generate_keys():
#     key = rsa.newkeys(2048)
#     private = key.export_key().decode()
#     public = key.publickey().export_key().decode()
#     return private, public
