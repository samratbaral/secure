import random
import string
from flask import Blueprint, render_template, current_app, url_for, redirect, request, session, flash
import os
import rsa
from Crypto.PublicKey import RSA

generate = Blueprint("generate", __name__, static_folder="static",
                     template_folder="templates")


@generate.route("/password")
def generate_password():
    return render_template("password-generate.html")

@generate.route("/password-result", method=['POST','GET'])
def generate_password():
    if request.method == 'POST':
        pass_length = int(request.form['password_length'])
        password = generate_password(pass_length)
        return render_template("password-result.html", password=password)

@generate.route("/key", method=['POST'])
def generate_key():
    return render_template("key-generate.html")

@generate.route("/key-result", method=['POST','GET'])
def generate_password():
     if request.method == 'POST':
        rsa_key = generate_keys()
        return render_template("key-result.html", rsa_key=rsa_key)

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def generate_keys():
    key = rsa.newkeys(2048)
    private = key.export_key().decode()
    public = key.publickey().export_key().decode()
    return private, public
