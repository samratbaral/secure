import os
from flask import Flask, render_template

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

app = Flask(__name__)

app.secret_key = "hello"

for mode, folders in MODES.items():
    app.config['UPLOAD_' + mode.upper() + '_FOLDER'] = folders['upload_folder']
    app.config[mode.upper() + '_CACHE_FOLDER'] = folders['cache_folder']

# Steganography
from type.image.image import image
from type.audio.audio import audio
from type.text.text import text
from type.video.video import video

# hashing, password, keys,rsa, aes
from privacy.generate.generate import generate
# from privacy.rsa.rsa import rsa
# from privacy.aes.aes import aes
# from privacy.file.file import file


app.register_blueprint(image, url_prefix="/image")
app.register_blueprint(audio, url_prefix="/audio")
app.register_blueprint(text, url_prefix="/text")
app.register_blueprint(video, url_prefix="/video")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/salvador")
def salvador():
    return "Hello, Salvador"

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/account")
def account():
    return render_template("account.html")

if __name__ == "__main__":
    app.run(debug=True)
