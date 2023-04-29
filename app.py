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
    }
}

app = Flask(__name__)

app.secret_key = "hello"

for mode, folders in MODES.items():
    app.config['UPLOAD_' + mode.upper() + '_FOLDER'] = folders['upload_folder']
    app.config[mode.upper() + '_CACHE_FOLDER'] = folders['cache_folder']

from type.image.image import image
# from type.audio.audio import audio
from type.text.text import text
from type.video.video import video

app.register_blueprint(image, url_prefix="/image")
# app.register_blueprint(audio, url_prefix="/audio")
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

if __name__ == "__main__":
    app.run(debug=True)
