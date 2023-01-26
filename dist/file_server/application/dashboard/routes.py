from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_required
from . import server_dashboard_blueprint
import re
from flask_login import login_required, current_user
import os
import hashlib
from ..models import Users
import base64
from werkzeug.utils import secure_filename
from .. import logging
from time import sleep
import requests

@server_dashboard_blueprint.route('', methods=['GET'])
@login_required
def getFiles():
    logging.debug("/dashboard endpoint GET method called on file server")
    return render_template('dashboard.html', image_list=getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]

def isAlphanumeric(text):
    if text is not None and re.match("^[a-zA-Z0-9]+$", text) is not None:
        logging.info(f"{text} is alphanumeric")
        return True
    logging.error(f"{text} is not alphanumeric")
    return False

def getImages() -> list:
    images = list()
    user_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], hashlib.md5(current_user.get_id().encode()).hexdigest())
    for f in os.listdir(user_dir):
        image = open(os.path.join(user_dir, f),'rb').read()
        images.append({"name": f, "image": base64.b64encode(image).decode()})
    return images

@server_dashboard_blueprint.errorhandler(413)
@login_required
def largefile_error(e):
    return render_template("dashboard.html", error="File too large max. 100 KB!", image_list = getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"])

@server_dashboard_blueprint.route('', methods=['POST'])
@login_required
def upload_file():
    logging.debug("/dashboard endpoint POST method called on file server")
    if 'file' not in request.files:
        logging.error("No file parameter was specified while uploading a file")
        return render_template("dashboard.html", error="no file was specified!", image_list=getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"]), 400

    f = request.files['file']

    if f.filename == '':
        logging.error("No filename was specified while uploading a file")
        return render_template("dashboard.html", error="the file has no filename!", image_list=getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"]), 400

    dirs = (f.filename).split("/")

    splitted = (dirs[-1]).split(".")
    if len(splitted) != 2:
        logging.error(f"user {current_user.get_id()} tried to upload a file with 2 or more dots!")
        return render_template("dashboard.html", error="not an allowed file", username=current_user.username, ip=current_app.config["PUBLIC_IP"])
    name, extension = splitted

    if isAlphanumeric(name) and extension in current_app.config["ALLOWED_EXTENSIONS"]:
        hashed_email = hashlib.md5(current_user.get_id().encode()).hexdigest()
        filename = secure_filename(f"{name}.{extension}")
        base_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], hashed_email)
        p = os.path.join(base_dir, "/".join(dirs))
        if len(os.listdir(base_dir)) == current_app.config["MAX_FILE_UPLOADS"]:
            logging.error(f"user {current_user.get_id()} attempted to upload more than 6 files!")
            return render_template("dashboard.html", error="you can't upload more than 6 files!", image_list = getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"])
        logging.debug(f"file will be stored under {p}")
        f.save(p)
        return redirect(url_for("server_dashboard_blueprint.getFiles"))

    logging.error("Bad file upload request!")
    return render_template("dashboard.html", error="the filename must be alphanumeric and has to have the extension: "
                                                   "jpg, jpeg, or png", image_list=getImages(), username=current_user.username, ip=current_app.config["PUBLIC_IP"]), 415
