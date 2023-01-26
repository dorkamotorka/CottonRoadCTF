import os
from flask import request, redirect, url_for, render_template, make_response, jsonify, send_file, abort, current_app
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
from . import server_api_blueprint
from ..models import Users
from .. import logging
import socket


@server_api_blueprint.route("/")
def index():
    logging.debug("/ endpoint called on fileserver")
    return redirect(url_for("server_auth_blueprint.login"))


@server_api_blueprint.route('/file', methods=['GET'])
def get_file():
    logging.debug("/file endpoint on file server called")
    name = request.args.get('image_name')

    if request.headers.get('ACCESS_APIKEY') != current_app.config["ACCESS_APIKEY"]:
        logging.error("Failed to authenticate webshop to file_server")
        abort(403, "Failed authentication")
    if not name:
        logging.error("Missing image name")
        abort(400, "Missing file name")
    try:
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], name)
        logging.debug(f"Trying to retrieve file from {path}")
        if not os.path.exists(path):
            raise Exception
        return send_file(path)
    except:
        logging.error("Failed to retrieve file from directory")
        abort(410, "Failed to retrieve file from directory")
