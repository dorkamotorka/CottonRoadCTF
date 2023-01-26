import base64
import json
import random
import string
from io import BytesIO
from functools import wraps
from authlib.jose import jwt, JsonWebKey, JWK_ALGORITHMS
import requests
import re
from flask import *
from . import server_api_blueprint
from .. import oauth, logging
from ..db import get_db
from ..models import *
import base64
import hashlib


@server_api_blueprint.route("/rsa_pub")
def jwtPub():
    jwk = JsonWebKey(algorithms=JWK_ALGORITHMS)
    return jsonify(jwk.dumps(current_app.config["JWT_PUBLIC_KEY"], kty="RSA"))


@server_api_blueprint.route("/oauth/login")
def oauth_login():
    logging.debug("/oauth/login endpoint called on webshop")
    redirect_uri = f"http://{current_app.config['PUBLIC_IP']}:10100/oauth/auth"
    logging.debug(f"Redirect uri in the /oauth/login is {redirect_uri}")
    return oauth.fileserver.authorize_redirect(redirect_uri)


@server_api_blueprint.route("/oauth/auth")
def oauth_auth():
    logging.debug("/oauth/auth endpoint called on webshop")
    session["_fileserver_authlib_state_"] = request.args.get("state")
    token = oauth.fileserver.authorize_access_token()
    try:
        res = oauth.fileserver.get("http://cottonroad-file-server:10101/oauth/username")
    except requests.exceptions.ConnectionError as e:
        return "Internal error", 500
    data = json.loads(res.text)
    username = data["username"]
    email = data["mail"]

    existing_user = User.get_from_email(email)
    username_check = User.get_from_username(username)

    if existing_user is None:
        if username_check is None:
            user = User(email=email, username=username, password=None)
            user.insert()
        else:
            user = username_check
        existing_user = user
    token = jwt.encode(
        {"alg": "RS256"},
        {"user": existing_user.username},
        current_app.config["JWT_PRIVATE_KEY"],
    )
    resp = make_response(redirect(url_for("server_api_blueprint.profile")))
    resp.set_cookie("access-token", token, samesite="Strict")
    return resp


def check_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logging.debug("check_token function called on webshop")
        cookie = request.cookies.get("access-token")
        if cookie:
            try:
                token = jwt.decode(cookie, current_app.config["JWT_PUBLIC_KEY"])
                logging.debug(f"This is the user token '{token}'")
                result = User.get_from_username(token["user"])
                logging.debug(f"This is the User from decoded token '{result}'")

                if result is None:
                    logging.error("Token correspoding to a user, doesn't exist!")
                    resp = make_response(redirect(url_for("login_api_blueprint.login")))
                    resp.set_cookie("access-token", "", samesite="Strict")
                    return resp
            except Exception as e:
                logging.error(e)
                resp = make_response(redirect(url_for("login_api_blueprint.login")))
                resp.set_cookie("access-token", "", samesite="Strict")
                return resp
            return func(*args, **kwargs)
        logging.warn("No cookie access-token found. Redirecting to login page!")
        return redirect(url_for("login_api_blueprint.login"))

    return wrapper


@server_api_blueprint.route("/profile", methods=["GET"])
@check_token
def profile():
    logging.debug("/profile endpoint called on webshop")
    username = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )["user"]
    return render_template(
        "profile.html", username=username, ip=current_app.config["PUBLIC_IP"]
    )


@server_api_blueprint.route("/")
def index():
    logging.debug("/ endpoint called on webshop")
    return redirect(url_for("server_api_blueprint.profile"))
