from .. import logging
from flask import (
    make_response,
    current_app,
    request,
    render_template,
    redirect,
    url_for,
)
from authlib.jose import jwt
from ..models import *
from . import login_api_blueprint
import re
from werkzeug.security import check_password_hash


def isAlphanumeric(text):
    if text is not None and re.match("^[a-zA-Z0-9]+$", text) is not None:
        logging.debug(f"{text} is alphanumeric")
        return True

    logging.debug(f"{text} is not alphanumeric")
    return False


@login_api_blueprint.route("/login", methods=["POST", "GET"])
def login():
    logging.debug("/login endpoint called on webshop")
    cookie = request.cookies.get("access-token")
    if cookie is not None:
        try:
            token = jwt.decode(cookie, current_app.config["JWT_PUBLIC_KEY"])
            result = User.get_from_username(token["user"])

            if result is None:
                logging.error("Token correspoding to a user, doesn't exist!")
                resp = make_response(
                    render_template("login.html", ip=current_app.config["PUBLIC_IP"])
                )
                resp.set_cookie("access-token", "", samesite="Strict")
                return resp, 400
            return redirect(url_for("server_api_blueprint.profile"))
        except Exception as e:
            logging.error(e)
            logging.error("Failed to decode a user token!")
            pass

    if request.method == "GET":
        return render_template("login.html", ip=current_app.config["PUBLIC_IP"])

    email = request.form.get("email")
    password = request.form.get("password")

    if email is None or password is None:
        logging.error("Either email or password input parameter is missing")
        return (
            render_template(
                "login.html",
                error="email or password field can't be empty!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    result = User.get_from_email(email)

    if (
        result is None
        or result.password is None
        or not check_password_hash(result.password, password)
    ):
        logging.error("Either email or password input parameter is invalid/wrong")
        return (
            render_template(
                "login.html",
                error="email or password is incorrect!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )
    token = jwt.encode(
        {"alg": "RS256"},
        {"user": result.username},
        current_app.config["JWT_PRIVATE_KEY"],
    )

    resp = make_response(redirect(url_for("server_api_blueprint.profile")))
    resp.set_cookie("access-token", token, samesite="Strict")

    return resp


@login_api_blueprint.route("/register", methods=["GET", "POST"])
def register():
    logging.debug("/register endpoint called on webshop")
    cookie = request.cookies.get("access-token")
    if cookie:
        try:
            token = jwt.decode(cookie, current_app.config["JWT_PUBLIC_KEY"])

            result = User.get_from_username(token["user"])

            if result is None:
                logging.error("Token correspoding to a user, doesn't exist!")
                resp = make_response(render_template("register.html"))
                resp.set_cookie("access-token", "", samesite="Strict")
                return resp, 400
            return redirect(url_for("server_api_blueprint.profile"))
        except:
            logging.error("Failed to decode a user token!")
            pass
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")

    if not isAlphanumeric(username):
        return (
            render_template("register.html", error="username has to be alphanumeric!"),
            400,
        )

    if email is None or email == "" or password is None or password == "":
        logging.error("Either email or password input parameter is missing")
        return (
            render_template("register.html", error="email or password can't be empty!"),
            400,
        )

    result = User.get_from_email_or_username(email, username)

    if result is not None:
        if result.email == email:
            logging.warn("User already exists")
            return (
                render_template(
                    "register.html", error="a user with this email already exists!"
                ),
                409,
            )
        if result.username == username:
            logging.warn(f"This username '{username}' is already taken")
            return (
                render_template(
                    "register.html", error="a user with this username already exists!"
                ),
                409,
            )

    new_user = User(email, username, password)
    new_user.insert()

    return redirect(url_for("login_api_blueprint.login"))


@login_api_blueprint.route("/logout", methods=["POST"])
def logout():
    logging.debug("/logout endpoint called on webshop")
    resp = make_response(redirect("login"))
    resp.set_cookie("access-token", "", samesite="Strict")

    return resp
