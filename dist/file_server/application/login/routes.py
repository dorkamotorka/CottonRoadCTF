from flask import Blueprint, render_template, redirect, url_for, request, flash, make_response, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import re
import hashlib
import os
import errno
from ..db import get_db
from ..models import Users
from . import server_auth_blueprint
from .. import logging
from .. import login_manager

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("server_auth_blueprint.login"))


def isAlphanumeric(text):
    if text is not None and re.match("^[a-zA-Z0-9]+$", text) is not None:
        logging.info(f"{text} is alphanumeric")
        return True
    logging.error(f"{text} is not alphanumeric")
    return False


def create_directory(email):
    try:
        hashed_email = hashlib.md5(email.encode()).hexdigest()
        os.mkdir(os.path.join(current_app.config["UPLOAD_FOLDER"], hashed_email))
        logging.info(f"Succesfully created directory {hashed_email} for email '{email}'")
        return True
    except OSError as exc:
        logging.info(f"Failed to create directory for email '{email}'")
        if exc.errno != errno.EEXIST:
            raise
        return False


@server_auth_blueprint.route('/login', methods=['GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("server_dashboard_blueprint.getFiles"))
    logging.debug("/login endpoint GET method called on file_server")
    return render_template('login.html', ip=current_app.config["PUBLIC_IP"])


@server_auth_blueprint.route('/login', methods=['POST'])
def login_post():
    logging.debug("/login endpoint POST method called on file_server")
    email = request.form.get('email')
    password = request.form.get('password')
    user = Users.get(email=email)
    if not user or not check_password_hash(user.password, password):
        logging.warn("Invalid login credentials...")
        flash('Please check your login details and try again.')
        return render_template('login.html', error="invalid username or password!", ip=current_app.config["PUBLIC_IP"]), 400 
    login_user(user, remember=True)
    if request.args.get("next"):
        return redirect(request.args.get("next"))
    return redirect(url_for('server_dashboard_blueprint.getFiles'))


@server_auth_blueprint.route('/register', methods=['GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("server_dashboard_blueprint.getFiles"))
    logging.debug("/register endpoint GET method called on file_server")
    return render_template('register.html')


@server_auth_blueprint.route('/register', methods=['POST'])
def register_post():
    logging.debug("/register endpoint POST method called on file_server")
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')

    if not isAlphanumeric(username):
        logging.error("Invalid characters in username")
        flash('Invalid characters in username')
        return render_template('register.html', error="username has to be alphanumeric!"), 400

    if username is None or username == "":
        logging.error("Username is None or empty")
        return render_template("register.html", error="username field can't be emtpy!"), 400

    if email is None or email == "" or password is None or password == "":
        logging.error("Either email or password input parameter is missing")
        return render_template("register.html", error="email or password field can't be empty!"), 400

    con = get_db()
    user = Users.get(email)
    if user:
        logging.error("Email address already in use")
        flash('Email address already in use')
        return render_template('register.html', error="email address is already in use!"), 400

    if not create_directory(email):
        logging.error("Failed to create user with that email")
        flash('Failed to create user with that email')
        return render_template('register.html', error="failed to create user with the given email!"), 500

    new_user = Users(username, email, password)
    new_user.insert()
    return redirect(url_for('server_auth_blueprint.login'))


@server_auth_blueprint.route('/logout')
@login_required
def logout():
    logging.debug("/logout endpoint called on file_server")
    logout_user()
    return redirect(url_for('server_auth_blueprint.login'))
