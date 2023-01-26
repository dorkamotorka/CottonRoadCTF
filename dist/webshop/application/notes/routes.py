from . import notes_api_blueprint
from functools import wraps
import json
from flask import (
    make_response,
    current_app,
    request,
    render_template,
    redirect,
    url_for,
)
from ..models import *
from authlib.jose import jwt
from .. import logging


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


@notes_api_blueprint.route("/notes", methods=["GET"])
@check_token
def get_notes():
    logging.debug("/notes endpoint called on webshop")
    decoded = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )
    result = Note.get_notes(decoded["user"])

    return render_template(
        "notes.html",
        notes_list=result,
        info=request.args.get("info"),
        ip=current_app.config["PUBLIC_IP"],
    )


@notes_api_blueprint.route("/notes/search", methods=["POST"])
@check_token
def get_filtered_notes():
    logging.debug("/notes/search endpoint called on webshop")
    decoded = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )
    search = request.form.get("search-form")
    result = Note.get_filtered_notes(search, decoded["user"])
    logging.debug(f"{result}")
    resp = make_response(
        render_template(
            "notes.html", notes_list=result, ip=current_app.config["PUBLIC_IP"]
        )
    )
    json_string = json.dumps([res.__dict__ for res in result])
    resp.headers = {"notes-result": json_string}

    return resp


@notes_api_blueprint.route("/notes/create", methods=["GET", "POST"])
@check_token
def create_note():
    logging.debug("/notes/create endpoint called on webshop")
    if request.method == "GET":
        return render_template("createNote.html", ip=current_app.config["PUBLIC_IP"])

    username = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )["user"]

    title = request.form.get("title").strip()
    content = request.form.get("content").strip()
    user_email = User.get_from_username(username).email

    if len(Note.get_notes(user_username=username)) == current_app.config["MAX_NOTES"]:
        logging.error(f"{user_email} wanted to create more than 10 notes!")
        return render_template(
            "createNote.html",
            error="you can only create max. 10 notes",
            ip=current_app.config["PUBLIC_IP"],
        )

    if title is None or title == "":
        logging.error("The notes title input parameter is missing")
        return (
            render_template(
                "createNote.html",
                error="title can't be empty!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    if content is None or content == "":
        logging.error("The notes content input parameter is missing")
        return (
            render_template(
                "createNote.html",
                error="content can't be empty!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    if len(content) > 450:
        logging.error("Notes content is too long!")
        return (
            render_template(
                "createNote.html",
                error="the content has a character limit of 450!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    new_note = Note(title, content, user_email, username)
    new_note.insert()

    inserted_note = Note.get_matching(
        title=new_note.title,
        content=new_note.content,
        user_email=new_note.user_email,
        user_username=new_note.user_username,
    )
    resp = make_response(
        redirect(
            url_for("notes_api_blueprint.get_notes", info="Note successfully added!")
        )
    )
    resp.headers["NOTE_ID"] = str(inserted_note.id)

    return resp
