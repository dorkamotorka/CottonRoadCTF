from flask import Blueprint

notes_api_blueprint = Blueprint("notes_api_blueprint", __name__)

from . import routes
