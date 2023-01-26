from flask import Blueprint

login_api_blueprint = Blueprint("login_api_blueprint", __name__)

from . import routes
