from flask import Blueprint

server_api_blueprint = Blueprint("server_api_blueprint", __name__)

from . import routes
