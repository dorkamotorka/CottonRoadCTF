from flask import Blueprint

items_api_blueprint = Blueprint("items_api_blueprint", __name__)

from . import routes
