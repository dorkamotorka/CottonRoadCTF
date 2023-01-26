from flask import Blueprint

server_auth_blueprint = Blueprint('server_auth_blueprint', __name__, url_prefix="/auth") 

from . import routes