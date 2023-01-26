from flask import Blueprint

server_oauth_blueprint = Blueprint('server_oauth_blueprint', __name__, url_prefix="/oauth") 

from . import authServer
from . import routes