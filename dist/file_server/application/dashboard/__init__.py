from flask import Blueprint

server_dashboard_blueprint = Blueprint('server_dashboard_blueprint', __name__, url_prefix="/dashboard") 

from . import routes