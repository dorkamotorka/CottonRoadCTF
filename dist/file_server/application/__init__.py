from flask import Flask, redirect
import flask_login
from authlib.integrations.flask_oauth2 import AuthorizationServer
import logging

login_manager = flask_login.LoginManager()

def create_app():
    global login_manager

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s  %(levelname)8s  %(message)s',
    )

    """Create app"""
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    """init login Manager"""
    login_manager.init_app(app)

    """init oauth server"""
    from .oAuth.authServer import config_oauth
    config_oauth(app)

    with app.app_context():
        # Import blueprints
        from .api import server_api_blueprint
        from .login import server_auth_blueprint
        from .dashboard import server_dashboard_blueprint
        from .oAuth import server_oauth_blueprint
        # Register Blueprints
        app.register_blueprint(server_dashboard_blueprint)
        app.register_blueprint(server_api_blueprint)
        app.register_blueprint(server_auth_blueprint)
        app.register_blueprint(server_oauth_blueprint)

        return app

