from flask import Flask
from authlib.integrations.flask_client import OAuth
import logging

oauth = None


def create_app():
    global oauth

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s  %(levelname)8s  %(message)s"
    )

    """Create app"""
    app = Flask(__name__)
    app.config.from_object("config.Config")
    logging.debug("Configuration loaded!")

    oauth = OAuth(app)
    oauth.register(name="fileserver", client_kwargs={"scope": "username email"})

    logging.debug("WebShop and oAuth instance deployed!")

    with app.app_context():
        # Import blueprints
        from .api import server_api_blueprint
        from .login import login_api_blueprint
        from .notes import notes_api_blueprint
        from .items import items_api_blueprint

        # Register Blueprints
        app.register_blueprint(server_api_blueprint)
        app.register_blueprint(login_api_blueprint)
        app.register_blueprint(notes_api_blueprint)
        app.register_blueprint(items_api_blueprint)
        app.url_map.strict_slashes = app.config["STRICT_SLASHES"]

        return app
