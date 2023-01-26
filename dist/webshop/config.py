import os
from os import environ, path
from dotenv import load_dotenv
from sqlalchemy.engine.url import URL

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, ".env"))


class Config:
    PUBLIC_IP = environ["PUBLIC_IP"]
    FILESERVER_CLIENT_ID = environ["FILESERVER_CLIENT_ID"]
    FILESERVER_CLIENT_SECRET = environ["FILESERVER_CLIENT_SECRET"]
    FILESERVER_AUTHORIZE_URL = f"http://{PUBLIC_IP}:10101/oauth/authorize"
    FILESERVER_ACCESS_TOKEN_URL = f"http://cottonroad-file-server:10101/oauth/token"
    SECRET_KEY = environ["SECRET_KEY"]
    SECRET_PASSWORD = environ["SECRET_PASSWORD"]
    ACCESS_APIKEY = environ["ACCESS_APIKEY"]
    JWT_PUBLIC_KEY = open(os.path.join(basedir, "keys", "jwtRS256.key.pub"), "r").read()
    JWT_PRIVATE_KEY = open(os.path.join(basedir, "keys", "jwtRS256.key"), "r").read()
    DATABASE = "database.db"
    STRICT_SLASHES = False
    MAX_NOTES = 10
    MAX_SHOP_ITEMS = 6
    FILESERVER_PORT = environ["FILESERVER_PORT"]
    WEBSHOP_PORT = environ["WEBSHOP_PORT"]
