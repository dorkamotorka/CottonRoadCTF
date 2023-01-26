import os
from os import environ, path
from dotenv import load_dotenv
from sqlalchemy.engine.url import URL

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

class Config():
    WEBSHOP_IP = "cottonroad-webshop"
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    ALLOWED_EXTENSIONS = {'jpg', 'png', 'jpeg'}
    MAX_CONTENT_LENGTH = 102400 #100kb
    MAX_FILE_UPLOADS = 6
    PUBLIC_IP = environ["PUBLIC_IP"]
    SECRET_KEY = environ["SECRET_KEY"]
    DATABASE = "database.db"
    ACCESS_APIKEY = environ["ACCESS_APIKEY"]
