from flask_login import UserMixin
import secrets
from datetime import datetime, timedelta
from .db import *
from werkzeug.security import generate_password_hash
from . import login_manager
from . import logging

class Users(UserMixin):

    username = ""
    email = ""
    password = ""


    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email = email
        self.password = password

    def get_id(self):
        return self.email

    @staticmethod
    @login_manager.user_loader
    def get(email):
        db = get_db()
        res = db.execute("SELECT * FROM Users WHERE email = ?", (email, )).fetchone()
        close_db()
        return Users(res[0], res[1], res[2]) if res else None

    def insert(self):
        db = get_db()
        hash = generate_password_hash(self.password, method='sha256')
        db.execute("INSERT INTO Users (username, email, password) VALUES (?,?,?)", (self.username, self.email, hash, ))
        close_db()

class Client:
    
    client_id = ""
    client_secret = ""
    default_redirect_uri = ""
    grant_types = [
        "code",
        "implicit",
        "authorization_code",
        "client_credentials",
        "password"
    ]
    allowed = [
        "username",
        "email"
    ]
    allowed_redirect_uris = list()
    response_types = list()

    def __init__(self, client_id: str, client_secret: str, default_redirect_uri: str, allowed_redirect_uris: list, response_types: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.default_redirect_uri = default_redirect_uri
        self.allowed_redirect_uris = allowed_redirect_uris
        self.response_types = response_types


    def check_client_secret(self, client_secret):
        return secrets.compare_digest(self.client_secret, client_secret)

    @classmethod
    def get_by_id(cls, client_id: str):
        db = get_db()
        client = db.execute("SELECT * FROM Client WHERE client_id = ?", (client_id, )).fetchone()
        close_db()
        return Client(client[0], client[1], client[2], [client[3]], [client[4]])

    def check_endpoint_auth_method(self, method, endpoint):
        return True
    
    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types
    
    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.allowed_redirect_uris
    
    def check_response_type(self, response_type):
        return response_type in self.response_types
    
    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        x = set(s for s in scope.split() if s in self.allowed)
        return list(x)
    
    def get_client_id(self):
        return self.client_id
    
    def get_default_redirect_uri(self):
        return self.default_redirect_uri

class Token:

    redirect_uri = ""
    scope = ""
    client_id = ""
    authorization_code = ""
    revoked = False
    user_id = ""
    expires_in = 0

    def __init__(self, redirect_uri = "", scope = "", client_id = "", revoked = False, expires_in = 0, authorization_code = "", user_id = ""):
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.client_id = client_id
        self.user_id = user_id
        self.revoked = revoked
        self.authorization_code = authorization_code
        self.expires_in = expires_in

    def insert(self):
        db = get_db()
        db.execute("INSERT INTO Token VALUES (?,?,?,?,?,?,?,?)", (None, self.redirect_uri, self.scope, self.client_id, self.revoked, self.expires_in, self.authorization_code, self.user_id, ))
        close_db()

    @classmethod
    def get(cls, token):
        db = get_db()
        x = db.execute("SELECT * FROM Token WHERE authorization_code = ?", (token, )).fetchone()
        close_db()
        return Token(x[1], x[2], x[3], x[4], x[5], x[6], x[7]) if x else None

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def check_client(self, client):
        return self.client_id == client.client_id
    
    def get_expires_in(self):
        return self.expires_in
    
    def is_expired(self):
        return False 
    
    def is_revoked(self):
        return False

class AuthorizationCode:
    code = ""
    client_id = ""
    redirect_uri = ""
    scope = ""
    user_id = ""
    code_challenge = ""
    code_challenge_method = ""

    def __init__(self, code, client_id, redirect_uri, scope, user_id, code_challenge, code_challenge_method) -> None:
        self.code = code
        self.client_id = client_id
        self.user_id = user_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
    

    def get_scope(self):
        return self.scope

    def insert(self):
        db = get_db()
        db.execute("INSERT INTO AuthorizationCode VALUES (?,?,?,?,?,?,?,?)", (None, self.code, self.client_id, self.redirect_uri, self.scope, self.user_id, self.code_challenge, self.code_challenge_method, ))
        close_db()

    @classmethod
    def get(cls, client: Client, code):
        db = get_db()
        res = db.execute("SELECT * FROM AuthorizationCode WHERE client_id = ? AND code = ?", (client.client_id, code, )).fetchone()
        close_db()
        return AuthorizationCode(res[1], res[2], res[3], res[4], res[5], res[6], res[7])

    def get_redirect_uri(self):
        return self.redirect_uri

    def is_expired(self):
        return False
    
    def delete(self):
        db = get_db()
        db.execute("DELETE FROM AuthorizationCode WHERE code = ? AND client_id = ?", (self.code, self.client_id, ))
        close_db()

