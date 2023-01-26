from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from ..models import Users
from ..models import Client, AuthorizationCode, Token


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.data.get('code_challenge')
        code_challenge_method = request.data.get('code_challenge_method')
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.email,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        auth_code.insert()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = AuthorizationCode.get(client, code)
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code: AuthorizationCode):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return Users.get(authorization_code.user_id)

def query_client(client_id):
    return Client.get_by_id(client_id)

def save_token(token, request):
    if request.user:
        user_id = request.user.get_id()
    else:
        user_id = None
    client = request.client
    item = Token(
        authorization_code = token["access_token"],
        client_id = client.client_id,
        scope="username email",
        user_id=user_id,
        expires_in=token["expires_in"]
    )
    item.insert()

authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)

class MyBearerTokenValidator(BearerTokenValidator):

    def authenticate_token(self, token_string):
        return Token.get(token_string)

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return False

require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyBearerTokenValidator())


def config_oauth(app):
    authorization.init_app(app)
    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
