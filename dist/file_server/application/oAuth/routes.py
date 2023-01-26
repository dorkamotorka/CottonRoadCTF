from werkzeug import exceptions
from . import server_oauth_blueprint
from flask_login import current_user
from flask import redirect, request, url_for, render_template, jsonify, current_app
from ..models import Users, Token
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .. import logging
from .authServer import authorization, require_oauth


@server_oauth_blueprint.errorhandler(exceptions.BadRequest)
def handle_bad_request(e):
    return redirect(url_for("server_auth_blueprint.login"))


@server_oauth_blueprint.route('/authorize', methods=['GET', 'POST'])
def authorize():
    logging.debug("/authorize endpoint called on file_server")
    user = current_user
    if not user.is_authenticated:
        return redirect(url_for('server_auth_blueprint.login', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error + "\n" + error.description
        return render_template('authorize.html', user=user, grant=grant, ip=current_app.config["PUBLIC_IP"])
    if not user and 'email' in request.form:
        email = request.form.get('email')
        user = Users.get(email)
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@server_oauth_blueprint.route('/token', methods=['POST'])
def issue_token():
    logging.debug("/token endpoint called on file_server")
    return authorization.create_token_response()


@server_oauth_blueprint.route("/username", methods=["GET", "POST"])
@require_oauth("username email")
def retrieveUsername():
    logging.debug("/username endpoint called on file_server")
    mail = current_token.user_id
    user = Users.get(mail)
    return jsonify({"username": user.username, "mail": mail})
