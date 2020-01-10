# -*- coding: utf-8 -*-
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Default configuration for the Airflow webserver"""
import os
import json

# from flask_appbuilder.security.manager import AUTH_DB

from airflow.configuration import conf

# from flask_appbuilder.security.manager import AUTH_LDAP
# from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.manager import AUTH_OID
# from flask_appbuilder.security.manager import AUTH_REMOTE_USER

from flask import redirect, request
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from flask_admin import expose

from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from airflow.www_rbac.security import AirflowSecurityManager
from logging import getLogger
log = getLogger(__name__)

# Set the OIDC field that should be used as a username
USERNAME_OIDC_FIELD = os.getenv('USERNAME_OIDC_FIELD', default='sub')
FIRST_NAME_OIDC_FIELD = os.getenv('FIRST_NAME_OIDC_FIELD',
                                  default='given_name')
LAST_NAME_OIDC_FIELD = os.getenv('LAST_NAME_OIDC_FIELD',
                                 default='family_name')

class AuthOIDCView(AuthOIDView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        auth0 = sm.auth0
        return auth0.authorize_redirect(redirect_uri=sm.oAuthSettings['login_redirect_url'])

    @expose('/logout/', methods=['GET'])
    def logout(self):

        log.info('logout')

        # log user out of airflow
        super(AuthOIDCView, self).logout()

        sm = self.appbuilder.sm
        auth0 = sm.auth0

        log.info('auth0 logout')

        # Redirect user to Auth0 logout endpoint
        return_to_url = url_for('routes.index', _external=True)
        log.info('return to url: ' + return_to_url)
        params = {'returnTo': return_to_url, 'client_id': sm.oAuthSettings['client_id']}
        return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

    @expose('/oidc_callback/', methods=['GET', 'POST'])
    def callback(self, flag=True):

        log.info('oidc_callback')

        sm = self.appbuilder.sm
        auth0 = sm.auth0

        # Handles response from token endpoint
        auth0.authorize_access_token()
        resp = auth0.get('userinfo')
        userinfo = resp.json()

        log.debug(userinfo)

        user = sm.auth_user_oid(userinfo['email'])

        if user is None:
            log.info('registering user')
            user = sm.add_user(
                username=userinfo[USERNAME_OIDC_FIELD],
                first_name=userinfo[FIRST_NAME_OIDC_FIELD],
                last_name=userinfo[LAST_NAME_OIDC_FIELD],
                email=userinfo['email'],
                role=sm.find_role(sm.auth_user_registration_role)
            )

        log.info('logging in user')
        login_user(user, remember=False)

        return redirect(self.appbuilder.get_url_for_index)

class OIDCSecurityManagerMixin:

    def __init__(self, appbuilder):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_OID:

            with open('client_secrets.json', 'r') as secrets_file:
                json_data=secrets_file.read()

            self.oAuthSettings = json.loads(json_data)

            self.oauth = OAuth(self.appbuilder.get_app)
            self.auth0 = self.oauth.register(
                'auth0',
                client_id=self.oAuthSettings['client_id'],
                client_secret=self.oAuthSettings['client_secret'],
                api_base_url=self.oAuthSettings['api_base_url'],
                access_token_url=self.oAuthSettings['access_token_url'],
                authorize_url=self.oAuthSettings['authorize_url'],
                client_kwargs={
                    'scope': self.oAuthSettings['scope'],
                },
            )
            self.authoidview = AuthOIDCView


class AirflowOIDCSecurityManager(OIDCSecurityManagerMixin, AirflowSecurityManager):
    pass



basedir = os.path.abspath(os.path.dirname(__file__))

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Flask-WTF flag for CSRF
CSRF_ENABLED = True

# ----------------------------------------------------
# AUTHENTICATION CONFIG
# ----------------------------------------------------
# For details on how to set up each of the following authentication, see
# http://flask-appbuilder.readthedocs.io/en/latest/security.html# authentication-methods
# for details.

# The authentication type
# AUTH_OID : Is for OpenID
# AUTH_DB : Is for database
# AUTH_LDAP : Is for LDAP
# AUTH_REMOTE_USER : Is for using REMOTE_USER from web server
# AUTH_OAUTH : Is for OAuth
AUTH_TYPE = AUTH_OID

SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager

# Uncomment to setup Full admin role name
AUTH_ROLE_ADMIN = 'Admin'

# Uncomment to setup Public role name, no authentication needed
# AUTH_ROLE_PUBLIC = 'Public'

# Will allow user self registration
AUTH_USER_REGISTRATION = True

# The default user self registration role
AUTH_USER_REGISTRATION_ROLE = "Admin"

# When using OAuth Auth, uncomment to setup provider(s) info
# Google OAuth example:
# OAUTH_PROVIDERS = [{
#   'name':'google',
#     'whitelist': ['@YOU_COMPANY_DOMAIN'],  # optional
#     'token_key':'access_token',
#     'icon':'fa-google',
#         'remote_app': {
#             'base_url':'https://www.googleapis.com/oauth2/v2/',
#             'request_token_params':{
#                 'scope': 'email profile'
#             },
#             'access_token_url':'https://accounts.google.com/o/oauth2/token',
#             'authorize_url':'https://accounts.google.com/o/oauth2/auth',
#             'request_token_url': None,
#             'consumer_key': CONSUMER_KEY,
#             'consumer_secret': SECRET_KEY,
#         }
# }]

OIDC_CLIENT_SECRETS = '/usr/local/airflow/client_secrets.json'
OIDC_SCOPES = 'openid profile email'

# When using LDAP Auth, setup the ldap server
# AUTH_LDAP_SERVER = "ldap://ldapserver.new"

# When using OpenID Auth, uncomment to setup OpenID providers.
# example for OpenID authentication
# OPENID_PROVIDERS = [
#    { 'name': 'Yahoo', 'url': 'https://me.yahoo.com' },
#    { 'name': 'AOL', 'url': 'http://openid.aol.com/<username>' },
#    { 'name': 'Flickr', 'url': 'http://www.flickr.com/<username>' },
#    { 'name': 'MyOpenID', 'url': 'https://www.myopenid.com' }]

# ----------------------------------------------------
# Theme CONFIG
# ----------------------------------------------------
# Flask App Builder comes up with a number of predefined themes
# that you can use for Apache Airflow.
# http://flask-appbuilder.readthedocs.io/en/latest/customizing.html#changing-themes
# Please make sure to remove "navbar_color" configuration from airflow.cfg
# in order to fully utilize the theme. (or use that property in conjunction with theme)
# APP_THEME = "bootstrap-theme.css"  # default bootstrap
# APP_THEME = "amelia.css"
# APP_THEME = "cerulean.css"
# APP_THEME = "cosmo.css"
# APP_THEME = "cyborg.css"
# APP_THEME = "darkly.css"
# APP_THEME = "flatly.css"
# APP_THEME = "journal.css"
# APP_THEME = "lumen.css"
# APP_THEME = "paper.css"
# APP_THEME = "readable.css"
# APP_THEME = "sandstone.css"
# APP_THEME = "simplex.css"
# APP_THEME = "slate.css"
# APP_THEME = "solar.css"
# APP_THEME = "spacelab.css"
# APP_THEME = "superhero.css"
# APP_THEME = "united.css"
# APP_THEME = "yeti.css"