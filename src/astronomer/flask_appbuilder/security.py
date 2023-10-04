# Copyright 2019 Astronomer Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
from logging import getLogger

from flask import abort, request
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.views import AuthView, expose
from flask_login import current_user, login_user
from jwcrypto import jwk, jws, jwt, common

from astronomer.flask_appbuilder.jwt_secrets import update_jwt_secret, get_jwt_secret

try:
    from airflow.www_rbac.security import AirflowSecurityManager, EXISTING_ROLES
except ImportError:
    try:
        from airflow.www.security import AirflowSecurityManager, EXISTING_ROLES
    except ImportError:
        # Airflow not installed, likely we are running setup.py to _install_ things
        class AirflowSecurityManager(object):
            def __init__(self, appbuilder):
                pass


        EXISTING_ROLES = []

__version__ = "1.5.0"

log = getLogger(__name__)


class AstroSecurityManagerMixin(object):
    """
    Flask-AppBuilder SecurityManager mix in that auto-creates users based on
    the signed JWT token from the Astronomer platform
    For this security manager to function the ``AUTH_TYPE`` in your FAB
    application's config must be set to
    ``AUTH_REMOTE_USER``:
    .. code:: python
        from flask_appbuilder.security.manager import AUTH_REMOTE_USER
        AUTH_TYPE = AUTH_REMOTE_USER
    **Required JWT token claims**
    We require the following claims in the token:
    ``sub``
        Subject. The User ID/username. This is used to find the user record
    ``aud``
        Audience. What "domain" this token is for. List of strings or string.
        The value of "allowed_audience" must appear in this list
    ``exp``
        Token expiry. Integer seconds since 1970 epoch.
    ``nbf``
        "Not Before". Earliest time at which token is valid. Integer seconds since 1970 epoch.
    ``email``
        User's email address.
    ``full_name``
        Must be present, but can be null, in which case ``email`` user's name
        will be set to email. This field is what FAB displays in the UI.
    ``roles``
        An array of role names that the user should be in. See :meth:`manage_user_roles`.
    :param appbuilder:
    :type appbuilder: flask_appbuilder.AppBuilder
    :param jwt_signing_cert: JsonWebKey that must have signed the token. Can be
        a public key, or a base64-encoded shared secret. See
        :class:`jwcrypto.jwk.JWK` for more info.
    :type jwt_signing_cert: jwcrypto.jwk.JWK
    :param allowed_audience: Valiid ``aud`` claims to accept
    :type allowed_audience: list[str] or str
    :param validity_leeway: Number of seconds past token expiry to accept. Default 60
    :type validity_leeway: int
    :param roles_to_manage: List of roles to manage. See
        :meth:`manage_user_roles` for behaviour of this parameter
    :type roles_to_manage: list[str] or None
    """

    def __init__(self, appbuilder, jwt_aws_secret_path, jwt_cookie_name, allowed_audience, default_role, roles_to_manage=None, validity_leeway=60, jwt_secret_override=None, admin_users=None):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_REMOTE_USER:
            self.authremoteuserview = AuthAstroJWTView
        self.jwt_aws_secret_path = jwt_aws_secret_path
        self.jwt_cookie_name = jwt_cookie_name
        self.allowed_audience = allowed_audience
        self.roles_to_manage = roles_to_manage
        self.validity_leeway = validity_leeway
        self.jwt_secret_override = jwt_secret_override
        self.admin_users = admin_users
        self.default_role = default_role

    def check_jwt_and_get_claims(self):
        """Check the jwt cookie exists and is valid
        Returns the claims from the jwt as a dict
        """

        auth_cookie = request.cookies.get(self.jwt_cookie_name)

        if not auth_cookie:
            log.info("No auth cookie supplied")
            return abort(403)

        try:
            token = jwt.JWT(
                check_claims={
                    # These must be present - any value
                    'sub': None,

                    # This must match exactly
                    'aud': self.allowed_audience,
                }
            )

            token.leeway = self.validity_leeway

            key = {'k': common.base64url_encode(get_jwt_secret(self.jwt_aws_secret_path, self.jwt_secret_override)), "kty": "oct", "alg": "HS256"}
            key = jwk.JWK(**key)
            token.deserialize(jwt=auth_cookie, key=key)
            claims = json.loads(token.claims)
            return claims
        except jws.InvalidJWSSignature as e:
            log.error(e)
            abort(403)
        except jwt.JWException as e:
            log.error(e)
            abort(403)

    def before_request(self):
        """ This functions runs on every request
        If the current user is anonymous (according to flask_login) then:
        - check the jwt and get the claims
        - If no airflow user exists, create one using the sub value from the claim
        - login the airflow user and remember they are logged in
        """
        if request.path == '/health':
            return super().before_request()

        if current_user.is_anonymous:
            update_jwt_secret(self.jwt_aws_secret_path)
            claims = self.check_jwt_and_get_claims()
            user = self.find_user(username=claims['sub'])

            email = claims['sub']
            # For DAG level access, need a role per user
            if self.find_role(email) is None:
                self.create_user_role(email, self.default_role)

            if email in self.admin_users:
                role_name = 'Admin'
            else:
                role_name = email

            if user is None:
                log.info('Creating airflow user details for %s from JWT', claims['sub'])

                user = self.user_model(
                    username=email,
                    first_name=email.split('.')[0],
                    last_name='',
                    email=email,
                    roles=[self.find_role(role_name)],
                    active=True
                )
            else:
                log.info('Found existing airflow user', claims['sub'])
                user.username = claims['sub']
                user.roles = [self.find_role(role_name)]
                user.active = True

            self.get_session.add(user)
            self.get_session.commit()

            log.info(f"Logging in user: {user.username}")
            if not login_user(user):
                raise RuntimeError("Error logging user in!")

        super().before_request()

    def manage_user_roles(self, user, roles):
        """
        Manage the core roles on the user
        If ``self.roles_to_manage`` is an empty list or None, then the user
        will only be in the roles passed via the ``roles`` parameter.
        Otherwise any role that the user is a member of that is not in the
        ``self.roles_to_manage`` list will remain.
        """
        desired = set(roles)

        if self.roles_to_manage:
            roles_to_remove = self.roles_to_manage - desired
        else:
            # Every role that isn't in `roles` should be removed from this
            # user
            roles_to_remove = {r.name for r in user.roles} - desired

        # Capture it in a variable - otherwise it changes underneath us as we
        # iterate and we miss some
        current_roles = list(user.roles)

        for role in current_roles:
            if role.name in roles_to_remove:
                user.roles.remove(role)
            elif role.name in desired:
                desired.remove(role.name)

        # Anything left in desired is a role we need to add
        for role in desired:
            user.roles.append(self.find_role(role))


class AirflowAstroSecurityManager(AstroSecurityManagerMixin, AirflowSecurityManager):
    """
    This class configures the FAB SecurityManager for use in Airflow, and reads
    settings under the ``[auth]`` section (or environment variables prefixed
    with ``AIRFLOW__AUTH__``).
    This class will only manage the "core" roles built in to Airflow
    (Admin, Op, User, Viewer, Public) are correct for the given user - if a
    user is added to any custom roles the membership of those will not be
    removed.
    **Required Airflow Config settings:**
    ``auth.jwt_secret_override``
        Raw text value of a JWT secret (for development)
    ``auth.jwt_aws_secret_path``
        Path to aan aws secret containing the JWT signing secret
    ``auth.jwt_audience``
        The audience value to accept in JWT tokens. This should be the hostname
        of this Airflow deployment
    ``auth.jwt_cookie_name``
        Name of the cookie to extract jwt from
    ``auth.admin_users``
        Comma separated list of users to make admin if/when we see them
    ``auth.default_role``
        The name of the airflow role users will be assigned to
    **Optioinal config settings:**
    ``astronomer.jwt_validity_leeway``
        Override the default leeway on validating token expiry time
    """

    def __init__(self, appbuilder):
        from airflow.configuration import conf
        from airflow.configuration import AirflowConfigException

        admin_users = []
        admin_users_str = conf.get('auth', 'admin_users')
        if admin_users_str:
            admin_users = admin_users_str.split(',')
            admin_users = [u.strip() for u in admin_users]

        kwargs = {
            'appbuilder': appbuilder,
            'allowed_audience': conf.get('auth', 'jwt_audience'),
            'jwt_cookie_name': conf.get('auth', 'jwt_cookie_name'),
            'jwt_aws_secret_path': conf.get('auth', 'jwt_aws_secret_path'),
            'default_role': conf.get('auth', 'default_role'),
            'admin_users': admin_users,
            'roles_to_manage': EXISTING_ROLES,
        }

        # optional kwargs
        # Airflow 1.10.2 doesn't have `fallback` support yet
        leeway = self.safe_get_config('astronomer', 'jwt_validity_leeway', fallback=None)
        if leeway is not None:
            kwargs['validity_leeway'] = int(leeway)
        kwargs['jwt_secret_override'] = self.safe_get_config('auth', 'jwt_secret_override', fallback=None)

        super().__init__(**kwargs)

    def safe_get_config(self, section, key, fallback):
        # Airflow 1.10.2 doesn't have `fallback` support yet
        from airflow.configuration import conf
        from airflow.configuration import AirflowConfigException
        val = None
        try:
            val = conf.get('astronomer', 'jwt_validity_leeway', fallback=None)
        except AirflowConfigException:
            pass
        if val is not None:
            return val
        else:
            return fallback

    def before_request(self):
        # To avoid making lots of stat requests don't do this for static
        # assets, just Airflow pages and API endpoints
        if not request.path.startswith("/static/"):
            # self.reload_jwt_signing_cert()
            pass
        return super().before_request()

    def create_user_role(self, username, base_role_name):
        """ Create a role with blank permissions"""
        base_role = self.find_role(base_role_name)
        if base_role:
            log.info(f"this is the base role: {base_role}")
            log.info(f"base_role.permissions: {base_role.permissions}")
            log.info(f"perm_view info: {[perm_view for perm_view in base_role.permissions]}")
            
            perms = set(
                {(perm_view.permission.name, perm_view.view_menu.name) for perm_view in base_role.permissions}
            )
        else:
            log.warning(f"Base role doesn't exist: {base_role_name}")
            perms = set({})  # Base role doesn't exist

        super().init_role(username, perms)

    # def sync_roles(self):
    #     super().sync_roles()
    #
    #     for (view_menu, permission) in [
    #         ('UserDBModelView', 'can_userinfo'),
    #         ('UserDBModelView', 'userinfoedit'),
    #         ('UserRemoteUserModelView', 'can_userinfo'),
    #         ('UserRemoteUserModelView', 'userinfoedit'),
    #         ('UserInfoEditView', 'can_this_form_get'),
    #         ('UserInfoEditView', 'can_this_form_post'),
    #     ]:
    #         perm = self.find_permission_view_menu(permission, view_menu)
    #         # If we are only using the RemoteUser auth type, then the DB permissions won't exist. Just continue
    #         if not perm:
    #             continue
    #
    #         self.add_permission_role(self.find_role("User"), perm)
    #         self.add_permission_role(self.find_role("Op"), perm)
    #         self.add_permission_role(self.find_role("Viewer"), perm)
    #
    #     for (view_menu, permission) in [
    #         ('Airflow', 'can_dagrun_success'),
    #         ('Airflow', 'can_dagrun_failed'),
    #         ('Airflow', 'can_failed'),
    #     ]:
    #         self.add_permission_role(self.find_role("User"), self.find_permission_view_menu(permission, view_menu))
    #         self.add_permission_role(self.find_role("Op"), self.find_permission_view_menu(permission, view_menu))
    #
    #     for (view_menu, permission) in [
    #         ('VariableModelView', 'varexport'),
    #     ]:
    #         self.add_permission_role(self.find_role("Op"), self.find_permission_view_menu(permission, view_menu))


class AuthAstroJWTView(AuthView):
    """
    If a user does not have permission, they are automatically rediected
    to the login function of this class. Since we handle everything externally
    we make this look more like an actual 403 error.
    Reference to FAB: https://github.com/dpgaspar/Flask-AppBuilder/blob/fd8e323fcd59ec4b28df91e12915eeebdf293060/flask_appbuilder/security/decorators.py#L134
    """

    @expose("/access-denied/")
    def login(self):
        return abort(403)


