"""
OAuth 2.0 Client Credentials Plugin for HTTPie.
"""

import os
import sys
from httpie.plugins import AuthPlugin
from oauthlib.oauth2 import (
    BackendApplicationClient,
    WebApplicationClient,
    InsecureTransportError,
)
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth, AuthBase

from httpie.cli.definition import parser

from httpie.context import Environment

__version__ = "0.3.0"
__author__ = "Brian Demers"
__licence__ = "BSD"


class OAuth2Plugin(AuthPlugin):

    name = "OAuth 2.0 Client Credentials"
    auth_type = "oauth2"
    description = "Authenticate using OAuth2 Client Credentials Flow."
    auth_require = False
    prompt_password = False

    oauth = parser.add_argument_group(title="OAuth 2.0")

    oauth.add_argument(
        "--client-id",
        default=os.environ.get("HTTPIE_OAUTH2_CLIENT_ID"),
        metavar="CLIENT_ID",
        help="""
        The OAuth 2.0 Client ID
        """,
    )

    oauth.add_argument(
        "--client-secret",
        default=os.environ.get("HTTPIE_OAUTH2_CLIENT_SECRET"),
        metavar="CLIENT_SECRET",
        help="""
        The OAuth 2.0 Client Secret
        """,
    )

    oauth.add_argument(
        "--issuer-uri",
        default=os.environ.get("HTTPIE_OAUTH2_ISSUER"),
        metavar="ISSUER_URI",
        help="""
        The OAuth 2.0 Issuer URI
        """,
    )

    oauth.add_argument(
        "--scope",
        default=os.environ.get("HTTPIE_OAUTH2_SCOPE"),
        metavar="SCOPE",
        help="""
        The OAuth 2.0 Scopes
        """,
    )

    def get_auth(self, username=None, password=None):
        args = parser.args
        client = BackendApplicationClient(client_id=args.client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(
            token_url=args.issuer_uri,
            scope=args.scope,
            include_client_id=True,
            client_secret=args.client_secret,
        )
        return BearerAuth(token=token["access_token"])


class BearerAuth(AuthBase):
    """Adds proof of authorization (Bearer token) to the request."""

    def __init__(self, token):
        """Construct a new Bearer authorization object.
        :param token: bearer token to attach to request
        """
        self.token = token

    def __call__(self, r):
        """Append an Bearer header to the request."""
        r.headers["Authorization"] = "Bearer %s" % self.token
        return r
