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
    OAuth2Error,
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
        if not args.issuer_uri:
            _fail("oauth2: no token endpoint; pass --issuer-uri or set HTTPIE_OAUTH2_ISSUER")
        if not args.client_id:
            _fail("oauth2: no client id; pass --client-id or set HTTPIE_OAUTH2_CLIENT_ID")
        client = BackendApplicationClient(client_id=args.client_id)
        oauth = OAuth2Session(client=client)
        oauth.register_compliance_hook(
            "access_token_response", self._reject_non_token_response
        )
        try:
            token = oauth.fetch_token(
                token_url=args.issuer_uri,
                scope=args.scope,
                include_client_id=True,
                client_secret=args.client_secret,
            )
        except OAuth2Error as error:
            _fail(
                "oauth2: token request to %s failed: %s"
                % (args.issuer_uri, error.description or error.error or error)
            )
        return BearerAuth(token=token["access_token"])

    @staticmethod
    def _reject_non_token_response(response):
        """Fail fast when the token endpoint returns something oauthlib would
        misreport as a "missing token" (e.g. an HTML 404 page)."""
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type:
            return response  # let oauthlib parse it, including JSON error bodies
        body = " ".join(response.text.split())
        snippet = (body[:200] + "...") if len(body) > 200 else body
        _fail(
            "oauth2: token endpoint %s returned HTTP %d with %s instead of a token:\n%s"
            % (
                response.url,
                response.status_code,
                content_type or "no content type",
                snippet,
            )
        )


def _fail(message):
    # HTTPie discards the message of a SystemExit raised during argument
    # parsing (httpie.core.raw_main), so write it to stderr ourselves.
    sys.stderr.write(message + "\n")
    sys.exit(1)


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
