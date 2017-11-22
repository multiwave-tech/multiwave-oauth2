#!/usr/bin/env python3


import logging
import json
import os

from wsgiref.simple_server import WSGIRequestHandler, make_server

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.store.redisdb import ClientStore, TokenStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import AuthorizationCodeGrantSiteAdapter, \
    ImplicitGrantSiteAdapter
from oauth2.web.wsgi import Application
from oauth2.grant import AuthorizationCodeGrant, ImplicitGrant, \
    RefreshToken, ClientCredentialsGrant


class OAuthRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    This handler is used by the python-oauth2 application.
    """
    def address_string(self):
        return "MULTIWAVE OAuth2.0"


class TestSiteAdapter(
    AuthorizationCodeGrantSiteAdapter,
        ImplicitGrantSiteAdapter):
    """
    This adapter renders a confirmation page so the user can confirm the auth
    request.
    """
    CONFIRMATION_TEMPLATE = """
        <!DOCTYPE html>
        <html>
        <body>
            <p>
                <a href="{url}&confirm=yes">Confirm</a>
            </p>
            <p>
                <a href="{url}&confirm=no">Deny</a>
            </p>
        </body>
        </html>
    """

    def render_auth_page(self, request, response, environ, scopes, client):
        url = request.path + '?' + request.query_string
        response.body = self.CONFIRMATION_TEMPLATE.format(url=url)

        return response

    def authenticate(self, request, environ, scopes, client):
        if request.method == 'GET' and request.get_param('confirm') == 'yes':
                return

        raise UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == 'GET' and request.get_param('confirm') == 'no':
                return True

        else:
            return False


class RunAuthServer():
    def __init__(self):
        try:
            with open('oauth2-server/config/config.json') as file:
                self.config = json.load(file)

        except FileNotFoundError:
            print('Did you configure the `oauth2-server/config/config.json` ?')
            os._exit(-1)

        except json.JSONDecodeError as e:
            print('\'oauth2-server/config/config.json\': \"' + e.msg +
                  '\" at line ' + str(e.lineno) + ' column ' + str(e.colno))
            os._exit(-1)

    def run(self):
        # Let's store our data into to Redis database(s)
        self.token_store = TokenStore(
            host=self.config['redis_server']['host'],
            port=self.config['redis_server']['port'],
            db=self.config['redis_server']['db']['token_store']
        )
        self.client_store = ClientStore(
            host=self.config['redis_server']['host'],
            port=self.config['redis_server']['port'],
            db=self.config['redis_server']['db']['client_store']
        )

        # Here, we just add each client registered into our Redis DB
        for x in self.config['clients']:
            self.client_store.add_client(
                client_id=x['client_id'],
                client_secret=x['client_secret'],
                redirect_uris=x['redirect_uris']
            )

        self.provider = Provider(
            access_token_store=self.token_store,
            auth_code_store=self.token_store,
            client_store=self.client_store,
            token_generator=Uuid4()
        )

        # We'll be granting access with authorization codes
        self.provider.add_grant(
            AuthorizationCodeGrant(site_adapter=TestSiteAdapter())
        )
        # But implicit grant too !
        self.provider.add_grant(
            ImplicitGrant(site_adapter=TestSiteAdapter())
        )
        # # Refresh token (still to test)
        self.provider.add_grant(
            RefreshToken(expires_in=2592000)
        )
        # Simple client credentials grant (see the test file)
        self.provider.add_grant(
            ClientCredentialsGrant()
        )

        # We're all set up, let's run a HTTP server
        self.httpd = make_server(self.config['auth_server']['host'],
                                 self.config['auth_server']['port'],
                                 Application(provider=self.provider),
                                 handler_class=OAuthRequestHandler)

        print("Starting OAuth2 server on <http://" +
              self.config['auth_server']['host'] + ':' +
              str(self.config['auth_server']['port']) + ">...")

        try:
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    RunAuthServer().run()
