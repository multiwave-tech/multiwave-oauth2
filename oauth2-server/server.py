#!/usr/bin/env python3


import os
import json
import logging
import threading

from urllib.request import urlopen
from urllib.parse import urlencode, parse_qs

from wsgiref.simple_server import make_server, WSGIRequestHandler

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.store.redisdb import ClientStore, TokenStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import AuthorizationCodeGrantSiteAdapter
from oauth2.web.wsgi import Application
from oauth2.grant import AuthorizationCodeGrant


class ClientRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    This handler is used by the client application.
    """
    def address_string(self):
        return "CLIENT APP"


class OAuthRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    This handler is used by the python-oauth2 application.
    """
    def address_string(self):
        return "MULTIWAVE OAuth2.0"


class TestSiteAdapter(AuthorizationCodeGrantSiteAdapter):
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


class ClientApplication():
    """
    Very basic application that simulates calls to the API of the
    python-oauth2 app.
    """
    callback_url = 'http://localhost:8081/callback'
    client_id = 'abc'
    client_secret = 'xyz'
    api_server_url = 'http://localhost:8080'

    def __init__(self):
        self.access_token = None
        self.auth_token = None
        self.token_type = ''

    def __call__(self, env, start_response):
        if env['PATH_INFO'] == '/app':
            status, body, headers = self._serve_application(env)
        elif env['PATH_INFO'] == '/callback':
            status, body, headers = self._read_auth_token(env)
        else:
            status = "301 Moved"
            body = ''
            headers = {'Location': '/app'}

        start_response(status, list(headers.items()))

        return [body.encode()]

    def _request_access_token(self):
        print("Requesting access token...")

        post_params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': self.auth_token,
            'grant_type': 'authorization_code',
            'redirect_uri': self.callback_url
        }

        result = json.loads(''.join(i.decode() for i in
                            urlopen(self.api_server_url + '/token',
                            urlencode(post_params).encode())))

        self.access_token = result['access_token']
        self.token_type = result['token_type']

        print("Received access token '%s' of type '%s'" % (
                        self.access_token, self.token_type))

        return "302 Found", '', {'Location': '/app'}

    def _read_auth_token(self, env):
        print("Receiving authorization token...")

        query_params = parse_qs(env['QUERY_STRING'])

        if 'error' in query_params:
            location = '/app?error=' + query_params['error'][0]
            return "302 Found", '', {'Location': location}

        self.auth_token = query_params['code'][0]

        print("Received temporary authorization token '%s'" % (
                self.auth_token,))

        return "302 Found", '', {'Location': '/app'}

    def _request_auth_token(self):
        print("Requesting authorization token...")

        auth_endpoint = self.api_server_url + '/authorize'
        query = urlencode({'client_id': 'abc',
                           'redirect_uri': self.callback_url,
                           'response_type': 'code'})

        return "302 Found", '', {'Location': auth_endpoint + '?' + query}

    def _serve_application(self, env):
        query_params = parse_qs(env['QUERY_STRING'])

        if 'error' in query_params and query_params['error'][0] \
                == 'access_denied':
            return "200 OK", "User has denied access.", {}

        if not self.access_token:
            if not self.auth_token:
                return self._request_auth_token()
            else:
                return self._request_access_token()
        else:
            confirmation = "Current access token '%s' of type '%s'" % (
                            self.access_token, self.token_type)

            return "200 OK", confirmation, {}


class RunAppServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        self.app = ClientApplication()

        try:
            self.httpd = make_server('', 8081, self.app,
                                     handler_class=ClientRequestHandler)

            print("Starting Client app on http://localhost:8081/...")
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


class RunAuthServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

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

        # We're all set up, let's run a HTTP server
        self.httpd = make_server(self.config['auth_server']['host'],
                                 self.config['auth_server']['port'],
                                 Application(provider=self.provider),
                                 handler_class=OAuthRequestHandler)

        print("Starting OAuth2 server on http://" +
              self.config['auth_server']['host'] + ':' +
              str(self.config['auth_server']['port']) + "...")

        try:
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    auth_server = RunAppServer()
    auth_server.start()

    app_server = RunAuthServer()
    app_server.start()

    auth_server.join()
    app_server.join()
