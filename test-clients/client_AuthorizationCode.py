#!/usr/bin/env python3

import json
import logging

from urllib.parse import parse_qs, urlencode
from urllib.request import urlopen

from wsgiref.simple_server import WSGIRequestHandler, make_server


class ClientRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.
    This handler is used by the client application.
    """
    def address_string(self):
        return "CLIENT APP"


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
        query = urlencode({'client_id': self.client_id,
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


class RunAppServer():
    def run(self):
        try:
            self.httpd = make_server('', 8081, ClientApplication(),
                                     handler_class=ClientRequestHandler)
            print("Starting Client app on <http://localhost:8081/>...")
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    RunAppServer().run()
