#!/usr/bin/env python3

import json
import logging

from urllib.parse import urlencode
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
    Serves the local JavaScript client.
    """
    def __init__(self, config):
        self.config = config

    def __call__(self, env, start_response):
        JS_APP = """
            <html>
            <head>
                <title>OAuth2 JS Test App</title>
            </head>
            <body>
                <script type="text/javascript">
                    var accessToken = null;
                    var params = {{}};
                    var hash = window.location.hash.substring(1);

                    if(hash == "" && accessToken == null) {{
                        window.location.href = "http://{0}:{1}/authorize?{2}";
                    }}

                    var hashParts = hash.split("&");
                    for(var i = 0; i < hashParts.length; i++) {{
                        var keyValue = hashParts[i].split("=");
                        params[keyValue[0]] = keyValue[1];
                    }}

                    if("access_token" in params) {{
                        alert("Your access token: " + params["access_token"]);
                    }}
                    else {{
                        if("error" in params) {{
                            if("access_denied" == params["error"]) {{
                                alert("User has denied access.");
                            }}
                        }}
                        else {{
                                alert("An error occurred: " + params["error"]);
                        }}
                    }}
                </script>
            </body>
            </html>
        """

        template = JS_APP.format(
            self.config['auth_server']['host'],
            self.config['auth_server']['port'],
            urlencode({
                'response_type': 'token',
                'client_id': self.config['clients'][0]['client_id'],
                'redirect_uri': self.config['clients'][0]['redirect_uris'][1],
                'scope': 'scope_write'
            })
        )

        start_response("200 OK", [('Content-Type', 'text/html')])

        return [template.encode()]


class RunAppServer():
    def run(self):
        # Retrieve configuration from server's sources for our tests
        with open('oauth2-server/config/config.json') as file:
            config = json.load(file)
            clientURI = config['clients'][0]['redirect_uris'][1]

        try:
            self.httpd = make_server(
                clientURI.rpartition(':')[0].rpartition('/')[2],
                int(clientURI.rpartition(':')[2].rstrip('/')),
                ClientApplication(config)
            )
            print("Starting Client app on <" + clientURI + ">...")
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    RunAppServer().run()
