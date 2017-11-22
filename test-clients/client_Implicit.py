#!/usr/bin/env python3

import logging

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
    def __call__(self, env, start_response):
        JS_APP = """
            <html>
                <head>
                    <title>OAuth2 JS Test App</title>
                </head>
                <body>
                    <script type="text/javascript">
                        var accessToken = null;
                        var params = {};
                        var hash = window.location.hash.substring(1);

                        if(hash == "" && accessToken == null) {
                            window.location.href = "http://localhost:8080/authorize?response_type=token&client_id=abc&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2F&scope=scope_write"
                        }

                        var hashParts = hash.split("&");
                        for(var i = 0; i < hashParts.length; i++) {
                            var keyValue = hashParts[i].split("=");
                            params[keyValue[0]] = keyValue[1]
                        }

                        if("access_token" in params) {
                            alert("Your access token: " + params["access_token"]);
                        }
                        else {
                            if("error" in params) {
                                if("access_denied" == params["error"]) {
                                    alert("User has denied access");
                                }
                                else {
                                    alert("An error occurred: " + params["error"]);
                                }
                            }
                        }
                    </script>
                </body>
            </html>
        """

        start_response("200 OK", [('Content-Type', 'text/html')])

        return [JS_APP.encode()]


class RunAppServer():
    def run(self):
        try:
            self.httpd = make_server('', 8081, ClientApplication())
            print("Starting Client app on <http://localhost:8081/>...")
            self.httpd.serve_forever()

        except KeyboardInterrupt:
            self.httpd.server_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    RunAppServer().run()
