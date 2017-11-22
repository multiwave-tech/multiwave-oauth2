#!/usr/bin/env python3


import json
import requests


if __name__ == '__main__':

    # Retrieve configuration from server's sources for our tests
    with open('oauth2-server/config/config.json') as file:
        config = json.load(file)

    # Simply making a POST request on `/token` to retrieve one
    res = requests.post(
        'http://{0}:{1}/{2}'.format(
            config['auth_server']['host'],
            config['auth_server']['port'],
            'token'
        ),
        data={
            'grant_type': 'client_credentials',
            'client_id': config['clients'][0]['client_id'],
            'client_secret': config['clients'][0]['client_secret']
        }
    )
    res.raise_for_status()

    print('{0} {1} -- {2}'.format(res.status_code, res.reason, res.json()))
