#!/usr/bin/env python3


import requests


if __name__ == '__main__':

    # Simply making a POST request on `/token` to retrieve one
    res = requests.post(
        'http://localhost:8080/token',
        data={
            'grant_type': 'client_credentials',
            'client_id': 'abc',
            'client_secret': 'xyz'
        }
    )
    res.raise_for_status()

    print('{0} {1} -- {2}'.format(res.status_code, res.reason, res.json()))
