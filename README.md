# multiwave-oauth2

## Deployment

We'll be using _Python_, so let's work something out with the [Python-OAuth2](https://github.com/wndhydrnt/python-oauth2) library :

1. Firstly, with a **root shell**, let's install _Docker_ (and some other dependencies) in order to set up a working environment :
	```sh
	# Some dependencies
	aptitude install apt-transport-https ca-certificates curl gnupg2 software-properties-common sysfsutils python3 python3-pip git
	pip3 install -r requirements.txt
    # if python-oauth2 is not available in v2.0.0 use this to install current master
    pip install git+https://github.com/wndhydrnt/python-oauth2.git
	# Some system tweaking
	sysctl vm.overcommit_memory=1
	echo 'kernel/mm/transparent_hugepage/enabled = never' >> /etc/sysfs.conf
	# Let's install Docker !
	curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
	add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
	aptitude update && aptitude install docker-ce
	service docker enable
	# Reboot to apply the system tweaking
	reboot
	# Let's fetch and run an image of Redis Server
	docker pull redis
	docker run --network="host" -p 127.0.0.1:6379:6379 --sysctl net.core.somaxconn=511 --name redis-server -d redis redis-server --appendonly yes
	```

2. Let's fetch the sources of the server :
	```sh
	git clone https://github.com/multiwave-tech/multiwave-oauth2.git
	cd multiwave-oauth2/
	```

3. For this project, we decided to "externalize" the server configuration and clients' secrets. You'll have to configure yours under `oauth2-server/config/config.json`. A basic example would be :
	```json
	{
		"redis_server": {
				"host": "127.0.0.1",
				"port": 6379,
				"db": {
					"token_store": 0,
					"client_store": 1
				}
		},
		"auth_server": {
			"host": "127.0.0.1",
			"port": 8080
		},
		"clients": [
			{
				"client_id": "abc",
				"client_secret": "xyz",
				"redirect_uris": [
					"http://localhost:8081/callback",
					"http://localhost:8081/"
				]
			}
		]
	}
	```

4. Now, we're all set to run it :
	```sh
	# Run the server
	./oauth2-server/server.py
	# Run the AuthorizationCodeGrant test client
	./tests-clients/client_AuthorizationCode.py
	# Run the ImplicitGrant test client
	./tests-clients/client_Implicit.py
	# Run the CredentialsGrant test client
	./test-clients/client_ClientCredentials.py
	```

4. To bind this new server to the 443 port, you could use an _Apache_ or _NGINX_ reverse proxy `your_public_IP:443 <=> 127.0.0.1:8080`.

## Acknowledgment

This code uses and relies on the [Markus Meyer's _python-oauth2_ library](https://github.com/wndhydrnt/python-oauth2).  
The sources you'll encounter there are more or less the [library examples](https://github.com/wndhydrnt/python-oauth2/blob/master/docs/examples/), re-factored and puzzled for maintainability reasons.
