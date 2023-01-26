# Account Panel (within the personel notes)

The first flag store will be a personal note that one of the users has. The user who has this note is identified using the flag ID.

Flag ID’s format: **username**

## Building and running the checker

Log into the private registry to access the base image:

	docker login -u ctf registry.w0y.at
	Password: glpat-6s4z9-yWaWaEcT_6scyH

You can test the checker using:

	docker-compose build
	TICK=0 docker-compose up

Note that ticks follow in order, so if you wanna test tick number 3 you need to first run the ticks 0, 1, 2.


## Service functionality checks

Besides `registration` and `login` also the the following functionalities are checked in a random order:

* View note
* Search note
* Own item (mine)
* Browse item
* View item
* Check item stock
* Check item stock api
* Check item image
* Check profile
* Check RSA

The checker randomly picks between them and validates the success.


## Traffic randomization

For each `tick` we randomly choose or generate the following parameters:

* `User-agent` in `requests` Python library
* `user metadata`
* `Order of service functionality tests`

in order to make it harder for other teams to fingerprint the checker network traffic and exploit the flag.
