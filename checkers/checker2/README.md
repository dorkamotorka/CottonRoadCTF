# Flag file uploaded by designated user (on the file upload server)

The flag is stored in a file uploaded by a designated user. The goal of the players is to read its content through multiple ways.

Flag ID’s format: **email**


## Building and running the checker

Log into the private registry to access the base image:

        docker login -u ctf registry.w0y.at
        Password: glpat-6s4z9-yWaWaEcT_6scyH

You can test the checker using:

	docker-compose build
        TICK=0 docker-compose up

Note that ticks follow in order, so if you wanna test tick number 3 you need to first run the ticks 0, 1, 2.


## Service functionality checks

Besides `registration` and `login` also the the following functionalities are checked:

* Upload file
* Retrieve file

## Traffic randomization

For each `tick` we randomly choose or generate the following parameters:

* `User-agent` in `requests` Python library 
* `user metadata`

in order to make it harder for other teams to fingerprint the checker network traffic and exploit the flag.
