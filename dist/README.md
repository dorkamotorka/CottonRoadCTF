## Requirements:

- python3.x needs to be installed to execute the prehook script

## How to run

In order to run the project, first let's clean the environment, in case there are any dangling resoures:

	make purge

To run the architecture, first initialize secrets using (WARNING: This resets the DB):

	python prehook.py	

Then you can run the architecture using:

	make start

This builds the `Dockerfiles` and runs the architecture.


## How to debug

There should be sufficient output information to tell you what's going on with the system. 
If you encounter any issues, try looking into **docker logs** since all components are spawned inside Docker containers.


## How to stop and purge

You can casually stop the architecture using **Ctrl+C**, but to delete the Docker resources, run:

	make purge
