FROM python:3.8-slim-buster

RUN pip3 install pipenv
RUN apt-get update -y
RUN apt-get install openssh-client libssl-dev -y

ENV PROJECT_DIR /usr/src/webshop_api

WORKDIR ${PROJECT_DIR}

COPY Pipfile .
COPY Pipfile.lock .
RUN pipenv install --deploy --ignore-pipfile

RUN mkdir keys
RUN ssh-keygen -t rsa -b 4096 -m PEM -f keys/jwtRS256.key
RUN openssl rsa -in keys/jwtRS256.key -pubout -outform PEM -out keys/jwtRS256.key.pub

COPY . .

ARG WEBSHOP_PORT=10100
ENV WEBSHOP_PORT $WEBSHOP_PORT
ENV FILESERVER_PORT $FILESERVER_PORT
EXPOSE $WEBSHOP_PORT

CMD ["pipenv", "run", "gunicorn", "--bind", "0.0.0.0:${WEBSHOP_PORT}", "--workers", "4", "wsgi:app"]
