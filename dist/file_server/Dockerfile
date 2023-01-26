FROM python:3.8-slim-buster

RUN pip3 install pipenv

ENV PROJECT_DIR /usr/src/server_api

WORKDIR ${PROJECT_DIR}

RUN mkdir uploads

COPY Pipfile .
COPY Pipfile.lock .
RUN pipenv install --deploy --ignore-pipfile

COPY . .

ARG FILESERVER_PORT=10101
ENV FILESERVER_PORT $FILESERVER_PORT
EXPOSE $FILESERVER_PORT

#CMD ["pipenv", "run", "gunicorn", "--bind", "0.0.0.0:${FILESERVER_PORT}", "--workers", "4", "wsgi:app"]
CMD pipenv run python init_db.py && \
    pipenv run gunicorn --bind 0.0.0.0:${FILESERVER_PORT} --workers 4 wsgi:app
