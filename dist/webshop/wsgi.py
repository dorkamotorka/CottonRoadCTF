from os import environ
from application import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=environ["WEBSHOP_PORT"])
