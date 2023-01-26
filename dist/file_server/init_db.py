import sqlite3
import requests
from os import environ

conn = sqlite3.connect('database.db')
ip = environ["PUBLIC_IP"] 

with open('schema.sql') as f:
    conn.executescript(f.read())

oauth_client = (
    environ["FILESERVER_CLIENT_ID"],
    environ["FILESERVER_CLIENT_SECRET"],
    f"http://{ip}:10100/oauth/auth",
    f"http://{ip}:10100/oauth/auth",
    "code"
)

conn.execute('INSERT INTO Client (client_id, client_secret, default_redirect_uri ,allowed_redirect_uris, response_types) VALUES (?,?,?,?,?)', oauth_client)
conn.commit()
conn.close()

