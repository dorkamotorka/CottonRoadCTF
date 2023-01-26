import sqlite3
from werkzeug.security import generate_password_hash


conn = sqlite3.connect("database.db")

with open("schema.sql") as f:
    conn.executescript(f.read())

cur = conn.cursor()

cur.execute(
    "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
    ("admin@admin.com", "admin", generate_password_hash("admin", method="sha256")),
)
cur.execute(
    "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
    ("nikola@nikola.com", "nikola", generate_password_hash("nikola", method="sha256")),
)
cur.execute(
    "INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
    ("teo@teo.com", "teo", generate_password_hash("teo", method="sha256")),
)

cur.execute(
    "INSERT INTO notes (title, content, user_email, user_username) VALUES (?, ?, ?, ?)",
    (
        "first post lol",
        "content hereaaaaaaaAAAAAAAAAAKILLME",
        "admin@admin.com",
        "admin",
    ),
)
cur.execute(
    "INSERT INTO notes (title, content, user_email, user_username) VALUES (?, ?, ?, ?)",
    (
        "second post lol",
        "content hereaaaaaaaAAAAAAAAAAKILLME2",
        "nikola@nikola.com",
        "nikola",
    ),
)
cur.execute(
    "INSERT INTO notes (title, content, user_email, user_username) VALUES (?, ?, ?, ?)",
    ("third post lol", "content hereaaaaaaaAAAAAAAAAAKILLME3", "teo@teo.com", "teo"),
)

cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("10g baba haze", "admin@admin.com", "admin", 1000),
)
cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("bike", "nikola@nikola.com", "nikola", 22),
)
cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("Anti tank missiles 3-pack", "teo@teo.com", "teo", 0),
)
cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("Anarchist Manifesto", "teo@teo.com", "teo", 1),
)
cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("flipper zero", "admin@admin.com", "admin", 33),
)
cur.execute(
    "INSERT INTO items (title, user_email, user_username, stock) VALUES (?, ?, ?, ?)",
    ("Crack pipe (used)", "nikola@nikola.com", "nikola", 12),
)

conn.commit()
conn.close()
