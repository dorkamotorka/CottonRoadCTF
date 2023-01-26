from datetime import datetime, timedelta
from .db import get_db, close_db
from werkzeug.security import generate_password_hash


class User:
    email = ""
    username = ""
    password = ""

    def __init__(self, email: str, username: str, password: str):
        self.username = username
        self.email = email
        self.password = password

    @staticmethod
    def get_from_email(email):
        db = get_db()
        res = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        close_db()
        return (
            User(username=res["username"], email=res["email"], password=res["password"])
            if res is not None
            else None
        )

    @staticmethod
    def get_from_username(username):
        db = get_db()
        res = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        close_db()
        return (
            User(username=res["username"], email=res["email"], password=res["password"])
            if res is not None
            else None
        )

    @staticmethod
    def get_from_email_or_username(email, username):
        db = get_db()
        res = db.execute(
            "SELECT * FROM users WHERE email = ? OR username = ?", (email, username)
        ).fetchone()
        close_db()
        return (
            User(username=res["username"], email=res["email"], password=res["password"])
            if res is not None
            else None
        )

    @staticmethod
    def get_usernames():
        usernames = []
        db = get_db()
        res = db.execute("SELECT * FROM users")
        close_db()
        for r in res:
            usernames.append(r["username"])
        return usernames

    def insert(self):
        db = get_db()
        hash = None
        if self.password:
            hash = generate_password_hash(self.password, method="sha256")
        db.execute(
            "INSERT INTO users (username, email, password) VALUES (?,?,?)",
            (self.username, self.email, hash),
        )
        close_db()



class Note:
    id = 0
    title = ""
    content = ""
    user_email = ""
    user_username = ""

    def __init__(
        self,
        title: str,
        content: str,
        user_email: str,
        user_username: str,
        id: int = None,
    ):
        self.id = id
        self.title = title
        self.content = content
        self.user_email = user_email
        self.user_username = user_username

    @staticmethod
    def get_notes(user_username):
        db = get_db()
        res = db.execute(
            "SELECT * FROM notes WHERE user_username = ?", (user_username,)
        ).fetchall()
        notes = []
        for note in res:
            notes.append(
                Note(
                    id=note["id"],
                    title=note["title"],
                    content=note["content"],
                    user_email=note["user_email"],
                    user_username=note["user_username"],
                )
            )
        close_db()
        return notes

    @staticmethod
    def get_filtered_notes(search, user_username):
        db = get_db()
        query = f"""
                SELECT * FROM notes WHERE user_username = ? AND title LIKE '%{search}%';"""

        notes = []

        try:

            res = db.execute(query, (user_username,)).fetchall()
        except Exception as e:
            raise e
        else:
            for note in res:
                notes.append(
                    Note(
                        id=note["id"],
                        title=note["title"],
                        content=note["content"],
                        user_email=note["user_email"],
                        user_username=note["user_username"],
                    )
                )
        finally:
            close_db()
            return notes

    @staticmethod
    def get_from_id(id):
        db = get_db()
        res = db.execute("SELECT * FROM notes WHERE id = ?", (id,)).fetchone()
        close_db()
        return (
            Note(
                id=res["id"],
                title=res["title"],
                content=res["content"],
                user_email=res["user_email"],
                user_username=res["user_username"],
            )
            if res is not None
            else None
        )

    @staticmethod
    def get_matching(title, content, user_email, user_username):
        db = get_db()
        res = db.execute(
            "SELECT * FROM notes WHERE title = ? AND content = ? AND user_email = ? AND user_username = ?",
            (title, content, user_email, user_username),
        ).fetchone()
        close_db()
        return (
            Note(
                id=res["id"],
                title=res["title"],
                content=res["content"],
                user_email=res["user_email"],
                user_username=res["user_username"],
            )
            if res is not None
            else None
        )

    def insert(self):
        db = get_db()
        db.execute(
            "INSERT INTO notes (title, content, user_email, user_username) VALUES (?, ?, ?, ?)",
            (self.title, self.content, self.user_email, self.user_username),
        )
        close_db()

def secure_filename(filename):
    return filename.replace("../", "")


class Item:
    id = 0
    title = ""
    filename = ""
    stock = 0
    user_email = ""
    user_username = ""

    def __init__(
        self,
        title: str,
        filename: str,
        stock: int,
        user_email: str,
        user_username: str,
        id: int = None,
    ):
        self.id = id
        self.title = title
        self.filename = filename
        self.stock = stock
        self.user_email = user_email
        self.user_username = user_username

    @staticmethod
    def get_from_id(item_id):
        db = get_db()
        res = db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        close_db()
        return (
            Item(
                id=res["id"],
                title=res["title"],
                filename=res["filename"],
                stock=res["stock"],
                user_email=res["user_email"],
                user_username=res["user_username"],
            )
            if res is not None
            else None
        )



    @staticmethod
    def get_all():
        db = get_db()
        res = db.execute("SELECT * FROM items").fetchall()
        items = []
        for item in res:
            items.append(
                Item(
                    id=item["id"],
                    title=item["title"],
                    filename=item["filename"],
                    user_email=item["user_email"],
                    stock=item["stock"],
                    user_username=item["user_username"],
                )
            )
        close_db()
        return items

    @staticmethod
    def get_from_username(user_username):
        db = get_db()
        res = db.execute(
            "SELECT * FROM items WHERE user_username = ?", (user_username,)
        ).fetchall()
        items = []
        for item in res:
            items.append(
                Item(
                    id=item["id"],
                    title=item["title"],
                    filename=item["filename"],
                    user_email=item["user_email"],
                    stock=item["stock"],
                    user_username=item["user_username"],
                )
            )
        close_db()
        return items

    @staticmethod
    def get_matching(title, filename, stock, user_username, user_email):
        db = get_db()
        res = db.execute(
            "SELECT * FROM items WHERE title = ? AND filename = ? AND stock = ? AND user_username = ? AND user_email = ?",
            (title, filename, stock, user_username, user_email),
        ).fetchone()
        close_db()
        return (
            Item(
                id=res["id"],
                title=res["title"],
                filename=res["filename"],
                stock=res["stock"],
                user_email=res["user_email"],
                user_username=res["user_username"],
            )
            if res is not None
            else None
        )

    def insert(self):
        db = get_db()
        db.execute(
            "INSERT INTO items (title, filename, user_email, stock, user_username) VALUES (?, ?, ?, ?, ?)",
            (
                self.title,
                self.filename,
                self.user_email,
                self.stock,
                self.user_username,
            ),
        )
        close_db()

    def lower_stock(self):
        db = get_db()
        db.execute("UPDATE items SET stock = stock - 1 WHERE id = ?", (self.id,))
        close_db()
