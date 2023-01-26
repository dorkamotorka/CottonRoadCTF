DROP TABLE IF EXISTS users;

CREATE TABLE users (
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    "password" TEXT,
    "created" DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (email, username)
);

DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    user_email TEXT NOT NULL,
    user_username TEXT NOT NULL,
    FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY(user_username) REFERENCES users(username) ON DELETE CASCADE
);

DROP TABLE IF EXISTS items;

CREATE TABLE items(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT,
    user_email TEXT NOT NULL,
    user_username TEXT NOT NULL,
    stock INTEGER NOT NULL, 
    FOREIGN KEY(user_email) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY(user_username) REFERENCES users(username) ON DELETE CASCADE
);


DROP TRIGGER IF EXISTS clean_up_database_users;

CREATE TRIGGER clean_up_database_users AFTER INSERT ON users
    BEGIN
        DELETE FROM users WHERE "created" < DATETIME('now', '-40 minutes');
    END;