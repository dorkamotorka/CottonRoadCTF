DROP TABLE IF EXISTS Users;

CREATE TABLE "Users" (
	"username"	TEXT NOT NULL,
	"email"	TEXT NOT NULL UNIQUE,
	"password"	TEXT NOT NULL,
	PRIMARY KEY("email")
);

DROP TABLE IF EXISTS Client;

CREATE TABLE "Client" (
	"client_id" TEXT NOT NULL UNIQUE PRIMARY KEY,
    "client_secret" TEXT NOT NULL,
    "default_redirect_uri" TEXT NOT NULL,
    "allowed_redirect_uris" TEXT NOT NULL,
    "response_types" TEXT
);

DROP TABLE IF EXISTS Token;

CREATE TABLE "Token" (
	"token_id" INTEGER NOT NULL UNIQUE,
	"redirect_uri" TEXT NOT NULL,
    "scope" TEXT,
    "client_id" TEXT,
	"revoked" TEXT,
	"expires_in" INTEGER,
    "authorization_code" TEXT,
    "user_id" TEXT,
	FOREIGN KEY("user_id") REFERENCES Users ON DELETE CASCADE,
	PRIMARY KEY ("token_id" AUTOINCREMENT)
);

DROP TABLE IF EXISTS AuthorizationCode;

CREATE TABLE "AuthorizationCode" (
	"id" INTEGER UNIQUE NOT NULL, 
	"code" TEXT, 
	"client_id" TEXT, 
	"redirect_uri" TEXT,
	"scope" TEXT, 
	"user_id" TEXT, 
	"code_challenge" TEXT, 
	"code_challenge_method" TEXT,
	FOREIGN KEY("user_id") REFERENCES Users ON DELETE CASCADE,
	PRIMARY KEY("id" AUTOINCREMENT)
);