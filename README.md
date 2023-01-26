CottonRoad
============

Authors:
* Philipp Schoeller, 11907084, Author 1
* Florian Schauer, 12019869, Author 2
* Nikola Radosavljevic, 12222119, Author 3
* Teodor Janez Podobnik, 12206639, Author 4

Categories:<br>
* Server-Side Security: **SQLi**<br>
* Cryptography: **JWT**<br>
* Server-Side Security: **oAuth**<br>
* Server-Side Security: **Path Traversal**
* Server-Side Security: **SSRF**<br>

Repository structure
--------

* `checkers` directory - The checkers code that place and retrieve flags from the service. Additionally it checks whether the service is online and healthy.
* `dist` directory - The root of the repository that will be distributed to each participating team and can be used to patch the service. 
* `exploits` directory - The code to exploit the service vulnerabilities
* `patches` directory - The code to patch the vulnerabilities in the service

How to run
--------
All following commands must be executed in the dist directory, so first make sure to do so by executing:

	cd dist

In order to run the project, first let's clean the environment, in case there are any dangling resoures:

	make purge

To run the architecture, first initialize secrets using (WARNING: This resets the DB):

	python prehook.py	

Then you can run the architecture using:

	make start

This builds the `Dockerfiles` and runs the architecture.


How to debug
--------
There should be sufficient output information to tell you what's going on with the system. 
If you encounter any issues, try looking into **docker logs** since all components are spawned inside Docker containers.


How to stop and purge
--------
You can casually stop the architecture using **Ctrl+C**, but to delete the Docker resources, run:

	make purge

Overview
--------
The service is split up into two smaller services:
- The WEBSHOP
- The FileServer

The first service is a WEBSHOP where users can create/view notes (private) and items (public). When entering the site one must create an account or login (via `email` + `password` OR oAuth using a FileServer account) to proceed.
In the webshop you can view your profile, create/view your own notes, create/view your own items, and view all items that exist in the store. Each store item has an idividual page where one can see the image (if available).
On the individual item page one can check the stock of the item, reserve the item (reducing the available stock), view the image data of the item and go to the previous item in the list.

All WEBSHOP Features:
- Register - a user can register an account using `username`, `email`, and `password`
    - `username` needs to be alphanumeric
    - `username` and `email` are unique
- Login - a user can login using `email` and `password` or via oAuth
    - via oAuth the user is redirected to the FileServer where they can login and grant access to the account
    - if the user (with the given `email`) does not exist on the WEBSHOP they are created
    - if the user does exist, they are logged in as the existing user with the corresponding `email`
- Create and view personal notes (private - can't be seen by other users)
    - up to 10 notes can be created per user account
    - notes can have any title and the content can be a maximum of 450 characters
    - personal notes can be searched by their title
- Create and view own shop items (public - can be seen when browsing all store items)
    - up to 6 items can be created per user account
    - when creating an item you can enter name, filename, stock
    - the filename should reference a file existing on the FileServer
        - e.g. filename = 'example.jpg' if it does not exist a generic image will be placed instead
    - stock - the available amount of this item
- Browse all available items - this lists all items created by all users
    - Items displayed show name of selling user, stock and item name
- Item page - each item has its own page where one can see the item id, name, image (if available); it also has multiple options:
    - Check Stock - checks how much of this item is available
    - Reserve item - lowers the amount of available stock by 1 if not sold out
    - Previous item - you can go to the item with the previous ID (all items are public anyways)
    - View Image - if the item has an image it can be viewed
- Profile page -  a welcome screen for the user
- Navbar - ability to go to all sections of the WEBSHOP

The second service is a FileServer. The FileServer requires a separate account and manages file uploads and oAuth. A user can upload a png, jpg, or jpeg file and then use this image in the WEBSHOP when creating an item. A user can also use their FileServer account to authenticate via oAuth in the WEBSHOP.

All FileServer Features:
- Register - a user can register an account using `username`, `email`, and `password`
    - `username` needs to be alphanumeric
    - `username` is non-unique
    - `email` is unique
- Login - a user can login using `email` and `password`
    - a normal login redirects the user to the dashboard
- oAuth - the FileServer is also a oAuth provider allowing a user to login to the WEBSHOP with their FileServer account
    - a user logging in from the WEBSHOP via oAuth will be redirected to the login page of the FileServer
    - logging in on the FileServer then redirects to a page where the user can grant oAuth access
- Dashboard - user can upload files and view them
    - File upload - a user can upload jpg, jpeg, and png files with a max size of 100KB
    - A user can upload up to 6 files
    - A user can view the uploaded files and their filename (should be used in the WEBSHOP to access them)

We plan to use **HTML**, **CSS**, **Javascript** **SQL**, **Python**, to build the webshop itself, and **Python** to build the apps listening on seperate ports, and **Linux Server** to host the webshop. The backend is run by **FLask**, which connects to a **SQLite database**. The App will be containerized and deployed using **Docker** utilities.

### Flag Store 1 - Personal Notes (within the flag-user account)
The first flag store is a personal note that one of the users has. The user who has this note is identified using the flag ID.

We use the following FlagID: **username**

### Flag Store 2 - Flag file uploaded by designated user (stored in the FileServer)
The flag is stored in a file uploaded by a designated user. The goal of the players is to read its content through multiple ways.

We use the following FlagID: **email**

Vulnerabilities
---------------

### Flag Store 1, Vuln 1
SQLi to read the personal notes of all users

The service has user input which is not sanitized properly, and one of the many queries will contain a **flaw in the usage of the untrusted input**, therefore allowing SQLi to be possible. The SQLi is located in the search feature for the notes. Using this SQLi the user gets access to a table containing all the users and their personal notes. The notes displayed by the search query can then be modified to show the notes of all users or one specific user (e.g. the flag-user). One specific user on the site will have the flag in their personal notes which can then be extracted and submitted.

* Difficulty: **easy**
* Discoverability: **easy**
* Patchability: **easy**

### Flag Store 1, Vuln 2
JWT Algorithm Confusion to login as a user by manipulating the JWT correctly

JWT Algorithm Confusion occurs when an **attacker is able to change the signing algorithm of JWT**. Therefore it can be possible for the attacker to sign its own tokens without knowing the secret key from the server.  

* Difficulty: **medium**
* Discoverability: **medium**
* Patchability: **easy**

Our webserver is configured to use RS256 as a signing algorithm. However, if the user manipulates the token and changes the algorithm (which is normally configured in the header) to HS256 the webserver will use the public key (as the symmetric key) to verify the token.

### Flag Store 1, Vuln 3
oAuth Login Bypass to login into an arbitrary account (`username` = flagid)

To implement this vulnerability we introduce a sub-service, which represents a file-upload service to upload pictures for the webshop. This sub-service serves as an identity provider for the webshop, so that it is possible to login to the webshop using oAuth.
To create an account for the file upload server one needs to enter the following values:

- `username` (**NOT** unique)
- `email` (unique)
- `password`

When logging in using oAuth the webshop checks if a user with the given email already exists in it's database. If there is an entry, the user is logged in as that user, otherwise a new account with the given parameters is created. The vulnerability allows for an attacker to be authenticated as an arbitrary webshop user, by oAuthing with any email address and the username of the targeted account.

* Difficulty: **medium**
* Discoverability: **hard**
* Patchability: **medium**

### Flag Store 2, Vuln 1
Path Traversal with faulty sanitization

Shop items will be loaded by sending a GET-request to the Web Server endpoint, which in turn retrieves a matching image (if existent) from the FileServer:

- GET **<em>{webshop}/item/view?id={id of existing item}&file={image-name of item}</em>**                     &#8594; returns the raw png data of the requested image

- GET **<em>{webshop}/item/view?id={id of existing item}&file=../../../etc/passwd</em>**               &#8594; returns some form of error

- GET **<em>example.com/images?name=....//....//....//etc/passwd</em>** &#8594; returns the content of /etc/passwd

**Malicious user is able to create a path to an arbitrary file** and read the flag.

* Difficulty: **medium**
* Discoverability: **easy**
* Patchability: **easy**

### Flag Store 2, Vuln 2
SSRF with an open redirect to send custom GET-requests to the webserver containing arbitrary http-endpoints.

There are two vital parts to this vulnerability:<br>
* The Web Server, serving users
* An internal API, checking and returning availability of an item (the File Upload Server)

The store has a check stock feature, which returns the amount of items available to the user. The Web Server checks the item stock by calling an endpoint on itself, giving `stockApi` as a parameter. `stockApi` is a string containing an endpoint the webshop should poll to get the available stock.

A **malicious user is able to manipulate part of the URL the webserver sends requests to**, by sending maliciously crafted parameters, containing arbitrary http-endpoints, to the webserver when checking the stock.

However, since the domain of the stock checker is hardcoded, the attack has to be paired with an open redirect to be successfully exploited. Since the webshop has valid credentials for the fileserver, an attacker can use this vulnerability to retrieve arbitrary images from any user on the fileserver.

* Difficulty: **medium**
* Discoverability: **medium**
* Patchability: **medium**

Patches
-------

### Flag Store 1, Vuln 1
**Fixing the flawed SQL query** will prevent the attacker from gaining access to the notes table and finding the flag.

### Flag Store 1, Vuln 2
The easiest way to patch this vulnerability is to configure the **JWT library so that it may only use asymmetric algorithms**, so that only RS256 is allowed.

### Flag Store 1, Vuln 3
A way to patch this vulnerability is to slightly change the given username of the person trying to oAuth, if this username is already taken in the webshop and an account for the given email doesn't exist.

### Flag Store 2, Vuln 1
**Prevent path traversal by making sure '..' (current directory exit) is not included in the path**.

### Flag Store 2, Vuln 2
A possible way to ensure security could be **sanitizing the redirect-to variable of incoming POST-requests**.

Work Packages
-------------

### WP 1, Basic Server- & Frontend Setup & dockerization

### WP 2, Implementing the Vulnerabilities

### WP 3, Implementing the Service-Checkers and Bots

### WP 4, Testing Service and Vulnerabilities

Timeline
--------

WP 1 (done by 02.12.2022)
* Nikola: **Setting up basic server functionality (setting up http listeners)** 
* Florian: **Frontend Web Design of the Shop**
* Philipp: **Create a database with corresponding tables**
* Teodor: **Dockerization**

WP 2 (done by 12.12.2022)
* Philipp: **SQLi**
* Teodor: **Path Traversal**
* Teodor & Nikola: **SSRF with an open redirect**
* Florian: **JWT Algorithm Confusion**
* Florian & Philipp: **oAuth Login Bypass**

WP 3 (done by 27.12.2022)
* All: **Extending Vulnerabilities with a Checker (dispatching the flag + app functionality testing)**

WP 4 (done by 02.01.2023)
* All: **Demonstrating (automated script) exploit and patch of the vulnerability**
