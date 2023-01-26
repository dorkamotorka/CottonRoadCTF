#!/usr/bin/env python3
import os
from typing import Tuple
from ctf_gameserver import checkerlib
import requests
import requests_random_user_agent # DO NOT REMOVE!
import random
import string
import sys
import base64
import hashlib
from Crypto.PublicKey import RSA
import json


### Monkey patching requests, timeout=5s by default
original_request = requests.Session.request

def monkeypatched_request(self, method, url, timeout=5, **kwargs):
    return original_request(self, method, url, timeout=timeout, **kwargs)

requests.Session.request = monkeypatched_request
###

def randomString(length):
    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))
    return name

class MinimalChecker(checkerlib.BaseChecker):
    SECRET = b'This project has been a very stressing experience'
    PASS = b'But it was also a lot of fun lol :)'

    def place_flag(self, tick: int) -> Tuple[checkerlib.CheckResult, str]:
        # Calculate credentials and set the flagid
        username = hashlib.sha256(checkerlib.get_flag(tick).encode() + __class__.SECRET).hexdigest()[:18]
        email = f"{username}@{username}.com"
        password = hashlib.sha256(checkerlib.get_flag(tick).encode() + __class__.PASS).hexdigest()[:26]
        checkerlib.set_flagid(username)

        # Prepare connection settings for webshop and fileserver
        wport = "10100"
        fport = "10101"
        webshop = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{wport}"
        fileserver = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{fport}"
        sess = requests.Session()
        
        shop_arguments = {
            "session": sess,
            "target": webshop,
            "email": email,
            "username": username,
            "password": password,
            "title": checkerlib.get_flag(tick),
            "content": checkerlib.get_flag(tick)
        }

        fs_arguments = {
            "session": sess,
            "target": fileserver,
            "email": email,
            "username": username,
            "password": password
        }
        
        try:
            insert_webshop_user(shop_arguments)
            insert_fileserver_user(fs_arguments)
            insert_note(shop_arguments)
        except requests.exceptions.ConnectionError as e:
                return (checkerlib.CheckResult.DOWN, f"Service unreachable")
        except Exception as e:
            return (checkerlib.CheckResult.FAULTY, e)
        return checkerlib.CheckResult.OK, ''

    def check_service(self) -> Tuple[checkerlib.CheckResult, str]:
        # Generate random credentials
        username = randomString(15)
        email = f"{username}@{username}.com"
        password = randomString(20)
        
        # Prepare connection settings for webshop and fileserver
        wport = "10100"
        fport = "10101"
        webshop = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{wport}"
        fileserver = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{fport}"
        sess = requests.Session()

        # Prepare file for upload
        filename = f"{randomString(5)}.jpg"
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'bluesquare.jpg')
        file = {'file': (f"{filename}", open(file_path, 'rb'))}
        image_b64 = base64.b64encode(open(file_path, 'rb').read()).decode()

        # Prepare functions to call and randomize them
        user_creation_functions = [
            insert_fileserver_user,
            insert_webshop_user
        ]
        random.shuffle(user_creation_functions)

        insert_functions = [
            insert_item,
            insert_note
        ]
        random.shuffle(insert_functions)

        check_function = [
            check_note_view_functionality,
            check_note_search_functionality,
            check_item_mine_functionality,
            check_item_browse_functionality,
            check_item_view_functionality,
            check_item_stock_functionality,
            # check_item_stockapi_functionality,
            check_item_previtem_functionality,
            check_profile_functionality,
            check_rsa_functionality
        ]
        random.shuffle(check_function)
        check_function.append(check_item_image_functionality)

        # Prepare arguments for functions
        note_title = randomString(10)
        shop_arguments = {
            "session": sess,
            "target": webshop,
            "username": username,
            "email": email,
            "password": password,
            "title": note_title,
            "content": randomString(10),
            "query": note_title,
            "item_title": randomString(5),
            "filename": filename,
            "stock": 10,
            "id": 1,
            "path": f"{hashlib.md5(email.encode()).hexdigest()}/{filename}",
            "image_b64": image_b64
        }

        fs_arguments = {
            "session": sess,
            "target": fileserver,
            "username": username,
            "email": email,
            "password": password,
            "file": file
        }

        # Call functions
        try:
            # test oAuth -> also test to oAuth with taken username? 
            
            insert_fileserver_user(fs_arguments)
            #res = fs_register(**fs_arguments)
            fs_arguments["target"] = webshop
            check_oauth_functionality(fs_arguments)
            fs_arguments["target"] = fileserver
            shop_arguments["session"] = fs_arguments["session"]
            
            for f in insert_functions:
                if f is insert_item: 
                    f(fs_arguments, shop_arguments)
                else: 
                    f(shop_arguments)
            
            for f in check_function:
                f(shop_arguments)

            check_item_reserve_functionality(shop_arguments)
            check_logout_functionality(shop_arguments)

            for f in user_creation_functions:
                if f is insert_fileserver_user: f({"session": requests.Session(), "target": fileserver, "email": f"{randomString(4)}@{randomString(5)}.com", "username": randomString(9), "password": randomString(11)})
                else: f({"session": requests.Session(), "target": webshop, "email": f"{randomString(4)}@{randomString(5)}.com", "username": randomString(9), "password": randomString(11)})
        except requests.exceptions.ConnectionError as e:
            return (checkerlib.CheckResult.DOWN, f"Service unreachable")
        except Exception as e:
            return (checkerlib.CheckResult.FAULTY, e)
        return checkerlib.CheckResult.OK, ''
    
    def check_flag(self, tick: int) -> Tuple[checkerlib.CheckResult, str]:
        # Calculate credentials and set the flagid
        username = hashlib.sha256(checkerlib.get_flag(tick).encode() + __class__.SECRET).hexdigest()[:18]
        email = f"{username}@{username}.com"
        password = hashlib.sha256(checkerlib.get_flag(tick).encode() + __class__.PASS).hexdigest()[:26]

        # Prepare connection settings for webshop and fileserver
        wport = "10100"
        fport = "10101"
        webshop = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{wport}"
        fileserver = f"http://{self.ip if self.ip != '127.0.0.1' else 'localhost'}:{fport}"
        sess = requests.Session()

        shop_arguments = {
            "session": sess,
            "target": webshop,
            "email": email,
            "password": password
        }
        try:

            web_login = shop_login(**shop_arguments)
            web_notes = shop_get_notes(**shop_arguments)

        except requests.exceptions.ConnectionError as e:
            return (checkerlib.CheckResult.FLAG_NOT_FOUND, f"Service unreachable")
        if not checkerlib.get_flag(tick) in web_notes.text:
            return (checkerlib.CheckResult.FLAG_NOT_FOUND, f"Flag for tick {tick} not found for flagID {username}")
        return checkerlib.CheckResult.OK, ''


################## WEBSHOP FUNCTIONS ##################

def shop_register(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/register", data = {
                                            "email": kwargs["email"],
                                            "username": kwargs["username"], 
                                            "password": kwargs["password"]
    })
    return res

def shop_login(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/login", data = {
                                            "email": kwargs["email"],
                                            "password": kwargs["password"]
    })
    return res

def shop_logout(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/logout")
    return res

def shop_get_profile(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + "/profile")
    return res

def shop_get_rsa(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/rsa_pub")
    return res


def shop_create_note(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/notes/create", data = {
                                            "title": kwargs["title"],
                                            "content": kwargs["content"]
    })
    return res

def shop_get_notes(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/notes")
    return res

def shop_search_notes(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/notes/search", data = {
                                            "search-form": kwargs["query"]
    })
    return res

def shop_create_item(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/item/create", data = {
                                            "title": kwargs["item_title"],
                                            "filename": kwargs["filename"],
                                            "stock": kwargs["stock"]
    })
    return res

def shop_get_item(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item/{kwargs['id']}")
    return res

def shop_get_prevItem(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item/prevItem?path=/item/{kwargs['id']}")
    return res

def shop_get_item_stock(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + f"/item/stock", data = {
                                            "stockApi": f"/item/stock/check?itemId={kwargs['id']}"
    })
    return res

def shop_test_stock_api(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item/stock/check?itemId={kwargs['id']}")
    return res

def shop_get_my_items(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item")
    return res

def shop_get_all_items(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item/browse")
    return res

def shop_reserve_item(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + f"/item/{kwargs['id']}")
    return res

def shop_view_item_image(**kwargs) -> requests.Response:
    res = kwargs["session"].get(kwargs["target"] + f"/item/view?id={kwargs['id']}&file={kwargs['filename']}")
    return res



def shop_oauth_login(**kwargs) -> requests.Response:
    print(kwargs["target"])
    res = kwargs["session"].get(kwargs["target"] + "/oauth/login")
    """
    res1 = kwargs["session"].post(res.url, data = {
                                            "email": kwargs["email"],
                                            "password": kwargs["password"]
    })
    """
    res2 = kwargs["session"].post(res.url, data = {"confirm": "on"})
    return res2

################## FILESERVER FUNCTIONS ##################

def fs_register(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/auth/register", data = {
                                                "email": kwargs["email"],
                                                "username": kwargs["username"], 
                                                "password": kwargs["password"]
    })
    return res

def fs_login(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/auth/login", data = {
                                                "email": kwargs["email"],
                                                "password": kwargs["password"]
    })
    return res

def fs_upload_file(**kwargs) -> requests.Response:
    res = kwargs["session"].post(kwargs["target"] + "/dashboard", files = kwargs["file"])
    return res

################## OAUTH USER-CREATION ##################

def check_oauth_functionality(web_args) -> None:
    res = shop_oauth_login(**web_args)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} trying to oAuth into webshop")
    if not web_args["username"] in res.text: raise Exception(f"Couldnt oAuth into webshop")

################## RANDOMIZABLE USER-CREATION FUNCTIONS ##################

def insert_fileserver_user(fs_kwargs) -> None:
    res = fs_register(**fs_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /auth/register in fileserver")
    
    res = fs_login(**fs_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /auth/login in fileserver")
    if fs_kwargs["session"].cookies.get("session") == "": raise Exception(f"Couldn't log into fileserver")
    if fs_kwargs["session"].cookies.get("remember_token") == "": raise Exception(f"Couldn't log into fileserver")

def insert_webshop_user(web_kwargs) -> None:
    res = shop_register(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /register in webshop")
    
    res = shop_login(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /login in webshop")
    if web_kwargs["session"].cookies.get("access-token") == "": raise Exception(f"Couldn't log into webshop")

################## RANDOMIZABLE INSERT FUNCTIONS ##################

def insert_note(web_kwargs) -> None:
    res = shop_create_note(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /notes/create in webshop")
    if res.history[0].headers["NOTE_ID"] is None: raise Exception(f"Got no note_id in /notes/create in webshop")

def insert_item(fs_kwargs, web_kwargs) -> None:
    res = fs_upload_file(**fs_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /dashboard in fileserver trying to upload a file")
    
    res = shop_create_item(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/create in webshop")
    web_kwargs["id"] = res.history[0].headers["ITEM_ID"]

################## RANDOMIZABLE CHECK FUNCTIONS ##################

def check_note_view_functionality(web_kwargs) -> None:
    res = shop_get_notes(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /notes/create in webshop")
    if not web_kwargs["title"] in res.text: raise Exception(f"Couldn't find part of or whole note in /notes")
    if not web_kwargs["content"] in res.text: raise Exception(f"Couldn't find part of or whole note in /notes")

def check_note_search_functionality(web_kwargs) -> None:
    res = shop_search_notes(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /notes/search in webshop")
    if not web_kwargs["title"] in res.text: raise Exception(f"Couldn't find part of or whole note in /notes/search")
    if not web_kwargs["content"] in res.text: raise Exception(f"Couldn't find part of or whole note in /notes/search")

def check_item_mine_functionality(web_kwargs) -> None:
    res = shop_get_my_items(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item in webshop")
    if not web_kwargs["item_title"] in res.text: raise Exception(f"Couldn't find part of or whole item in /item")
    if not str(web_kwargs["stock"]) in res.text: raise Exception(f"Couldn't find part of or whole item in /item")

def check_item_browse_functionality(web_kwargs) -> None:
    res = shop_get_all_items(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/browse in webshop")
    if not web_kwargs["item_title"] in res.text: raise Exception(f"Couldn't find part of or whole item in /item/browse")
    if not str(web_kwargs["stock"]) in res.text: raise Exception(f"Couldn't find part of or whole item in /item/browse")
    
def check_item_view_functionality(web_kwargs) -> None:
    res = shop_get_item(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/<id> in webshop")
    if not web_kwargs["item_title"] in res.text: raise Exception(f"Couldn't find part of or whole item in /item/<id>")
    if not web_kwargs["image_b64"] in res.text: raise Exception(f"Couldn't find part of or whole item in /item/<id>")

def check_item_image_functionality(web_kwargs) -> None:
    res = shop_view_item_image(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/view in webshop")
    if not web_kwargs["image_b64"] == base64.b64encode(res.content).decode(): raise Exception(f"Couldn't find correct image in /item/view")

def check_item_stock_functionality(web_kwargs) -> None:
    res = shop_get_item_stock(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/stock in webshop")
    if not str(web_kwargs["stock"]) in res.text: raise Exception(f"Couldn't find correct stock in /item/stock")
    
# def check_item_stockapi_functionality(web_kwargs) -> None:
#     res = shop_test_stock_api(**web_kwargs)
#     if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/stock/check in webshop")
#     if not str(web_kwargs["stock"]) in res.text: raise Exception(f"Couldn't find correct stock in /item/stock/check")
    
def check_item_previtem_functionality(web_kwargs) -> None:
    res = shop_get_prevItem(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} in /item/prevItem in webshop")

def check_profile_functionality(web_kwargs) -> None:
    res = shop_get_profile(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} int /profile in webshop")
    if not web_kwargs["username"] in res.text: raise Exception(f"Username not correctly displayed in /profile in webshop")

def check_rsa_functionality(web_kwargs) -> None:
    res = shop_get_rsa(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} int /rsa_pub in webshop")

################## NON-RANDOMIZABLE STATE-CHANGING FUNCTIONS ##################

def check_item_reserve_functionality(web_kwargs) -> None:
    res = shop_reserve_item(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} while reserving an item in webshop")
    if not str(web_kwargs["stock"]-1) in res.text: raise Exception(f"Stock couldn't be reserved in webshop")

def check_logout_functionality(web_kwargs) -> None:
    res = shop_logout(**web_kwargs)
    if not res.status_code == 200: raise Exception(f"Got {res.status_code} on /logout in webshop")
    if not web_kwargs["session"].cookies.get("access-token") == None: raise Exception(f"Unable to log out of webshop")
    
if __name__ == '__main__':
    checkerlib.run_check(MinimalChecker)
