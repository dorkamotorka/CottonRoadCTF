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
from io import BytesIO


def randomString(length):
    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(length))
    return name

def upload_file(sess, url, timeout):
    ret = 0
    file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'testimage.jpg')
    file = {'file': ("testimage.jpg", open(file_path, 'rb'))}
    try:
        resp = sess.post(url + "/dashboard", files=file, timeout=timeout)
        if not resp.status_code == 200:
            ret = 1
    except requests.exceptions.ConnectionError as e:
        ret = 2
    return ret

def retrieve_file(sess, url, timeout):
    ret = 0
    try:
        resp = sess.get(url + f"/dashboard", timeout=timeout)
        file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'testimage.jpg')
        image = base64.b64encode(open(file_path, 'rb').read()).decode()
        if not image in resp.text:
            ret = 1
    except requests.exceptions.ConnectionError as e:
        ret = 2
    return ret

class MinimalChecker(checkerlib.BaseChecker):

    def __init__(self, ip: str, team: int):
        super().__init__(ip, team)
        self.ip = ip
        self.team = team
        self.timeout = 5
        self.fport = "10101"
        self.file_server = f"http://{self.ip}:{self.fport}"
        self.wport = "10100"
        self.webshop = f"http://{self.ip}:{self.wport}"
        self.secret = "supersecret"

    def generate_credentials(self, tick):
        flag = checkerlib.get_flag(tick)
        h = hashlib.sha256((flag + self.secret).encode('latin-1')).hexdigest()
        username = 'bot' + h[0:20]
        email = f"{username}@{username}.com"
        password = h[20:40] 

        return username, email, password, flag

    def place_flag(self, tick: int) -> Tuple[checkerlib.CheckResult, str]:
        s = requests.Session()
        username, email, password, flag = self.generate_credentials(tick)
        checkerlib.set_flagid(email)

        try:
            r = s.post(self.file_server + "/auth/register", data={"email": email, "username": username, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /auth/register on the file_server")

            r = s.post(self.file_server + "/auth/login", data = {"email": email, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /auth/login on the file_server")

            r = s.post(self.webshop + "/register", data={"email": email, "username": username, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /register on the webshop")

            r = s.post(self.webshop + "/login", data = {"email": email, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /login on the webshop")

        except requests.exceptions.ConnectionError as e:
            return (checkerlib.CheckResult.DOWN, "Service unreachable")

        f = BytesIO(flag.encode()) 
        flagfile = {'file': (f"flag.jpg", f.getvalue())}
        try:
            resp = s.post(self.file_server + "/dashboard", files=flagfile, timeout=self.timeout)
            if not resp.status_code == 200:
                return (checkerlib.CheckResult.FAULTY, f"Failed to store file on the file_server when calling /dashboard")
        except requests.exceptions.ConnectionError as e: 
            return (checkerlib.CheckResult.DOWN, "Service unresponsive")

        return checkerlib.CheckResult.OK, ''

    def check_service(self) -> Tuple[checkerlib.CheckResult, str]:
        username = randomString(random.randint(5, 10))
        email = f"{username}@{username}.com"
        password = randomString(random.randint(8, 15))
        s = requests.Session()
        r = s.post(self.file_server + "/auth/register", data={"email": email, "username": username, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /auth/register on the file_server")

        r = s.post(self.file_server + "/auth/login", data = {"email": email, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /auth/login on the file_server")

        r = s.post(self.webshop + "/register", data={"email": email, "username": username, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /register on the webshop")

        r = s.post(self.webshop + "/login", data = {"email": email, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            return (checkerlib.CheckResult.FAULTY, f"Got {r.status_code} in the /login on the webshop")

        functions = [upload_file, retrieve_file]
        for x in range(len(functions)):
            ret = functions[x](s, self.file_server, self.timeout)
            if ret == 1:
                return (checkerlib.CheckResult.FAULTY, "Failed to upload/retrieve a file")
            if ret == 2:
                return (checkerlib.CheckResult.DOWN, "Service unreachable")
            else:
                print(f"Successfully passed {x + 1} service checks")

        return checkerlib.CheckResult.OK, ''


    def check_flag(self, tick: int) -> Tuple[checkerlib.CheckResult, str]:
        s = requests.Session()
        username, email, password, flag = self.generate_credentials(tick)
        try:
            r = s.post(self.file_server + "/auth/login", data = {"email": email, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FLAG_NOT_FOUND, f"Got {r.status_code} in the /auth/login on the file_server")

            r = s.post(self.webshop + "/login", data = {"email": email, "password": password}, timeout=self.timeout)
            if r.status_code != 200:
                return (checkerlib.CheckResult.FLAG_NOT_FOUND, f"Got {r.status_code} in the /login on the webshop")

        except requests.exceptions.ConnectionError as e:
            return (checkerlib.CheckResult.FLAG_NOT_FOUND, "Service unreachable")

        try:
            r = s.get(self.file_server + f"/dashboard", timeout=self.timeout)
            try:
                flag = base64.b64encode(checkerlib.get_flag(tick).encode()).decode()
                if not flag in r.text:
                    return (checkerlib.CheckResult.FLAG_NOT_FOUND, "Failed to retrieve the flag")
            except:
                return (checkerlib.CheckResult.FLAG_NOT_FOUND, "Failed to base64 decode the image data")

        except requests.exceptions.ConnectionError as e:
            return (checkerlib.CheckResult.FLAG_NOT_FOUND, "Service unreachable")

        return checkerlib.CheckResult.OK, ''


if __name__ == '__main__':
    checkerlib.run_check(MinimalChecker)
