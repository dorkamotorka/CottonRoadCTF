
"""
    !!!ATTENTION!!!

    THIS FILE NEEDS TO BE EXECUTED BEFORE THE CONTAINER IS BUILT, OTHERWISE THE SERVICE WON'T WORK!!!
    
    !!!ATTENTION!!!
"""
import os
import secrets

def writeToFile(filename: str, config: dict) -> None:
    with open(filename, 'w') as f:
        for name, value in config.items():
            f.write(name + "=" + value)
    

def parseFile(filename: str) -> dict:
    ret = dict()
    with open(filename, 'r') as f:
        for line in f:
            ret[line.split("=", 1)[0]] = line.split("=", 1)[1]
    return ret

def generateSecrets() -> None:
    webshopenv = parseFile("./webshop/.env")
    fileenv = parseFile("./file_server/.env")
    fileserver_client_id = '"' + secrets.token_hex(32) + '"\n'
    fileserver_client_secret = '"' + secrets.token_hex(32) + '"\n'
    secret_key = '"' + secrets.token_hex(32) + '"\n'
    secret_password = '"' + secrets.token_hex(32) + '"\n'
    fileserver_apikey = '"' + secrets.token_hex(32) + '"\n'
    webshopenv["FILESERVER_CLIENT_ID"] = fileserver_client_id
    webshopenv["FILESERVER_CLIENT_SECRET"] = fileserver_client_secret
    webshopenv["SECRET_KEY"] = secret_key
    webshopenv["SECRET_PASSWORD"] = secret_password
    webshopenv["FILESERVER_APIKEY"] = fileserver_apikey
    fileenv["FILESERVER_CLIENT_SECRET"] = fileserver_client_secret
    fileenv["FILESERVER_CLIENT_ID"] = fileserver_client_id
    fileenv["SECRET_KEY"] = secret_key
    writeToFile("./file_server/.env", fileenv)
    writeToFile("./webshop/.env", webshopenv)


if __name__ == "__main__":
    generateSecrets()
    print("Generated new secrets!")
    #os.system("cd file_server && pipenv run python init_db.py && cd ..")
    os.system("cd webshop && pipenv run python init_db.py && cd ..")
    print("Initialized database!")
