from . import items_api_blueprint
from functools import wraps
from io import BytesIO
from authlib.jose import jwt
from .. import logging
from flask import (
    make_response,
    current_app,
    request,
    render_template,
    redirect,
    url_for,
    send_file,
)
import os
import requests
from ..models import *
import hashlib
import base64

def check_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logging.debug("check_token function called on webshop")
        cookie = request.cookies.get("access-token")
        if cookie:
            try:
                token = jwt.decode(cookie, current_app.config["JWT_PUBLIC_KEY"])
                logging.debug(f"This is the user token '{token}'")
                result = User.get_from_username(token["user"])
                logging.debug(f"This is the User from decoded token '{result}'")

                if result is None:
                    logging.error("Token correspoding to a user, doesn't exist!")
                    resp = make_response(redirect(url_for("login_api_blueprint.login")))
                    resp.set_cookie("access-token", "", samesite="Strict")
                    return resp
            except Exception as e:
                logging.error(e)
                resp = make_response(redirect(url_for("login_api_blueprint.login")))
                resp.set_cookie("access-token", "", samesite="Strict")
                return resp
            return func(*args, **kwargs)
        logging.warn("No cookie access-token found. Redirecting to login page!")
        return redirect(url_for("login_api_blueprint.login"))

    return wrapper


@items_api_blueprint.route("/item/browse", methods=["GET"])
@check_token
def get_all_items():
    logging.debug("/item/browse endpoint called on webshop")
    res = Item.get_all()
    return render_template(
        "browseItems.html", items_list=res, ip=current_app.config["PUBLIC_IP"]
    )


@items_api_blueprint.route("/item", methods=["GET"])
@check_token
def get_own_items():
    logging.debug("/item endpoint called on webshop")
    decoded = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )
    res = Item.get_from_username(decoded["user"])

    return render_template(
        "myItems.html",
        items_list=res,
        info=request.args.get("info"),
        ip=current_app.config["PUBLIC_IP"],
    )


@items_api_blueprint.route("/item/<item_id>", methods=["POST"])
@check_token
def reserve_item(item_id):
    logging.debug(f"/item/{item_id} endpoint called on webshop")
    res = Item.get_from_id(item_id)

    if res is None:
        logging.error(f"Item with {item_id} ID not found in webshop")
        return render_template("notfound.html"), 404

    if res.stock > 0:
        logging.info(f"Lower stock in webshop")
        res.lower_stock()
    else:
        logging.warn(f"Item with {item_id} ID is sold out in webshop")
        return redirect(
            url_for(
                "items_api_blueprint.get_item", item_id=item_id, error="item sold out!"
            )
        )
    return redirect(
        url_for(
            "items_api_blueprint.get_item",
            item_id=item_id,
            info="item successfully reserved!",
        )
    )


@items_api_blueprint.route("/item/<item_id>", methods=["GET"])
@check_token
def get_item(item_id):
    logging.debug(f"/item/{item_id} endpoint called on webshop")
    result = Item.get_from_id(item_id)

    if result is None:
        logging.error(f"Item with {item_id} ID not found in webshop")
        return render_template("notfound.html"), 404

    try:
        item_image_type = result.filename.split(".")[-1]
        hashed_email = hashlib.md5(result.user_email.encode()).hexdigest()

        item_image_raw = requests.get(
            f"http://cottonroad-file-server:10101/file?image_name={hashed_email}/{result.filename}",
            headers= {"ACCESS_APIKEY": current_app.config["ACCESS_APIKEY"]}
        )
        if item_image_raw.status_code != 200:
            logging.error(
                f"Failed to retrieve Item with {item_id} ID from fileserver in webshop. Retrieving default instead..."
            )
            raise Exception
        item_image_b64 = base64.b64encode(item_image_raw.content).decode()
    except:
        with open(
            os.path.join(f"{os.getcwd()}/application/static/nopicfound.png"), "rb"
        ) as f:
            item_image_b64 = base64.b64encode(f.read()).decode()
        item_image_type = "png"

    prevItem = result.id - 1 if result.id > 1 else result.id
    item_owner_hashed = hashlib.md5(result.user_email.encode()).hexdigest()

    return render_template(
        "viewItem.html",
        prevItem=prevItem,
        item_id=result.id,
        item_title=result.title,
        item_image=item_image_b64,
        item_image_type=item_image_type,
        item_owner=item_owner_hashed,
        item_image_name=result.filename,
        info=request.args.get("info"),
        error=request.args.get("error"),
        ip=current_app.config["PUBLIC_IP"],
    )


@items_api_blueprint.route("/item/view", methods=["GET"])
@check_token
def view_item():
    logging.debug(f"/item/view endpoint called on webshop")
    item_id = request.args.get("id")
    filename = request.args.get("file")

    if item_id is None or item_id == "" or filename is None or filename == "":
        logging.error(f"Parameters are invalid: None")
        return render_template("notfound.html"), 404

    found_item = Item.get_from_id(item_id)
    if found_item is None:
        logging.error(f"Item not found")
        return render_template("notfound.html"), 404
        
    filename = secure_filename(filename)
    hashed_mail = hashlib.md5(found_item.user_email.encode()).hexdigest()

    try:
        logging.debug(f"Trying to retrieve raw content of image from file_server...")
        item_image_raw = requests.get(
            f"http://cottonroad-file-server:10101/file?image_name={hashed_mail}/{filename}",
            headers= {"ACCESS_APIKEY": current_app.config["ACCESS_APIKEY"]}
        )
        if item_image_raw.status_code != 200:
            raise Exception
        content_type = item_image_raw.headers.get("content-type")
        item_image_raw = BytesIO(item_image_raw.content)
    except:
        logging.error(
            f"WebShop couldn't find image on the file_server. Retrieving default instead..."
        )
        notfound_pic = open(
            os.path.join(f"{os.getcwd()}/application/static/nopicfound.png"), "rb"
        )
        item_image_raw = BytesIO(notfound_pic.read())
        content_type = "image/png"
        notfound_pic.close()

    return send_file(item_image_raw, mimetype=content_type)


@items_api_blueprint.route("/item/prevItem", methods=["GET"])
def get_prevItem():
    logging.debug(f"/item/prevItem endpoint called on webshop")
    path = request.args.get("path")
    return redirect(path)


@items_api_blueprint.route("/item/stock", methods=["POST"])
@check_token
def stock_api():
    logging.debug(f"/item/stock endpoint called on webshop")
    stockApi = request.form.get("stockApi")
    try:
        item_stock = requests.get(
            f"http://{current_app.config['PUBLIC_IP']}:10100{stockApi}",
            headers= {"ACCESS_APIKEY": current_app.config["ACCESS_APIKEY"]}
        )
    except requests.exceptions.ConnectionError as e:
        return "Internal error", 500

    if item_stock.status_code == 404:
        logging.error(f"Failed to retrieve item stock in the webshop")
        return "Service not found", 404
    return item_stock.content


@items_api_blueprint.route("/item/stock/check", methods=["GET"])
def check_stock():
    logging.debug(f"/item/stock/check endpoint called on webshop")

    if request.headers.get('ACCESS_APIKEY') != current_app.config["ACCESS_APIKEY"]:
        logging.error("Failed to authenticate webshop in stockApi")
        return "No authentication present", 404
    item_id = request.args.get("itemId")
    result = Item.get_from_id(item_id)

    if result is None:
        logging.error(f"Item with {item_id} not found in the webshop")
        return "Item not found", 404

    return "Stock available: " + str(result.stock)


@items_api_blueprint.route("/item/create", methods=["GET", "POST"])
@check_token
def create_item():
    logging.debug(f"/item/create endpoint called on webshop")
    if request.method == "GET":
        return render_template("createItem.html", ip=current_app.config["PUBLIC_IP"])

    decoded = jwt.decode(
        request.cookies.get("access-token"), current_app.config["JWT_PUBLIC_KEY"]
    )

    title = request.form.get("title").strip()
    filename = request.form.get("filename").strip()

    if (
        len(Item.get_from_username(user_username=decoded["user"]))
        == current_app.config["MAX_SHOP_ITEMS"]
    ):
        logging.error(f'user {decoded["user"]} attempted to create more than 6 items!')
        return render_template(
            "createItem.html",
            error="you cannot create more than 6 items!",
            ip=current_app.config["PUBLIC_IP"],
        )

    try:
        stock = int(request.form.get("stock"))
    except:
        logging.error("Invalid input parameters when creating an item in a webshop")
        return (
            render_template(
                "createItem.html",
                error="stock is not an integer!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    if title is None or title == "":
        logging.error("Invalid input parameters when creating an item in a webshop")
        return (
            render_template(
                "createItem.html",
                error="the title field can't be empty!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    if stock is None or stock < 0:
        logging.error("Invalid input parameters when creating an item in a webshop")
        return (
            render_template(
                "createItem.html",
                error="the stock field can't be less than 0!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            400,
        )

    if stock > 9000000000000000000:
        logging.error("Stock number is too large!")
        return (
            render_template(
                "createItem.html",
                error="the maximum amount of stock possible is: 9000000000000000000!",
                ip=current_app.config["PUBLIC_IP"],
            ),
            429,
        )

    db_user = User.get_from_username(decoded["user"])

    if db_user is None:
        resp = make_response(redirect(url_for("login_api_blueprint.login")))
        resp.set_cookie("access-token", "", samesite="Strict")
        return resp

    if filename is None or filename == "":
        new_item = Item(
            title=title,
            filename="",
            stock=stock,
            user_email=db_user.email,
            user_username=decoded["user"],
        )
        new_item.insert()
    else:
        new_item = Item(
            title=title,
            filename=filename,
            stock=stock,
            user_email=db_user.email,
            user_username=decoded["user"],
        )
        new_item.insert()

    inserted_item = Item.get_matching(
            title=new_item.title,
            filename=new_item.filename,
            stock=new_item.stock,
            user_email=new_item.user_email,
            user_username=new_item.user_username,
        )

    resp = redirect(
        url_for("items_api_blueprint.get_own_items", info="item successfully added!")
    )
    resp.headers["ITEM_ID"] = str(inserted_item.id)
    logging.debug(f"{resp.headers}")
    logging.debug(f"{resp.headers['ITEM_ID']}")
    return resp
