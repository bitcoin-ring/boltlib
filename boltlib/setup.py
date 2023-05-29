# -*- coding: utf-8 -*-
"""BoltRing Setup Script"""
import os
import json
from pathlib import Path
from typing import Optional, Tuple
import boltlib as bl
from loguru import logger as log
import humanhash
import httpx
import secrets
import qrcode
from PIL import Image, ImageDraw, ImageFont
import pathlib
from boltlib.provision import provision, wipe
from dotenv import load_dotenv
from hashlib import sha256


load_dotenv()
server = os.getenv("server")
admin_key = os.getenv("admin_key")
admin_id = os.getenv("admin_id")
HERE = pathlib.Path(__file__).parent.absolute()
Image.MAX_IMAGE_PIXELS = 10000 * 14000 * 2


def uid_to_username(uid: str) -> str:
    """Create a deterministig username for uid"""
    hex_hash = sha256(bytes.fromhex(uid)).hexdigest()
    username = humanhash.humanize(hex_hash, words=2)
    return username


def get_user(uid: str) -> Optional[dict]:
    """Get LNbits user account for UID."""
    username = uid_to_username(uid)
    url = f"{server}/usermanager/api/v1/users"
    resp = httpx.get(url, params={"name": username}, headers={"X-Api-Key": admin_key})
    data = resp.json()
    log.debug(f"Retrieved User: {data}")
    if data:
        if len(data) > 1:
            raise ValueError(f"Multiple results for user {username}")
        else:
            return data[0]


def create_account(uid: str):
    """Create (or get) account for UID (idempotent)."""
    user = get_user(uid=uid)
    if not user:
        user_name = uid_to_username(uid)
        log.info(f"Create user {user_name} for {uid}")
        data = {
            "user_name": user_name,
            "wallet_name": "BoltRing",
            "admin_id": admin_id,
        }
        url = f"{server}/usermanager/api/v1/users"
        resp = httpx.post(url, json=data, headers={"X-Api-Key": admin_key})
        user = resp.json()
        log.debug(f"Created user {user}")
    return user


def enable_extension(extension: str, userid: str) -> dict:
    """Enable extension for userid"""
    url = f"{server}/usermanager/api/v1/extensions"
    params = {"extension": extension, "userid": userid, "active": True}
    resp = httpx.post(url, params=params)
    log.debug(f"Activated {extension} for userid {userid}: {resp.json()}")
    return resp.json()


def get_wallet(userid: str) -> dict:
    """Get first wallet of user"""
    url = f"{server}/usermanager/api/v1/wallets/{userid}"
    resp = httpx.get(url, headers={"X-Api-Key": admin_key})
    try:
        wallet = resp.json()[0]
        log.debug(f"Retrieved wallet: {wallet['id']}")
        return wallet
    except Exception:
        log.error(f"Failed wallet retrieve: {resp.json()}")
        raise ValueError


def get_card(wallet: dict) -> Optional[dict]:
    """Returns fist Card for wallet if it exists"""
    url = f"{server}/boltcards/api/v1/cards"
    resp = httpx.get(url, headers={"X-Api-Key": wallet["adminkey"]})
    data = resp.json()
    if len(data) > 1:
        raise ValueError(f"Multiple cards found for wallet {wallet}")
    if len(data) == 0:
        return None
    card = data[0]
    log.debug(
        f"Retrieved Card for UID {card['uid']} with external id {card['external_id']}"
    )
    return card


def create_card(wallet: dict, uid: str) -> dict:
    """Create BoltCard entry on LNbits"""
    url = f"{server}/boltcards/api/v1/cards"
    card = get_card(wallet)
    if not card:
        card = {
            "card_name": "BoltRing",
            "uid": uid,
            "counter": 0,
            "tx_limit": 200000,
            "daily_limit": 1000000,
            "enable": True,
            "k0": secrets.token_hex(16),
            "k1": secrets.token_hex(16),
            "k2": secrets.token_hex(16),
        }
        resp = httpx.post(url, json=card, headers={"X-Api-Key": wallet["adminkey"]})
        card = resp.json()
        log.debug(
            f"Created Card for UID {card['uid']} with external id {card['external_id']}"
        )
    assert card["uid"] == uid
    return card


def get_paylink(wallet: dict) -> Optional[dict]:
    """Returns fist paylink for wallet if it exists"""
    url = f"{server}/lnurlp/api/v1/links"
    resp = httpx.get(url, headers={"X-Api-Key": wallet["adminkey"]})
    data = resp.json()
    if len(data) > 1:
        raise ValueError(f"Multiple paylinks found for wallet {wallet}")
    if len(data) == 0:
        log.debug(f"No links found for wallet {wallet}")
        return None
    paylink = data[0]
    log.debug(f"Retrieved Paylink: {paylink['id']}")
    return paylink


def create_paylink(wallet: dict, uid: str) -> dict:
    """Create LNURLp Link on LNbits"""
    paylink = get_paylink(wallet)
    if paylink:
        return paylink
    username = uid_to_username(uid)
    url = f"{server}/lnurlp/api/v1/links"
    link = {
        "description": "BoltRing Funding",
        "min": 1,
        "max": 1000000,
        "comment_chars": 50,
        "username": username,
        "success_text": "Funds received on BoltRing",
    }
    resp = httpx.post(url, json=link, headers={"X-Api-Key": wallet["adminkey"]})
    paylink = resp.json()
    log.debug(f"Created Paylink: {paylink['id']}")
    return paylink


def create_leaflet(wallet: dict, card: dict, paylink: dict) -> Tuple[Path, Path]:
    """Create leaflet for printing"""
    log.debug("Creating Leaflet")
    img_front = Image.open(HERE.parent / ".data/front.png")
    paylink_uri = f"lightning:{paylink['lnurl']}"
    img_qr_paylink = qrcode.make(paylink_uri).resize((1987, 1987), Image.LANCZOS)
    img_front.paste(img_qr_paylink, (1498, 4290))
    fnt = ImageFont.truetype((HERE.parent / ".data/font.ttf").as_posix(), 330)
    draw = ImageDraw.Draw(img_front)
    uid_text = f"UID: {card['uid']}"
    draw.text((5555, 3100), uid_text, font=fnt, fill=(0, 0, 0))

    path_front = HERE.parent / f".data/{card['uid']}_front.png"
    img_front.save(path_front)

    img_back = Image.open(HERE.parent / ".data/back.png")
    wallet_url = f"{server}/wallet?usr={wallet['user']}&wal={wallet['id']}"
    img_qr_wallet = qrcode.make(wallet_url).resize((1987, 1987), Image.LANCZOS)
    img_back.paste(img_qr_wallet, (1492, 4262))
    reset_code = json.dumps(
        {
            "action": "wipe",
            "k0": card["k0"],
            "k1": card["k1"],
            "k2": card["k2"],
            "k3": card["k1"],
            "k4": card["k2"],
            "uid": card["uid"],
            "version": 1,
        },
        separators=(",", ":"),
    )
    img_qr_reset = qrcode.make(reset_code).resize((1987, 1987), Image.LANCZOS)
    img_back.paste(img_qr_reset, (6450, 4262))
    path_back = HERE.parent / f".data/{card['uid']}_back.png"
    img_back.save(path_back)

    return path_front, path_back


def provision_device(card: dict) -> None:
    """Provision device with LNbits card"""
    lnurlw = (
        f"lnurlw://lnbits.bolt-ring.com/boltcards/api/v1/scan/{card['external_id']}"
    )
    keys = [card["k0"], card["k1"], card["k2"], card["k1"], card["k2"]]
    provision(lnurlw, keys)


def wipe_device(card: dict) -> None:
    """Wipe device based on LNbits card object"""
    keys = [card["k0"], card["k1"], card["k2"], card["k1"], card["k2"]]
    wipe(keys)


def topup(wallet: dict, amount=40000):
    """Add funds to wallet"""
    balance = get_balance(wallet)
    if balance != 0:
        log.warning(f"Skip Topup! Existing Balance of {balance} on {wallet['id']}")
        return
    url = f"{server}/admin/api/v1/topup/"
    params = {"usr": admin_id}
    payload = {"id": wallet["id"], "amount": amount}
    resp = httpx.put(url, params=params, json=payload, headers={"X-Api-Key": admin_key})
    log.debug(f"Wallet funded {resp.json()}")


def get_balance(wallet: dict) -> int:
    """Get wallet balance"""
    url = f"{server}/api/v1/wallet"
    resp = httpx.get(url, headers={"X-Api-Key": wallet["adminkey"]})
    return resp.json()["balance"]


def run():
    """Main provisioning loop"""
    log.info("Started BoltDevice Setup")
    while True:
        user_input = input(
            "Place device on NFC reader and hit enter (or q to quit)!\n"
        ).lower()
        if user_input == "q":
            raise KeyboardInterrupt
        uid = bl.read_uid()
        user = create_account(uid)

        # Enable extensions
        userid = user["id"]
        enable_extension("boltcards", userid)
        enable_extension("lnurlp", userid)

        # Create Card
        wallet = get_wallet(userid)
        card = create_card(wallet, uid)
        paylink = create_paylink(wallet, uid)
        front, back = create_leaflet(wallet, card, paylink)

        input("Insert Paper Front and hit enter to print\n").lower()
        os.startfile(front.as_posix(), "print")

        input("Insert Paper Back and hit enter to print\n").lower()
        os.startfile(back.as_posix(), "print")

        input(f"Hit enter to provision device {uid}")
        provision_device(card)

        input(f"Hit enter to topup account with 40k sats")
        topup(wallet, amount=40000)


def audit():
    """Audit LNbits funds"""
    url = f"{server}/api/v1/audit"
    params = {"usr": admin_id}
    resp = httpx.get(url, params=params, headers={"X-Api-Key": admin_key})
    print(json.dumps(resp.json(), indent=2))


def main():
    try:
        run()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        log.info("Good bye!")


if __name__ == "__main__":
    main()
