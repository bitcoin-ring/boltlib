# -*- coding: utf-8 -*-
"""
BoltCard Read/Write Library based on pyscard.

See:
NTAG 424 DNA documentation: https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf
And AN12343 Documentation: https://www.nxp.com/docs/en/application-note/AN12343.pdf
GetFileSettings MACed see: https://www.nxp.com/docs/en/application-note/AN12196.pdf  page 21
"""
from collections import deque
from typing import Optional, Tuple, List
from urllib.parse import unquote
from loguru import logger as log
from smartcard.CardRequest import CardRequest
from smartcard.CardService import CardService
from smartcard.CardType import CardType
import ndef
from smartcard.util import toBytes, toHexString
import secrets
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

__all__ = [
    "wait_for_card",
    "get_version",
    "check_version",
    "read_uid",
    "read_uri",
    "write_uri",
]

import boltlib


class DESfire(CardType):
    """NTAG 424 DNA qaulifies as Mifare DESfire card"""

    def matches(self, atr, reader=None):
        is_desfire = atr == toBytes("3B 81 80 01 80 80")
        if is_desfire:
            log.debug("Mifare DESFire Card detected")
        else:
            log.error(f"Incompatible card detected - ATR: {toHexString(atr)}")
        return is_desfire


class Response:
    def __init__(self, raw: Tuple):
        self.raw = raw

    def __str__(self):
        return f"{self.status} -  {self.data}"

    @property
    def text(self) -> str:
        return bytes(self.raw[0]).decode("utf-8", errors="ignore")

    @property
    def ba(self) -> bytearray:
        """Response data as bytearray (without status)"""
        return bytearray(self.raw[0])

    @property
    def data(self) -> str:
        """Response data as hex string"""
        return bytes(self.raw[0]).hex().upper()

    @property
    def status(self) -> str:
        """Response status as hex string"""
        return bytes(self.raw[1:]).hex().upper()


def wait_for_card(timeout=None) -> CardService:
    """Wait for a compatible card and return a connection when a card is found."""
    cardtype = DESfire()
    cardrequest = CardRequest(cardType=cardtype, timeout=timeout)
    log.debug("Waiting for BoltCard")
    cardservice = cardrequest.waitforcard()
    cardservice.connection.connect()
    reader = cardservice.connection.getReader()
    log.debug(f"Card connected on {reader}")
    return cardservice


def get_version(cs: Optional[CardService] = None) -> str:
    """Execute GetVersion command sequence and return concatenated responses as hex string."""
    cs = cs or wait_for_card()
    GET_VERSION_A = toBytes("9060000000")
    GET_VERSION_B = toBytes("90AF000000")
    v1 = Response(cs.connection.transmit(GET_VERSION_A))
    assert v1.status == "91AF", f"GetVersion 3 response error {v1.status}"
    v2 = Response(cs.connection.transmit(GET_VERSION_B))
    assert v2.status == "91AF", f"GetVersion 3 response error {v2.status}"
    v3 = Response(cs.connection.transmit(GET_VERSION_B))
    assert v3.status == "9100", f"GetVersion 3 response error {v3.status}"
    result = v1.data + v2.data + v3.data
    log.debug(f"Version: {result}")
    return result


def check_version(version: str) -> None:
    """Check version information retrieved from card is NTAG 424 DNA comptible."""
    v = boltlib.parse_version(version)
    assert v.HW_VendorID == 0x04, "Vendor ID not NXP"
    assert v.HW_Type == 0x04, "HW type not NTAG"
    assert v.HW_MajorVersion == 0x30, "HW major version not 30"
    assert v.HW_Protocol == 0x05, "HW protocol not 05"
    log.debug(f"Card compatibility ok")


def read_uid(cs: Optional[CardService] = None) -> str:
    """Get UID of card."""
    cs = cs or wait_for_card()
    GET_UID = toBytes("FFCA000000")
    result = Response(cs.connection.transmit(GET_UID))
    log.debug(f"GET_UID: {result}")
    return result.data


def read_uri(cs: Optional[CardService] = None) -> Optional[str]:
    """Read and decode the first NDEF record from the card."""
    cs = cs or wait_for_card()
    SELECT_A = toBytes(
        "00A4040007D276000085010100"
    )  # Select application (DF name D2760000850101)
    SELECT_B = toBytes(
        "00A4000002E10400"
    )  # Select 256 bytes NDEF (SDM & Mirroring supported)
    READ_BINARY_ALL = toBytes("00B0000000")
    select_a = Response(cs.connection.transmit(SELECT_A))
    assert select_a.status == "9000"
    select_b = Response(cs.connection.transmit(SELECT_B))
    assert select_b.status == "9000"
    response = Response(cs.connection.transmit(READ_BINARY_ALL))
    log.debug(f"READ_BINARY: {response.status} - {response.data[:32]}...")
    try:
        records: List[ndef.UriRecord] = list(ndef.message_decoder(response.ba[2:]))
    except ndef.DecodeError:
        log.error("NO NDEF record found.")
        return None
    # Log records
    for record in records:
        log.debug(record)
    record = records[0]
    try:
        return unquote(record.uri)
    except AttributeError:
        return None


def write_uri(uri: str, cs: Optional[CardService] = None) -> ndef.UriRecord:
    """Write URI to tag (only for un-provisioned BoltCards!!!)."""

    # Commands
    SELECT_A = toBytes("00A4040007D276000085010100")
    SELECT_B = toBytes("00A4000002E10400")
    UPDATE_PREFIX = toBytes("00D60000")

    # Select
    cs = cs or wait_for_card()
    response = Response(cs.connection.transmit(SELECT_A))
    assert response.status == "9000"  # OK
    response = Response(cs.connection.transmit(SELECT_B))
    assert response.status == "9000"  # OK

    # Build payload
    log.debug(f"Encoding: {uri}")
    record = ndef.UriRecord(uri)
    URI_PAYLOAD = list(b"".join(ndef.message_encoder([record])))
    WRITE_PAYLOAD = UPDATE_PREFIX.copy()
    WRITE_PAYLOAD.append(len(URI_PAYLOAD) + 2)
    WRITE_PAYLOAD.append(0)
    WRITE_PAYLOAD.append(len(URI_PAYLOAD))
    WRITE_PAYLOAD.extend(URI_PAYLOAD)
    log.debug(f"UPDATE_BINARY: {bytes(WRITE_PAYLOAD).hex()}")

    # Write payload
    response = Response(cs.connection.transmit(WRITE_PAYLOAD))
    log.debug(f"UPDATE_STATUS: {response.status}")
    assert (
        response.status == "9000"
    ), f"Write uri failed with status {response.status}"  # OK
    return record


def authenticate(key: str = "", cs: Optional[CardService] = None) -> boltlib.Session:
    cs = cs or wait_for_card()
    key = key or "00000000000000000000000000000000"
    key = bytes.fromhex(key)
    # IsoSelectFile
    response = Response(cs.connection.transmit(toBytes("00A4040007D276000085010100")))
    assert response.status == "9000"

    # AuthenticateFirst - Returns an Encrypted PICC challenge of 16 bytes
    response = Response(cs.connection.transmit(toBytes("9071000005000300000000")))
    log.debug(f"PICC encrypted challenge: {response.data}")
    assert response.status == "91AF"  # ADDITIONAL_FRAME

    # Decrypt Challenge with key
    IVbytes = b"\x00" * 16
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    decrypted_challenge = cipher.decrypt(response.ba)
    # The Challenge is the 16 by RND_B from PICC
    RND_B = decrypted_challenge
    log.debug(f"PICC decrypted challenge: {decrypted_challenge.hex().upper()}")
    rotated_challenge = deque(decrypted_challenge)
    rotated_challenge.rotate(-1)
    rotated_challenge = bytes(rotated_challenge)
    log.debug(f"Rotated challenge: {rotated_challenge.hex().upper()}")

    # Answer challenge
    prefix = b"\x90\xAF\x00\x00\x20"
    postfix = b"\x00"
    rnd_a = secrets.token_bytes(16)
    RND_A = rnd_a
    rnd_b = rotated_challenge
    answer = rnd_a + rnd_b
    log.debug(f"Plain answer {answer.hex().upper()}")
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    encrypted_answer = cipher.encrypt(answer)
    log.debug(f"Encrypted Answer {encrypted_answer.hex().upper()}")
    apdu = bytearray(prefix + encrypted_answer + postfix)
    log.debug(f"Full Answer APDU: {apdu.hex().upper()} - {len(apdu)}")
    auth_response = Response(cs.connection.transmit(list(apdu)))

    # Decrypt AuthResponse
    log.debug(f"Encrypted Auth repsonse: {auth_response.status} - {auth_response.data}")
    assert auth_response.status == "9100"  # OPERATION_OK
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    decrypted_auth_response = cipher.decrypt(auth_response.ba)
    auth_obj = boltlib.parse_auth_response(decrypted_auth_response)
    log.debug(f"Decrypted AuthResponse: {auth_obj}")

    enc, mac = derive_session_keys(key, RND_A, RND_B)
    log.debug(f"SesAuthENCKey: {enc.hex().upper()}")
    log.debug(f"SesAuthMACKey: {mac.hex().upper()}")
    log.debug(f"TransactionID: {auth_obj.TI.hex().upper()}")
    result = boltlib.Session(key_enc=enc, key_mac=mac, auth_info=auth_obj)
    return result


def get_file_settings(key: str = "", cs: Optional[CardService] = None):
    cs = cs or wait_for_card()
    key = key or "00000000000000000000000000000000"
    ses = authenticate(key, cs)
    prefix = bytes.fromhex("90 F5 00 00 09 02")
    cmd = bytes.fromhex("F5")
    cmd_counter = bytes.fromhex("00 00")
    transaction_id = ses.auth_info.TI
    cmd_header = bytes.fromhex("02")
    msg = cmd + cmd_counter + transaction_id + cmd_header
    log.debug(f"MSG for GetFileSettings CMAC: {msg.hex().upper()} - {len(msg)}")
    cmac = cmac_short(ses.key_mac, msg)
    log.debug(f"Message CMAC: {cmac.hex().upper()}")
    apdu = prefix + cmac + b"\x00"
    log.debug(f"GetFileSettings Request: {bytes(apdu).hex().upper()}")
    get_file_respons = Response(cs.connection.transmit(list(apdu)))
    log.debug(f"GetFileSettings Response: {get_file_respons}")


def derive_session_keys(key, rnd_a, rnd_b):
    # type: (bytes, bytes, bytes) -> Tuple[bytes, bytes]
    """Derive and return SessionKeys as Tuple of (SesAuthENCKey, SesAuthMACKey)"""
    f1 = rnd_a[0:2]
    f2 = rnd_a[2:8]
    f3 = rnd_b[0:6]
    f4 = rnd_b[6:16]
    f5 = rnd_a[8:16]
    SV1 = bytes.fromhex("A55A00010080") + f1 + bxor(f2, f3) + f4 + f5
    SV2 = bytes.fromhex("5AA500010080") + f1 + bxor(f2, f3) + f4 + f5
    enc = CMAC.new(key, SV1, ciphermod=AES).digest()
    mac = CMAC.new(key, SV2, ciphermod=AES).digest()
    return enc, mac


def bxor(b1: bytes, b2: bytes) -> bytes:
    """XOR bytes"""
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result


def cmac_short(key, msg):
    # type: (bytes, bytes) -> bytes
    """Calculate truncted CMAC (8 even numbered bytes)."""
    return CMAC.new(key, msg, ciphermod=AES).digest()[1::2]


if __name__ == "__main__":
    get_file_settings()
