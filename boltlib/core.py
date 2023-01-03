# -*- coding: utf-8 -*-
"""
BoltCard Read/Write Library based on pyscard.

NTAG 424 DNA documentation: https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf

"""
from time import sleep
from typing import Optional, Tuple, List
from urllib.parse import unquote
from loguru import logger as log
from smartcard.CardRequest import CardRequest
from smartcard.CardService import CardService
from smartcard.CardType import CardType
import ndef
from smartcard.util import toBytes, toHexString


__all__ = [
    "wait_for_card",
    "check_card",
    "read_uid",
    "read_uri",
    "write_uri",
]


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
    sleep(1)  # We have to wait a bit here else check_card fails with a fresh card
    check_card(cardservice)
    return cardservice


def check_card(cs: Optional[CardService] = None) -> str:
    """Get Card compatibility via version information.

    Example Responses:
    Hardware:   0404023000110591AF
    Software:   0404020102110591AF
    Production: 00000000000000CF5CD4556043219100 (000..-> UID)
    """
    cs = cs or wait_for_card()
    GET_VERSION_A = toBytes("9060000000")
    GET_VERSION_B = toBytes("90AF000000")
    log.debug(f"Checking Card compatibility")
    v1 = Response(cs.connection.transmit(GET_VERSION_A))
    assert v1.status == "91AF", f"GetVersion 3 response error {v1.status}"
    assert v1.data[:2] == "04", "Vendor ID not NXP"
    assert v1.data[2:4] == "04", "HW type not NTAG"
    assert v1.data[6:8] == "30", "HW major version not 30"
    assert v1.data[12:14] == "05", "HW communication protocol type not 05"

    v2 = Response(cs.connection.transmit(GET_VERSION_B))
    assert v2.status == "91AF", f"GetVersion 3 response error {v2.status}"
    assert v2.data.startswith("04040201"), "Invalid Card Software"

    v3 = Response(cs.connection.transmit(GET_VERSION_B))
    assert v3.status == "9100", f"GetVersion 3 response error {v3.status}"
    uid = v3.data[:14]
    batch_no = int(v3.data[14:22], 16)
    week = v3.data[24:26]
    year = v3.data[26:28]
    log.trace(f"  HW UID   {uid}")
    log.trace(f"  HW BATCH {batch_no}")
    log.trace(f"  HW YEAR  {year}")
    log.trace(f"  HW WEEK  {week}")
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
