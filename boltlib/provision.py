# -*- coding: utf-8 -*-
from smartcard.util import toBytes
import boltlib as bl
from loguru import logger as log


class NFCWriter:
    def __init__(self, card_service):
        self.cs = card_service

    def write(self, apdus):
        response = None
        for apdu in apdus:
            log.debug(f"-> {apdu}")
            response = bl.Response(self.cs.connection.transmit(toBytes(apdu)))
            log.debug(f"<- {response}")
        return response


def provision(url, keys):
    # type: (str, list[str]) -> None
    """Provision a BoltRing/BoltCard"""
    card = bl.wait_for_card()
    writer = NFCWriter(card)

    log.debug("Write URL Template")
    writer.write(bl.burn_01_write_url(url))

    log.debug("Authenticate")
    session = bl.AuthSession()
    response = writer.write(bl.burn_02_auth_challenge())
    response = writer.write(bl.burn_03_auth_response(session, response.hex))
    bl.burn_04_auth_finalize(session, response.hex)

    log.debug("Configure PICC")
    writer.write(bl.burn_05_configure_picc(session, url))
    log.debug("Change KEYS")
    writer.write(bl.burn_06_change_keys(session, keys))
