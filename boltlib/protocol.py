# -*- coding: utf-8 -*-
"""BoltCard Burn & Wipe protocol functions (sans I/O)"""
import boltlib as bl

__all__ = [
    "burn_01_write_url",
    "burn_02_auth_challenge",
    "burn_03_auth_response",
    "burn_04_auth_finalize",
]


def burn(url, nfc_writer):
    # type: (str, bl.NFCWriter) -> None
    """Burn (provision) a Bolt Card"""

    # Write URL Template
    apdus = burn_01_write_url(url)
    response = nfc_writer.write(apdus)

    # Authenticate
    session = bl.Session()
    apdus = burn_02_auth_challenge(session)
    response = nfc_writer.write(apdus)
    apdus = burn_03_auth_response(session, response)
    response = nfc_writer.write(apdus)
    burn_04_auth_finalize(session, response)
    ...


def burn_01_write_url(url):
    # type: (str) -> list[str]
    """
    Takes a base URL or URL template and returns an APDU comand list for writing.

    :param str url: Withdraw endpoint URL or URL template
    :return: List of APDU commands (hex) to write the URI Template to the NFC device
    """
    # IsoSelectFile - 00A4040007D276000085010100
    # IsoSelectFile - 00A4000002E10300
    url_obj = bl.build_url_template(url)
    ...
    return []


def burn_02_auth_challenge(session):
    # type: (bl.Session) -> list[str]
    """
    Create a list of APDU commands to request an authentication challenge from NFC device.

    :param Session session: Session object (use key 00000000000000000000000000000000 for new cards)
    :return: List of APDU commands (hex) to initiate authentication procedure
    """
    # IsoSelectFile - 00A4040007D276000085010100
    # AuthenticateFirst - 9071000005000300000000
    return []


def burn_03_auth_response(session, response):
    # type: (bl.Session, str) -> list[str]
    """
    Create ADPU commands to respond to auth challenge.

    Note: will set rnd_a & rnd_b properties on `Session`

    :param Session session: Session object
    :param str response: The response from burn_02 command
    :return:
    """
    return []


def burn_04_auth_finalize(session, response):
    # type: (bl.Session, str) -> None
    """
    Finalize `Session` object

    Note: will set `key_enc`, `key_mac` and `ti` properties on `Session`

    :param Session session: Session object
    :param response: Response from burn_03 command
    """
    return None
