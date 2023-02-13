# -*- coding: utf-8 -*-
"""BoltCard Burn & Wipe protocol functions (sans I/O)"""
import boltlib as bl

__all__ = [
    "burn_01_write_url",
    "burn_02_auth_challenge",
    "burn_03_auth_response",
    "burn_04_auth_finalize",
    "burn_05_configure_picc",
    "burn_06_change_keys",
]

APDU_SELECT_NTAG_424 = "00A4040007D276000085010100"
APDU_SELECT_NDEF = "00A4000002E10400"


def burn(url, keys, nfc_writer):
    # type: (str, list[str], bl.NFCWriter) -> None
    """Burn (provision) a Bolt Card"""

    # Write URL Template
    apdus = burn_01_write_url(url)
    nfc_writer.write(apdus)

    # Authenticate
    session = bl.AuthSession()
    apdus = burn_02_auth_challenge(session)
    response = nfc_writer.write(apdus)
    apdus = burn_03_auth_response(session, response)
    response = nfc_writer.write(apdus)
    burn_04_auth_finalize(session, response)

    # Configure PICC
    apdus = burn_05_configure_picc(session, url)
    nfc_writer.write(apdus)

    # Change Keys
    apdus = burn_06_change_keys(session, keys)
    nfc_writer.write(apdus)


def burn_01_write_url(url):
    # type: (str) -> list[str]
    """
    Takes a base URL or URL template and returns an APDU comand list for writing.

    :param str url: Withdraw endpoint URL or URL template
    :return: List of APDU commands (hex) to write the URI Template to the NFC device
    """
    apdus = [APDU_SELECT_NTAG_424, APDU_SELECT_NDEF]
    url_obj = bl.build_url_template(url)

    # Command Header
    cla_ins = "00D6"
    p1_p2 = "0000"
    url_len = len(url_obj.url)
    lc = int.to_bytes(url_len + 7, 1, "big", signed=False).hex().upper()

    cmd_header = cla_ins + p1_p2 + lc

    # NDEF Header
    # header = "00D6 0000 84 | 0082 D1 01 7E 55 00"
    ndef_length = int.to_bytes(url_len + 5, 2, "big", signed=False).hex().upper()
    tnf = "D1"
    type_len = "01"
    payload_len = int.to_bytes(url_len + 1, 1, "big", signed=False).hex().upper()
    rec_type = "55"  # Uri
    uri_type = "00"  # No scheme prepending

    ndef_header = ndef_length + tnf + type_len + payload_len + rec_type + uri_type

    full_header = cmd_header + ndef_header
    payload = url_obj.url.encode("utf-8").hex().upper()

    apdu = full_header + payload
    apdus.append(apdu)
    return apdus


def burn_02_auth_challenge(session):
    # type: (bl.AuthSession) -> list[str]
    """
    Create a list of APDU commands to request an authentication challenge from NFC device.

    :param AuthSession session: AuthSession object (use key 00000000000000000000000000000000 for new cards)
    :return: List of APDU commands (hex) to initiate authentication procedure
    """
    # MAYBE (IsoSelectFile - 00A4040007D276000085010100)
    # AuthenticateFirst - 9071000005000300000000
    return []


def burn_03_auth_response(session, response):
    # type: (bl.AuthSession, str) -> list[str]
    """
    Create ADPU commands to respond to auth challenge.

    Note: will set rnd_a & rnd_b properties on `AuthSession`

    :param AuthSession session: AuthSession object
    :param str response: The response from burn_02 command
    :return:
    """
    return []


def burn_04_auth_finalize(session, response):
    # type: (bl.AuthSession, str) -> None
    """
    Finalize `AuthSession` object

    Note: will set `key_enc`, `key_mac` and `ti` properties on `AuthSession`

    :param AuthSession session: AuthSession object
    :param response: Response from burn_03 command
    """
    return None


def burn_05_configure_picc(session, url):
    # type: (bl.AuthSession, str) -> list[str]
    """
    Configure PICC mirroring, SUN Messaging and other stuff
    """
    return []


def burn_06_change_keys(session, keys):
    # type: (bl.AuthSession, list[str]) -> list[str]
    """
    Change Keys
    """
    assert len(keys) == 5, "Exactly 5 keys required"
    assert session.authenticated, "Authenticated session required"
    return []


def wipe_01_auth_challenge(session):
    # type: (bl.AuthSession) -> list[str]
    pass


def wipe_02_auth_response(session, response):
    # type: (bl.AuthSession, str) -> list[str]
    pass


def wipe_03_auth_finalize(session, response):
    # type: (bl.AuthSession, str) -> None
    pass


def wipe_04_reset_picc(session):
    # type: (bl.AuthSession) -> list[str]
    pass


def wipe_05_changekeys(session, keys):
    # type: (bl.AuthSession, list[str]) -> list[str]
    pass


def wipe_06_clear_ndef():
    # type: () -> list[str]
    pass
