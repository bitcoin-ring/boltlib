# -*- coding: utf-8 -*-
"""BoltCard Burn & Wipe protocol functions (sans I/O)"""
from Cryptodome.Cipher import AES

import boltlib as bl

__all__ = [
    "burn_01_write_url",
    "burn_02_auth_challenge",
    "burn_03_auth_response",
    "burn_04_auth_finalize",
    "burn_05_configure_picc",
    "burn_06_change_keys",
]

DEFAULT_KEY = "00000000000000000000000000000000"
APDU_SELECT_NTAG_424 = "00A4040007D276000085010100"
APDU_SELECT_NDEF = "00A4000002E10400"
APDU_AUTH_FIRST_PART_1 = "9071000005000300000000"


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

    :param AuthSession session: AuthSession object (use zero-key for new cards)
    :return: List of APDU commands (hex) to initiate authentication procedure
    """
    return [APDU_SELECT_NTAG_424, APDU_AUTH_FIRST_PART_1]


def burn_03_auth_response(session, response):
    # type: (bl.AuthSession, str, bytes) -> list[str]
    """
    Create ADPU commands to respond to auth challenge.

    Note: will set rnd_a & rnd_b properties on `AuthSession`

    :param AuthSession session: AuthSession object
    :param str response: The response from burn_02 command
    :return: List of APDUs
    """
    # Decrypt Challenge - The challenge is the 16 byte RND_B from PICC
    IVbytes = b"\x00" * 16
    key = bytes.fromhex(DEFAULT_KEY)
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    response = bytearray(bytes.fromhex(response[:-4]))
    rnd_b = cipher.decrypt(response)

    # Answer challenge with our own secret (RND_A) + rotated RND_B
    rnd_b_rot = bl.rotate_bytes(rnd_b, -1)
    rnd_a = session.rnd_a
    answer = rnd_a + rnd_b_rot
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    encrypted_answer = cipher.encrypt(answer)
    prefix = b"\x90\xAF\x00\x00\x20"
    postfix = b"\x00"
    apdu = bytearray(prefix + encrypted_answer + postfix).hex().upper()
    session.rnd_a = rnd_a
    session.rnd_b = rnd_b
    # log.debug(f"> AUTH 2 - PCD encrypted answer: {apdu.hex().upper()} - {len(apdu)}")
    return [apdu]


def burn_04_auth_finalize(session, response):
    # type: (bl.AuthSession, str) -> None
    """
    Finalize `AuthSession` object

    Note: will set `key_enc`, `key_mac` and `ti` properties on `AuthSession`

    :param AuthSession session: AuthSession object
    :param response: Response from burn_03 command
    """
    IVbytes = b"\x00" * 16
    key = bytes.fromhex(DEFAULT_KEY)
    cipher = AES.new(key, AES.MODE_CBC, IVbytes)
    response = bytearray(bytes.fromhex(response[:-4]))
    decrypted_auth_response = cipher.decrypt(response)
    session.ti = decrypted_auth_response[:4]
    session.key_enc, session.key_mac = bl.derive_session_keys(
        key, session.rnd_a, session.rnd_b
    )


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
