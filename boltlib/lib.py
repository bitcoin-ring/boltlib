# -*- coding: utf-8 -*-
from collections import deque
from typing import Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
import boltlib as bl

__all__ = [
    "build_url_template",
    "rotate_bytes",
    "derive_session_keys",
    "pad",
]


def build_url_template(url):
    # type: (str) -> bl.UrlTemplate
    """
    Takes a base URL or URL template and builds the UrlTemplate to be written to the BoltCard.

    Examples:
        url=lnurlw://boltserver.com/withdraw  # Will append p and c query sting
        url=lnurlw://boltserver.com/withdraw=?p={picc}&c={cmac}  # Will substitute {picc} & {cmac}

    :param str url: Withdraw endpoint URL or URL template
    """

    if not url.startswith("lnurlw://"):
        raise ValueError("url must start with scheme lnurlw://")

    if "{picc}" in url and "{cmac}" in url:
        p_value = "p" * 32
        c_value = "c" * 16
        url = url.format(picc=p_value, cmac=c_value)
        picc_offset = url.index(p_value) + 7
        cmac_offset = url.index(c_value) + 7
    else:
        if "?" in url:
            raise ValueError("base url must not include any query strings")
        suffix = "?p=00000000000000000000000000000000&c=0000000000000000"
        base_len = len(url)
        picc_offset = base_len + 10
        cmac_offset = base_len + 45
        url += suffix

    if len(url) >= 250:
        raise ValueError("expanded url must be shorter than 250 characters")

    return bl.UrlTemplate(url, picc_offset, cmac_offset)


def rotate_bytes(b, n):
    # type: (bytes, int) -> bytes
    """Return new bytes rotated by `n`. (Negative `n` for left rotation)"""
    d = deque(b)
    d.rotate(n)
    return bytes(d)


def xor(b1, b2):
    # type: (bytes, bytes) -> bytes
    """XOR byte sequences of even length"""
    return bytes(x ^ y for x, y in zip(b1, b2))


def derive_session_keys(key, rnd_a, rnd_b):
    # type: (bytes, bytes, bytes) -> Tuple[bytes, bytes]
    """Derive and return SessionKeys as Tuple of (SesAuthENCKey, SesAuthMACKey)"""
    f1 = rnd_a[0:2]
    f2 = rnd_a[2:8]
    f3 = rnd_b[0:6]
    f4 = rnd_b[6:16]
    f5 = rnd_a[8:16]
    SV1 = bytes.fromhex("A55A00010080") + f1 + xor(f2, f3) + f4 + f5
    SV2 = bytes.fromhex("5AA500010080") + f1 + xor(f2, f3) + f4 + f5
    enc = CMAC.new(key, SV1, ciphermod=AES).digest()
    mac = CMAC.new(key, SV2, ciphermod=AES).digest()
    return enc, mac


def pad(data, blocksize):
    # add padding
    rlen = len(data)
    elen = len(data) % blocksize
    if elen:
        data += bytearray(blocksize - elen)
        fslist = bytearray(data)
        fslist[rlen] = 0x80
        data = fslist
    return data
