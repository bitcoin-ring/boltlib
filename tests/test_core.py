# -*- coding: utf-8 -*-
from boltlib.core import derive_session_keys, cmac_short, xor


def test_derive_session_keys():
    """
    Test Vectors from
    https://www.nxp.com/docs/en/application-note/AN12343.pdf
    Chapter 7.1.3.1
    """
    key = bytes.fromhex("00000000000000000000000000000000")
    rnd_a = bytes.fromhex("B04D0787C93EE0CC8CACC8E86F16C6FE")
    rnd_b = bytes.fromhex("FA659AD0DCA738DD65DC7DC38612AD81")
    SesAuthENCKey = bytes.fromhex("63DC07286289A7A6C0334CA31C314A04")
    SesAuthMACKey = bytes.fromhex("774F26743ECE6AF5033B6AE8522946F6")
    assert derive_session_keys(key, rnd_a, rnd_b) == (SesAuthENCKey, SesAuthMACKey)


def test_cmac_short():
    key = bytes.fromhex("00000000000000000000000000000000")
    cmac = cmac_short(key, b"hello world")
    assert cmac.hex() == "4b168d0e45065165"


def test_xor():
    a = bytes.fromhex("0011aaff")
    b = bytes.fromhex("1100bbcc")
    assert xor(a, b).hex() == "11111133"
