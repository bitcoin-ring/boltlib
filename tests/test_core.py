# -*- coding: utf-8 -*-
from boltlib.core import derive_session_keys


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
