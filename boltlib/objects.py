# -*- coding: utf-8 -*-
import secrets
from typing import Protocol

__all__ = [
    "UrlTemplate",
    "AuthSession",
    "NFCWriter",
]


class UrlTemplate:
    """URL template to be written to BoltCard"""

    def __init__(self, url, picc_offset, cmac_offset):
        # type: (str, int, int) -> None
        self.url = url
        self.picc_offset = picc_offset
        self.cmac_offset = cmac_offset


class AuthSession:
    """Authenticated NFC Session data"""

    def __init__(self, key="00000000000000000000000000000000"):
        # type: (str) -> None
        self.key = key
        self.rnd_a: bytes = secrets.token_bytes(16)
        self.rnd_b: bytes = b""
        self.key_enc: bytes = b""
        self.key_mac: bytes = b""
        self.ti: bytes = b""
        self.cmd_counter: int = 0

    @property
    def authenticated(self):
        return all([self.key_enc, self.key_mac, self.ti])


class NFCWriter(Protocol):
    """Interface writer interface"""

    def write(self, apdu):
        # type: (Union[str,List[str]]) -> str
        """Writes one or more hex coded APDU message to NFC device and returns HEX response"""
        ...
