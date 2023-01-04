# -*- coding: utf-8 -*-
from construct import StreamError
import boltlib
import pytest


V = "0404023000110504040201021105040B6532CA0F90CF5CD455604321"


def test_parse_version_hex_string():
    v_obj = boltlib.parse_version(V)
    assert v_obj.HW_VendorID == 0x04


def test_parse_version_bytes():
    v_obj = boltlib.parse_version(bytes.fromhex(V))
    assert v_obj.HW_VendorID == 0x04


def test_parse_version_raises_bad_type():
    with pytest.raises(ValueError):
        boltlib.parse_version([1, 4])


def test_parse_version_raises_bad_struct():
    with pytest.raises(StreamError):
        boltlib.parse_version(V[:2])
