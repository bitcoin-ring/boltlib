# -*- coding: utf-8 -*-
"""NFC Message Parsers"""
import dataclasses
from typing import Union

from construct import Int8ub, Int32ub, Bytes, Hex
from construct_typed import DataclassMixin, DataclassStruct, csfield

__all__ = ["parse_version"]


@dataclasses.dataclass
class Version(DataclassMixin):
    """Concatenated 3 Part GetVersion response"""

    HW_VendorID: bytes = csfield(Hex(Int8ub))
    HW_Type: bytes = csfield(Hex(Int8ub))
    HW_SubType: bytes = csfield(Hex(Int8ub))
    HW_MajorVersion: bytes = csfield(Hex(Int8ub))
    HW_MinorVersion: bytes = csfield(Hex(Int8ub))
    HW_StorageSize: bytes = csfield(Hex(Int8ub))
    HW_Protocol: bytes = csfield(Hex(Int8ub))
    SW_VendorID: bytes = csfield(Hex(Int8ub))
    SW_Type: bytes = csfield(Hex(Int8ub))
    SW_SubType: bytes = csfield(Hex(Int8ub))
    SW_MajorVersion: bytes = csfield(Hex(Int8ub))
    SW_MinorVersion: bytes = csfield(Hex(Int8ub))
    SW_StorageSize: bytes = csfield(Hex(Int8ub))
    SW_Protocol: bytes = csfield(Hex(Int8ub))
    PR_UID: bytes = csfield(Hex(Bytes(7)))
    PR_BatchNo: int = csfield(Int32ub)
    PR_FabKey: bytes = csfield(Hex(Int8ub))
    PR_CWProd: bytes = csfield(Hex(Int8ub))
    PR_YearProd: bytes = csfield(Hex(Int8ub))


version_parser = DataclassStruct(Version)


def parse_version(data: Union[bytes, str]) -> Version:
    """Parse NFC Card Version information from bytes or hex string."""
    if isinstance(data, bytes):
        return version_parser.parse(data)
    elif isinstance(data, str):
        return version_parser.parse(bytes.fromhex(data))
    else:
        raise ValueError("Version data must be bytes or string")
