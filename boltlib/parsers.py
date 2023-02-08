# -*- coding: utf-8 -*-
"""NFC Message Parsers"""
import dataclasses
from typing import Union, Optional
from bitarray import bitarray, frozenbitarray
from bitarray.util import ba2int
from construct import Int8ub, Int32ub, Bytes, Hex, Int24ub, Int16ub, BitsInteger
from construct_typed import DataclassMixin, DataclassStruct, csfield

__all__ = [
    "AuthResponse",
    "Session",
    "FileSettings",
    "parse_version",
    "parse_auth_response",
    "parse_file_settings",
]


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


@dataclasses.dataclass
class AuthResponse(DataclassMixin):
    TI: bytes = csfield(Hex(Bytes(4)))
    RndA: bytes = csfield(Hex(Bytes(16)))
    PDcap2: bytes = csfield(Hex(Bytes(6)))
    PCDcap2: bytes = csfield(Hex(Bytes(6)))


auth_response_parser = DataclassStruct(AuthResponse)


@dataclasses.dataclass
class Session:
    key_enc: bytes
    key_mac: bytes
    auth_info: AuthResponse


@dataclasses.dataclass
class FileSettings:

    file_type: Optional[int] = None
    communication_mode: Optional[str] = None


def parse_file_settings(data: bytes) -> FileSettings:
    """Parse NTAG 424 DNA FileSettings"""
    ba = bitarray()
    ba.frombytes(data)
    ba = frozenbitarray(ba)
    fs = FileSettings()

    fs.file_type = ba2int(ba[:8])
    cm = {
        frozenbitarray("00"): "Plain",
        frozenbitarray("10"): "Plain",
        frozenbitarray("01"): "MAC",
        frozenbitarray("11"): "Full",
    }

    fs.communication_mode = cm[ba[8:10]]
    return fs


# @dataclasses.dataclass
# class FileSettings(DataclassMixin):
#     """GetFileSettings Response"""
#     file_type: bytes = csfield(Int8ub)
#     file_option: bytes = csfield(Hex(Int8ub))
#     access_rights: bytes = csfield(Hex(Int16ub))
#     file_size: bytes = csfield(Int24ub)
#     sdm_options: bytes = csfield(Hex(Int8ub))
#
#
# file_settings_parser = DataclassStruct(FileSettings)
#
#
# def parse_file_settings(data: bytes) -> FileSettings:
#     """Parse NTAG 424 DNA FileSettings"""
#     return file_settings_parser.parse(data)


def parse_version(data: Union[bytes, str]) -> Version:
    """Parse NFC Card Version information from bytes or hex string."""
    if isinstance(data, bytes):
        return version_parser.parse(data)
    elif isinstance(data, str):
        return version_parser.parse(bytes.fromhex(data))
    else:
        raise ValueError("Version data must be bytes or string")


def parse_auth_response(data: Union[bytes, str]) -> AuthResponse:
    if isinstance(data, bytes):
        return auth_response_parser.parse(data)
    elif isinstance(data, str):
        return auth_response_parser.parse(bytes.fromhex(data))
    else:
        raise ValueError("AuthResponse data must be bytes or string")
