import base64
import ctypes
from ctypes import wintypes


CRYPTPROTECT_UI_FORBIDDEN = 0x01
_PREFIX = "dpapi:"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32


def _blob_from_bytes(data):
    if not data:
        return DATA_BLOB(0, None), None
    buffer = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(len(data), buffer), buffer


def _bytes_from_blob(blob):
    if not blob.cbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def encrypt_secret(value):
    if value is None or value == "":
        return None
    if isinstance(value, str) and value.startswith(_PREFIX):
        return value
    raw = value.encode("utf-8")
    in_blob, _ = _blob_from_bytes(raw)
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        encrypted = _bytes_from_blob(out_blob)
        return _PREFIX + base64.b64encode(encrypted).decode("ascii")
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def decrypt_secret(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.startswith(_PREFIX):
        return value
    payload = base64.b64decode(value[len(_PREFIX):])
    in_blob, _ = _blob_from_bytes(payload)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(out_blob).decode("utf-8")
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def looks_encrypted(value):
    return isinstance(value, str) and value.startswith(_PREFIX)
