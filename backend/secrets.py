import base64
import os
import sys

# Windows-specific imports
try:
    import ctypes
    from ctypes import wintypes
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    IS_WINDOWS = sys.platform == "win32"
except (AttributeError, ImportError):
    IS_WINDOWS = False


CRYPTPROTECT_UI_FORBIDDEN = 0x01
_PREFIX = "dpapi:"
_PLAIN_PREFIX = "plain:"


def encrypt_secret(value):
    if value is None or value == "":
        return None
    if isinstance(value, str) and (value.startswith(_PREFIX) or value.startswith(_PLAIN_PREFIX)):
        return value
    
    if IS_WINDOWS:
        try:
            # Original DPAPI implementation
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            def _blob_from_bytes(data):
                buffer = (ctypes.c_byte * len(data)).from_buffer_copy(data)
                return DATA_BLOB(len(data), buffer), buffer

            raw = value.encode("utf-8")
            in_blob, _ = _blob_from_bytes(raw)
            out_blob = DATA_BLOB()
            if crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0x01, ctypes.byref(out_blob)):
                encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                kernel32.LocalFree(out_blob.pbData)
                return _PREFIX + base64.b64encode(encrypted).decode("ascii")
        except Exception:
            pass

    # Fallback to plain prefix if not on Windows or DPAPI fails
    return _PLAIN_PREFIX + value


def decrypt_secret(value):
    if value is None or value == "":
        return None
    
    if not isinstance(value, str):
        return value

    if value.startswith(_PLAIN_PREFIX):
        return value[len(_PLAIN_PREFIX):]

    if value.startswith(_PREFIX) and IS_WINDOWS:
        try:
            # Original DPAPI implementation
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

            def _blob_from_bytes(data):
                payload = base64.b64decode(value[len(_PREFIX):])
                buffer = (ctypes.c_byte * len(payload)).from_buffer_copy(payload)
                return DATA_BLOB(len(payload), buffer), buffer

            in_blob, _ = _blob_from_bytes(None)
            out_blob = DATA_BLOB()
            if crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0x01, ctypes.byref(out_blob)):
                decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                kernel32.LocalFree(out_blob.pbData)
                return decrypted.decode("utf-8")
        except Exception:
            pass

    # Se estiver com prefixo DPAPI mas em Linux, ou se falhar, retorna o valor original sem o prefixo (se possível)
    # ou o valor como está (melhor do que crashar)
    return value



def looks_encrypted(value):
    return isinstance(value, str) and value.startswith(_PREFIX)
