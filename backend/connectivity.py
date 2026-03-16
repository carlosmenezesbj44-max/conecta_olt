import random
import socket
from urllib.parse import urlparse

from backend import db


def test_olt_connection(olt_id):
    connection = db.fetch_connection_for_olt(olt_id)
    host = connection.get("olt_host")
    transport_type = (connection.get("transport_type") or "ssh").lower()
    port = int(connection.get("port") or _default_port(transport_type))
    if not host:
        raise ValueError("Host da OLT nao configurado.")

    try:
        if transport_type == "ssh":
            message = _test_tcp(host, port, "SSH")
        elif transport_type == "telnet":
            message = _test_tcp(host, port, "Telnet")
        elif transport_type == "api":
            message = _test_tcp(host, port, "API")
        elif transport_type == "snmp":
            extra = connection.get("extra_config") or {}
            community = (
                extra.get("snmp_read_community")
                or extra.get("snmp_community")
                or connection.get("password")
                or "public"
            )
            message = _test_snmp_v2c(host, port, community)
        else:
            raise ValueError(f"Tipo de conexao nao suportado: {transport_type}")

        db.update_connection_connect_status(olt_id, "connected", message, db.utc_now())
        return {
            "status": "connected",
            "transport_type": transport_type,
            "host": host,
            "port": port,
            "message": message,
        }
    except Exception as error:
        db.update_connection_connect_status(olt_id, "error", str(error), db.utc_now())
        return {
            "status": "error",
            "transport_type": transport_type,
            "host": host,
            "port": port,
            "message": str(error),
        }


def _default_port(transport_type):
    return {
        "ssh": 22,
        "telnet": 23,
        "snmp": 161,
        "api": 443,
    }.get((transport_type or "ssh").lower(), 22)


def _test_tcp(host, port, label):
    with socket.create_connection((host, port), timeout=4):
        return f"{label} conectado em {host}:{port}"


def _test_snmp_v2c(host, port, community):
    request_id = random.randint(1000, 999999)
    packet = _build_snmp_get(community, request_id, [1, 3, 6, 1, 2, 1, 1, 1, 0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.sendto(packet, (host, port))
        response, _ = sock.recvfrom(4096)
    if not response:
        raise TimeoutError("SNMP sem resposta.")
    return f"SNMP respondeu em {host}:{port}"


def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    parts = []
    while length:
        parts.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(parts), *parts])


def _encode_integer(value):
    if value == 0:
        payload = b"\x00"
    else:
        payload = bytearray()
        current = value
        while current:
            payload.insert(0, current & 0xFF)
            current >>= 8
        if payload[0] & 0x80:
            payload.insert(0, 0)
        payload = bytes(payload)
    return b"\x02" + _encode_length(len(payload)) + payload


def _encode_octet_string(value):
    payload = value.encode("utf-8")
    return b"\x04" + _encode_length(len(payload)) + payload


def _encode_null():
    return b"\x05\x00"


def _encode_oid(oid_parts):
    first = 40 * oid_parts[0] + oid_parts[1]
    payload = bytearray([first])
    for part in oid_parts[2:]:
        encoded = []
        current = part
        encoded.insert(0, current & 0x7F)
        current >>= 7
        while current:
            encoded.insert(0, 0x80 | (current & 0x7F))
            current >>= 7
        payload.extend(encoded)
    return b"\x06" + _encode_length(len(payload)) + bytes(payload)


def _encode_sequence(tag, payload):
    return bytes([tag]) + _encode_length(len(payload)) + payload


def _build_snmp_get(community, request_id, oid_parts):
    varbind = _encode_sequence(0x30, _encode_oid(oid_parts) + _encode_null())
    varbinds = _encode_sequence(0x30, varbind)
    pdu = _encode_sequence(
        0xA0,
        _encode_integer(request_id) + _encode_integer(0) + _encode_integer(0) + varbinds,
    )
    return _encode_sequence(0x30, _encode_integer(1) + _encode_octet_string(community) + pdu)
