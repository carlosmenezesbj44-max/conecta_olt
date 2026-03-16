import random
import socket


def walk(
    host,
    community,
    base_oid,
    port=161,
    timeout=3,
    max_rows=8192,
    version="2c",
    retries=2,
    max_repetitions=25,
):
    base = _parse_oid(base_oid)
    current = base
    request_id = random.randint(1000, 9999999)
    version_tag = _snmp_version_tag(version)
    use_bulk = version_tag == 1
    rows = []
    for _ in range(max_rows):
        request_id += 1
        if use_bulk:
            packet = _build_getbulk_request(
                community,
                request_id,
                current,
                version_tag,
                max_repetitions=max(1, int(max_repetitions)),
            )
        else:
            packet = _build_getnext_request(community, request_id, current, version_tag)
        response = None
        last_error = None
        for _attempt in range(max(1, int(retries) + 1)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(packet, (host, int(port)))
                    response, _ = sock.recvfrom(65535)
                    break
            except Exception as error:
                last_error = error
        if response is None:
            if use_bulk:
                # Some Huawei agents timeout on GETBULK for specific tables.
                # Fallback to GETNEXT keeps polling functional, with lower performance.
                use_bulk = False
                continue
            if rows:
                break
            raise last_error or TimeoutError("SNMP timeout")
        try:
            varbinds = _parse_getresponse_varbinds(response)
        except Exception:
            if use_bulk:
                use_bulk = False
                continue
            raise
        if not varbinds:
            break

        advanced = False
        for oid, value in varbinds:
            if not _oid_starts_with(oid, base):
                return rows
            if oid <= current:
                continue
            rows.append((oid, value))
            current = oid
            advanced = True
            if len(rows) >= max_rows:
                return rows
        if not advanced:
            break
    return rows


def get(
    host,
    community,
    oid,
    port=161,
    timeout=3,
    version="2c",
    retries=2,
):
    target_oid = _parse_oid(oid)
    request_id = random.randint(1000, 9999999)
    version_tag = _snmp_version_tag(version)
    last_error = None
    for _attempt in range(max(1, int(retries) + 1)):
        try:
            request_id += 1
            packet = _build_get_request(community, request_id, target_oid, version_tag)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (host, int(port)))
                response, _ = sock.recvfrom(65535)
            rows = _parse_getresponse_varbinds(response)
            if not rows:
                raise ValueError("Resposta SNMP sem varbinds.")
            response_oid, value = rows[0]
            return response_oid, value
        except Exception as error:
            last_error = error
    raise last_error or TimeoutError("SNMP timeout")


def _snmp_version_tag(version):
    normalized = str(version or "2c").strip().lower()
    if normalized in {"1", "v1"}:
        return 0
    if normalized in {"2", "2c", "v2c"}:
        return 1
    raise ValueError(f"Versao SNMP nao suportada: {version}")


def _parse_oid(value):
    if isinstance(value, (tuple, list)):
        return tuple(int(part) for part in value)
    parts = [part.strip() for part in str(value).strip(".").split(".") if part.strip()]
    return tuple(int(part) for part in parts)


def _oid_starts_with(oid, prefix):
    return len(oid) >= len(prefix) and oid[: len(prefix)] == prefix


def _oid_suffix(oid, base_oid):
    return oid[len(base_oid) :]


def normalize_serial(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.hex().upper()
    else:
        text = str(value).upper()
    return "".join(ch for ch in text if ch.isalnum())


def build_indexed_map(rows, base_oid):
    base = _parse_oid(base_oid)
    mapped = {}
    for oid, value in rows:
        suffix = _oid_suffix(oid, base)
        mapped[suffix] = value
    return mapped


def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    chunks = []
    remaining = length
    while remaining:
        chunks.insert(0, remaining & 0xFF)
        remaining >>= 8
    return bytes([0x80 | len(chunks), *chunks])


def _encode_integer(value):
    number = int(value)
    if number == 0:
        payload = b"\x00"
    else:
        payload = bytearray()
        negative = number < 0
        current = abs(number)
        while current:
            payload.insert(0, current & 0xFF)
            current >>= 8
        if negative:
            payload = bytearray((~b) & 0xFF for b in payload)
            carry = 1
            for idx in range(len(payload) - 1, -1, -1):
                total = payload[idx] + carry
                payload[idx] = total & 0xFF
                carry = 1 if total > 0xFF else 0
            if payload and (payload[0] & 0x80) == 0:
                payload.insert(0, 0xFF)
        elif payload[0] & 0x80:
            payload.insert(0, 0)
        payload = bytes(payload)
    return b"\x02" + _encode_length(len(payload)) + payload


def _encode_octet_string(value):
    payload = value.encode("utf-8")
    return b"\x04" + _encode_length(len(payload)) + payload


def _encode_null():
    return b"\x05\x00"


def _encode_oid(oid):
    oid = tuple(int(part) for part in oid)
    first = 40 * oid[0] + oid[1]
    encoded = bytearray([first])
    for part in oid[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(stack)
    return b"\x06" + _encode_length(len(encoded)) + bytes(encoded)


def _encode_sequence(tag, payload):
    return bytes([tag]) + _encode_length(len(payload)) + payload


def _build_getnext_request(community, request_id, oid, version_tag):
    varbind = _encode_sequence(0x30, _encode_oid(oid) + _encode_null())
    varbind_list = _encode_sequence(0x30, varbind)
    pdu = _encode_sequence(
        0xA1,
        _encode_integer(request_id) + _encode_integer(0) + _encode_integer(0) + varbind_list,
    )
    return _encode_sequence(0x30, _encode_integer(version_tag) + _encode_octet_string(community) + pdu)


def _build_get_request(community, request_id, oid, version_tag):
    varbind = _encode_sequence(0x30, _encode_oid(oid) + _encode_null())
    varbind_list = _encode_sequence(0x30, varbind)
    pdu = _encode_sequence(
        0xA0,
        _encode_integer(request_id) + _encode_integer(0) + _encode_integer(0) + varbind_list,
    )
    return _encode_sequence(0x30, _encode_integer(version_tag) + _encode_octet_string(community) + pdu)


def _build_getbulk_request(community, request_id, oid, version_tag, max_repetitions=25):
    varbind = _encode_sequence(0x30, _encode_oid(oid) + _encode_null())
    varbind_list = _encode_sequence(0x30, varbind)
    pdu = _encode_sequence(
        0xA5,
        _encode_integer(request_id)
        + _encode_integer(0)  # non-repeaters
        + _encode_integer(max_repetitions)
        + varbind_list,
    )
    return _encode_sequence(0x30, _encode_integer(version_tag) + _encode_octet_string(community) + pdu)


def _read_tlv(data, offset):
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte & 0x80:
        size = length_byte & 0x7F
        length = int.from_bytes(data[offset : offset + size], "big")
        offset += size
    else:
        length = length_byte
    start = offset
    end = offset + length
    return tag, start, end


def _decode_integer(payload, signed=True):
    if not payload:
        return 0
    return int.from_bytes(payload, "big", signed=signed)


def _decode_oid(payload):
    if not payload:
        return ()
    first = payload[0]
    oid = [first // 40, first % 40]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if (byte & 0x80) == 0:
            oid.append(value)
            value = 0
    return tuple(oid)


def _parse_value(tag, payload):
    if tag == 0x02:
        return _decode_integer(payload, signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return _decode_integer(payload, signed=False)
    if tag == 0x04:
        if not payload:
            return ""
        # Keep binary OCTET STRING as bytes (common for ONU serial fields in Huawei MIB).
        printable = sum(1 for byte in payload if 32 <= byte <= 126)
        ratio = printable / len(payload)
        if ratio < 0.85:
            return payload
        try:
            return payload.decode("utf-8", errors="ignore").strip("\x00")
        except Exception:
            return payload
    if tag == 0x06:
        return _decode_oid(payload)
    if tag == 0x40:
        return ".".join(str(part) for part in payload)
    if tag == 0x05:
        return None
    return payload


def _parse_getresponse_varbinds(packet):
    tag, start, end = _read_tlv(packet, 0)
    if tag != 0x30:
        raise ValueError("Resposta SNMP invalida.")
    index = start

    _, v_start, v_end = _read_tlv(packet, index)
    index = v_end

    _, c_start, c_end = _read_tlv(packet, index)
    index = c_end

    pdu_tag, p_start, p_end = _read_tlv(packet, index)
    if pdu_tag not in (0xA2,):
        raise ValueError("PDU SNMP inesperado.")
    p_index = p_start

    _, rid_start, rid_end = _read_tlv(packet, p_index)
    p_index = rid_end

    _, err_start, err_end = _read_tlv(packet, p_index)
    error_status = _decode_integer(packet[err_start:err_end], signed=True)
    p_index = err_end
    _, eidx_start, eidx_end = _read_tlv(packet, p_index)
    p_index = eidx_end
    if error_status:
        raise ValueError(f"SNMP error-status={error_status}.")

    vbl_tag, vbl_start, vbl_end = _read_tlv(packet, p_index)
    if vbl_tag != 0x30:
        raise ValueError("VarBindList SNMP invalido.")

    rows = []
    vb_index = vbl_start
    while vb_index < vbl_end:
        vb_tag, vb_start, vb_end = _read_tlv(packet, vb_index)
        if vb_tag != 0x30:
            raise ValueError("VarBind SNMP invalido.")

        oid_tag, oid_start, oid_end = _read_tlv(packet, vb_start)
        if oid_tag != 0x06:
            raise ValueError("OID SNMP invalido.")
        oid = _decode_oid(packet[oid_start:oid_end])

        val_tag, val_start, val_end = _read_tlv(packet, oid_end)
        value = _parse_value(val_tag, packet[val_start:val_end])
        rows.append((oid, value))
        vb_index = vb_end
    return rows


def _parse_getresponse(packet):
    rows = _parse_getresponse_varbinds(packet)
    if not rows:
        raise ValueError("Resposta SNMP sem varbinds.")
    return rows[0]
