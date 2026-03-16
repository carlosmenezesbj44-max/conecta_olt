import re
from collections import defaultdict


def parse_huawei_cli_snapshot(files):
    olt_metrics = parse_olt_metrics(files.get("olt.txt", ""))
    boards = parse_boards(files.get("board.txt", ""))
    ont_rows = parse_ont_summary(files.get("ont_summary.txt", ""))
    traffic_map = parse_traffic(files.get("traffic.txt", ""))
    optical_map = parse_optical(files.get("optical.txt", ""))
    vlan_map = parse_service_ports(files.get("service_port.txt", ""))
    vlan_inventory = parse_vlan_inventory(files.get("vlan_inventory.txt", ""))
    autofind = parse_autofind(files.get("autofind.txt", ""))

    onus = []
    port_usage = defaultdict(int)
    description_map = parse_ont_descriptions(files.get("ont_summary.txt", ""))

    for row in ont_rows:
        key = (row["board_slot"], row["port_name"], row["pon_position"])
        traffic = traffic_map.get(key, {})
        optical = optical_map.get(key, {})
        vlan_id = vlan_map.get(key) or vlan_map.get((row["board_slot"], row["port_name"], None))
        description = (
            (row.get("description") or "").strip()
            or (description_map.get((row["board_slot"], row["port_name"], row["pon_position"])) or "").strip()
        )
        onus.append(
            {
                "serial": row["serial"],
                "model": row["model"],
                "description": description or None,
                "status": row["status"],
                "signal_dbm": optical.get("signal_dbm"),
                "traffic_down_mbps": traffic.get("traffic_down_mbps", 0.0),
                "traffic_up_mbps": traffic.get("traffic_up_mbps", 0.0),
                "temperature_c": optical.get("temperature_c"),
                "board_slot": row["board_slot"],
                "port_name": row["port_name"],
                "pon_position": row["pon_position"],
                "vlan_id": vlan_id,
            }
        )
        port_usage[(row["board_slot"], row["port_name"])] += 1

    ports = []
    seen_ports = set()
    for board in boards:
        for port_number in range(1, int(board["ports_total"]) + 1):
            key = (board["slot"], f"PON {port_number}")
            seen_ports.add(key)
            ports.append(
                {
                    "board_slot": board["slot"],
                    "name": key[1],
                    "capacity_onu": 128,
                    "alert_threshold_pct": 80,
                    "used_onu": port_usage.get(key, 0),
                }
            )

    for key, used_onu in port_usage.items():
        if key in seen_ports:
            continue
        ports.append(
            {
                "board_slot": key[0],
                "name": key[1],
                "capacity_onu": 128,
                "alert_threshold_pct": 80,
                "used_onu": used_onu,
            }
        )

    events = []
    for onu in onus:
        if onu.get("signal_dbm") is not None and onu["signal_dbm"] <= -27.0:
            events.append(
                {
                    "level": "warning",
                    "message": f'Sinal baixo na ONU {onu["serial"]}: {onu["signal_dbm"]} dBm',
                    "details": {
                        "serial": onu["serial"],
                        "board_slot": onu["board_slot"],
                        "port_name": onu["port_name"],
                    },
                }
            )

    observed_olt_vlans = sorted(
        {
            int(vlan_id)
            for vlan_id in list(vlan_map.values()) + list(vlan_inventory)
            if isinstance(vlan_id, int) and 1 <= int(vlan_id) <= 4094
        }
    )

    return {
        "olt_metrics": olt_metrics,
        "boards": boards,
        "ports": ports,
        "onus": onus,
        "olt_vlans": [{"vlan_id": vlan_id, "source": "observed"} for vlan_id in observed_olt_vlans],
        "authorization_requests": autofind,
        "events": events,
    }


def parse_olt_metrics(text):
    text = _normalize_cli_text(text)
    return {
        "temperature_c": _find_float(text, [r"System\s+Temperature\s*:\s*([0-9.]+)", r"Temperature\s*:\s*([0-9.]+)"]) or 40.0,
        "cpu_usage": _find_float(text, [r"CPU\s+Usage\s*:\s*([0-9.]+)", r"CPU\s*:\s*([0-9.]+)"]) or 30.0,
        "memory_usage": _find_float(text, [r"Memory\s+Usage\s*:\s*([0-9.]+)", r"Memory\s*:\s*([0-9.]+)"]) or 50.0,
    }


def parse_boards(text):
    text = _normalize_cli_text(text)
    boards = []
    pattern = re.compile(
        r"(?P<slot>\d+/\d+)\s+(?P<model>[A-Z0-9-]+)\s+(?P<status>Normal|Online|Offline|Fault|Warning)\s+(?P<ports>\d+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        status = match.group("status").lower()
        boards.append(
            {
                "slot": match.group("slot"),
                "model": match.group("model"),
                "status": "online" if status in {"normal", "online"} else "warning",
                "ports_total": int(match.group("ports")),
            }
        )
    return boards


def parse_ont_summary(text):
    text = _normalize_cli_text(text)
    rows = []
    seen_keys = set()
    pattern = re.compile(
        r"(?P<path>\d+/\d+/\d+)\s+"
        r"(?P<ont_id>\d+)\s+"
        r"(?P<serial>[A-Z0-9]+)\s+"
        r"(?P<run_state>online|offline)\s+"
        r"(?P<config_state>\w+)\s+"
        r"(?P<model>[A-Z0-9-]+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        key = (board_slot, port_name, int(match.group("ont_id")))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        rows.append(
            {
                "board_slot": board_slot,
                "port_name": port_name,
                "pon_position": int(match.group("ont_id")),
                "serial": match.group("serial").upper(),
                "status": "active" if match.group("run_state").lower() == "online" else "warning",
                "model": match.group("model"),
            }
        )

    # Alternate MA56xx table format (common in Telnet output):
    # 0/ 0/15   20  ABCD1234EF567890  active  online  normal  mismatch  no
    alt_pattern = re.compile(
        r"(?P<frame>\d+)\s*/\s*(?P<slot>\d+)\s*/\s*(?P<port>\d+)\s+"
        r"(?P<ont_id>\d+)\s+"
        r"(?P<serial>[A-Z0-9]{8,20})\s+"
        r"\w+\s+"
        r"(?P<run_state>online|offline)\s+"
        r"(?P<config_state>\w+)",
        re.IGNORECASE,
    )
    for match in alt_pattern.finditer(text):
        board_slot = f'{int(match.group("frame"))}/{int(match.group("slot"))}'
        port_name = f'PON {int(match.group("port")) + 1}'
        key = (board_slot, port_name, int(match.group("ont_id")))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        rows.append(
            {
                "board_slot": board_slot,
                "port_name": port_name,
                "pon_position": int(match.group("ont_id")),
                "serial": match.group("serial").upper(),
                "status": "active" if match.group("run_state").lower() == "online" else "warning",
                "model": "Desconhecido",
            }
        )

    # Block format used by some Huawei outputs:
    # "In port 0/1/0 ...", then a run-state table and a "ONT SN Type ..." table.
    current_path = None
    run_state_map = {}
    current_description_key = None
    port_header_pattern = re.compile(r"(?i)\bin\s+port\s+(?P<path>\d+\s*/\s*\d+\s*/\s*\d+)\b")
    run_state_pattern = re.compile(r"^\s*(?P<ont_id>\d+)\s+(?P<run_state>online|offline)\b", re.IGNORECASE)
    # Example:
    # 0   5A4E... 2301   1611  -28.86/2.90  client_name...
    sn_row_pattern = re.compile(
        r"^\s*(?P<ont_id>\d+)\s+"
        r"(?P<serial>[A-Z0-9]{8,20})\s+"
        r"(?P<model>[A-Za-z0-9_.-]+)"
        r"(?:\s+(?P<distance>-|\d+)\s+(?P<power>-?[\d.]+/-?[\d.]+|-/-)\s*(?P<description>.*))?",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        header = port_header_pattern.search(line)
        if header:
            raw_path = re.sub(r"\s+", "", header.group("path"))
            if "/" in raw_path:
                current_path = raw_path
            current_description_key = None
            continue
        if not current_path:
            continue
        run_match = run_state_pattern.match(line)
        if run_match:
            board_slot, port_name = normalize_huawei_path(current_path)
            run_state_map[(board_slot, port_name, int(run_match.group("ont_id")))] = run_match.group("run_state").lower()
            continue
        sn_match = sn_row_pattern.match(line)
        if not sn_match:
            if current_description_key and line.startswith(" "):
                continuation = " ".join(line.strip().split())
                lowered = continuation.lower()
                if (
                    continuation
                    and not continuation.startswith("---")
                    and "in port " not in lowered
                    and "ont id" not in lowered
                    and "ont sn" not in lowered
                    and "rx/tx power" not in lowered
                ):
                    current_description_key["description"] = (
                        f'{current_description_key.get("description", "")} {continuation}'.strip()
                    )
            continue
        board_slot, port_name = normalize_huawei_path(current_path)
        ont_id = int(sn_match.group("ont_id"))
        key = (board_slot, port_name, ont_id)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        run_state = run_state_map.get(key, "online")
        model = sn_match.group("model")
        description = " ".join((sn_match.group("description") or "").split()).strip()
        if description in {"-", "--"}:
            description = ""
        rows.append(
            {
                "board_slot": board_slot,
                "port_name": port_name,
                "pon_position": ont_id,
                "serial": sn_match.group("serial").upper(),
                "status": "active" if run_state == "online" else "warning",
                "model": model if model != "-" else "Desconhecido",
                "description": description or None,
            }
        )
        current_description_key = rows[-1]
    return rows


def parse_ont_descriptions(text):
    text = _normalize_cli_text(text)
    lines = text.splitlines()
    descriptions = {}
    in_description_table = False
    current_key = None

    row_pattern = re.compile(
        r"^\s*(?P<frame>\d+)\s*/\s*(?P<slot>\d+)\s*/\s*(?P<port>\d+)\s+"
        r"(?P<ont_id>\d+)\s+(?P<description>.+?)\s*$"
    )

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("f/s/p") and "description" in stripped.lower():
            in_description_table = True
            current_key = None
            continue
        if not in_description_table:
            continue
        if stripped.startswith("----"):
            continue
        if "the total of ont" in stripped.lower():
            break

        match = row_pattern.match(line)
        if match:
            board_slot = f'{int(match.group("frame"))}/{int(match.group("slot"))}'
            port_name = f'PON {int(match.group("port")) + 1}'
            ont_id = int(match.group("ont_id"))
            description = " ".join(match.group("description").split())
            key = (board_slot, port_name, ont_id)
            descriptions[key] = description
            current_key = key
            continue

        if current_key:
            continuation = " ".join(stripped.split())
            descriptions[current_key] = f'{descriptions[current_key]} {continuation}'.strip()

    return descriptions


def parse_traffic(text):
    text = _normalize_cli_text(text)
    rows = {}
    line_pattern = re.compile(
        r"^\s*(?P<path>\d+/\d+/\d+)\s+"
        r"(?P<ont_id>\d+)\s+"
        r"(?P<down>[0-9.]+)\s+"
        r"(?P<up>[0-9.]+)\b",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        match = line_pattern.match(line)
        if not match:
            continue
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, int(match.group("ont_id")))] = {
            "traffic_down_mbps": float(match.group("down")),
            "traffic_up_mbps": float(match.group("up")),
        }
    return rows


def parse_optical(text):
    text = _normalize_cli_text(text)
    rows = {}
    pattern = re.compile(
        r"(?P<path>\d+/\d+/\d+)\s+"
        r"(?P<ont_id>\d+)\s+"
        r"(?P<signal>-?[0-9.]+)\s+"
        r"(?P<temperature>[0-9.]+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, int(match.group("ont_id")))] = {
            "signal_dbm": float(match.group("signal")),
            "temperature_c": float(match.group("temperature")),
        }
    return rows


def parse_service_ports(text):
    text = _normalize_cli_text(text)
    # Huawei often prints F/S/P as "0/ 0/0" or "0 /0 / 0" in some outputs.
    text = re.sub(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", r"\1/\2/\3", text)
    rows = {}
    ont_pattern = re.compile(
        r"(?P<path>\d+/\d+/\d+)\s+(?P<ont_id>\d+)\s+(?P<vlan>\d+)",
        re.IGNORECASE,
    )
    port_pattern = re.compile(
        r"(?P<path>\d+/\d+/\d+)\s+all\s+(?P<vlan>\d+)",
        re.IGNORECASE,
    )
    for match in ont_pattern.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, int(match.group("ont_id")))] = int(match.group("vlan"))
    for match in port_pattern.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, None)] = int(match.group("vlan"))

    # Fallback for common Huawei "display service-port all" output variants:
    # e.g. "... gpon 0/0/0 ont 5 ... user-vlan 1806 ..."
    line_fallback = re.compile(
        r"(?i)\bgpon\s+(?P<path>\d+/\d+/\d+)\b.*?\bont\s+(?P<ont_id>\d+)\b.*?\b(?:user-?vlan|svlan|cvlan|vlan)\s+(?P<vlan>\d+)\b"
    )
    for match in line_fallback.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, int(match.group("ont_id")))] = int(match.group("vlan"))

    # Fallback without explicit ONT id on line: bind VLAN per port.
    port_fallback = re.compile(
        r"(?i)\bgpon\s+(?P<path>\d+/\d+/\d+)\b.*?\b(?:user-?vlan|svlan|cvlan|vlan)\s+(?P<vlan>\d+)\b"
    )
    for match in port_fallback.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows.setdefault((board_slot, port_name, None), int(match.group("vlan")))

    # Common "display current-configuration | include service-port" style:
    # service-port <id> vlan <vlan> gpon 0/0/0 ont <id> ...
    cfg_with_ont = re.compile(
        r"(?i)\bservice-port\s+\d+\s+vlan\s+(?P<vlan>\d+)\s+gpon\s+(?P<path>\d+/\d+/\d+)\s+ont\s+(?P<ont_id>\d+)\b"
    )
    for match in cfg_with_ont.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows[(board_slot, port_name, int(match.group("ont_id")))] = int(match.group("vlan"))

    # Port-level service-port without explicit ONT id.
    cfg_port_only = re.compile(
        r"(?i)\bservice-port\s+\d+\s+vlan\s+(?P<vlan>\d+)\s+gpon\s+(?P<path>\d+/\d+/\d+)\b(?!.*\bont\b)"
    )
    for match in cfg_port_only.finditer(text):
        board_slot, port_name = normalize_huawei_path(match.group("path"))
        rows.setdefault((board_slot, port_name, None), int(match.group("vlan")))
    return rows


def parse_vlan_inventory(text):
    text = _normalize_cli_text(text)
    vlans = set()

    # Common VLAN table lines: "1234  <name> ..."
    table_pattern = re.compile(r"(?m)^\s*(?P<vlan>\d{1,4})\s+[A-Za-z0-9_.-]+")
    for match in table_pattern.finditer(text):
        vlan_id = int(match.group("vlan"))
        if 1 <= vlan_id <= 4094:
            vlans.add(vlan_id)

    # Fallback for config lines: "vlan 1234"
    cfg_pattern = re.compile(r"(?mi)^\s*vlan\s+(?P<vlan>\d{1,4})\b")
    for match in cfg_pattern.finditer(text):
        vlan_id = int(match.group("vlan"))
        if 1 <= vlan_id <= 4094:
            vlans.add(vlan_id)

    return sorted(vlans)


def parse_profile_summary(text):
    text = _normalize_cli_text(text)
    rows = []
    seen_refs = set()
    pattern = re.compile(
        r"^\s*(?P<profile_ref>\d+)\s+(?P<name>.+?)\s+(?P<binding_times>\d+)\s*$",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        profile_ref = int(match.group("profile_ref"))
        if profile_ref in seen_refs:
            continue
        seen_refs.add(profile_ref)
        rows.append(
            {
                "profile_ref": profile_ref,
                "name": " ".join(match.group("name").split()),
                "binding_times": int(match.group("binding_times")),
            }
        )
    return rows


def _guess_autofind_model(serial=None, equipment_id=None, alias=None, vendor_id=None):
    equipment = " ".join(str(equipment_id or "").split()).strip()
    if equipment and equipment not in {"-", "--"}:
        return equipment

    alias_value = str(alias or "").strip().upper()
    if alias_value:
        vendor = "".join(ch for ch in alias_value.split("-", 1)[0] if ch.isalnum())
        if vendor:
            return f"ONU-{vendor}"

    vendor_value = "".join(ch for ch in str(vendor_id or "").upper() if ch.isalnum())
    if vendor_value and vendor_value not in {"0X00000000", "00000000"}:
        return f"ONU-{vendor_value}"

    raw = "".join(ch for ch in str(serial or "").upper() if ch.isalnum())
    if len(raw) >= 8:
        prefix = raw[:8]
        try:
            vendor = bytes.fromhex(prefix).decode("ascii", errors="ignore").strip()
            vendor = "".join(ch for ch in vendor if ch.isalnum())
        except Exception:
            vendor = ""
        if vendor:
            return f"ONU-{vendor}"
        return f"ONU-{prefix}"

    return "Desconhecido"


def _append_autofind_row(rows, seen, path, serial, model, notes=None):
    normalized_path = str(path or "").strip()
    normalized_serial = "".join(ch for ch in str(serial or "").upper() if ch.isalnum())
    if not normalized_path or len(normalized_serial) < 8:
        return
    key = (normalized_path, normalized_serial)
    if key in seen:
        return
    seen.add(key)
    board_slot, port_name = normalize_huawei_path(normalized_path)
    note_value = " ".join(str(notes or "").split()).strip() or "Detectada pelo autofind Huawei."
    rows.append(
        {
            "serial": normalized_serial,
            "detected_model": (str(model or "").strip() or "Desconhecido"),
            "board_slot": board_slot,
            "port_name": port_name,
            "requested_signal_dbm": -22.0,
            "requested_temperature_c": 45.0,
            "notes": note_value,
        }
    )


def parse_autofind(text):
    text = _normalize_cli_text(text)
    rows = []
    seen = set()

    current = {}

    def flush_current():
        if not current.get("path") or not current.get("serial"):
            current.clear()
            return
        _append_autofind_row(
            rows,
            seen,
            current.get("path"),
            current.get("serial"),
            _guess_autofind_model(
                serial=current.get("serial"),
                equipment_id=current.get("equipment_id"),
                alias=current.get("alias"),
                vendor_id=current.get("vendor_id"),
            ),
            notes=current.get("alias") or current.get("vendor_id") or "",
        )
        current.clear()

    for line in text.splitlines():
        number_match = re.match(r"^\s*Number\s*:\s*\d+\s*$", line, re.IGNORECASE)
        if number_match:
            flush_current()
            continue
        path_match = re.match(r"^\s*F/S/P\s*:\s*(?P<path>\d+/\d+/\d+)\s*$", line, re.IGNORECASE)
        if path_match:
            current["path"] = path_match.group("path")
            continue
        serial_match = re.match(
            r"^\s*Ont\s+SN\s*:\s*(?P<serial>[A-Z0-9]{8,20})(?:\s+\((?P<alias>[^)]+)\))?\s*$",
            line,
            re.IGNORECASE,
        )
        if serial_match:
            current["serial"] = serial_match.group("serial")
            current["alias"] = serial_match.group("alias") or ""
            continue
        equipment_match = re.match(r"^\s*Ont\s+EquipmentID\s*:\s*(?P<value>.+?)\s*$", line, re.IGNORECASE)
        if equipment_match:
            current["equipment_id"] = equipment_match.group("value")
            continue
        vendor_match = re.match(r"^\s*VendorID\s*:\s*(?P<value>.+?)\s*$", line, re.IGNORECASE)
        if vendor_match:
            current["vendor_id"] = vendor_match.group("value")
            continue
    flush_current()

    table_pattern = re.compile(
        r"^\s*(?P<path>\d+/\d+/\d+)\s+"
        r"(?P<serial>[A-Z0-9]{8,20})(?:\s+\([^)]+\))?\s+"
        r"(?P<model>[A-Z0-9_.-]{2,})\s*"
        r"(?P<note>.*)$",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in table_pattern.finditer(text):
        _append_autofind_row(
            rows,
            seen,
            match.group("path"),
            match.group("serial"),
            match.group("model"),
            notes=match.group("note"),
        )
    return rows


def normalize_huawei_path(path):
    frame, slot, port = [int(part) for part in path.split("/")]
    board_slot = f"{frame}/{slot}"
    port_name = f"PON {port + 1}"
    return board_slot, port_name


def _find_float(text, patterns):
    text = _normalize_cli_text(text)
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def _normalize_cli_text(text):
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"-+\s*More\s*\(.*?\)\s*-+", "\n", text, flags=re.IGNORECASE)
    text = text.replace("\x07", "").replace("\b", "")
    return text
