import re
import socket
import time

from backend.collectors.huawei_profiles import ont_summary_commands_for_profile, resolve_profile

PROMPT_PATTERN = re.compile(r"(<[^>\n]+>|\[[^\]\n]+\]|[A-Za-z0-9._()/:-]+[>#])\s*$")
CONFIRM_PATTERN = re.compile(r"(?i)(are you sure|continue\?|[(\[]\s*(?:y/n|yes/no)\s*[)\]])")
INPUT_PROMPT_PATTERN = re.compile(r"(?is)\{[^{}\n]{1,300}\}:\s*$")
LOGIN_PROMPTS = ("username:", "user name:", "login:")
PASSWORD_PROMPTS = ("password:",)
MORE_PATTERN = re.compile(r"--+\s*More\s*\(.*?\)\s*--+", re.IGNORECASE)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

HUAWEI_TELNET_COMMANDS = [
    ("olt.txt", "display device"),
    ("board.txt", "display board 0"),
    # Collect all ONTs in frame 0 across every slot/board, not only slot 0.
    ("ont_summary.txt", "display ont info summary 0 all"),
    ("traffic.txt", ""),
    ("optical.txt", "display ont optical-info 0 all"),
    ("vlan_inventory.txt", "display current-configuration | include vlan"),
    ("service_port.txt", "display service-port all"),
    ("autofind.txt", "display ont autofind all"),
]

IAC = 255
DO = 253
DONT = 254
WILL = 251
WONT = 252
SB = 250
SE = 240


def collect_huawei_cli_files_over_telnet(
    host,
    username,
    password,
    port=23,
    timeout=30,
    command_timeout=None,
    allow_partial=True,
    progress_callback=None,
    collector_profile="auto",
    command_overrides=None,
):
    if not username:
        raise ValueError("Usuario Telnet da OLT nao informado.")
    if password is None or password == "":
        raise ValueError("Senha Telnet da OLT nao informada.")

    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(0.5)
    try:
        try:
            phase, _ = _wait_for_any_prompt(sock, timeout)
        except TimeoutError:
            _send_line(sock, "")
            phase, _ = _wait_for_any_prompt(sock, timeout)
        if phase == "login":
            _send_line(sock, username)
            phase, _ = _wait_for_any_prompt(sock, timeout)
            if phase == "password":
                _send_line(sock, password)
                _read_until_device_prompt(sock, timeout)
            elif phase != "device":
                raise TimeoutError("Prompt de senha Telnet nao encontrado.")
        elif phase == "password":
            _send_line(sock, password)
            _read_until_device_prompt(sock, timeout)
        elif phase != "device":
            raise TimeoutError("Prompt inicial Telnet nao reconhecido.")

        _send_line(sock, "enable")
        _read_until_device_prompt(sock, timeout)
        _send_line(sock, "return")
        _read_until_device_prompt(sock, timeout)
        _send_line(sock, "screen-length 0 temporary")
        _read_until_device_prompt(sock, timeout)
        version_output = ""
        try:
            _send_line(sock, "display version")
            version_raw = _read_until_device_prompt(sock, min(25, int(timeout)))
            version_output = _clean_output(version_raw, "display version")
        except Exception:
            version_output = ""
        resolved_profile = resolve_profile(collector_profile, version_output)

        outputs = {}
        detected_commands = {}
        executable = [(filename, command) for filename, command in HUAWEI_TELNET_COMMANDS if command]
        total_commands = len(executable) or 1
        command_timeout = int(command_timeout or timeout)
        command_timeout = max(10, min(command_timeout, int(timeout)))
        completed = 0

        for filename, command in HUAWEI_TELNET_COMMANDS:
            if not command:
                outputs[filename] = ""
                continue
            if progress_callback:
                start_pct = 30 + int((completed / total_commands) * 28)
                progress_callback(start_pct, f"CLI Telnet {completed + 1}/{total_commands}: {command}")
            if filename == "vlan_inventory.txt":
                output, used_command = _collect_vlan_inventory_with_fallback_telnet(
                    sock=sock,
                    base_timeout=max(command_timeout, min(int(timeout), 45)),
                    allow_partial=allow_partial,
                    preferred_commands=_preferred_override_commands(command_overrides, "vlan_inventory"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["vlan_inventory"] = used_command
            elif filename == "ont_summary.txt":
                output, used_command = _collect_ont_summary_with_fallback_telnet(
                    sock=sock,
                    base_timeout=max(command_timeout, min(int(timeout), 45)),
                    allow_partial=allow_partial,
                    resolved_profile=resolved_profile,
                    preferred_commands=_preferred_override_commands(command_overrides, "ont_summary"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["ont_summary"] = used_command
            elif filename == "service_port.txt":
                output, used_command = _collect_service_port_with_fallback_telnet(
                    sock=sock,
                    base_timeout=max(command_timeout, min(int(timeout), 45)),
                    allow_partial=allow_partial,
                    preferred_commands=_preferred_override_commands(command_overrides, "service_port"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["service_port"] = used_command
            else:
                _send_line(sock, command)
                try:
                    raw = _read_until_device_prompt(sock, command_timeout)
                    outputs[filename] = _clean_output(raw, command)
                except TimeoutError:
                    outputs[filename] = ""
                    if not allow_partial:
                        raise
                    _interrupt_to_prompt(sock, 8)
            completed += 1
            if progress_callback:
                end_pct = 30 + int((completed / total_commands) * 28)
                progress_callback(end_pct, f"CLI Telnet {completed}/{total_commands} concluido")

        outputs["_collector_profile_detected"] = resolved_profile
        outputs["_command_overrides_detected"] = detected_commands
        _send_line(sock, "quit")
        return outputs
    finally:
        sock.close()


def run_huawei_commands_over_telnet(
    host,
    username,
    password,
    commands,
    port=23,
    timeout=30,
    command_timeout=None,
):
    if not username:
        raise ValueError("Usuario Telnet da OLT nao informado.")
    if password is None or password == "":
        raise ValueError("Senha Telnet da OLT nao informada.")

    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(0.5)
    try:
        try:
            phase, _ = _wait_for_any_prompt(sock, timeout)
        except TimeoutError:
            _send_line(sock, "")
            phase, _ = _wait_for_any_prompt(sock, timeout)
        if phase == "login":
            _send_line(sock, username)
            phase, _ = _wait_for_any_prompt(sock, timeout)
            if phase == "password":
                _send_line(sock, password)
                _read_until_device_prompt(sock, timeout)
            elif phase != "device":
                raise TimeoutError("Prompt de senha Telnet nao encontrado.")
        elif phase == "password":
            _send_line(sock, password)
            _read_until_device_prompt(sock, timeout)
        elif phase != "device":
            raise TimeoutError("Prompt inicial Telnet nao reconhecido.")

        _send_line(sock, "enable")
        _read_until_device_prompt(sock, timeout)
        _send_line(sock, "return")
        _read_until_device_prompt(sock, timeout)
        _send_line(sock, "screen-length 0 temporary")
        _read_until_device_prompt(sock, timeout)

        command_timeout = int(command_timeout or timeout)
        command_timeout = max(8, min(command_timeout, int(timeout)))
        outputs = []
        for command in commands:
            _send_line(sock, command)
            raw = _read_until_device_prompt(sock, command_timeout)
            # If CLI asks for "<cr>", send Enter to execute the command.
            cr_continuations = 0
            while _looks_like_carriage_return_prompt(raw) and cr_continuations < 2:
                _send_line(sock, "")
                raw = raw + "\n" + _read_until_device_prompt(sock, command_timeout)
                cr_continuations += 1
            # Some Huawei commands ask for y/n confirmation before applying.
            confirmations = 0
            while _looks_like_confirmation_prompt(raw) and confirmations < 2:
                _send_line(sock, "y")
                raw = raw + "\n" + _read_until_device_prompt(sock, command_timeout)
                confirmations += 1
            outputs.append({"command": command, "output": _clean_output(raw, command)})
        _send_line(sock, "quit")
        return outputs
    finally:
        sock.close()


def _send_line(sock, text):
    # Telnet CLIs on Huawei expect CRLF. Using LF-only can collapse tokens.
    sock.sendall((text + "\r\n").encode("utf-8"))


def _wait_for_prompt(sock, prompts, timeout):
    end = time.monotonic() + timeout
    buffer = ""
    normalized_prompts = tuple(item.lower() for item in prompts)
    while time.monotonic() < end:
        chunk = _recv_processed(sock)
        if chunk:
            buffer += chunk
            lower = buffer.lower()
            if any(token in lower for token in normalized_prompts):
                return buffer
        else:
            time.sleep(0.1)
    raise TimeoutError("Timeout aguardando prompt de autenticacao Telnet.")


def _wait_for_any_prompt(sock, timeout):
    end = time.monotonic() + timeout
    buffer = ""
    while time.monotonic() < end:
        chunk = _recv_processed(sock)
        if chunk:
            buffer += chunk
            lower = buffer.lower()
            if "invalid" in lower or "login failed" in lower:
                raise PermissionError("Usuario ou senha Telnet invalidos.")
            if any(token in lower for token in LOGIN_PROMPTS):
                return "login", buffer
            if any(token in lower for token in PASSWORD_PROMPTS):
                return "password", buffer
            normalized = buffer.replace("\r\n", "\n").replace("\r", "\n")
            if PROMPT_PATTERN.search(normalized):
                return "device", buffer
        else:
            time.sleep(0.1)
    raise TimeoutError("Timeout aguardando prompt inicial Telnet.")


def _read_until_device_prompt(sock, timeout):
    end = time.monotonic() + timeout
    chunks = []
    last_data = time.monotonic()
    saw_data = False
    pagination_tail = ""
    while time.monotonic() < end:
        chunk = _recv_processed(sock)
        if chunk:
            chunks.append(chunk)
            last_data = time.monotonic()
            saw_data = True
            merged = "".join(chunks).lower()
            if "invalid" in merged or "login failed" in merged:
                raise PermissionError("Usuario ou senha Telnet invalidos.")
            pagination_tail = (pagination_tail + chunk)[-1200:]
            if MORE_PATTERN.search(pagination_tail):
                sock.sendall(b" ")
                pagination_tail = ""
            continue
        if saw_data:
            current = "".join(chunks).replace("\r\n", "\n").replace("\r", "\n")
            if _looks_like_confirmation_prompt(current) and (time.monotonic() - last_data) >= 0.12:
                return current
            if _looks_like_command_input_prompt(current) and (time.monotonic() - last_data) >= 0.12:
                return current
            if PROMPT_PATTERN.search(current) and (time.monotonic() - last_data) >= 0.25:
                return current
        time.sleep(0.08)
    raise TimeoutError("Timeout aguardando resposta da OLT Huawei via Telnet.")


def _interrupt_to_prompt(sock, timeout):
    try:
        sock.sendall(b"\x03")
    except Exception:
        return
    try:
        _read_until_device_prompt(sock, max(3, int(timeout)))
    except Exception:
        return


def _recv_processed(sock):
    try:
        data = sock.recv(8192)
    except TimeoutError:
        return ""
    except socket.timeout:
        return ""
    if not data:
        return ""
    return _strip_telnet_negotiation(data).decode("utf-8", errors="ignore")


def _strip_telnet_negotiation(data):
    out = bytearray()
    i = 0
    length = len(data)
    while i < length:
        byte = data[i]
        if byte != IAC:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= length:
            break
        cmd = data[i + 1]
        if cmd in (DO, DONT, WILL, WONT):
            i += 3
            continue
        if cmd == SB:
            i += 2
            while i < length - 1:
                if data[i] == IAC and data[i + 1] == SE:
                    i += 2
                    break
                i += 1
            continue
        i += 2
    return bytes(out)


def _clean_output(raw_output, command):
    normalized = raw_output.replace("\r\n", "\n").replace("\r", "\n")
    normalized = ANSI_ESCAPE_PATTERN.sub("", normalized)
    normalized = normalized.replace("\x07", "")
    lines = normalized.splitlines()
    cleaned = []
    for line in lines:
        line = line.replace("\b", "")
        stripped = line.strip()
        if not stripped:
            cleaned.append("")
            continue
        if stripped == command.strip():
            continue
        if stripped.startswith("<") and stripped.endswith(">"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            continue
        if stripped.lower().startswith("screen-length 0 temporary"):
            continue
        if stripped.lower().startswith("quit"):
            continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned).strip()


def _looks_like_confirmation_prompt(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return False
    tail = "\n".join(lines[-4:])
    return bool(CONFIRM_PATTERN.search(tail))


def _looks_like_command_input_prompt(text):
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return False
    tail = "\n".join(lines[-3:])
    return bool(INPUT_PROMPT_PATTERN.search(tail))


def _looks_like_carriage_return_prompt(text):
    tail = "\n".join([line.strip() for line in (text or "").splitlines() if line.strip()][-3:])
    lowered = tail.lower()
    return "<cr>" in lowered and lowered.rstrip().endswith(":")


def _collect_service_port_with_fallback_telnet(sock, base_timeout, allow_partial, preferred_commands=None):
    commands = [
        "display service-port all",
        "display service-port all sort-by vlan",
        "display current-configuration | include service-port",
    ]
    return _run_with_fallback_telnet(
        sock=sock,
        base_timeout=max(int(base_timeout), 120),
        allow_partial=allow_partial,
        commands=commands,
        payload_check=_looks_like_vlan_payload,
        preferred_commands=preferred_commands,
    )


def _collect_ont_summary_with_fallback_telnet(
    sock,
    base_timeout,
    allow_partial,
    resolved_profile="huawei_generic",
    preferred_commands=None,
):
    if any(str(item).strip() == "__snmp_bootstrap__" for item in (preferred_commands or [])):
        return "", None
    commands = ont_summary_commands_for_profile(resolved_profile)
    return _run_with_fallback_telnet(
        sock=sock,
        base_timeout=max(10, min(int(base_timeout or 20), 35)),
        allow_partial=allow_partial,
        commands=commands,
        payload_check=_looks_like_ont_summary_payload,
        preferred_commands=preferred_commands,
    )


def _collect_vlan_inventory_with_fallback_telnet(sock, base_timeout, allow_partial, preferred_commands=None):
    commands = [
        "display current-configuration | include vlan",
    ]
    return _run_with_fallback_telnet(
        sock=sock,
        base_timeout=base_timeout,
        allow_partial=allow_partial,
        commands=commands,
        payload_check=_looks_like_vlan_inventory_payload,
        preferred_commands=preferred_commands,
    )


def _preferred_override_commands(command_overrides, key):
    overrides = command_overrides or {}
    value = str(overrides.get(key) or "").strip()
    if not value:
        return []
    return [value]


def _merge_command_lists(preferred_commands, commands):
    merged = []
    for command in list(preferred_commands or []) + list(commands or []):
        normalized = str(command or "").strip()
        if not normalized or normalized in merged:
            continue
        merged.append(normalized)
    return merged


def _run_with_fallback_telnet(
    sock,
    base_timeout,
    allow_partial,
    commands,
    payload_check,
    preferred_commands=None,
):
    command_list = _merge_command_lists(preferred_commands, commands)
    last_output = ""
    used_command = None
    for command in command_list:
        _sync_device_prompt(sock)
        _send_line(sock, command)
        try:
            raw = _read_until_device_prompt(sock, base_timeout)
            output = _clean_output(raw, command)
        except TimeoutError:
            output = ""
            if not allow_partial:
                raise
            _interrupt_to_prompt(sock, 8)
        if _looks_like_unknown_command(output):
            last_output = output
            _interrupt_to_prompt(sock, 4)
            continue
        if payload_check(output):
            return output, command
        if output.strip():
            last_output = output
            if used_command is None:
                used_command = command
    return last_output, used_command


def _sync_device_prompt(sock, timeout=2):
    try:
        _send_line(sock, "")
        _read_until_device_prompt(sock, max(1, int(timeout)))
    except Exception:
        return


def _looks_like_unknown_command(output):
    lowered = (output or "").lower()
    return (
        "unknown command" in lowered
        or "error locates at '^'" in lowered
        or "unrecognized command" in lowered
    )


def _looks_like_vlan_payload(output):
    text = (output or "").lower()
    return "service-port" in text or "user-vlan" in text or "f/s/p" in text


def _looks_like_vlan_inventory_payload(output):
    text = (output or "").lower()
    return "vlan " in text or "vid" in text


def _looks_like_ont_summary_payload(output):
    text = output or ""
    lowered = text.lower()
    if "the total of ont" in lowered:
        return True
    return bool(
        re.search(
            r"(?m)^\s*\d+\s*/\s*\d+\s*/\s*\d+\s+\d+\s+[A-Z0-9]{8,20}\b",
            text,
        )
    )
