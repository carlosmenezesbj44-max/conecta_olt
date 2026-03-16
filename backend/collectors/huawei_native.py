import re
import time

import paramiko

from backend.collectors.huawei_profiles import ont_summary_commands_for_profile, resolve_profile
from backend.collectors.huawei_ssh import HUAWEI_COMMANDS


PROMPT_PATTERN = re.compile(r"(<[^>\n]+>|\[[^\]\n]+\]|[A-Za-z0-9._()-]+[>#])\s*$")
CONFIRM_PATTERN = re.compile(r"(?i)(are you sure|continue\?|[(\[]\s*(?:y/n|yes/no)\s*[)\]])")
INPUT_PROMPT_PATTERN = re.compile(r"(?is)\{[^{}\n]{1,300}\}:\s*$")


def collect_huawei_cli_files_native(
    host,
    username,
    password=None,
    port=22,
    timeout=30,
    key_path=None,
    collector_profile="auto",
    command_overrides=None,
):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_args = {
        "hostname": host,
        "port": int(port),
        "username": username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "look_for_keys": not password and not key_path,
        "allow_agent": not password and not key_path,
    }
    if password:
        connect_args["password"] = password
    if key_path:
        connect_args["key_filename"] = key_path

    try:
        client.connect(**connect_args)
        channel = client.invoke_shell(width=200, height=2000)
        channel.settimeout(1.0)
        _read_until_prompt(channel, timeout)
        _run_command(channel, "screen-length 0 temporary", timeout)
        try:
            version_output = _run_command(channel, "display version", min(25, int(timeout)))
        except Exception:
            version_output = ""
        resolved_profile = resolve_profile(collector_profile, version_output)
        outputs = {}
        detected_commands = {}
        for filename, command in HUAWEI_COMMANDS:
            if filename == "vlan_inventory.txt":
                output, used_command = _collect_vlan_inventory_with_fallback(
                    channel,
                    timeout,
                    preferred_commands=_preferred_override_commands(command_overrides, "vlan_inventory"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["vlan_inventory"] = used_command
                continue
            if filename == "ont_summary.txt":
                output, used_command = _collect_ont_summary_with_fallback(
                    channel,
                    timeout,
                    resolved_profile=resolved_profile,
                    preferred_commands=_preferred_override_commands(command_overrides, "ont_summary"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["ont_summary"] = used_command
                continue
            if filename == "service_port.txt":
                output, used_command = _collect_service_port_with_fallback(
                    channel,
                    timeout,
                    preferred_commands=_preferred_override_commands(command_overrides, "service_port"),
                )
                outputs[filename] = output
                if used_command:
                    detected_commands["service_port"] = used_command
                continue
            outputs[filename] = _run_command(channel, command, timeout)
        outputs["_collector_profile_detected"] = resolved_profile
        outputs["_command_overrides_detected"] = detected_commands
        channel.send("quit\n")
        time.sleep(0.2)
        channel.close()
        return outputs
    finally:
        client.close()


def run_huawei_commands_native(
    host,
    username,
    commands,
    password=None,
    port=22,
    timeout=30,
    key_path=None,
):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_args = {
        "hostname": host,
        "port": int(port),
        "username": username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "look_for_keys": not password and not key_path,
        "allow_agent": not password and not key_path,
    }
    if password:
        connect_args["password"] = password
    if key_path:
        connect_args["key_filename"] = key_path

    try:
        client.connect(**connect_args)
        channel = client.invoke_shell(width=200, height=2000)
        channel.settimeout(1.0)
        _read_until_prompt(channel, timeout)
        outputs = []
        for command in commands:
            raw_output = _run_command(channel, command, timeout)
            # If CLI asks for "<cr>", send Enter to execute the command.
            cr_continuations = 0
            while _looks_like_carriage_return_prompt(raw_output) and cr_continuations < 2:
                channel.send("\n")
                raw_output = raw_output + "\n" + _read_until_prompt(channel, timeout)
                cr_continuations += 1
            outputs.append(
                {
                    "command": command,
                    "output": _clean_output(raw_output, command),
                }
            )
        channel.send("quit\n")
        time.sleep(0.2)
        channel.close()
        return outputs
    finally:
        client.close()


def _run_command(channel, command, timeout):
    while channel.recv_ready():
        channel.recv(4096)
    channel.send(command + "\n")
    raw_output = _read_until_prompt(channel, timeout)
    # Some destructive Huawei commands require a y/n confirmation.
    # Auto-confirm to keep command execution non-interactive.
    confirmations = 0
    while _looks_like_confirmation_prompt(raw_output) and confirmations < 2:
        channel.send("y\n")
        raw_output = raw_output + "\n" + _read_until_prompt(channel, timeout)
        confirmations += 1
    return _clean_output(raw_output, command)


def _read_until_prompt(channel, timeout):
    chunks = []
    start = time.monotonic()
    last_data_at = start
    saw_data = False
    while time.monotonic() - start < timeout:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="ignore")
            chunks.append(chunk)
            last_data_at = time.monotonic()
            saw_data = True
            continue
        if saw_data:
            current = "".join(chunks).replace("\r\n", "\n").replace("\r", "\n")
            if _looks_like_confirmation_prompt(current) and (time.monotonic() - last_data_at) >= 0.15:
                return current
            if _looks_like_command_input_prompt(current) and (time.monotonic() - last_data_at) >= 0.15:
                return current
            if PROMPT_PATTERN.search(current) and (time.monotonic() - last_data_at) >= 0.3:
                return current
        time.sleep(0.1)
    raise TimeoutError("Timeout aguardando resposta da OLT Huawei.")


def _clean_output(raw_output, command):
    lines = raw_output.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    cleaned = []
    for line in lines:
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


def _collect_service_port_with_fallback(channel, timeout, preferred_commands=None):
    commands = [
        "display current-configuration | include service-port",
        "display service-port all",
        "display service-port all sort-by vlan",
    ]
    return _run_with_fallback(
        channel=channel,
        timeout=max(timeout, 45),
        commands=commands,
        payload_check=_looks_like_vlan_payload,
        preferred_commands=preferred_commands,
    )


def _collect_ont_summary_with_fallback(
    channel,
    timeout,
    resolved_profile="huawei_generic",
    preferred_commands=None,
):
    if any(str(item).strip() == "__snmp_bootstrap__" for item in (preferred_commands or [])):
        return "", None
    commands = ont_summary_commands_for_profile(resolved_profile)
    return _run_with_fallback(
        channel=channel,
        timeout=max(12, min(int(timeout or 20), 35)),
        commands=commands,
        payload_check=_looks_like_ont_summary_payload,
        preferred_commands=preferred_commands,
    )


def _collect_vlan_inventory_with_fallback(channel, timeout, preferred_commands=None):
    commands = [
        "display current-configuration | include vlan",
    ]
    return _run_with_fallback(
        channel=channel,
        timeout=max(timeout, 45),
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


def _run_with_fallback(channel, timeout, commands, payload_check, preferred_commands=None):
    command_list = _merge_command_lists(preferred_commands, commands)
    last_output = ""
    used_command = None
    for command in command_list:
        try:
            output = _run_command(channel, command, timeout)
        except Exception:
            continue
        if _looks_like_unknown_command(output):
            last_output = output
            continue
        if payload_check(output):
            return output, command
        if output.strip():
            last_output = output
            if used_command is None:
                used_command = command
    return last_output, used_command


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
