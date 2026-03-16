import subprocess
from pathlib import Path


HUAWEI_COMMANDS = [
    ("olt.txt", "display device"),
    ("board.txt", "display board 0"),
    ("ont_summary.txt", "display ont info summary 0 all"),
    ("traffic.txt", "display ont traffic 0 all"),
    ("optical.txt", "display ont optical-info 0 all"),
    ("vlan_inventory.txt", "display current-configuration | include vlan"),
    ("service_port.txt", "display service-port all"),
    ("autofind.txt", "display ont autofind all"),
]


def collect_huawei_cli_files_over_ssh(
    host,
    username,
    port=22,
    key_path=None,
    timeout=30,
    ssh_binary="ssh",
    accept_new_hostkey=True,
):
    commands = [command for _, command in HUAWEI_COMMANDS]
    transcript = _run_interactive_ssh(
        host=host,
        username=username,
        port=port,
        key_path=key_path,
        timeout=timeout,
        ssh_binary=ssh_binary,
        accept_new_hostkey=accept_new_hostkey,
        commands=commands,
    )
    outputs = extract_command_blocks(transcript, commands)
    service_port = outputs.get("display service-port all", "")
    if not _looks_like_vlan_payload(service_port):
        fallback_commands = [
            "display service-port all sort-by vlan",
            "display current-configuration | include service-port",
        ]
        fallback_transcript = _run_interactive_ssh(
            host=host,
            username=username,
            port=port,
            key_path=key_path,
            timeout=max(timeout, 90),
            ssh_binary=ssh_binary,
            accept_new_hostkey=accept_new_hostkey,
            commands=fallback_commands,
        )
        fallback_outputs = extract_command_blocks(fallback_transcript, fallback_commands)
        for command in fallback_commands:
            candidate = fallback_outputs.get(command, "")
            if _looks_like_vlan_payload(candidate):
                outputs["display service-port all"] = candidate
                break
    return {
        filename: outputs.get(command, "")
        for filename, command in HUAWEI_COMMANDS
    }


def save_cli_files(output_dir, files):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (output_dir / filename).write_text(content, encoding="utf-8")


def extract_command_blocks(transcript, commands):
    normalized = transcript.replace("\r\n", "\n")
    segments = {}
    positions = []
    cursor = 0
    for command in commands:
        index = normalized.find(command, cursor)
        if index == -1:
            segments[command] = ""
            continue
        positions.append((command, index))
        cursor = index + len(command)

    for idx, (command, index) in enumerate(positions):
        start = normalized.find("\n", index)
        if start == -1:
            start = index + len(command)
        else:
            start += 1
        if idx + 1 < len(positions):
            end = positions[idx + 1][1]
        else:
            quit_index = normalized.find("quit", start)
            end = quit_index if quit_index != -1 else len(normalized)
        raw_block = normalized[start:end].strip()
        cleaned_lines = []
        for line in raw_block.splitlines():
            stripped = line.strip()
            if stripped.startswith("<") and stripped.endswith(">"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                continue
            cleaned_lines.append(line)
        segments[command] = "\n".join(cleaned_lines).strip()
    return segments


def _run_interactive_ssh(
    host,
    username,
    port,
    key_path,
    timeout,
    ssh_binary,
    accept_new_hostkey,
    commands,
):
    ssh_args = [
        ssh_binary,
        "-tt",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
    ]
    if accept_new_hostkey:
        ssh_args.extend(["-o", "StrictHostKeyChecking=accept-new"])
    if key_path:
        ssh_args.extend(["-i", str(key_path)])
    ssh_args.append(f"{username}@{host}")

    session_input = "\n".join(["screen-length 0 temporary", *commands, "quit"]) + "\n"
    completed = subprocess.run(
        ssh_args,
        input=session_input,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    transcript = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    if completed.returncode != 0:
        raise RuntimeError(transcript.strip() or f"ssh retornou codigo {completed.returncode}")
    return transcript


def _looks_like_vlan_payload(output):
    text = (output or "").lower()
    if "unknown command" in text or "error locates at '^'" in text:
        return False
    return "service-port" in text or "user-vlan" in text or "f/s/p" in text
