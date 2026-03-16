import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.collectors.huawei_cli import parse_huawei_cli_snapshot
from backend.collectors.huawei_ssh import collect_huawei_cli_files_over_ssh, save_cli_files


EXPECTED_FILES = [
    "olt.txt",
    "board.txt",
    "ont_summary.txt",
    "traffic.txt",
    "optical.txt",
    "vlan_inventory.txt",
    "service_port.txt",
    "autofind.txt",
]


def main():
    parser = argparse.ArgumentParser(
        description="Converte saidas CLI Huawei em payload normalizado para o ConectaOLT."
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--input-dir",
        help="Diretorio com os arquivos de saida CLI.",
    )
    source_group.add_argument(
        "--host",
        help="Host ou IP da OLT Huawei para coleta via SSH.",
    )
    parser.add_argument("--username", help="Usuario SSH.")
    parser.add_argument("--port", type=int, default=22, help="Porta SSH.")
    parser.add_argument("--key-path", default=None, help="Chave privada SSH.")
    parser.add_argument("--ssh-binary", default="ssh", help="Binario do cliente SSH.")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout de cada sessao SSH.")
    parser.add_argument(
        "--save-dir",
        default=None,
        help="Diretorio opcional para salvar os arquivos CLI coletados via SSH.",
    )
    parser.add_argument(
        "--collected-at",
        default=None,
        help="Timestamp ISO opcional para fixar o momento da coleta.",
    )
    args = parser.parse_args()

    if args.input_dir:
        input_dir = Path(args.input_dir)
        if not input_dir.exists():
            raise SystemExit(f"Diretorio nao encontrado: {input_dir}")
        files = {}
        for filename in EXPECTED_FILES:
            file_path = input_dir / filename
            if file_path.exists():
                files[filename] = file_path.read_text(encoding="utf-8")
            else:
                files[filename] = ""
    else:
        if not args.username:
            raise SystemExit("--username e obrigatorio quando --host for usado.")
        files = collect_huawei_cli_files_over_ssh(
            host=args.host,
            username=args.username,
            port=args.port,
            key_path=args.key_path,
            timeout=args.timeout,
            ssh_binary=args.ssh_binary,
        )
        if args.save_dir:
            save_cli_files(args.save_dir, files)

    payload = parse_huawei_cli_snapshot(files)
    if args.collected_at:
        payload["collected_at"] = args.collected_at
    print(json.dumps(payload, ensure_ascii=True))


if __name__ == "__main__":
    main()
