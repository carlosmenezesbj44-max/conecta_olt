import os

from backend.server import run


def _read_int_env(name, default):
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError as error:
        raise SystemExit(f"Variavel {name} invalida: {raw!r}") from error


if __name__ == "__main__":
    host = (os.getenv("HOST") or "127.0.0.1").strip() or "127.0.0.1"
    port = _read_int_env("PORT", 8080)
    fallback_port = _read_int_env("FALLBACK_PORT", 8180)

    try:
        run(host=host, port=port)
    except PermissionError as error:
        if getattr(error, "winerror", None) == 10013 and port == 8080 and fallback_port != port:
            print(
                f"Porta {port} indisponivel (WinError 10013). "
                f"Iniciando em {fallback_port}.",
                flush=True,
            )
            run(host=host, port=fallback_port)
        else:
            raise
