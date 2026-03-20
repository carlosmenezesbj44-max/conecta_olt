import sys
import traceback
from io import BytesIO


PROJECT_PATH = "/home/carlosviptelecom/conecta_olt"
if PROJECT_PATH not in sys.path:
    sys.path.insert(0, PROJECT_PATH)

from backend import db
from backend.server import AppHandler


db.init_db()


def _build_headers(environ):
    headers = {}
    for key, value in environ.items():
        if not key.startswith("HTTP_"):
            continue
        header_name = key[5:].replace("_", "-").title()
        headers[header_name] = value
    if environ.get("CONTENT_TYPE"):
        headers["Content-Type"] = environ["CONTENT_TYPE"]
    if environ.get("CONTENT_LENGTH"):
        headers["Content-Length"] = environ["CONTENT_LENGTH"]
    return headers


def _build_handler(environ):
    handler = AppHandler.__new__(AppHandler)
    handler.rfile = environ["wsgi.input"]
    handler.wfile = BytesIO()
    handler.headers = _build_headers(environ)
    handler.command = str(environ.get("REQUEST_METHOD") or "GET").upper()
    handler.path = environ.get("PATH_INFO") or "/"
    if environ.get("QUERY_STRING"):
        handler.path += "?" + environ["QUERY_STRING"]
    handler.request_version = environ.get("SERVER_PROTOCOL") or "HTTP/1.1"
    handler.requestline = f"{handler.command} {handler.path} {handler.request_version}"
    handler.client_address = ((environ.get("REMOTE_ADDR") or "127.0.0.1"), 0)
    handler.server = None
    handler.connection = None
    handler.request = None
    handler.close_connection = True
    handler._headers_buffer = []
    return handler


def _extract_response(raw_response):
    if not raw_response:
        return "204 No Content", [], b""

    header_end = raw_response.find(b"\r\n\r\n")
    if header_end == -1:
        return "200 OK", [("Content-Type", "application/octet-stream")], raw_response

    header_block = raw_response[:header_end].decode("iso-8859-1")
    body = raw_response[header_end + 4 :]
    header_lines = header_block.split("\r\n")
    status = "200 OK"
    if header_lines and " " in header_lines[0]:
        status = header_lines[0].split(" ", 1)[1]

    headers = []
    for line in header_lines[1:]:
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        headers.append((key, value))
    return status, headers, body


def application(environ, start_response):
    try:
        handler = _build_handler(environ)
        method_name = f"do_{handler.command}"
        if not hasattr(handler, method_name):
            start_response("501 Not Implemented", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Method not implemented"]

        getattr(handler, method_name)()
        status, headers, body = _extract_response(handler.wfile.getvalue())
        start_response(status, headers)
        return [body]
    except Exception:
        error_stream = environ.get("wsgi.errors")
        if error_stream is not None:
            error_stream.write(traceback.format_exc())
            error_stream.flush()
        body = b'{"error":"internal server error"}'
        start_response(
            "500 Internal Server Error",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]
