import json
import mimetypes
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend import connectivity
from backend import db
from backend.collectors import service as collector_service
from backend.poller import PollingScheduler
from backend.vendors import get_vendor_catalog


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


class AppHandler(BaseHTTPRequestHandler):
    @staticmethod
    def _is_client_disconnect(error):
        return isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError))

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/api/vendors":
            self._send_json(get_vendor_catalog())
            return
        if parsed.path == "/api/dashboard":
            self._send_json(db.fetch_dashboard())
            return
        if parsed.path == "/api/olts":
            self._send_json(db.fetch_olts())
            return
        if parsed.path == "/api/onus":
            self._send_json(db.fetch_onus())
            return
        if parsed.path == "/api/profiles":
            self._send_json(db.fetch_profiles())
            return
        if parsed.path == "/api/authorization-requests":
            self._send_json(db.fetch_authorization_requests())
            return
        if parsed.path == "/api/connections":
            self._send_json(db.fetch_connections())
            return
        if parsed.path == "/api/connection-templates":
            self._send_json(db.fetch_connection_templates())
            return
        if parsed.path == "/api/history/dashboard":
            limit = int(query.get("limit", ["12"])[0])
            self._send_json(db.fetch_history_dashboard(limit))
            return
        if parsed.path == "/api/events":
            limit = int(query.get("limit", ["20"])[0])
            self._send_json(db.fetch_events(limit))
            return
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "poll-progress":
            self._send_json(collector_service.get_poll_progress(int(parts[2])))
            return
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "vlans":
            try:
                self._send_json(db.fetch_olt_vlans(int(parts[2])))
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "profiles":
            try:
                self._send_json(db.fetch_olt_profiles(int(parts[2])))
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(parts) == 4 and parts[:2] == ["api", "onus"] and parts[3] == "history":
            try:
                self._send_json(db.fetch_onu_history(int(parts[2])))
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(parts) == 4 and parts[:2] == ["api", "onus"] and parts[3] == "delete-progress":
            self._send_json(collector_service.get_onu_delete_progress(int(parts[2])))
            return
        if len(parts) == 4 and parts[:2] == ["api", "authorization-requests"] and parts[3] == "progress":
            self._send_json(collector_service.get_request_authorize_progress(int(parts[2])))
            return
        self._serve_static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/sync":
            self._send_json(collector_service.poll_all())
            return

        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 4 and parts[:2] == ["api", "onus"] and parts[3] == "collect":
            payload = self._read_json()
            fields = payload.get("fields") if isinstance(payload, dict) else None
            try:
                self._send_json(collector_service.collect_onu_live(int(parts[2]), fields=fields))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 4 and parts[:2] == ["api", "onus"] and parts[3] == "delete":
            payload = self._read_json()
            live_flag = True if not isinstance(payload, dict) else bool(payload.get("live", True))
            try:
                result = collector_service.start_onu_delete(int(parts[2]), live=live_flag)
                status = HTTPStatus.ACCEPTED if result.get("status") in {"started", "running"} else HTTPStatus.BAD_REQUEST
                self._send_json(result, status=status)
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if parts == ["api", "authorization-requests", "autofind-all"]:
            try:
                self._send_json(collector_service.run_autofind_all())
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if parts == ["api", "authorization-requests", "sync-olt-profiles"]:
            try:
                self._send_json(collector_service.run_olt_profile_sync_all())
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 5 and parts[:2] == ["api", "onus"] and parts[3] == "actions":
            try:
                self._send_json(collector_service.run_onu_action(int(parts[2]), parts[4]))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 4 and parts[:2] == ["api", "authorization-requests"]:
            request_id = int(parts[2])
            payload = self._read_json()
            try:
                if parts[3] == "preview":
                    self._send_json(collector_service.build_request_provisioning_preview(request_id, payload))
                    return
                if parts[3] == "authorize":
                    result = collector_service.start_request_authorization(request_id, payload)
                    status = HTTPStatus.ACCEPTED if result.get("status") in {"started", "running"} else HTTPStatus.BAD_REQUEST
                    self._send_json(result, status=status)
                    return
                if parts[3] == "move":
                    self._send_json(db.move_request(request_id, payload))
                    return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if parts == ["api", "olts"]:
            try:
                self._send_json(db.create_olt(self._read_json()))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 3 and parts[:2] == ["api", "connections"]:
            try:
                self._send_json(db.save_connection(int(parts[2]), self._read_json()))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 4 and parts[:2] == ["api", "connections"] and parts[3] == "apply-template":
            try:
                payload = self._read_json()
                overwrite = True if not isinstance(payload, dict) else bool(payload.get("overwrite", True))
                self._send_json(db.apply_connection_template(int(parts[2]), overwrite=overwrite))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if parts == ["api", "connection-templates"]:
            try:
                self._send_json(db.save_connection_template(self._read_json()))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "connect-test":
            try:
                result = connectivity.test_olt_connection(int(parts[2]))
                status = HTTPStatus.OK if result.get("status") == "connected" else HTTPStatus.BAD_REQUEST
                self._send_json(result, status=status)
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "poll":
            payload = self._read_json()
            force_full_inventory = False
            if isinstance(payload, dict):
                force_full_inventory = bool(payload.get("force_full_inventory", False))
            result = collector_service.start_poll_olt(
                int(parts[2]),
                force_full_inventory=force_full_inventory,
            )
            status = HTTPStatus.ACCEPTED if result.get("status") in {"started", "running"} else HTTPStatus.BAD_REQUEST
            self._send_json(result, status=status)
            return
        if len(parts) == 4 and parts[:2] == ["api", "olts"] and parts[3] == "vlans":
            try:
                self._send_json(db.save_olt_vlan(int(parts[2]), self._read_json()))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return

        self._send_json({"error": "Rota nao encontrada."}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "olts"]:
            try:
                self._send_json(db.delete_olt(int(parts[2])))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 3 and parts[:2] == ["api", "onus"]:
            try:
                onu_id = int(parts[2])
                live_flag = str(query.get("live", ["1"])[0]).strip().lower() not in {"0", "false", "no", "off"}
                self._send_json(collector_service.delete_onu(onu_id, live=live_flag))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 5 and parts[:2] == ["api", "olts"] and parts[3] == "vlans":
            try:
                self._send_json(db.delete_olt_vlan(int(parts[2]), int(parts[4])))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        if len(parts) == 3 and parts[:2] == ["api", "connection-templates"]:
            try:
                self._send_json(db.delete_connection_template(int(parts[2])))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        self._send_json({"error": "Rota nao encontrada."}, status=HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "olts"]:
            try:
                self._send_json(db.update_olt(int(parts[2]), self._read_json()))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
        self._send_json({"error": "Rota nao encontrada."}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, fmt, *args):
        return

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def _send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError as error:
            if not self._is_client_disconnect(error):
                raise

    def _serve_static(self, route_path):
        path = "index.html" if route_path in {"", "/"} else route_path.lstrip("/")
        file_path = (STATIC_DIR / path).resolve()
        if STATIC_DIR not in file_path.parents and file_path != STATIC_DIR / "index.html":
            self._send_json({"error": "Arquivo invalido."}, status=HTTPStatus.BAD_REQUEST)
            return
        if not file_path.exists() or file_path.is_dir():
            file_path = STATIC_DIR / "index.html"

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        content = file_path.read_bytes()
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except OSError as error:
            if not self._is_client_disconnect(error):
                raise


def run(host="127.0.0.1", port=8080):
    db.init_db()
    scheduler = PollingScheduler()
    scheduler.start()
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"ConectaOLT rodando em http://{host}:{port}")
    server.serve_forever()
