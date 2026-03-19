import json
import mimetypes
from http import HTTPStatus
from http.cookies import SimpleCookie
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
SESSION_COOKIE_NAME = "conectaolt_session"


class AppHandler(BaseHTTPRequestHandler):
    @staticmethod
    def _is_client_disconnect(error):
        return isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError))

    def _route_parts(self, route_path=None):
        path = route_path if route_path is not None else urlparse(self.path).path
        return [part for part in path.strip("/").split("/") if part]

    def _request_permission(self, method, parts):
        if not parts or parts[0] != "api":
            return None
        safe_method = str(method or "GET").upper()
        is_read = safe_method == "GET"
        if len(parts) >= 2 and parts[1] == "users":
            return "users_view" if is_read else "users_manage"
        if len(parts) >= 2 and parts[1] in {"dashboard", "history", "vendors"}:
            return "dashboard_view"
        if len(parts) >= 2 and parts[1] == "olts":
            if len(parts) >= 4 and parts[3] == "profiles":
                return "requests_view" if is_read else "requests_manage"
            if len(parts) >= 4 and parts[3] in {"poll", "poll-progress", "connect-test"}:
                return "collection_view" if is_read else "collection_manage"
            return "olts_view" if is_read else "olts_manage"
        if len(parts) >= 2 and parts[1] in {"onus"}:
            return "onus_view" if is_read else "onus_manage"
        if len(parts) >= 2 and parts[1] == "authorization-requests":
            if len(parts) >= 4 and parts[3] == "preview":
                return "requests_view"
            return "requests_view" if is_read else "requests_manage"
        if len(parts) >= 2 and parts[1] == "profiles":
            return "requests_view" if is_read else "requests_manage"
        if len(parts) >= 2 and parts[1] in {"connections", "connection-templates", "events", "sync"}:
            return "collection_view" if is_read else "collection_manage"
        return None

    def _is_public_api_route(self, method, parts):
        if not parts or parts[0] != "api":
            return False
        if parts == ["api", "health"]:
            return True
        if len(parts) >= 2 and parts[1] == "auth":
            if method == "GET" and parts == ["api", "auth", "session"]:
                return True
            if method == "POST" and parts in (["api", "auth", "login"], ["api", "auth", "bootstrap"]):
                return True
        return False

    def _session_cookie_header(self, token):
        return (
            f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={db.SESSION_DURATION_SEC}"
        )

    def _clear_session_cookie_header(self):
        return (
            f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; "
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0"
        )

    def _read_cookie_value(self, name):
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        jar = SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _client_ip(self):
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
        return self.client_address[0] if self.client_address else None

    def _user_agent(self):
        return (self.headers.get("User-Agent") or "").strip() or None

    def _auth_context(self):
        cached = getattr(self, "_cached_auth_context", None)
        if cached is not None:
            return cached
        token = self._read_cookie_value(SESSION_COOKIE_NAME)
        context = db.fetch_auth_session(token)
        self._cached_auth_context = context
        return context

    def _require_auth(self, permission=None):
        context = self._auth_context()
        if not context.get("authenticated"):
            self._send_json(
                {
                    "error": "Nao autenticado.",
                    "authenticated": False,
                    "bootstrap_required": context.get("bootstrap_required", False),
                },
                status=HTTPStatus.UNAUTHORIZED,
            )
            return None
        if permission and not db.has_permission(context, permission):
            self._send_json({"error": "Sem permissao para esta acao."}, status=HTTPStatus.FORBIDDEN)
            return None
        return context

    def _authorize_api_request(self, method, parsed_path):
        if not parsed_path.startswith("/api/"):
            return True
        parts = self._route_parts(parsed_path)
        if self._is_public_api_route(method, parts):
            return True
        if parts == ["api", "auth", "logout"]:
            return self._require_auth() is not None
        permission = self._request_permission(method, parts)
        return self._require_auth(permission=permission) is not None

    def do_GET(self):
        parsed = urlparse(self.path)
        if not self._authorize_api_request("GET", parsed.path):
            return
        query = parse_qs(parsed.query)
        if parsed.path == "/api/auth/session":
            self._send_json(db.fetch_auth_session(self._read_cookie_value(SESSION_COOKIE_NAME)))
            return
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if parsed.path == "/api/users":
            self._send_json(
                {
                    "items": db.fetch_users(),
                    "permission_catalog": db.get_permission_catalog(),
                }
            )
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
        if not self._authorize_api_request("POST", parsed.path):
            return
        if parsed.path == "/api/auth/login":
            payload = self._read_json()
            try:
                result = db.authenticate_user(
                    payload.get("username"),
                    payload.get("password"),
                    ip_address=self._client_ip(),
                    user_agent=self._user_agent(),
                )
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.UNAUTHORIZED)
                return
            token = result.pop("token")
            self._send_json(
                result,
                extra_headers=[("Set-Cookie", self._session_cookie_header(token))],
            )
            return
        if parsed.path == "/api/auth/bootstrap":
            payload = self._read_json()
            try:
                result = db.bootstrap_admin_user(
                    payload,
                    ip_address=self._client_ip(),
                    user_agent=self._user_agent(),
                )
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            token = result.pop("token")
            self._send_json(
                result,
                status=HTTPStatus.CREATED,
                extra_headers=[("Set-Cookie", self._session_cookie_header(token))],
            )
            return
        if parsed.path == "/api/auth/logout":
            db.logout_session(self._read_cookie_value(SESSION_COOKIE_NAME))
            self._send_json(
                {"status": "ok"},
                extra_headers=[("Set-Cookie", self._clear_session_cookie_header())],
            )
            return
        if parsed.path == "/api/sync":
            self._send_json(collector_service.poll_all())
            return

        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if parts == ["api", "users"]:
            payload = self._read_json()
            actor = (self._auth_context().get("user") or {}).get("id")
            try:
                self._send_json(
                    {
                        "item": db.create_user(payload, actor_user_id=actor),
                        "permission_catalog": db.get_permission_catalog(),
                    },
                    status=HTTPStatus.CREATED,
                )
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
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
        if not self._authorize_api_request("DELETE", parsed.path):
            return
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            actor = (self._auth_context().get("user") or {}).get("id")
            try:
                self._send_json(db.delete_user(int(parts[2]), actor_user_id=actor))
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
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
        if not self._authorize_api_request("PUT", parsed.path):
            return
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            actor = (self._auth_context().get("user") or {}).get("id")
            try:
                self._send_json(
                    {
                        "item": db.update_user(int(parts[2]), self._read_json(), actor_user_id=actor),
                        "permission_catalog": db.get_permission_catalog(),
                    }
                )
                return
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
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
        try:
            return json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}

    def _send_json(self, payload, status=HTTPStatus.OK, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for header_name, header_value in (extra_headers or []):
                self.send_header(header_name, header_value)
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
