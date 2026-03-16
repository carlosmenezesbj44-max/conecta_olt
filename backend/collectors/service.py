import json
import math
import random
import re
import shlex
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from backend import db
from backend.collectors.base import BaseCollector, CollectorError
from backend.collectors.huawei_cli import parse_autofind, parse_huawei_cli_snapshot, parse_profile_summary, parse_traffic
from backend.collectors.huawei_native import collect_huawei_cli_files_native, run_huawei_commands_native
from backend.collectors.huawei_telnet import collect_huawei_cli_files_over_telnet, run_huawei_commands_over_telnet
from backend import snmp_client


POLL_LOCK = threading.Lock()
POLL_PROGRESS_LOCK = threading.Lock()
POLL_PROGRESS = {}
ASYNC_POLL_LOCK = threading.Lock()
ASYNC_POLL_THREADS = {}
ONU_DELETE_PROGRESS_LOCK = threading.Lock()
ONU_DELETE_PROGRESS = {}
ASYNC_ONU_DELETE_LOCK = threading.Lock()
ASYNC_ONU_DELETE_THREADS = {}
REQUEST_AUTHORIZE_PROGRESS_LOCK = threading.Lock()
REQUEST_AUTHORIZE_PROGRESS = {}
ASYNC_REQUEST_AUTHORIZE_LOCK = threading.Lock()
ASYNC_REQUEST_AUTHORIZE_THREADS = {}
SNMP_INDEX_CACHE_LOCK = threading.Lock()
SNMP_INDEX_CACHE = {}
IFINDEX_CACHE_LOCK = threading.Lock()
IFINDEX_CACHE = {}
TRAFFIC_COUNTER_CACHE_LOCK = threading.Lock()
TRAFFIC_COUNTER_CACHE = {}


def _set_poll_progress(olt_id, progress_pct, stage, status="running", details=None, coverage=None):
    with POLL_PROGRESS_LOCK:
        payload = {
            "olt_id": int(olt_id),
            "status": status,
            "progress_pct": max(0, min(100, int(progress_pct))),
            "stage": stage or "",
            "details": details or "",
            "updated_at": db.utc_now(),
        }
        if coverage is not None:
            payload["coverage"] = coverage
        POLL_PROGRESS[int(olt_id)] = payload


def get_poll_progress(olt_id):
    with POLL_PROGRESS_LOCK:
        item = POLL_PROGRESS.get(int(olt_id))
    if item:
        return item
    return {
        "olt_id": int(olt_id),
        "status": "idle",
        "progress_pct": 0,
        "stage": "Aguardando coleta",
        "details": "",
        "updated_at": db.utc_now(),
    }


def _extract_poll_coverage(events):
    best = None
    for event in events or []:
        if not isinstance(event, dict):
            continue
        details = event.get("details") or {}
        if not isinstance(details, dict):
            continue
        touched = details.get("onus_touched")
        total = details.get("onus_total")
        ratio = details.get("coverage_ratio")
        try:
            if ratio is None and touched is not None and total not in (None, 0, "0"):
                ratio = float(touched) / float(total)
            ratio_value = None if ratio is None else round(float(ratio), 3)
        except Exception:
            ratio_value = None
        if ratio_value is None and touched is None and total is None:
            continue
        summary = {
            "mode": str(details.get("mode") or "").strip(),
            "ratio": ratio_value,
            "onus_touched": int(touched) if touched is not None else None,
            "onus_total": int(total) if total is not None else None,
            "stale_onus": int(details.get("stale_onus")) if details.get("stale_onus") is not None else None,
            "message": str(event.get("message") or "").strip(),
            "level": str(event.get("level") or "info").strip().lower() or "info",
        }
        if best is None:
            best = summary
            continue
        if summary["level"] == "warning" and best.get("level") != "warning":
            best = summary
            continue
        best_ratio = best.get("ratio")
        current_ratio = summary.get("ratio")
        if current_ratio is not None and (best_ratio is None or current_ratio < best_ratio):
            best = summary
    return best


def _format_poll_coverage_details(coverage):
    if not coverage:
        return ""
    parts = []
    ratio = coverage.get("ratio")
    if ratio is not None:
        parts.append(f"Cobertura ONU {round(float(ratio) * 100)}%")
    touched = coverage.get("onus_touched")
    total = coverage.get("onus_total")
    if touched is not None and total is not None:
        parts.append(f"{int(touched)}/{int(total)} ONUs")
    stale_onus = coverage.get("stale_onus")
    if stale_onus:
        parts.append(f"{int(stale_onus)} ajustadas para warning")
    return " | ".join(parts)


def _set_onu_delete_progress(onu_id, progress_pct, stage, status="running", details=None, steps=None):
    with ONU_DELETE_PROGRESS_LOCK:
        current = ONU_DELETE_PROGRESS.get(int(onu_id)) or {}
        ONU_DELETE_PROGRESS[int(onu_id)] = {
            "onu_id": int(onu_id),
            "status": status,
            "progress_pct": max(0, min(100, int(progress_pct))),
            "stage": stage or "",
            "details": details or "",
            "steps": list(steps if steps is not None else current.get("steps") or []),
            "updated_at": db.utc_now(),
        }


def get_onu_delete_progress(onu_id):
    with ONU_DELETE_PROGRESS_LOCK:
        item = ONU_DELETE_PROGRESS.get(int(onu_id))
    if item:
        return item
    return {
        "onu_id": int(onu_id),
        "status": "idle",
        "progress_pct": 0,
        "stage": "Aguardando exclusao",
        "details": "",
        "steps": [],
        "updated_at": db.utc_now(),
    }


def _build_onu_delete_steps(active_key=None, failed_key=None, error_message=None, live=True):
    labels = (
        [
            ("lookup", "Localizando ONU na OLT"),
            ("service_port_lookup", "Localizando service-port"),
            ("service_port_delete", "Excluindo service-port"),
            ("onu_delete", "Excluindo ONU na OLT"),
            ("local_delete", "Removendo cadastro local"),
            ("done", "ONU excluida com sucesso"),
        ]
        if live
        else [
            ("local_delete", "Removendo cadastro local"),
            ("done", "ONU excluida com sucesso"),
        ]
    )
    index_by_key = {key: idx for idx, (key, _) in enumerate(labels)}
    active_index = index_by_key.get(active_key, -1)
    failed_index = index_by_key.get(failed_key, -1)
    steps = []
    for idx, (key, label) in enumerate(labels):
        if failed_key == key:
            state = "error"
        elif key == active_key:
            state = "running"
        elif active_key == "done":
            state = "done"
        else:
            completed_until = failed_index if failed_index >= 0 else active_index
            state = "done" if completed_until > idx else "pending"
        item = {"key": key, "label": label, "state": state}
        if failed_key == key and error_message:
            item["details"] = error_message
        steps.append(item)
    return steps


def _update_onu_delete_stage(onu_id, progress_pct, stage, active_key, details=None, live=True):
    _set_onu_delete_progress(
        onu_id,
        progress_pct,
        stage,
        status="running",
        details=details,
        steps=_build_onu_delete_steps(active_key=active_key, live=live),
    )


def _complete_onu_delete_progress(onu_id, details=None, live=True):
    _set_onu_delete_progress(
        onu_id,
        100,
        "ONU excluida com sucesso",
        status="ok",
        details=details,
        steps=_build_onu_delete_steps(active_key="done", live=live),
    )


def _fail_onu_delete_progress(onu_id, active_key, error_message, live=True):
    _set_onu_delete_progress(
        onu_id,
        100,
        "Falha na exclusao da ONU",
        status="error",
        details=error_message,
        steps=_build_onu_delete_steps(failed_key=active_key, error_message=error_message, live=live),
    )


def _set_request_authorize_progress(request_id, progress_pct, stage, status="running", details=None, steps=None, result=None):
    with REQUEST_AUTHORIZE_PROGRESS_LOCK:
        current = REQUEST_AUTHORIZE_PROGRESS.get(int(request_id)) or {}
        REQUEST_AUTHORIZE_PROGRESS[int(request_id)] = {
            "request_id": int(request_id),
            "status": status,
            "progress_pct": max(0, min(100, int(progress_pct))),
            "stage": stage or "",
            "details": details or "",
            "steps": list(steps if steps is not None else current.get("steps") or []),
            "result": result if result is not None else current.get("result"),
            "updated_at": db.utc_now(),
        }


def get_request_authorize_progress(request_id):
    with REQUEST_AUTHORIZE_PROGRESS_LOCK:
        item = REQUEST_AUTHORIZE_PROGRESS.get(int(request_id))
    if item:
        return item
    return {
        "request_id": int(request_id),
        "status": "idle",
        "progress_pct": 0,
        "stage": "Aguardando autorizacao",
        "details": "",
        "steps": [],
        "result": None,
        "updated_at": db.utc_now(),
    }


def _build_request_authorize_steps(active_key=None, failed_key=None, error_message=None):
    labels = [
        ("prepare", "Validando solicitacao"),
        ("olt_add", "Adicionando ONU na OLT"),
        ("ont_lookup", "Confirmando ONT-ID"),
        ("native_vlan", "Aplicando native-vlan"),
        ("service_port", "Criando service-port"),
        ("local_save", "Gravando cadastro local"),
        ("done", "ONU autorizada com sucesso"),
    ]
    index_by_key = {key: idx for idx, (key, _) in enumerate(labels)}
    active_index = index_by_key.get(active_key, -1)
    failed_index = index_by_key.get(failed_key, -1)
    steps = []
    for idx, (key, label) in enumerate(labels):
        if failed_key == key:
            state = "error"
        elif key == active_key:
            state = "running"
        elif active_key == "done":
            state = "done"
        else:
            completed_until = failed_index if failed_index >= 0 else active_index
            state = "done" if completed_until > idx else "pending"
        item = {"key": key, "label": label, "state": state}
        if failed_key == key and error_message:
            item["details"] = error_message
        steps.append(item)
    return steps


def _update_request_authorize_stage(request_id, progress_pct, stage, active_key, details=None):
    _set_request_authorize_progress(
        request_id,
        progress_pct,
        stage,
        status="running",
        details=details,
        steps=_build_request_authorize_steps(active_key=active_key),
    )


def _complete_request_authorize_progress(request_id, result=None, details=None):
    _set_request_authorize_progress(
        request_id,
        100,
        "ONU autorizada com sucesso",
        status="ok",
        details=details,
        steps=_build_request_authorize_steps(active_key="done"),
        result=result,
    )


def _fail_request_authorize_progress(request_id, active_key, error_message):
    _set_request_authorize_progress(
        request_id,
        100,
        "Falha na autorizacao da ONU",
        status="error",
        details=error_message,
        steps=_build_request_authorize_steps(failed_key=active_key, error_message=error_message),
    )


def _parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "sim"}


def _is_full_inventory_due(connection):
    extra = connection.get("extra_config") or {}
    if _parse_bool(extra.get("force_full_inventory"), False):
        return True
    interval_sec = int(extra.get("full_inventory_interval_sec") or 1800)
    last_poll_at = connection.get("last_poll_at")
    if not last_poll_at:
        return True
    try:
        last = datetime.fromisoformat(str(last_poll_at))
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        return elapsed >= max(60, interval_sec)
    except Exception:
        return True


def _build_payload_from_context_snapshot(olt, context):
    collected_at = db.utc_now()
    boards = [
        {
            "slot": board["slot"],
            "model": board["model"],
            "status": board["status"],
            "ports_total": board["ports_total"],
        }
        for board in context.get("boards", [])
    ]
    port_usage = {}
    onus = []
    observed_vlans = set()
    for onu in context.get("onus", []):
        vlan_id = onu.get("vlan_id")
        if vlan_id is not None:
            try:
                numeric_vlan = int(vlan_id)
                if 1 <= numeric_vlan <= 4094:
                    observed_vlans.add(numeric_vlan)
            except Exception:
                pass
        onus.append(
            {
                "serial": onu["serial"],
                "model": onu.get("model") or "Desconhecido",
                "status": onu.get("status") or "active",
                "signal_dbm": onu.get("signal_dbm"),
                "traffic_down_mbps": onu.get("traffic_down_mbps"),
                "traffic_up_mbps": onu.get("traffic_up_mbps"),
                "temperature_c": onu.get("temperature_c"),
                "board_slot": onu["board_slot"],
                "port_name": onu["port_name"],
                "pon_position": onu.get("pon_position"),
                "vlan_id": onu.get("vlan_id"),
            }
        )
        key = (onu["board_slot"], onu["port_name"])
        port_usage[key] = port_usage.get(key, 0) + 1

    ports = []
    for port in context.get("ports", []):
        key = (port["board_slot"], port["name"])
        ports.append(
            {
                "board_slot": port["board_slot"],
                "name": port["name"],
                "capacity_onu": int(port.get("capacity_onu") or 128),
                "alert_threshold_pct": int(port.get("alert_threshold_pct") or 80),
                "used_onu": int(port_usage.get(key, 0)),
            }
        )

    return {
        "collected_at": collected_at,
        "olt_metrics": {
            "temperature_c": float(olt.get("temperature_c") or 0.0),
            "cpu_usage": float(olt.get("cpu_usage") or 0.0),
            "memory_usage": float(olt.get("memory_usage") or 0.0),
        },
        "boards": boards,
        "ports": ports,
        "onus": onus,
        "olt_vlans": [{"vlan_id": vlan_id, "source": "observed"} for vlan_id in sorted(observed_vlans)],
        "authorization_requests": [],
        "events": [
            {
                "level": "info",
                "message": "Coleta rapida: inventario CLI reutilizado.",
                "details": {"mode": "fast"},
            }
        ],
    }


def _payload_uses_fast_snapshot(payload):
    for event in payload.get("events", []):
        if not isinstance(event, dict):
            continue
        details = event.get("details") or {}
        if isinstance(details, dict) and details.get("mode") == "fast":
            return True
    return False


class MockCollector(BaseCollector):
    protocol = "mock"

    def collect(self):
        collected_at = db.utc_now()
        olt_metrics = {
            "temperature_c": round(
                max(33.0, min(58.0, self.olt["temperature_c"] + random.uniform(-1.1, 1.4))),
                1,
            ),
            "cpu_usage": round(
                max(11.0, min(95.0, self.olt["cpu_usage"] + random.uniform(-5.0, 7.0))),
                1,
            ),
            "memory_usage": round(
                max(24.0, min(97.0, self.olt["memory_usage"] + random.uniform(-4.0, 5.0))),
                1,
            ),
        }

        boards = [
            {
                "slot": board["slot"],
                "model": board["model"],
                "status": board["status"],
                "ports_total": board["ports_total"],
            }
            for board in self.context["boards"]
        ]

        ports = []
        onus = []
        port_usage = {}
        for port in self.context["ports"]:
            key = (port["board_slot"], port["name"])
            port_usage[key] = 0

        for onu in self.context["onus"]:
            signal_dbm = round(
                max(-29.5, min(-18.0, onu["signal_dbm"] + random.uniform(-0.8, 0.7))),
                1,
            )
            down = round(max(5.0, onu["traffic_down_mbps"] + random.uniform(-70.0, 90.0)), 1)
            up = round(max(1.0, onu["traffic_up_mbps"] + random.uniform(-25.0, 35.0)), 1)
            temperature_c = round(
                max(38.0, min(66.0, onu["temperature_c"] + random.uniform(-1.0, 1.5))),
                1,
            )
            onus.append(
                {
                    "serial": onu["serial"],
                    "model": onu["model"],
                    "status": onu["status"],
                    "signal_dbm": signal_dbm,
                    "traffic_down_mbps": down,
                    "traffic_up_mbps": up,
                    "temperature_c": temperature_c,
                    "board_slot": onu["board_slot"],
                    "port_name": onu["port_name"],
                    "pon_position": onu["pon_position"],
                }
            )
            key = (onu["board_slot"], onu["port_name"])
            port_usage[key] = port_usage.get(key, 0) + 1

        for port in self.context["ports"]:
            key = (port["board_slot"], port["name"])
            ports.append(
                {
                    "board_slot": port["board_slot"],
                    "name": port["name"],
                    "capacity_onu": port["capacity_onu"],
                    "alert_threshold_pct": port["alert_threshold_pct"],
                    "used_onu": port_usage.get(key, 0),
                }
            )

        authorization_requests = [
            {
                "serial": item["serial"],
                "detected_model": item["detected_model"],
                "board_slot": item["board_slot"],
                "port_name": item["port_name"],
                "requested_signal_dbm": item["requested_signal_dbm"],
                "requested_temperature_c": item["requested_temperature_c"],
                "notes": "Coleta mock confirmou solicitacao pendente.",
            }
            for item in self.context["pending_requests"]
        ]
        events = [
            {
                "level": "info",
                "message": f'Polling mock executado para {self.olt["name"]}',
                "details": {"protocol": self.protocol},
            }
        ]
        return {
            "collected_at": collected_at,
            "olt_metrics": olt_metrics,
            "boards": boards,
            "ports": ports,
            "onus": onus,
            "authorization_requests": authorization_requests,
            "events": events,
        }


class JsonFileCollector(BaseCollector):
    protocol = "json-file"

    def collect(self):
        source_path = (self.connection.get("source_path") or "").strip()
        if not source_path:
            raise CollectorError("source_path nao configurado para o protocolo json-file.")
        file_path = Path(source_path)
        if not file_path.exists():
            raise CollectorError(f"Arquivo de coleta nao encontrado: {source_path}")
        return _validate_payload(json.loads(file_path.read_text(encoding="utf-8")))


class CommandCollector(BaseCollector):
    protocol = "command"

    def collect(self):
        command_line = (self.connection.get("command_line") or "").strip()
        if not command_line:
            raise CollectorError("command_line nao configurado para o protocolo command.")
        timeout = int(self.connection.get("command_timeout_sec") or 20)
        completed = subprocess.run(
            shlex.split(command_line, posix=False),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            raise CollectorError(f"Comando retornou erro: {stderr or completed.returncode}")
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as error:
            raise CollectorError(f"Saida do comando nao e JSON valido: {error}") from error
        return _validate_payload(payload)


class ApiCollector(BaseCollector):
    protocol = "api"

    def collect(self):
        api_base_url = (self.connection.get("api_base_url") or "").strip()
        if not api_base_url:
            raise CollectorError("api_base_url nao configurada para o protocolo api.")
        request = Request(api_base_url)
        if self.connection.get("api_token"):
            request.add_header("Authorization", f'Bearer {self.connection["api_token"]}')
        request.add_header("Accept", "application/json")
        try:
            with urlopen(request, timeout=int(self.connection.get("command_timeout_sec") or 20)) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise CollectorError(f"API respondeu com erro HTTP {error.code}") from error
        except URLError as error:
            raise CollectorError(f"Falha ao acessar API: {error.reason}") from error
        return _validate_payload(payload)


class NativeCollector(BaseCollector):
    protocol = "native"

    def collect(self):
        brand = (self.olt.get("brand") or "").strip().lower()
        transport_type = (self.connection.get("transport_type") or "ssh").strip().lower()
        extra = self.connection.get("extra_config") or {}
        command_overrides = _load_huawei_command_overrides(extra)
        fast_mode_enabled = _parse_bool(extra.get("fast_poll_enabled"), True)
        allow_empty_inventory = _parse_bool(extra.get("allow_empty_onu_inventory"), False)
        full_inventory_due = _is_full_inventory_due(self.connection)
        can_use_fast_snapshot = _has_inventory_snapshot(self.context)
        if (
            brand == "huawei"
            and transport_type in {"ssh", "telnet"}
            and fast_mode_enabled
            and not full_inventory_due
            and can_use_fast_snapshot
        ):
            _set_poll_progress(self.olt["id"], 30, "Coleta rapida: reutilizando inventario")
            payload = _validate_payload(_build_payload_from_context_snapshot(self.olt, self.context))
            _set_poll_progress(self.olt["id"], 60, "Atualizando metricas via SNMP")
            _enrich_huawei_payload_with_snmp(payload, self.olt, self.connection)
            _set_poll_progress(self.olt["id"], 80, "Finalizando payload rapido")
            return payload
        if brand == "huawei" and transport_type == "ssh":
            _set_poll_progress(self.olt["id"], 30, "Coletando CLI Huawei via SSH")
            username = (self.connection.get("username") or "").strip()
            if not username:
                raise CollectorError("Usuario da OLT nao configurado para a coleta Huawei SSH.")
            files = collect_huawei_cli_files_native(
                host=self.olt["host"],
                username=username,
                password=self.connection.get("password"),
                port=int(self.connection.get("port") or 22),
                timeout=int(self.connection.get("command_timeout_sec") or 30),
                key_path=(self.connection.get("extra_config") or {}).get("ssh_key_path"),
                collector_profile=extra.get("collector_profile") or "auto",
                command_overrides=command_overrides,
            )
            detected_profile = files.get("_collector_profile_detected")
            detected_overrides = files.get("_command_overrides_detected") or {}
            ont_summary_unknown = _looks_like_unknown_command_output(files.get("ont_summary.txt"))
            if detected_profile or detected_overrides:
                updates = {}
                if detected_profile:
                    updates["collector_profile_detected"] = detected_profile
                if isinstance(detected_overrides, dict):
                    merged_overrides = dict(command_overrides)
                    merged_overrides.update(detected_overrides)
                    if ont_summary_unknown and "ont_summary" not in merged_overrides:
                        merged_overrides["ont_summary"] = "__snmp_bootstrap__"
                    updates["command_overrides"] = merged_overrides
                db.update_connection_extra_config(
                    self.olt["id"],
                    updates,
                )
            payload = _validate_payload(parse_huawei_cli_snapshot(files))
            _set_poll_progress(self.olt["id"], 60, "Enriquecendo com SNMP")
            _enrich_huawei_payload_with_snmp(payload, self.olt, self.connection)
            _assert_huawei_inventory_not_empty(
                files=files,
                payload=payload,
                transport_type=transport_type,
                allow_empty_inventory=allow_empty_inventory,
            )
            _set_poll_progress(self.olt["id"], 80, "Finalizando payload")
            return payload
        if brand == "huawei" and transport_type == "telnet":
            _set_poll_progress(self.olt["id"], 30, "Coletando CLI Huawei via Telnet")
            telnet_command_timeout = int(
                (extra.get("telnet_command_timeout_sec") or min(120, int(self.connection.get("command_timeout_sec") or 30)))
            )
            telnet_allow_partial = _parse_bool(extra.get("telnet_allow_partial"), True)

            def _on_telnet_progress(pct, stage):
                _set_poll_progress(self.olt["id"], pct, stage)

            files = collect_huawei_cli_files_over_telnet(
                host=self.olt["host"],
                username=(self.connection.get("username") or "").strip(),
                password=self.connection.get("password"),
                port=int(self.connection.get("port") or 23),
                timeout=max(180, int(self.connection.get("command_timeout_sec") or 30)),
                command_timeout=telnet_command_timeout,
                allow_partial=telnet_allow_partial,
                progress_callback=_on_telnet_progress,
                collector_profile=extra.get("collector_profile") or "auto",
                command_overrides=command_overrides,
            )
            detected_profile = files.get("_collector_profile_detected")
            detected_overrides = files.get("_command_overrides_detected") or {}
            ont_summary_unknown = _looks_like_unknown_command_output(files.get("ont_summary.txt"))
            if detected_profile or detected_overrides:
                updates = {}
                if detected_profile:
                    updates["collector_profile_detected"] = detected_profile
                if isinstance(detected_overrides, dict):
                    merged_overrides = dict(command_overrides)
                    merged_overrides.update(detected_overrides)
                    if ont_summary_unknown and "ont_summary" not in merged_overrides:
                        merged_overrides["ont_summary"] = "__snmp_bootstrap__"
                    updates["command_overrides"] = merged_overrides
                db.update_connection_extra_config(
                    self.olt["id"],
                    updates,
                )
            payload = _validate_payload(parse_huawei_cli_snapshot(files))
            _set_poll_progress(self.olt["id"], 60, "Enriquecendo com SNMP")
            _enrich_huawei_payload_with_snmp(payload, self.olt, self.connection)
            _assert_huawei_inventory_not_empty(
                files=files,
                payload=payload,
                transport_type=transport_type,
                allow_empty_inventory=allow_empty_inventory,
            )
            _set_poll_progress(self.olt["id"], 80, "Finalizando payload")
            return payload
        raise CollectorError(
            f"Coleta nativa ainda nao suportada para {self.olt.get('brand')} via {transport_type}."
        )


COLLECTOR_BY_PROTOCOL = {
    "native": NativeCollector,
    "mock": MockCollector,
    "json-file": JsonFileCollector,
    "command": CommandCollector,
    "api": ApiCollector,
}


def _validate_payload(payload):
    required = ["olt_metrics", "boards", "ports", "onus"]
    missing = [key for key in required if key not in payload]
    if missing:
        raise CollectorError(f"Payload de coleta incompleto: faltando {', '.join(missing)}.")
    payload.setdefault("authorization_requests", [])
    payload.setdefault("events", [])
    payload.setdefault("collected_at", db.utc_now())
    return payload


def _has_inventory_snapshot(context):
    context = context or {}
    return bool(context.get("onus"))


def _load_huawei_command_overrides(extra):
    extra = extra or {}
    overrides = extra.get("command_overrides") or {}
    if not isinstance(overrides, dict):
        return {}
    normalized = {}
    for key in ("ont_summary", "service_port", "vlan_inventory"):
        value = str(overrides.get(key) or "").strip()
        if value:
            normalized[key] = value
    return normalized


def _looks_like_unknown_command_output(output):
    text = str(output or "").lower()
    return (
        "unknown command" in text
        or "error locates at '^'" in text
        or "unrecognized command" in text
    )


def _extract_ont_total_from_summary(summary_text):
    text = summary_text or ""
    match = re.search(
        r"the\s+total\s+of\s+onts?\s+are\s*:?\s*(\d+)",
        text,
        re.IGNORECASE,
    )
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _assert_huawei_inventory_not_empty(files, payload, transport_type, allow_empty_inventory=False):
    onu_count = len(payload.get("onus") or [])
    if onu_count > 0:
        return
    if allow_empty_inventory:
        return

    summary = str((files or {}).get("ont_summary.txt") or "")
    total_hint = _extract_ont_total_from_summary(summary)
    lowered = summary.lower()

    if total_hint == 0:
        raise CollectorError(
            "Coleta concluida sem ONUs (CLI retornou total 0). "
            "Se esta OLT estiver vazia, habilite allow_empty_onu_inventory."
        )
    if total_hint and total_hint > 0:
        raise CollectorError(
            f"Inventario inconsistente: CLI indica {total_hint} ONUs, mas parser retornou 0."
        )
    if not summary.strip():
        raise CollectorError(
            f"Resumo de ONUs vazio via {transport_type}. Verifique comando/permissao/timeout de coleta."
        )
    if (
        "unknown command" in lowered
        or "error locates at '^'" in lowered
        or "unrecognized command" in lowered
    ):
        raise CollectorError(
            "Comando de resumo de ONUs nao suportado pela OLT (unknown command)."
        )
    raise CollectorError(
        "Coleta retornou 0 ONUs sem indicacao valida de OLT vazia. "
        "Revise o comando de resumo e credenciais."
    )


def _decode_huawei_serial_index(index_suffix):
    if index_suffix is None:
        return None
    if not isinstance(index_suffix, (tuple, list)):
        try:
            index_suffix = (int(index_suffix),)
        except Exception:
            return None
    parts = []
    for item in index_suffix:
        try:
            parts.append(int(item))
        except Exception:
            return None
    if not parts:
        return None

    candidates = []
    if len(parts) >= 4:
        candidates.append((parts[-4], parts[-3], parts[-2], parts[-1]))
        candidates.append((parts[0], parts[1], parts[2], parts[3]))
    if len(parts) == 3:
        candidates.append((0, parts[0], parts[1], parts[2]))
    if len(parts) == 2:
        encoded_port, ont_id = parts
        # Some Huawei SNMP tables expose (ifIndex, ontId) instead of a direct GPON location.
        # Treating a large ifIndex as a port index collapses many ONUs into 0/0 PON 1 ont 0.
        # In that case we must skip bootstrap rather than invent a fake location.
        if encoded_port > 65535:
            encoded_port = -1
        if encoded_port >= 0:
            candidates.append((0, 0, encoded_port % 256, ont_id))
    if len(parts) == 1:
        value = parts[0]
        if value >= 0:
            candidates.append((0, 0, value % 256, value // 256))

    for frame, slot, port_index, ont_id in candidates:
        if frame < 0 or slot < 0 or port_index < 0 or ont_id < 0:
            continue
        if frame > 32 or slot > 32 or port_index > 255 or ont_id > 4096:
            continue
        return frame, slot, port_index, ont_id
    return None


def _bootstrap_onus_from_snmp_serial_index(payload, serial_to_index, ifname_by_index=None):
    if payload.get("onus"):
        return 0
    created = []
    seen = set()
    for serial, variants in (serial_to_index or {}).items():
        if not serial:
            continue
        normalized_serial = snmp_client.normalize_serial(serial)
        if not normalized_serial:
            continue
        for variant in variants or []:
            decoded = _decode_huawei_serial_index(variant)
            location = None
            if decoded:
                frame, slot, port_index, ont_id = decoded
                location = {
                    "board_slot": f"{frame}/{slot}",
                    "port_name": f"PON {port_index + 1}",
                    "pon_position": int(ont_id),
                }
            elif isinstance(variant, (tuple, list)) and len(variant) >= 2:
                try:
                    ifindex = int(variant[0])
                    ont_id = int(variant[1])
                except Exception:
                    ifindex = None
                    ont_id = None
                if ifindex is not None and ont_id is not None:
                    ifname = (ifname_by_index or {}).get(ifindex)
                    parsed = _extract_huawei_location_from_ifname(ifname)
                    if parsed:
                        location = {
                            "board_slot": parsed["board_slot"],
                            "port_name": parsed["port_name"],
                            "pon_position": int(ont_id),
                        }
            if not location:
                continue
            key = (
                normalized_serial,
                location["board_slot"],
                location["port_name"],
                location["pon_position"],
            )
            if key in seen:
                continue
            seen.add(key)
            created.append(
                {
                    "serial": normalized_serial,
                    "model": "Desconhecido",
                    "status": "active",
                    "signal_dbm": None,
                    "traffic_down_mbps": 0.0,
                    "traffic_up_mbps": 0.0,
                    "temperature_c": None,
                    "board_slot": location["board_slot"],
                    "port_name": location["port_name"],
                    "pon_position": location["pon_position"],
                    "vlan_id": None,
                }
            )
            break

    if not created:
        return 0

    payload["onus"] = created
    board_by_slot = {}
    for board in payload.get("boards", []):
        slot = str(board.get("slot") or "")
        if slot:
            board_by_slot[slot] = board
    port_keys = {
        (str(port.get("board_slot") or ""), str(port.get("name") or ""))
        for port in payload.get("ports", [])
    }

    for onu in created:
        board_slot = str(onu.get("board_slot") or "")
        port_name = str(onu.get("port_name") or "")
        try:
            required_ports = max(16, int(port_name.split()[-1]))
        except Exception:
            required_ports = 16
        board = board_by_slot.get(board_slot)
        if not board:
            board = {
                "slot": board_slot,
                "model": "GPON",
                "status": "online",
                "ports_total": required_ports,
            }
            payload.setdefault("boards", []).append(board)
            board_by_slot[board_slot] = board
        else:
            board["ports_total"] = max(int(board.get("ports_total") or 0), required_ports)
        port_key = (board_slot, port_name)
        if port_key not in port_keys:
            payload.setdefault("ports", []).append(
                {
                    "board_slot": board_slot,
                    "name": port_name,
                    "capacity_onu": 128,
                    "alert_threshold_pct": 80,
                    "used_onu": 0,
                }
            )
            port_keys.add(port_key)

    return len(created)


def _enrich_huawei_payload_with_snmp(payload, olt, connection):
    extra = connection.get("extra_config") or {}
    uses_fast_snapshot = _payload_uses_fast_snapshot(payload)
    default_signal_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
    serial_oid = (extra.get("snmp_serial_oid") or "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3").strip()
    vlan_oid = (extra.get("snmp_vlan_oid") or extra.get("snmp_onu_vlan_oid") or "").strip()
    signal_oid = (extra.get("snmp_signal_oid") or default_signal_oid).strip()
    signal_tx_oid = (extra.get("snmp_signal_tx_oid") or "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3").strip()
    signal_olt_rx_oid = (extra.get("snmp_signal_olt_rx_oid") or "").strip()
    temperature_oid = (extra.get("snmp_temperature_oid") or "").strip()
    status_oid = (extra.get("snmp_status_oid") or "").strip()
    distance_oid = (extra.get("snmp_distance_oid") or "").strip()
    port_status_oid = (extra.get("snmp_port_status_oid") or "").strip()
    port_count_oid = (extra.get("snmp_port_count_oid") or "").strip()
    ifname_oid = (extra.get("snmp_ifname_oid") or "1.3.6.1.2.1.31.1.1.1.1").strip()
    snmp_fast_mode = _parse_bool(extra.get("snmp_fast_mode"), True)
    fast_partial_onu_updates = _parse_bool(extra.get("fast_partial_onu_updates"), True)
    if snmp_fast_mode:
        # OIDs with very large tables that increase latency significantly.
        distance_oid = ""
        status_oid = ""
    if (
        not vlan_oid
        and not signal_oid
        and not signal_tx_oid
        and not signal_olt_rx_oid
        and not temperature_oid
        and not status_oid
        and not distance_oid
        and not port_status_oid
        and not port_count_oid
    ):
        return

    community = (
        extra.get("snmp_read_community")
        or extra.get("snmp_community")
        or connection.get("password")
        or "public"
    ).strip()
    if not community:
        return

    host = olt.get("host")
    snmp_version = (extra.get("snmp_version") or "2c").strip().lower()
    port = int(extra.get("snmp_port") or 161)
    timeout = int(extra.get("snmp_timeout_sec") or 4)
    max_rows = int(extra.get("snmp_max_rows") or 8192)
    retries = int(extra.get("snmp_retries") or 2)
    bulk_repetitions = int(extra.get("snmp_bulk_repetitions") or 25)
    if snmp_fast_mode:
        max_rows = min(max_rows, int(extra.get("snmp_fast_max_rows") or 1200))
        retries = min(retries, int(extra.get("snmp_fast_retries") or 1))
        timeout = min(timeout, int(extra.get("snmp_fast_timeout_sec") or 3))
    signal_scale = float(extra.get("snmp_signal_multiplier") or 1.0)
    signal_offset = float(extra.get("snmp_signal_offset") or 0.0)
    signal_tx_scale = float(extra.get("snmp_signal_tx_multiplier") or signal_scale)
    signal_tx_offset = float(extra.get("snmp_signal_tx_offset") or signal_offset)
    parallel_walks = int(extra.get("snmp_parallel_walks") or (2 if snmp_fast_mode else 4))
    temp_scale = float(extra.get("snmp_temperature_multiplier") or 1.0)
    temp_offset = float(extra.get("snmp_temperature_offset") or 0.0)

    try:
        walk_errors = []

        def _safe_walk(oid_value, oid_label):
            if not oid_value:
                return []
            try:
                return snmp_client.walk(
                    host,
                    community,
                    oid_value,
                    port=port,
                    timeout=timeout,
                    version=snmp_version,
                    max_rows=max_rows,
                    retries=retries,
                    max_repetitions=bulk_repetitions,
                )
            except Exception as error:
                walk_errors.append(f"{oid_label}: {error}")
                return []

        def _backfill_metric_with_get(metric_label, metric_oid, metric_indexed):
            if not metric_oid:
                return metric_indexed, 0
            onu_rows = payload.get("onus", [])
            if not onu_rows:
                return metric_indexed, 0
            expected_rows = len(onu_rows)
            if len(metric_indexed) >= max(16, int(expected_rows * 0.7)):
                return metric_indexed, 0

            try:
                base_oid_parts = tuple(
                    int(part) for part in str(metric_oid).strip(".").split(".") if str(part).strip()
                )
            except Exception:
                return metric_indexed, 0

            suffix_candidates = []
            seen_suffixes = set(metric_indexed.keys())
            for onu in onu_rows:
                serial = snmp_client.normalize_serial(onu.get("serial"))
                variants = serial_to_index.get(serial, [])
                if not variants:
                    variants = _onu_index_candidates(onu)
                for variant in variants:
                    if not isinstance(variant, tuple):
                        continue
                    if variant in seen_suffixes:
                        continue
                    seen_suffixes.add(variant)
                    suffix_candidates.append(variant)
                    break

            if not suffix_candidates:
                return metric_indexed, 0

            fetched = {}
            get_errors = []

            def _safe_get(index_suffix):
                suffix_str = ".".join(str(int(part)) for part in index_suffix)
                response_oid, value = snmp_client.get(
                    host,
                    community,
                    f"{metric_oid}.{suffix_str}",
                    port=port,
                    timeout=timeout,
                    version=snmp_version,
                    retries=retries,
                )
                if (
                    isinstance(response_oid, tuple)
                    and len(response_oid) >= len(base_oid_parts)
                    and response_oid[: len(base_oid_parts)] == base_oid_parts
                ):
                    return tuple(response_oid[len(base_oid_parts) :]), value
                return index_suffix, value

            max_workers = max(1, min(parallel_walks * 3, len(suffix_candidates)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_safe_get, suffix): suffix for suffix in suffix_candidates}
                for future in as_completed(futures):
                    try:
                        suffix, value = future.result()
                        fetched[suffix] = value
                    except Exception as error:
                        get_errors.append(str(error))
            if get_errors:
                walk_errors.append(f"{metric_label}-get: {len(get_errors)} falhas")
            if fetched:
                metric_indexed.update(fetched)
            return metric_indexed, len(fetched)

        serial_to_index = {}
        serial_rows_count = 0
        cache_hit = False
        use_cached_index = _parse_bool(extra.get("snmp_use_cached_serial_index"), True)
        with SNMP_INDEX_CACHE_LOCK:
            cached = dict(SNMP_INDEX_CACHE.get(int(olt.get("id") or 0)) or {})
        if use_cached_index and cached:
            cache_hit = True
            for serial, raw_index in cached.items():
                if raw_index is None:
                    continue
                index_suffix = tuple(raw_index) if isinstance(raw_index, (list, tuple)) else (raw_index,)
                variants = [index_suffix]
                for item in _expand_metric_index_suffix(index_suffix):
                    if item not in variants:
                        variants.append(item)
                serial_to_index[serial] = variants

        walk_results = {}
        walk_plan = [
            ("onu_vlan", vlan_oid),
            ("signal", signal_oid),
            ("signal_tx", signal_tx_oid),
            ("signal_olt_rx", signal_olt_rx_oid),
            ("temperature", temperature_oid),
            ("onu_status", status_oid),
            ("distance", distance_oid),
            ("port_status", port_status_oid),
            ("port_count", port_count_oid),
            ("ifname", ifname_oid),
        ]
        if serial_oid and not cache_hit:
            walk_plan.insert(0, ("serial", serial_oid))
        requested = [(label, oid_value) for label, oid_value in walk_plan if oid_value]
        if requested:
            max_workers = max(1, min(parallel_walks, len(requested)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_safe_walk, oid_value, label): label
                    for label, oid_value in requested
                }
                for future in as_completed(futures):
                    label = futures[future]
                    try:
                        walk_results[label] = future.result()
                    except Exception as error:
                        walk_errors.append(f"{label}: {error}")
                        walk_results[label] = []

        if serial_oid and not cache_hit:
            serial_rows = walk_results.get("serial", [])
            serial_rows_count = len(serial_rows)
            serial_indexed = snmp_client.build_indexed_map(serial_rows, serial_oid)
            for index_suffix, raw_serial in serial_indexed.items():
                normalized = snmp_client.normalize_serial(raw_serial)
                if normalized:
                    variants = [index_suffix]
                    converted = _expand_metric_index_suffix(index_suffix)
                    for item in converted:
                        if item not in variants:
                            variants.append(item)
                    serial_to_index[normalized] = variants
        ifname_by_index = {}
        if ifname_oid:
            ifname_rows = walk_results.get("ifname", [])
            ifname_indexed = snmp_client.build_indexed_map(ifname_rows, ifname_oid)
            for index_suffix, raw_ifname in ifname_indexed.items():
                if not isinstance(index_suffix, tuple) or len(index_suffix) != 1:
                    continue
                try:
                    ifname_by_index[int(index_suffix[0])] = str(raw_ifname or "")
                except Exception:
                    continue
        bootstrapped_serials = set()
        bootstrapped_onus = _bootstrap_onus_from_snmp_serial_index(payload, serial_to_index, ifname_by_index)
        if bootstrapped_onus:
            bootstrapped_serials = {
                snmp_client.normalize_serial(onu.get("serial"))
                for onu in payload.get("onus", [])
                if snmp_client.normalize_serial(onu.get("serial"))
            }
            payload.setdefault("events", []).append(
                {
                    "level": "info",
                    "message": f"Inventario ONU reconstruido via SNMP ({bootstrapped_onus} ONUs).",
                    "details": {"mode": "snmp-serial-bootstrap"},
                }
            )

        signal_indexed = {}
        signal_rows_count = 0
        if signal_oid:
            signal_rows = walk_results.get("signal", [])
            signal_indexed = snmp_client.build_indexed_map(signal_rows, signal_oid)
            signal_rows_count = len(signal_rows)
            signal_indexed, signal_get_rows_count = _backfill_metric_with_get("signal", signal_oid, signal_indexed)
            signal_rows_count += signal_get_rows_count
        else:
            signal_get_rows_count = 0

        vlan_indexed = {}
        vlan_rows_count = 0
        if vlan_oid:
            vlan_rows = walk_results.get("onu_vlan", [])
            vlan_indexed = snmp_client.build_indexed_map(vlan_rows, vlan_oid)
            vlan_rows_count = len(vlan_rows)

        signal_tx_indexed = {}
        signal_tx_rows_count = 0
        if signal_tx_oid:
            signal_tx_rows = walk_results.get("signal_tx", [])
            signal_tx_indexed = snmp_client.build_indexed_map(signal_tx_rows, signal_tx_oid)
            signal_tx_rows_count = len(signal_tx_rows)
            signal_tx_indexed, signal_tx_get_rows_count = _backfill_metric_with_get(
                "signal_tx",
                signal_tx_oid,
                signal_tx_indexed,
            )
            signal_tx_rows_count += signal_tx_get_rows_count
        else:
            signal_tx_get_rows_count = 0

        signal_olt_rx_indexed = {}
        signal_olt_rx_rows_count = 0
        if signal_olt_rx_oid:
            signal_olt_rx_rows = walk_results.get("signal_olt_rx", [])
            signal_olt_rx_indexed = snmp_client.build_indexed_map(signal_olt_rx_rows, signal_olt_rx_oid)
            signal_olt_rx_rows_count = len(signal_olt_rx_rows)
            signal_olt_rx_indexed, signal_olt_rx_get_rows_count = _backfill_metric_with_get(
                "signal_olt_rx",
                signal_olt_rx_oid,
                signal_olt_rx_indexed,
            )
            signal_olt_rx_rows_count += signal_olt_rx_get_rows_count
        else:
            signal_olt_rx_get_rows_count = 0

        temp_indexed = {}
        temp_rows_count = 0
        if temperature_oid:
            temp_rows = walk_results.get("temperature", [])
            temp_indexed = snmp_client.build_indexed_map(temp_rows, temperature_oid)
            temp_rows_count = len(temp_rows)

        status_indexed = {}
        status_rows_count = 0
        if status_oid:
            status_rows = walk_results.get("onu_status", [])
            status_indexed = snmp_client.build_indexed_map(status_rows, status_oid)
            status_rows_count = len(status_rows)

        distance_indexed = {}
        distance_rows_count = 0
        if distance_oid:
            distance_rows = walk_results.get("distance", [])
            distance_indexed = snmp_client.build_indexed_map(distance_rows, distance_oid)
            distance_rows_count = len(distance_rows)

        port_status_indexed = {}
        port_status_rows_count = 0
        if port_status_oid:
            port_status_rows = walk_results.get("port_status", [])
            port_status_indexed = snmp_client.build_indexed_map(port_status_rows, port_status_oid)
            port_status_rows_count = len(port_status_rows)

        port_count_indexed = {}
        port_count_rows_count = 0
        if port_count_oid:
            port_count_rows = walk_results.get("port_count", [])
            port_count_indexed = snmp_client.build_indexed_map(port_count_rows, port_count_oid)
            port_count_rows_count = len(port_count_rows)

        applied = 0
        port_index_by_name = {}
        discovered_cache = {}
        touched_serials = set(bootstrapped_serials)
        for onu in payload.get("onus", []):
            serial = snmp_client.normalize_serial(onu.get("serial"))
            optical_signal_updated = False
            status_sample_applied = False
            index_suffix = None
            for variant in serial_to_index.get(serial, []):
                if (
                        (vlan_indexed and variant in vlan_indexed)
                        or
                        (signal_indexed and variant in signal_indexed)
                        or (signal_tx_indexed and variant in signal_tx_indexed)
                        or (signal_olt_rx_indexed and variant in signal_olt_rx_indexed)
                        or (temp_indexed and variant in temp_indexed)
                    or (status_indexed and variant in status_indexed)
                    or (distance_indexed and variant in distance_indexed)
                ):
                    index_suffix = variant
                    break
            if not index_suffix:
                for candidate in _onu_index_candidates(onu):
                    if (
                        (vlan_indexed and candidate in vlan_indexed)
                        or
                        (signal_indexed and candidate in signal_indexed)
                        or (signal_tx_indexed and candidate in signal_tx_indexed)
                        or (signal_olt_rx_indexed and candidate in signal_olt_rx_indexed)
                        or (temp_indexed and candidate in temp_indexed)
                        or (status_indexed and candidate in status_indexed)
                        or (distance_indexed and candidate in distance_indexed)
                    ):
                        index_suffix = candidate
                        break
            if not index_suffix:
                continue
            if serial and isinstance(index_suffix, tuple):
                discovered_cache[serial] = index_suffix

            if vlan_indexed and index_suffix in vlan_indexed:
                try:
                    vlan_value = int(vlan_indexed[index_suffix])
                    if 1 <= vlan_value <= 4094:
                        onu["vlan_id"] = vlan_value
                        if serial:
                            touched_serials.add(serial)
                except Exception:
                    pass

            if isinstance(index_suffix, tuple) and len(index_suffix) >= 2:
                try:
                    encoded_port = int(index_suffix[0])
                    port_key = (str(onu.get("board_slot") or ""), str(onu.get("port_name") or ""))
                    if port_key[0] and port_key[1]:
                        port_index_by_name.setdefault(port_key, encoded_port)
                except Exception:
                    pass

            if signal_indexed and index_suffix in signal_indexed:
                raw_signal = signal_indexed[index_suffix]
                if isinstance(raw_signal, (int, float)):
                    if _is_valid_snmp_metric(raw_signal):
                        converted_signal = round(raw_signal * signal_scale + signal_offset, 2)
                        if _is_valid_onu_signal_dbm(converted_signal):
                            onu["signal_dbm"] = converted_signal
                            applied += 1
                            optical_signal_updated = True
                            if serial:
                                touched_serials.add(serial)
                else:
                    try:
                        value = float(raw_signal)
                        if _is_valid_snmp_metric(value):
                            converted_signal = round(value * signal_scale + signal_offset, 2)
                            if _is_valid_onu_signal_dbm(converted_signal):
                                onu["signal_dbm"] = converted_signal
                                applied += 1
                                optical_signal_updated = True
                                if serial:
                                    touched_serials.add(serial)
                    except Exception:
                        pass

            if signal_tx_indexed and index_suffix in signal_tx_indexed:
                raw_signal_tx = signal_tx_indexed[index_suffix]
                if isinstance(raw_signal_tx, (int, float)):
                    if _is_valid_snmp_metric(raw_signal_tx):
                        converted_signal_tx = round(raw_signal_tx * signal_tx_scale + signal_tx_offset, 2)
                        if _is_valid_onu_signal_tx_dbm(converted_signal_tx):
                            onu["signal_tx_dbm"] = converted_signal_tx
                            if serial:
                                touched_serials.add(serial)
                else:
                    try:
                        value = float(raw_signal_tx)
                        if _is_valid_snmp_metric(value):
                            converted_signal_tx = round(value * signal_tx_scale + signal_tx_offset, 2)
                            if _is_valid_onu_signal_tx_dbm(converted_signal_tx):
                                onu["signal_tx_dbm"] = converted_signal_tx
                                if serial:
                                    touched_serials.add(serial)
                    except Exception:
                        pass

            if signal_olt_rx_indexed and index_suffix in signal_olt_rx_indexed:
                raw_signal_olt_rx = signal_olt_rx_indexed[index_suffix]
                converted_signal_olt_rx = _convert_signal_olt_rx_dbm(
                    raw_signal_olt_rx,
                    signal_scale,
                    signal_offset,
                )
                if converted_signal_olt_rx is not None:
                    onu["signal_olt_rx_dbm"] = converted_signal_olt_rx
                    optical_signal_updated = True
                    if serial:
                        touched_serials.add(serial)

            if temp_indexed and index_suffix in temp_indexed:
                raw_temp = temp_indexed[index_suffix]
                if isinstance(raw_temp, (int, float)):
                    if _is_valid_snmp_metric(raw_temp):
                        converted_temp = round(raw_temp * temp_scale + temp_offset, 2)
                        if _is_valid_onu_temperature_c(converted_temp):
                            onu["temperature_c"] = converted_temp
                            if serial:
                                touched_serials.add(serial)
                else:
                    try:
                        value = float(raw_temp)
                        if _is_valid_snmp_metric(value):
                            converted_temp = round(value * temp_scale + temp_offset, 2)
                            if _is_valid_onu_temperature_c(converted_temp):
                                onu["temperature_c"] = converted_temp
                                if serial:
                                    touched_serials.add(serial)
                    except Exception:
                        pass

            if status_indexed and index_suffix in status_indexed:
                status_value = status_indexed[index_suffix]
                try:
                    code = int(status_value)
                    onu["status"] = "active" if code == 1 else "warning"
                    status_sample_applied = True
                    if serial:
                        touched_serials.add(serial)
                except Exception:
                    pass
            if not status_sample_applied and optical_signal_updated and _has_optical_signal_evidence(onu):
                onu["status"] = "active"
                if serial:
                    touched_serials.add(serial)

            if distance_indexed and index_suffix in distance_indexed:
                distance_value = distance_indexed[index_suffix]
                try:
                    onu["distance_m"] = int(distance_value)
                    if serial:
                        touched_serials.add(serial)
                except Exception:
                    pass

        if snmp_fast_mode and fast_partial_onu_updates:
            onu_rows = payload.get("onus", [])
            total_onus = len(onu_rows)
            touched_ratio = (len(touched_serials) / float(total_onus)) if total_onus else 0.0
            can_infer_missing_onus = total_onus > 0 and (
                touched_ratio >= 0.5
                or len(touched_serials) >= max(1, total_onus - 2)
            )
            if uses_fast_snapshot and can_infer_missing_onus:
                stale_onus = 0
                stale_kept_active = 0
                rewritten_onus = []
                for onu in onu_rows:
                    serial = snmp_client.normalize_serial(onu.get("serial"))
                    if serial in touched_serials:
                        rewritten_onus.append(onu)
                        continue
                    stale_onu = dict(onu)
                    current_status = str(stale_onu.get("status") or "").strip().lower()
                    if current_status == "active" and _has_optical_signal_evidence(stale_onu):
                        stale_onu["status"] = "active"
                        stale_kept_active += 1
                    else:
                        stale_onu["status"] = "warning"
                        stale_onus += 1
                    stale_onu["traffic_down_mbps"] = 0.0
                    stale_onu["traffic_up_mbps"] = 0.0
                    rewritten_onus.append(stale_onu)
                payload["onus"] = rewritten_onus
                if stale_onus or stale_kept_active:
                    message_parts = []
                    if stale_onus:
                        message_parts.append(f"{stale_onus} ONU(s) ajustadas para warning")
                    if stale_kept_active:
                        message_parts.append(
                            f"{stale_kept_active} ONU(s) mantidas online por evidencia de sinal optico"
                        )
                    payload.setdefault("events", []).append(
                        {
                            "level": "warning",
                            "message": "Poll rapido sem metrica completa: " + "; ".join(message_parts) + ".",
                            "details": {
                                "mode": "fast-stale-onu-reset",
                                "stale_onus": stale_onus,
                                "stale_kept_active": stale_kept_active,
                                "onus_touched": len(touched_serials),
                                "onus_total": total_onus,
                                "coverage_ratio": round(touched_ratio, 3),
                            },
                        }
                    )
            elif uses_fast_snapshot:
                payload["onus"] = [
                    onu
                    for onu in onu_rows
                    if snmp_client.normalize_serial(onu.get("serial")) in touched_serials
                ]
                payload.setdefault("events", []).append(
                    {
                        "level": "warning",
                        "message": "Cobertura SNMP insuficiente para inferir ONUs ausentes no poll rapido.",
                        "details": {
                            "mode": "fast-partial-skip",
                            "onus_touched": len(touched_serials),
                            "onus_total": total_onus,
                            "coverage_ratio": round(touched_ratio, 3),
                        },
                    }
                )

        ports_updated = 0
        for port_row in payload.get("ports", []):
            dynamic_candidates = []
            port_key = (str(port_row.get("board_slot") or ""), str(port_row.get("name") or ""))
            if port_key in port_index_by_name:
                dynamic_candidates.append((int(port_index_by_name[port_key]),))
            for candidate in dynamic_candidates + _port_index_candidates(port_row):
                matched = False
                if port_count_indexed and candidate in port_count_indexed:
                    try:
                        port_row["used_onu"] = int(port_count_indexed[candidate])
                        matched = True
                    except Exception:
                        pass
                if port_status_indexed and candidate in port_status_indexed:
                    try:
                        status_code = int(port_status_indexed[candidate])
                        port_row["status"] = "online" if status_code == 1 else "warning"
                        matched = True
                    except Exception:
                        pass
                if matched:
                    ports_updated += 1
                    break

        payload.setdefault("events", []).append(
            {
                "level": "info",
                "message": f"SNMP aplicado em {applied} ONUs.",
                "details": {
                    "snmp_version": snmp_version,
                    "snmp_timeout_sec": timeout,
                    "snmp_retries": retries,
                    "snmp_max_rows": max_rows,
                    "snmp_bulk_repetitions": bulk_repetitions,
                    "serial_oid": serial_oid,
                    "vlan_oid": vlan_oid,
                    "signal_oid": signal_oid,
                    "signal_tx_oid": signal_tx_oid,
                    "signal_olt_rx_oid": signal_olt_rx_oid,
                    "temperature_oid": temperature_oid,
                    "status_oid": status_oid,
                    "distance_oid": distance_oid,
                    "port_status_oid": port_status_oid,
                    "port_count_oid": port_count_oid,
                    "serial_rows": serial_rows_count,
                    "serial_cache_hit": cache_hit,
                    "vlan_rows": vlan_rows_count,
                    "signal_rows": signal_rows_count,
                    "signal_get_rows": signal_get_rows_count,
                    "signal_tx_rows": signal_tx_rows_count,
                    "signal_tx_get_rows": signal_tx_get_rows_count,
                    "signal_olt_rx_rows": signal_olt_rx_rows_count,
                    "signal_olt_rx_get_rows": signal_olt_rx_get_rows_count,
                    "temperature_rows": temp_rows_count,
                    "status_rows": status_rows_count,
                    "distance_rows": distance_rows_count,
                    "port_status_rows": port_status_rows_count,
                    "port_count_rows": port_count_rows_count,
                    "ports_updated": ports_updated,
                    "onus_touched": len(touched_serials),
                    "onus_sent_to_db": len(payload.get("onus", [])),
                    "walk_errors": walk_errors,
                },
            }
        )
        if discovered_cache:
            with SNMP_INDEX_CACHE_LOCK:
                cache_for_olt = dict(SNMP_INDEX_CACHE.get(int(olt.get("id") or 0)) or {})
                cache_for_olt.update(discovered_cache)
                SNMP_INDEX_CACHE[int(olt.get("id") or 0)] = cache_for_olt
    except Exception as error:
        payload.setdefault("events", []).append(
            {
                "level": "warning",
                "message": f"SNMP nao aplicado: {error}",
                "details": {
                    "snmp_version": snmp_version,
                    "serial_oid": serial_oid,
                    "vlan_oid": vlan_oid,
                    "signal_oid": signal_oid,
                    "signal_tx_oid": signal_tx_oid,
                    "signal_olt_rx_oid": signal_olt_rx_oid,
                    "temperature_oid": temperature_oid,
                    "status_oid": status_oid,
                    "distance_oid": distance_oid,
                    "port_status_oid": port_status_oid,
                    "port_count_oid": port_count_oid,
                },
            }
        )


def _expand_metric_index_suffix(index_suffix):
    # Huawei may encode ONU metric index as single integer:
    # encoded = port_index + (ont_id * 256), while inventory tables expose (port_index, ont_id).
    if isinstance(index_suffix, tuple) and len(index_suffix) == 2:
        try:
            port_index = int(index_suffix[0])
            ont_id = int(index_suffix[1])
            return [(port_index + (ont_id * 256),)]
        except Exception:
            return []
    return []


def _onu_index_candidates(onu):
    board_slot = str(onu.get("board_slot") or "")
    port_name = str(onu.get("port_name") or "")
    ont_id = onu.get("pon_position")
    if ont_id is None:
        return []
    try:
        ont_id = int(ont_id)
    except Exception:
        return []

    frame_slot = []
    if "/" in board_slot:
        parts = board_slot.split("/")
        if len(parts) == 2:
            try:
                frame_slot = [int(parts[0]), int(parts[1])]
            except Exception:
                frame_slot = []

    port_number = None
    if port_name.upper().startswith("PON"):
        try:
            port_number = int(port_name.split()[-1]) - 1
        except Exception:
            port_number = None

    candidates = []
    if frame_slot and port_number is not None:
        candidates.append((frame_slot[0], frame_slot[1], port_number, ont_id))
    if frame_slot and port_number is not None:
        candidates.append((frame_slot[1], port_number, ont_id))
    if port_number is not None:
        candidates.append((port_number, ont_id))
    candidates.append((ont_id,))
    return candidates


def _port_index_candidates(port_row):
    board_slot = str(port_row.get("board_slot") or "")
    port_name = str(port_row.get("name") or "")
    frame = None
    slot = None
    if "/" in board_slot:
        parts = board_slot.split("/")
        if len(parts) == 2:
            try:
                frame = int(parts[0])
                slot = int(parts[1])
            except Exception:
                frame = None
                slot = None
    port_num = None
    if port_name.upper().startswith("PON"):
        try:
            port_num = int(port_name.split()[-1])
        except Exception:
            port_num = None
    if port_num is None:
        return []
    zero = port_num - 1
    candidates = []
    if frame is not None and slot is not None:
        candidates.extend(
            [
                (frame, slot, zero),
                (frame, slot, port_num),
            ]
        )
    if slot is not None:
        candidates.extend(
            [
                (slot, zero),
                (slot, port_num),
            ]
        )
    candidates.extend([(zero,), (port_num,)])
    return candidates


def _is_valid_snmp_metric(value):
    try:
        numeric = float(value)
    except Exception:
        return False
    if numeric >= 2147483647:
        return False
    if numeric <= -2147483647:
        return False
    return True


def _is_valid_onu_signal_dbm(value):
    if not _is_valid_snmp_metric(value):
        return False
    try:
        numeric = float(value)
    except Exception:
        return False
    if abs(numeric) < 0.001:
        return False
    return -45.0 <= numeric <= 10.0


def _is_valid_onu_signal_tx_dbm(value):
    if not _is_valid_snmp_metric(value):
        return False
    try:
        numeric = float(value)
    except Exception:
        return False
    return -10.0 <= numeric <= 10.0


def _has_optical_signal_evidence(onu):
    if not isinstance(onu, dict):
        return False
    signal_dbm = onu.get("signal_dbm")
    signal_olt_rx_dbm = onu.get("signal_olt_rx_dbm")
    return _is_valid_onu_signal_dbm(signal_dbm) or _is_valid_onu_signal_dbm(signal_olt_rx_dbm)


def _is_valid_onu_temperature_c(value):
    if not _is_valid_snmp_metric(value):
        return False
    try:
        numeric = float(value)
    except Exception:
        return False
    return -20.0 <= numeric <= 120.0


def _convert_signal_olt_rx_dbm(value, scale, offset):
    if not _is_valid_snmp_metric(value):
        return None
    try:
        numeric = float(value)
    except Exception:
        return None
    # Huawei hwGponOntOpticalDdmOltRxOntPower often comes in nW (e.g. 7400),
    # while other firmwares expose centi-dBm like the regular signal OIDs.
    if numeric > 1000:
        try:
            converted = round(10.0 * math.log10(max(numeric, 1.0) / 1_000_000.0), 2)
        except Exception:
            return None
        return converted if _is_valid_onu_signal_dbm(converted) else None
    converted = round(numeric * scale + offset, 2)
    return converted if _is_valid_onu_signal_dbm(converted) else None


def _build_collector(olt_id):
    context = db.fetch_olt_context(olt_id)
    olt = context["olt"]
    connection = db.fetch_connection_for_olt(olt_id)
    protocol = (connection.get("protocol") or "mock").lower()
    collector_cls = COLLECTOR_BY_PROTOCOL.get(protocol)
    if not collector_cls:
        raise CollectorError(f"Protocolo de coleta nao suportado: {protocol}")
    return collector_cls(olt, connection, context)


def poll_olt(olt_id, force_full_inventory=False):
    with POLL_LOCK:
        try:
            _set_poll_progress(olt_id, 5, "Iniciando coleta")
            collector = _build_collector(olt_id)
            if force_full_inventory and isinstance(collector, NativeCollector):
                extra = dict(collector.connection.get("extra_config") or {})
                extra["force_full_inventory"] = True
                collector.connection["extra_config"] = extra
            _set_poll_progress(olt_id, 20, "Conectando e lendo dados")
            payload = collector.collect()
            coverage = _extract_poll_coverage(payload.get("events"))
            _set_poll_progress(olt_id, 85, "Aplicando dados no banco")
            applied = db.apply_collection(olt_id, payload)
            db.update_connection_poll_status(olt_id, "ok", None, applied["collected_at"])
            _set_poll_progress(
                olt_id,
                100,
                "Coleta concluida",
                status="ok",
                details=_format_poll_coverage_details(coverage),
                coverage=coverage,
            )
            return {
                "olt_id": olt_id,
                "status": "ok",
                "protocol": collector.protocol,
                "collected_at": applied["collected_at"],
                "events_added": applied["events_added"],
                "coverage": coverage,
            }
        except Exception as error:
            protocol = "unknown"
            if "collector" in locals():
                protocol = collector.protocol
            db.update_connection_poll_status(olt_id, "error", str(error), db.utc_now())
            db.add_collector_event(olt_id, "error", str(error), {"protocol": protocol})
            _set_poll_progress(olt_id, 100, "Falha na coleta", status="error", details=str(error))
            return {"olt_id": olt_id, "status": "error", "error": str(error)}


def start_poll_olt(olt_id, force_full_inventory=False):
    with ASYNC_POLL_LOCK:
        thread = ASYNC_POLL_THREADS.get(int(olt_id))
        if thread and thread.is_alive():
            progress = get_poll_progress(olt_id)
            return {
                "olt_id": int(olt_id),
                "status": "running",
                "message": "Coleta ja em andamento.",
                "progress": progress,
            }

        _set_poll_progress(int(olt_id), 1, "Coleta enfileirada", status="running")

        def _runner():
            try:
                poll_olt(int(olt_id), force_full_inventory=force_full_inventory)
            finally:
                with ASYNC_POLL_LOCK:
                    current = ASYNC_POLL_THREADS.get(int(olt_id))
                    if current is threading.current_thread():
                        ASYNC_POLL_THREADS.pop(int(olt_id), None)

        thread = threading.Thread(
            target=_runner,
            name=f"poll-olt-{int(olt_id)}",
            daemon=True,
        )
        ASYNC_POLL_THREADS[int(olt_id)] = thread
        thread.start()

    return {
        "olt_id": int(olt_id),
        "status": "started",
        "message": "Coleta iniciada em segundo plano.",
    }


def poll_all():
    results = []
    for olt_id in [item["olt_id"] for item in db.fetch_connections() if item["enabled"]]:
        results.append(poll_olt(olt_id))
    return {"status": "ok", "results": results, "updated_at": db.utc_now()}


def poll_due_connections():
    results = []
    for olt_id in db.list_due_connections():
        results.append(poll_olt(olt_id))
    return results


def _build_autofind_payload(authorization_requests):
    boards_by_slot = {}
    ports_by_key = {}
    normalized_requests = []

    for item in authorization_requests or []:
        board_slot = str(item.get("board_slot") or "").strip()
        port_name = str(item.get("port_name") or "").strip()
        serial = str(item.get("serial") or "").strip().upper()
        detected_model = str(item.get("detected_model") or "Desconhecido").strip() or "Desconhecido"
        if not board_slot or not port_name or not serial:
            continue
        try:
            port_number = max(1, int(port_name.split()[-1]))
        except Exception:
            port_number = 1
        board = boards_by_slot.get(board_slot)
        if not board:
            board = {
                "slot": board_slot,
                "model": "GPON",
                "status": "online",
                "ports_total": port_number,
            }
            boards_by_slot[board_slot] = board
        else:
            board["ports_total"] = max(int(board.get("ports_total") or 0), port_number)
        port_key = (board_slot, port_name)
        if port_key not in ports_by_key:
            ports_by_key[port_key] = {
                "board_slot": board_slot,
                "name": port_name,
                "capacity_onu": 128,
                "alert_threshold_pct": 80,
                "used_onu": 0,
            }
        normalized_requests.append(
            {
                "serial": serial,
                "detected_model": detected_model,
                "board_slot": board_slot,
                "port_name": port_name,
                "requested_signal_dbm": item.get("requested_signal_dbm"),
                "requested_temperature_c": item.get("requested_temperature_c"),
                "notes": item.get("notes") or "Detectada pelo autofind Huawei.",
            }
        )

    return {
        "collected_at": db.utc_now(),
        "olt_metrics": {},
        "boards": list(boards_by_slot.values()),
        "ports": list(ports_by_key.values()),
        "onus": [],
        "authorization_requests": normalized_requests,
        "events": [],
    }


def _extract_command_output(outputs, command):
    for item in outputs or []:
        if item.get("command") == command:
            return item.get("output") or ""
    return ""


def _run_huawei_cli_commands(connection, commands, purpose):
    transport_type = (connection.get("transport_type") or "ssh").strip().lower()
    host = connection.get("olt_host")
    username = (connection.get("username") or "").strip()
    password = connection.get("password")
    if not host or not username:
        raise CollectorError(f"Host/usuario da OLT nao configurados para {purpose}.")

    extra = connection.get("extra_config") or {}
    command_timeout = int(connection.get("command_timeout_sec") or 30)
    if transport_type == "ssh":
        return run_huawei_commands_native(
            host=host,
            username=username,
            password=password,
            port=int(connection.get("port") or 22),
            timeout=max(20, command_timeout),
            key_path=extra.get("ssh_key_path"),
            commands=commands,
        )
    if transport_type == "telnet":
        return run_huawei_commands_over_telnet(
            host=host,
            username=username,
            password=password,
            port=int(connection.get("port") or 23),
            timeout=max(25, command_timeout),
            command_timeout=int(extra.get("telnet_command_timeout_sec") or min(20, command_timeout)),
            commands=commands,
        )
    raise CollectorError(f"{purpose.capitalize()} suporta apenas SSH ou Telnet.")


def _collect_huawei_autofind_requests(connection):
    autofind_command = "display ont autofind all"
    commands = ["screen-length 0 temporary", autofind_command]
    outputs = _run_huawei_cli_commands(connection, commands, "autofind")
    autofind_output = _extract_command_output(outputs, autofind_command)
    lowered_output = str(autofind_output or "").strip().lower()
    if "automatically found onts do not exist" in lowered_output:
        return [], autofind_output
    if _looks_like_huawei_command_failure(autofind_output):
        raise CollectorError("Falha ao executar display ont autofind all na OLT.")
    requests = []
    for item in parse_autofind(autofind_output):
        normalized = dict(item)
        suggestion = db.suggest_detected_onu_model(
            normalized.get("serial"),
            normalized.get("detected_model"),
        )
        suggested_model = str(suggestion.get("model") or "").strip()
        if suggested_model:
            normalized["detected_model"] = suggested_model
        if suggestion.get("source") == "serial-prefix" and suggested_model:
            details = f"modelo inferido do inventario: {suggested_model}"
            current_notes = str(normalized.get("notes") or "").strip()
            if details.lower() not in current_notes.lower():
                normalized["notes"] = f"{current_notes} | {details}".strip(" |")
        requests.append(normalized)
    return requests, autofind_output


def _collect_huawei_profile_catalog(connection):
    line_command = "display ont-lineprofile gpon all"
    service_command = "display ont-srvprofile gpon all"
    outputs = _run_huawei_cli_commands(
        connection,
        ["screen-length 0 temporary", line_command, service_command],
        "coleta de perfis",
    )
    line_output = _extract_command_output(outputs, line_command)
    service_output = _extract_command_output(outputs, service_command)
    if _looks_like_huawei_command_failure(line_output):
        raise CollectorError("Falha ao executar display ont-lineprofile gpon all na OLT.")
    if _looks_like_huawei_command_failure(service_output):
        raise CollectorError("Falha ao executar display ont-srvprofile gpon all na OLT.")

    line_profiles = parse_profile_summary(line_output)
    service_profiles = parse_profile_summary(service_output)
    if not line_profiles:
        raise CollectorError("Nenhum line profile reconhecido na OLT.")
    if not service_profiles:
        raise CollectorError("Nenhum service profile reconhecido na OLT.")
    return {
        "collected_at": db.utc_now(),
        "line": line_profiles,
        "service": service_profiles,
    }


def sync_olt_profiles(olt_id):
    connection = db.fetch_connection_for_olt(int(olt_id))
    if not connection.get("enabled"):
        raise CollectorError("Coleta desabilitada para esta OLT.")
    brand = (connection.get("olt_brand") or "").strip().lower()
    protocol = (connection.get("protocol") or "").strip().lower()
    if brand != "huawei" or protocol != "native":
        raise CollectorError("Sincronizacao de perfis disponivel apenas para Huawei native.")

    catalog = _collect_huawei_profile_catalog(connection)
    db.replace_olt_profiles(
        int(olt_id),
        {"line": catalog["line"], "service": catalog["service"]},
        source="cli",
        collected_at=catalog["collected_at"],
    )
    db.add_collector_event(
        int(olt_id),
        "info",
        (
            f'Perfis da OLT sincronizados: {len(catalog["line"])} line profile(s) e '
            f'{len(catalog["service"])} service profile(s).'
        ),
        {
            "mode": "manual-profile-sync",
            "line_profiles": len(catalog["line"]),
            "service_profiles": len(catalog["service"]),
        },
        created_at=catalog["collected_at"],
    )
    return {
        "status": "ok",
        "olt_id": int(olt_id),
        "olt_name": connection.get("olt_name") or f"OLT {olt_id}",
        "line_profiles": len(catalog["line"]),
        "service_profiles": len(catalog["service"]),
        "updated_at": catalog["collected_at"],
    }


def run_olt_profile_sync_all():
    results = []
    total_line_profiles = 0
    total_service_profiles = 0
    ok_count = 0
    error_count = 0
    skipped_count = 0

    for connection in db.fetch_connections():
        olt_id = int(connection["olt_id"])
        brand = (connection.get("olt_brand") or "").strip().lower()
        protocol = (connection.get("protocol") or "").strip().lower()
        item = {
            "olt_id": olt_id,
            "olt_name": connection.get("olt_name") or f"OLT {olt_id}",
            "status": "skipped",
            "line_profiles": 0,
            "service_profiles": 0,
        }
        if not connection.get("enabled"):
            item["reason"] = "Coleta desabilitada."
            results.append(item)
            skipped_count += 1
            continue
        if brand != "huawei" or protocol != "native":
            item["reason"] = "Sincronizacao de perfis disponivel apenas para Huawei native."
            results.append(item)
            skipped_count += 1
            continue

        try:
            result = sync_olt_profiles(olt_id)
            item.update(result)
            total_line_profiles += int(result.get("line_profiles") or 0)
            total_service_profiles += int(result.get("service_profiles") or 0)
            ok_count += 1
        except Exception as error:
            item["status"] = "error"
            item["error"] = str(error)
            error_count += 1
            db.add_collector_event(
                olt_id,
                "error",
                f"Falha na sincronizacao de perfis: {error}",
                {"mode": "manual-profile-sync"},
            )
        results.append(item)

    return {
        "status": "ok",
        "updated_at": db.utc_now(),
        "line_profiles": total_line_profiles,
        "service_profiles": total_service_profiles,
        "olts_ok": ok_count,
        "olts_error": error_count,
        "olts_skipped": skipped_count,
        "results": results,
    }


def run_autofind_all():
    results = []
    total_requests = 0
    ok_count = 0
    error_count = 0
    skipped_count = 0

    for connection in db.fetch_connections():
        olt_id = int(connection["olt_id"])
        brand = (connection.get("olt_brand") or "").strip().lower()
        protocol = (connection.get("protocol") or "").strip().lower()
        item = {
            "olt_id": olt_id,
            "olt_name": connection.get("olt_name") or f"OLT {olt_id}",
            "status": "skipped",
            "requests_found": 0,
        }
        if not connection.get("enabled"):
            item["reason"] = "Coleta desabilitada."
            results.append(item)
            skipped_count += 1
            continue
        if brand != "huawei" or protocol != "native":
            item["reason"] = "Autofind manual disponivel apenas para Huawei native."
            results.append(item)
            skipped_count += 1
            continue

        try:
            requests, _ = _collect_huawei_autofind_requests(connection)
            payload = _build_autofind_payload(requests)
            payload["events"].append(
                {
                    "level": "info",
                    "message": f"Autofind manual executado: {len(requests)} solicitacoes detectadas.",
                    "details": {"mode": "manual-autofind"},
                }
            )
            db.apply_collection(olt_id, payload)
            item["status"] = "ok"
            item["requests_found"] = len(requests)
            total_requests += len(requests)
            ok_count += 1
        except Exception as error:
            item["status"] = "error"
            item["error"] = str(error)
            error_count += 1
            db.add_collector_event(
                olt_id,
                "error",
                f"Falha no autofind manual: {error}",
                {"mode": "manual-autofind"},
            )
        results.append(item)

    return {
        "status": "ok",
        "updated_at": db.utc_now(),
        "requests_found": total_requests,
        "olts_ok": ok_count,
        "olts_error": error_count,
        "olts_skipped": skipped_count,
        "results": results,
    }


def _parse_first_service_port_index_from_config(output):
    for line in (output or "").splitlines():
        match = re.match(r"(?i)^\s*service-port\s+(?P<index>\d+)\s+vlan\s+\d+\s+gpon\b", line)
        if match:
            return int(match.group("index"))
    return None


def _parse_huawei_service_port_defaults(output):
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    gemport_match = re.search(r"(?im)^\s*GEM port index\s*:\s*(\d+)\s*$", text)
    tx_match = re.search(r"(?im)^\s*TX\s*:\s*(\d+)\s*$", text)
    rx_match = re.search(r"(?im)^\s*RX\s*:\s*(\d+)\s*$", text)
    tag_match = re.search(r"(?im)^\s*Tag transform\s*:\s*([A-Za-z-]+)\s*$", text)
    return {
        "gemport": int(gemport_match.group(1)) if gemport_match else 1,
        "tx": int(tx_match.group(1)) if tx_match else None,
        "rx": int(rx_match.group(1)) if rx_match else None,
        "tag_transform": (tag_match.group(1).strip().lower() if tag_match else "translate"),
    }


def _infer_huawei_service_port_defaults(connection):
    extra = connection.get("extra_config") or {}
    configured_tx = extra.get("provision_inbound_traffic_table")
    configured_rx = extra.get("provision_outbound_traffic_table")
    configured_gemport = extra.get("provision_gemport")
    configured_tag = extra.get("provision_tag_transform")
    if configured_tx not in (None, "") and configured_rx not in (None, ""):
        return {
            "gemport": int(configured_gemport or 1),
            "tx": int(configured_tx),
            "rx": int(configured_rx),
            "tag_transform": str(configured_tag or "translate").strip().lower() or "translate",
            "source": "config",
        }

    try:
        base_command = "display current-configuration | include service-port"
        outputs = _run_huawei_cli_commands(connection, [base_command], "inferir service-port")
        config_output = _extract_command_output(outputs, base_command)
        service_port_index = _parse_first_service_port_index_from_config(config_output)
        if service_port_index is None:
            return {
                "gemport": int(configured_gemport or 1),
                "tx": int(configured_tx) if configured_tx not in (None, "") else None,
                "rx": int(configured_rx) if configured_rx not in (None, "") else None,
                "tag_transform": str(configured_tag or "translate").strip().lower() or "translate",
                "source": "fallback",
            }
        detail_command = f"display service-port {service_port_index}"
        detail_outputs = _run_huawei_cli_commands(connection, [detail_command], "detalhar service-port")
        detail_output = _extract_command_output(detail_outputs, detail_command)
        parsed = _parse_huawei_service_port_defaults(detail_output)
        parsed["source"] = "live"
        return parsed
    except Exception:
        return {
            "gemport": int(configured_gemport or 1),
            "tx": int(configured_tx) if configured_tx not in (None, "") else None,
            "rx": int(configured_rx) if configured_rx not in (None, "") else None,
            "tag_transform": str(configured_tag or "translate").strip().lower() or "translate",
            "source": "fallback",
        }


def _sanitize_huawei_description(value, max_length=64):
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return "Cliente sem nome"
    return text.replace('"', "'")[:max_length]


def _infer_huawei_native_vlan_eth_port(connection, context=None):
    extra = connection.get("extra_config") or {}
    requested_port = context.get("native_vlan_eth_port") if isinstance(context, dict) else None
    try:
        eth_port = int(requested_port or extra.get("provision_native_vlan_eth_port") or 1)
    except Exception:
        eth_port = 1
    return max(1, eth_port)


def _build_huawei_native_vlan_command(context, ont_id, eth_port=1):
    rendered_ont_id = int(ont_id) if isinstance(ont_id, (int, float)) or str(ont_id).isdigit() else str(ont_id)
    return (
        f'ont port native-vlan {int(context["port_index"])} {rendered_ont_id} '
        f'eth {max(1, int(eth_port))} vlan {int(context["vlan_id"])} priority 0'
    )


def _build_huawei_authorize_plan(context, connection):
    warnings = []
    notes = [
        "O comando de ont add retorna o ONT-ID; use esse valor no service-port.",
    ]
    line_profile = context.get("line_profile") or {}
    service_profile = context.get("service_profile") or {}
    if not line_profile.get("name"):
        warnings.append("Line profile nao definido para a solicitacao.")
    if not service_profile.get("name"):
        warnings.append("Service profile nao definido para a solicitacao.")
    if int(context.get("vlan_id") or 0) < 1:
        warnings.append("VLAN nao definida; ajuste antes de provisionar.")

    desc_value = _sanitize_huawei_description(context.get("client_name"))
    port_index = int(context.get("port_index") or 0)
    add_by_name_command = None
    if line_profile.get("name") and service_profile.get("name"):
        add_by_name_parts = [
            f'ont add {port_index} sn-auth {context["serial"]} omci',
            f'ont-lineprofile-name {line_profile["name"]}',
            f'ont-srvprofile-name {service_profile["name"]}',
            f'desc "{desc_value}"',
        ]
        add_by_name_command = " ".join(add_by_name_parts)

    add_by_id_command = None
    if line_profile.get("profile_ref") is not None and service_profile.get("profile_ref") is not None:
        add_by_id_parts = [
            f'ont add {port_index} sn-auth {context["serial"]} omci',
            f'ont-lineprofile-id {int(line_profile["profile_ref"])}',
            f'ont-srvprofile-id {int(service_profile["profile_ref"])}',
            f'desc "{desc_value}"',
        ]
        add_by_id_command = " ".join(add_by_id_parts)

    defaults = _infer_huawei_service_port_defaults(connection)
    if defaults.get("source") == "live":
        notes.append("Gemport e traffic-tables inferidos do service-port atual da OLT.")
    elif defaults.get("source") == "config":
        notes.append("Gemport e traffic-tables vieram do template configurado na conexao da OLT.")
    else:
        notes.append("Gemport e traffic-tables estao em fallback; confirme no padrao operacional da OLT.")

    if defaults.get("tx") is None:
        warnings.append("Inbound traffic-table nao identificado; revise antes de executar o service-port.")
    if defaults.get("rx") is None:
        warnings.append("Outbound traffic-table nao identificado; revise antes de executar o service-port.")
    native_vlan_eth_port = _infer_huawei_native_vlan_eth_port(connection, context)
    onu_mode = str(context.get("onu_mode") or "bridge").strip().lower()
    notes.append(f'Modo selecionado: {"Routing" if onu_mode == "route" else "Bridging"}.')
    notes.append(f"Native VLAN sera aplicada na porta ETH {native_vlan_eth_port}.")

    return {
        "warnings": warnings,
        "notes": notes,
        "defaults": defaults,
        "native_vlan_eth_port": native_vlan_eth_port,
        "add_by_name_command": add_by_name_command,
        "add_by_id_command": add_by_id_command,
    }


def _build_huawei_service_port_command(context, defaults, ont_id):
    rendered_ont_id = int(ont_id) if isinstance(ont_id, (int, float)) or str(ont_id).isdigit() else str(ont_id)
    parts = [
        f'service-port vlan {int(context["vlan_id"])} gpon {context["fsp"]} ont {rendered_ont_id} gemport {int(defaults.get("gemport") or 1)}',
        f'multi-service user-vlan {int(context["vlan_id"])}',
    ]
    if defaults.get("tag_transform"):
        parts.append(f'tag-transform {defaults["tag_transform"]}')
    if defaults.get("tx") is not None:
        parts.append(f'inbound traffic-table index {int(defaults["tx"])}')
    if defaults.get("rx") is not None:
        parts.append(f'outbound traffic-table index {int(defaults["rx"])}')
    return " ".join(parts)


def _build_huawei_authorize_preview(context, connection):
    plan = _build_huawei_authorize_plan(context, connection)
    defaults = plan["defaults"]
    native_vlan_command = _build_huawei_native_vlan_command(
        context,
        "<ONT_ID>",
        eth_port=plan["native_vlan_eth_port"],
    )
    service_port_command = _build_huawei_service_port_command(context, defaults, "<ONT_ID>")

    commands = [
        {"step": "Entrar em configuracao", "command": "config"},
        {"step": "Entrar na interface GPON", "command": f'interface gpon {context["board_slot"]}'},
    ]
    if plan["add_by_name_command"]:
        commands.append({"step": "Adicionar ONU por nome de profile", "command": plan["add_by_name_command"]})
    if plan["add_by_id_command"]:
        commands.append(
            {
                "step": "Alternativa por ID de profile",
                "command": plan["add_by_id_command"],
                "optional": True,
            }
        )
    commands.append({"step": "Aplicar native-vlan", "command": native_vlan_command})
    commands.append({"step": "Criar service-port", "command": service_port_command})
    return {
        "supported": True,
        "mode": "huawei-native-authorize-preview",
        "commands": commands,
        "warnings": plan["warnings"],
        "notes": plan["notes"],
        "placeholders": {
            "ont_id": "Retornado pelo comando ont add",
            "service_port_index": "Automatico quando o comando nao informa index",
        },
        "template": {
            "gemport": int(plan["defaults"].get("gemport") or 1),
            "tag_transform": plan["defaults"].get("tag_transform") or "translate",
            "inbound_traffic_table": plan["defaults"].get("tx"),
            "outbound_traffic_table": plan["defaults"].get("rx"),
            "source": plan["defaults"].get("source") or "fallback",
        },
    }


def _resolve_huawei_onu_location_with_retry(context, connection, transport_type, command_timeout, retries=3, delay_sec=1.0):
    lookup_onu = {
        "serial": context.get("serial"),
        "olt_host": context.get("olt_host"),
    }
    for attempt in range(max(1, int(retries))):
        resolved = _resolve_huawei_onu_location_by_serial(lookup_onu, connection, transport_type, command_timeout)
        if resolved and resolved.get("ont_id") is not None:
            return resolved
        if attempt + 1 < retries:
            time.sleep(delay_sec)
    return None


def _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout):
    serial = str(context.get("serial") or "").strip()
    onu = {
        "serial": serial,
        "olt_id": int(context["olt_id"]),
        "olt_host": context.get("olt_host"),
    }
    if (not resolved_location or resolved_location.get("ont_id") is None) and serial:
        resolved_location = _resolve_huawei_onu_location_with_retry(
            context,
            connection,
            transport_type,
            command_timeout,
            retries=2,
            delay_sec=0.8,
        )
    rollback = {
        "serial": serial,
        "service_ports_removed": [],
        "delete_attempts": [],
    }

    fsp = (resolved_location or {}).get("fsp")
    effective_ont_id = int((resolved_location or {}).get("ont_id") or ont_id or 0)
    if fsp and effective_ont_id:
        cleanup = _remove_huawei_service_ports_for_onu(
            onu=onu,
            connection=connection,
            transport_type=transport_type,
            command_timeout=command_timeout,
            fsp=fsp,
            ont_id=effective_ont_id,
        )
        rollback["service_ports_removed"] = cleanup.get("removed") or []

    board_slot = str((resolved_location or {}).get("board_slot") or context.get("board_slot") or "").strip()
    port_name = str((resolved_location or {}).get("port_name") or context.get("port_name") or "").strip()
    if not board_slot or not effective_ont_id:
        return rollback

    for delete_command in _huawei_delete_command_candidates(board_slot, port_name, effective_ont_id):
        try:
            outputs = _run_huawei_cli_commands(
                connection,
                ["enable", "config", f"interface gpon {board_slot}", delete_command, "quit", "quit"],
                "rollback de provisionamento",
            )
        except Exception as error:
            rollback["delete_attempts"].append({"command": delete_command, "output": str(error)})
            continue
        delete_output = _extract_command_output(outputs, delete_command)
        rollback["delete_attempts"].append({"command": delete_command, "output": delete_output})
        if not _looks_like_huawei_command_failure(delete_output):
            rollback["deleted"] = True
            rollback["delete_command"] = delete_command
            return rollback
    return rollback


def _summarize_huawei_attempts(attempts):
    if not attempts:
        return ""
    parts = []
    for item in attempts:
        command = item.get("command") or "comando"
        output = " ".join(str(item.get("output") or "").split())
        parts.append(f"{command}: {output[:160] or 'sem resposta'}")
    return "; ".join(parts)


def authorize_request_on_olt(request_id, payload=None, progress_callback=None):
    payload = payload or {}
    if progress_callback:
        progress_callback(8, "Validando solicitacao", "prepare")
    context = db.prepare_request_provisioning_context(int(request_id), payload)
    connection = db.fetch_connection_for_olt(int(context["olt_id"]))
    brand = str(context.get("olt_brand") or "").strip().lower()
    protocol = str(connection.get("protocol") or "").strip().lower()
    transport_type = (connection.get("transport_type") or "ssh").strip().lower()

    if context.get("action") != "authorize":
        raise CollectorError("A solicitacao exige mover a ONU. Use a acao de mover.")
    if brand != "huawei":
        raise CollectorError("Provisionamento real suportado apenas para Huawei.")
    if protocol != "native":
        raise CollectorError("Provisionamento real requer protocolo native.")
    if transport_type not in {"ssh", "telnet"}:
        raise CollectorError("Provisionamento real requer transporte SSH ou Telnet.")

    plan = _build_huawei_authorize_plan(context, connection)
    add_candidates = []
    for candidate in [plan.get("add_by_name_command"), plan.get("add_by_id_command")]:
        if candidate and candidate not in add_candidates:
            add_candidates.append(candidate)
    if not add_candidates:
        raise CollectorError("Line profile/service profile da OLT nao configurados para provisionamento.")

    if progress_callback:
        progress_callback(28, "Adicionando ONU na OLT", "olt_add", details=f'Interface GPON {context["board_slot"]}')
    add_attempts = []
    add_command = None
    add_output = ""
    for candidate in add_candidates:
        try:
            outputs = _run_huawei_cli_commands(
                connection,
                ["enable", "config", f'interface gpon {context["board_slot"]}', candidate, "quit", "quit"],
                "provisionamento de ONU",
            )
        except Exception as error:
            add_attempts.append({"command": candidate, "output": str(error)})
            continue
        candidate_output = _extract_command_output(outputs, candidate)
        add_attempts.append({"command": candidate, "output": candidate_output})
        if not _looks_like_huawei_command_failure(candidate_output):
            add_command = candidate
            add_output = candidate_output
            break

    if not add_command:
        details = _summarize_huawei_attempts(add_attempts)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Falha ao provisionar ONU {context["serial"]} na OLT',
            {"request_id": int(request_id), "attempts": add_attempts},
        )
        raise CollectorError(f"Falha ao adicionar ONU na OLT. {details}".strip())

    command_timeout = int(connection.get("command_timeout_sec") or 30)
    if progress_callback:
        progress_callback(54, "Confirmando ONT-ID", "ont_lookup", details="Consultando display ont info by-sn")
    resolved_location = _resolve_huawei_onu_location_with_retry(
        context,
        connection,
        transport_type,
        command_timeout,
    )
    ont_id = (resolved_location or {}).get("ont_id")
    if ont_id is None:
        rollback = _rollback_huawei_authorize_onu(context, connection, None, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'ONU {context["serial"]} adicionada sem ONT-ID confirmado; rollback acionado',
            {"request_id": int(request_id), "rollback": rollback, "add_command": add_command},
        )
        raise CollectorError("A ONU foi adicionada, mas nao foi possivel confirmar o ONT-ID retornado pela OLT.")

    native_vlan_command = _build_huawei_native_vlan_command(
        context,
        ont_id,
        eth_port=plan["native_vlan_eth_port"],
    )
    if progress_callback:
        progress_callback(
            68,
            "Aplicando native-vlan",
            "native_vlan",
            details=f'ETH {int(plan["native_vlan_eth_port"])} / VLAN {int(context["vlan_id"])}',
        )
    try:
        native_vlan_outputs = _run_huawei_cli_commands(
            connection,
            ["enable", "config", f'interface gpon {context["board_slot"]}', native_vlan_command, "quit", "quit"],
            "aplicacao de native-vlan",
        )
    except Exception as error:
        rollback = _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Falha ao aplicar native-vlan da ONU {context["serial"]}; rollback acionado',
            {
                "request_id": int(request_id),
                "error": str(error),
                "native_vlan_command": native_vlan_command,
                "rollback": rollback,
            },
        )
        raise CollectorError(f"Falha ao aplicar native-vlan na OLT: {error}")

    native_vlan_output = _extract_command_output(native_vlan_outputs, native_vlan_command)
    if _looks_like_huawei_command_failure(native_vlan_output):
        rollback = _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Falha ao aplicar native-vlan da ONU {context["serial"]}; rollback acionado',
            {
                "request_id": int(request_id),
                "native_vlan_command": native_vlan_command,
                "native_vlan_output": native_vlan_output,
                "rollback": rollback,
            },
        )
        raise CollectorError(f"Falha ao aplicar native-vlan na OLT: {native_vlan_output}")

    service_port_command = _build_huawei_service_port_command(context, plan["defaults"], ont_id)
    if progress_callback:
        progress_callback(82, "Criando service-port", "service_port", details=f'ONT-ID {int(ont_id)} / VLAN {int(context["vlan_id"])}')
    try:
        service_outputs = _run_huawei_cli_commands(
            connection,
            ["enable", "config", service_port_command, "quit"],
            "criacao de service-port",
        )
    except Exception as error:
        rollback = _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Falha ao criar service-port da ONU {context["serial"]}; rollback acionado',
            {
                "request_id": int(request_id),
                "error": str(error),
                "service_port_command": service_port_command,
                "rollback": rollback,
            },
        )
        raise CollectorError(f"Falha ao criar service-port na OLT: {error}")

    service_output = _extract_command_output(service_outputs, service_port_command)
    if _looks_like_huawei_command_failure(service_output):
        rollback = _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Falha ao finalizar provisionamento da ONU {context["serial"]}; rollback acionado',
            {
                "request_id": int(request_id),
                "service_port_command": service_port_command,
                "service_output": service_output,
                "rollback": rollback,
            },
        )
        raise CollectorError(f"Falha ao criar service-port na OLT: {service_output}")

    try:
        if progress_callback:
            progress_callback(94, "Gravando cadastro local", "local_save")
        local_result = db.authorize_request(int(request_id), payload, pon_position=ont_id)
    except Exception as error:
        rollback = _rollback_huawei_authorize_onu(context, connection, ont_id, resolved_location, transport_type, command_timeout)
        db.add_collector_event(
            int(context["olt_id"]),
            "warning",
            f'Provisionamento da ONU {context["serial"]} foi revertido por falha no banco local',
            {"request_id": int(request_id), "error": str(error), "rollback": rollback},
        )
        raise CollectorError(f"Provisionamento realizado na OLT, mas falhou ao gravar localmente: {error}")

    db.add_collector_event(
        int(context["olt_id"]),
        "info",
        f'ONU {context["serial"]} provisionada na OLT e autorizada no sistema',
        {
            "request_id": int(request_id),
            "onu_id": int(local_result["onu_id"]),
            "ont_id": int(ont_id),
            "resolved_fsp": (resolved_location or {}).get("fsp") or context.get("fsp"),
            "transport": transport_type,
            "add_command": add_command,
            "native_vlan_command": native_vlan_command,
            "service_port_command": service_port_command,
        },
    )
    return {
        "status": "authorized",
        "onu_id": int(local_result["onu_id"]),
        "ont_id": int(ont_id),
        "resolved_fsp": (resolved_location or {}).get("fsp") or context.get("fsp"),
        "transport_type": transport_type,
    }


def start_request_authorization(request_id, payload=None):
    request_id = int(request_id)
    payload = dict(payload or {})
    with ASYNC_REQUEST_AUTHORIZE_LOCK:
        thread = ASYNC_REQUEST_AUTHORIZE_THREADS.get(request_id)
        if thread and thread.is_alive():
            progress = get_request_authorize_progress(request_id)
            return {
                "request_id": request_id,
                "status": "running",
                "message": "Autorizacao ja em andamento.",
                "progress": progress,
            }

        _set_request_authorize_progress(
            request_id,
            1,
            "Autorizacao enfileirada",
            status="running",
            steps=_build_request_authorize_steps(active_key="prepare"),
        )

        def _runner():
            try:
                result = authorize_request_on_olt(
                    request_id,
                    payload,
                    progress_callback=lambda pct, stage, active_key, details=None: _update_request_authorize_stage(
                        request_id,
                        pct,
                        stage,
                        active_key,
                        details,
                    ),
                )
                _complete_request_authorize_progress(
                    request_id,
                    result=result,
                    details="ONU provisionada na OLT e gravada no sistema local.",
                )
            except Exception as error:
                progress = get_request_authorize_progress(request_id)
                steps = progress.get("steps") or []
                running_step = next((item for item in steps if item.get("state") == "running"), None)
                current_stage = running_step.get("key") if running_step else "prepare"
                _fail_request_authorize_progress(request_id, current_stage, str(error))
            finally:
                with ASYNC_REQUEST_AUTHORIZE_LOCK:
                    current = ASYNC_REQUEST_AUTHORIZE_THREADS.get(request_id)
                    if current is threading.current_thread():
                        ASYNC_REQUEST_AUTHORIZE_THREADS.pop(request_id, None)

        thread = threading.Thread(
            target=_runner,
            name=f"authorize-request-{request_id}",
            daemon=True,
        )
        ASYNC_REQUEST_AUTHORIZE_THREADS[request_id] = thread
        thread.start()

    return {
        "request_id": request_id,
        "status": "started",
        "message": "Autorizacao iniciada em segundo plano.",
    }


def build_request_provisioning_preview(request_id, payload=None):
    context = db.prepare_request_provisioning_context(int(request_id), payload or {})
    connection = db.fetch_connection_for_olt(int(context["olt_id"]))
    brand = str(context.get("olt_brand") or "").strip().lower()
    protocol = str(connection.get("protocol") or "").strip().lower()

    if context.get("action") != "authorize":
        return {
            "status": "ok",
            "request_id": int(request_id),
            "action": context.get("action") or "authorize",
            "supported": False,
            "warnings": ["Preview de mover ONU na OLT ainda nao implementado."],
            "notes": ["A movimentacao real vai exigir localizar a ONU antiga, remover service-port e reprovisionar na nova porta."],
            "commands": [],
            "context": context,
        }

    if brand != "huawei" or protocol != "native":
        return {
            "status": "ok",
            "request_id": int(request_id),
            "action": context.get("action") or "authorize",
            "supported": False,
            "warnings": ["Preview de provisionamento disponivel apenas para Huawei native."],
            "notes": [],
            "commands": [],
            "context": context,
        }

    preview = _build_huawei_authorize_preview(context, connection)
    preview.update(
        {
            "status": "ok",
            "request_id": int(request_id),
            "action": context.get("action") or "authorize",
            "context": context,
        }
    )
    return preview


def _huawei_delete_command_candidates(board_slot, port_name, ont_id):
    try:
        port_number = int(str(port_name).split()[-1])
        port_zero_based = max(0, port_number - 1)
        port_candidates = [port_zero_based, port_number]
    except Exception:
        port_candidates = [0]
    try:
        ont_id = int(ont_id)
    except Exception:
        ont_id = 0

    candidates = []
    for port_index in port_candidates:
        candidates.extend(
            [
                f"ont delete {port_index} {ont_id}",
                f"ont delete {port_index} ontid {ont_id}",
                f"undo ont {port_index} {ont_id}",
            ]
        )
    deduped = []
    for item in candidates:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _looks_like_huawei_command_failure(output):
    text = (output or "").strip().lower()
    if not text:
        return False
    # Huawei may return syntax continuation prompts like "{ ... }:" when command is incomplete/invalid.
    if re.search(r"\{[^{}\n]{1,300}\}:\s*$", text, flags=re.IGNORECASE | re.DOTALL):
        return True
    strict_markers = [
        "unknown command",
        "unrecognized command",
        "% error",
        "error:",
        "invalid",
        "not exist",
        "cannot",
        "wrong parameter",
        "parameter error",
        "in use",
    ]
    if any(marker in text for marker in strict_markers):
        return True
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    failure_line_patterns = [
        r"^fail(?:ed|ure)?\b",
        r"^error\b",
        r"^the command .* fail(?:ed|ure)?\b",
    ]
    return any(re.search(pattern, line) for line in lines[-4:] for pattern in failure_line_patterns)


def _parse_huawei_location_from_by_sn_output(output):
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    fs_match = re.search(r"(?im)^\s*F/S/P\s*:\s*(\d+/\d+/\d+)\s*$", text)
    ont_match = re.search(r"(?im)^\s*ONT-ID\s*:\s*(\d+)\s*$", text)
    if not fs_match or not ont_match:
        return None
    parts = fs_match.group(1).split("/")
    if len(parts) != 3:
        return None
    try:
        frame = int(parts[0])
        slot = int(parts[1])
        port_index = int(parts[2])
        ont_id = int(ont_match.group(1))
    except Exception:
        return None
    return {
        "board_slot": f"{frame}/{slot}",
        "port_name": f"PON {port_index + 1}",
        "ont_id": ont_id,
        "fsp": f"{frame}/{slot}/{port_index}",
    }


def _parse_service_port_indexes_from_output(output):
    indexes = []
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "gpon" not in stripped.lower():
            continue
        match = re.match(r"^\s*(\d+)\s+\d+\s+\S+\s+gpon\b", line, flags=re.IGNORECASE)
        if not match:
            continue
        index = int(match.group(1))
        if index not in indexes:
            indexes.append(index)
    return indexes


def _remove_huawei_service_ports_for_onu(onu, connection, transport_type, command_timeout, fsp, ont_id):
    host = onu.get("olt_host") or connection.get("olt_host")
    username = (connection.get("username") or "").strip()
    password = connection.get("password")
    if not host or not username:
        return {"removed": [], "lookup_output": "", "lookup_command": ""}
    extra = connection.get("extra_config") or {}
    lookup_command = f"display service-port port {fsp} ont {int(ont_id)}"

    try:
        if transport_type == "ssh":
            lookup_outputs = run_huawei_commands_native(
                host=host,
                username=username,
                password=password,
                port=int(connection.get("port") or 22),
                timeout=max(20, command_timeout),
                key_path=extra.get("ssh_key_path"),
                commands=["enable", lookup_command],
            )
        else:
            lookup_outputs = run_huawei_commands_over_telnet(
                host=host,
                username=username,
                password=password,
                port=int(connection.get("port") or 23),
                timeout=max(25, command_timeout),
                command_timeout=int(extra.get("telnet_command_timeout_sec") or min(20, command_timeout)),
                commands=["enable", lookup_command],
            )
    except Exception:
        return {"removed": [], "lookup_output": "", "lookup_command": lookup_command}

    lookup_output = ""
    for item in lookup_outputs:
        if item.get("command") == lookup_command:
            lookup_output = item.get("output") or ""
            break
    indexes = _parse_service_port_indexes_from_output(lookup_output)
    if not indexes:
        return {"removed": [], "lookup_output": lookup_output, "lookup_command": lookup_command}

    removed = []
    for index in indexes:
        undo_command = f"undo service-port {int(index)}"
        try:
            if transport_type == "ssh":
                undo_outputs = run_huawei_commands_native(
                    host=host,
                    username=username,
                    password=password,
                    port=int(connection.get("port") or 22),
                    timeout=max(20, command_timeout),
                    key_path=extra.get("ssh_key_path"),
                    commands=["enable", "config", undo_command, "quit"],
                )
            else:
                undo_outputs = run_huawei_commands_over_telnet(
                    host=host,
                    username=username,
                    password=password,
                    port=int(connection.get("port") or 23),
                    timeout=max(25, command_timeout),
                    command_timeout=int(extra.get("telnet_command_timeout_sec") or min(20, command_timeout)),
                    commands=["enable", "config", undo_command, "quit"],
                )
        except Exception:
            continue

        undo_output = ""
        for item in undo_outputs:
            if item.get("command") == undo_command:
                undo_output = item.get("output") or ""
                break
        if not _looks_like_huawei_command_failure(undo_output):
            removed.append(index)

    return {"removed": removed, "lookup_output": lookup_output, "lookup_command": lookup_command}


def _resolve_huawei_onu_location_by_serial(onu, connection, transport_type, command_timeout):
    serial = str(onu.get("serial") or "").strip()
    if not serial:
        return None

    host = onu.get("olt_host") or connection.get("olt_host")
    username = (connection.get("username") or "").strip()
    password = connection.get("password")
    if not host or not username:
        return None

    extra = connection.get("extra_config") or {}
    lookup_command = f"display ont info by-sn {serial}"
    try:
        if transport_type == "ssh":
            outputs = run_huawei_commands_native(
                host=host,
                username=username,
                password=password,
                port=int(connection.get("port") or 22),
                timeout=max(20, command_timeout),
                key_path=extra.get("ssh_key_path"),
                commands=["enable", lookup_command],
            )
        else:
            outputs = run_huawei_commands_over_telnet(
                host=host,
                username=username,
                password=password,
                port=int(connection.get("port") or 23),
                timeout=max(25, command_timeout),
                command_timeout=int(extra.get("telnet_command_timeout_sec") or min(20, command_timeout)),
                commands=["enable", lookup_command],
            )
    except Exception:
        return None

    for item in outputs:
        if item.get("command") == lookup_command:
            return _parse_huawei_location_from_by_sn_output(item.get("output") or "")
    return None


def delete_onu_on_olt(onu_id, progress_callback=None):
    onu_id = int(onu_id)
    if progress_callback:
        progress_callback(15, "Localizando ONU na OLT", "lookup")
    onu = db.fetch_onu_by_id(onu_id)
    connection = db.fetch_connection_for_olt(int(onu["olt_id"]))
    brand = (onu.get("olt_brand") or "").strip().lower()
    transport_type = (connection.get("transport_type") or "ssh").strip().lower()
    protocol = (connection.get("protocol") or "").strip().lower()

    if brand != "huawei":
        raise CollectorError("Exclusao na OLT real suportada apenas para Huawei.")
    if protocol != "native":
        raise CollectorError("Exclusao na OLT real requer protocolo native.")
    if transport_type not in {"ssh", "telnet"}:
        raise CollectorError("Exclusao na OLT real requer transporte SSH ou Telnet.")

    host = onu.get("olt_host") or connection.get("olt_host")
    username = (connection.get("username") or "").strip()
    password = connection.get("password")
    if not host or not username:
        raise CollectorError("Host/usuario da OLT nao configurados.")

    command_timeout = int(connection.get("command_timeout_sec") or 30)
    resolved_location = _resolve_huawei_onu_location_by_serial(onu, connection, transport_type, command_timeout)

    board_slot = str((resolved_location or {}).get("board_slot") or onu.get("board_slot") or "").strip()
    if not board_slot:
        raise CollectorError("Slot da ONU nao encontrado.")
    port_name = str((resolved_location or {}).get("port_name") or onu.get("port_name") or "").strip()
    ont_id = (resolved_location or {}).get("ont_id", onu.get("pon_position"))

    fsp = (resolved_location or {}).get("fsp")
    service_port_cleanup = {"removed": []}
    if fsp and ont_id is not None:
        if progress_callback:
            progress_callback(35, "Localizando service-port", "service_port_lookup")
        service_port_cleanup = _remove_huawei_service_ports_for_onu(
            onu=onu,
            connection=connection,
            transport_type=transport_type,
            command_timeout=command_timeout,
            fsp=fsp,
            ont_id=ont_id,
        )
        if progress_callback:
            removed = service_port_cleanup.get("removed") or []
            progress_callback(
                55,
                "Excluindo service-port",
                "service_port_delete",
                details=(
                    f"Service-port removido: {', '.join(str(item) for item in removed)}"
                    if removed
                    else "Nenhum service-port adicional encontrado para remover."
                ),
            )

    startup_commands = [
        "enable",
        "config",
        f"interface gpon {board_slot}",
    ]
    exit_commands = ["quit", "quit"]
    candidates = _huawei_delete_command_candidates(board_slot, port_name, ont_id)
    extra = connection.get("extra_config") or {}

    attempts = []
    for delete_command in candidates:
        if progress_callback:
            progress_callback(75, "Excluindo ONU na OLT", "onu_delete", details=f"Comando: {delete_command}")
        commands = startup_commands + [delete_command] + exit_commands
        try:
            if transport_type == "ssh":
                outputs = run_huawei_commands_native(
                    host=host,
                    username=username,
                    password=password,
                    port=int(connection.get("port") or 22),
                    timeout=max(20, command_timeout),
                    key_path=extra.get("ssh_key_path"),
                    commands=commands,
                )
            else:
                outputs = run_huawei_commands_over_telnet(
                    host=host,
                    username=username,
                    password=password,
                    port=int(connection.get("port") or 23),
                    timeout=max(25, command_timeout),
                    command_timeout=int(extra.get("telnet_command_timeout_sec") or min(20, command_timeout)),
                    commands=commands,
                )
        except Exception as error:
            attempts.append({"command": delete_command, "output": str(error)})
            continue

        delete_output = ""
        for item in outputs:
            if item.get("command") == delete_command:
                delete_output = item.get("output") or ""
                break
        attempts.append({"command": delete_command, "output": delete_output})
        if not _looks_like_huawei_command_failure(delete_output):
            db.add_collector_event(
                int(onu["olt_id"]),
                "info",
                f'ONU {onu.get("serial")} removida na OLT via comando {delete_command}',
                {
                    "onu_id": onu_id,
                    "command": delete_command,
                    "transport": transport_type,
                    "resolved_fsp": (resolved_location or {}).get("fsp"),
                    "service_ports_removed": service_port_cleanup.get("removed") or [],
                },
            )
            return {
                "status": "ok",
                "onu_id": onu_id,
                "transport_type": transport_type,
                "command": delete_command,
                "output": delete_output,
                "resolved_fsp": (resolved_location or {}).get("fsp"),
                "service_ports_removed": service_port_cleanup.get("removed") or [],
            }

    raise CollectorError(
        "Nao foi possivel remover a ONU na OLT. Verifique permissao/comando. "
        + "; ".join(f"{item['command']}: {item['output'][:120]}" for item in attempts)
    )


def delete_onu(onu_id, live=True, progress_enabled=False):
    onu_id = int(onu_id)
    if progress_enabled:
        _update_onu_delete_stage(
            onu_id,
            5,
            "Preparando exclusao" if live else "Preparando remocao local",
            "lookup" if live else "local_delete",
            live=live,
        )
    current_stage_key = "lookup" if live else "local_delete"
    try:
        live_result = None
        if live:
            live_result = delete_onu_on_olt(
                onu_id,
                progress_callback=(
                    (lambda pct, stage, active_key, details=None: _update_onu_delete_stage(
                        onu_id, pct, stage, active_key, details, live=live
                    ))
                    if progress_enabled
                    else None
                ),
            )
            current_stage_key = "local_delete"
        if progress_enabled:
            _update_onu_delete_stage(onu_id, 90, "Removendo cadastro local", "local_delete", live=live)
        local_result = db.delete_onu(onu_id)
    except Exception as error:
        if progress_enabled:
            _fail_onu_delete_progress(onu_id, current_stage_key, str(error), live=live)
        raise

    payload = dict(local_result)
    if live_result is not None:
        payload["live_result"] = live_result
    if progress_enabled:
        _complete_onu_delete_progress(
            onu_id,
            details="ONU removida da OLT e do sistema local." if live else "ONU removida somente do sistema local.",
            live=live,
        )
        payload["delete_progress"] = get_onu_delete_progress(onu_id)
    return payload


def start_onu_delete(onu_id, live=True):
    onu_id = int(onu_id)
    with ASYNC_ONU_DELETE_LOCK:
        thread = ASYNC_ONU_DELETE_THREADS.get(onu_id)
        if thread and thread.is_alive():
            progress = get_onu_delete_progress(onu_id)
            return {
                "onu_id": onu_id,
                "status": "running",
                "message": "Exclusao ja em andamento.",
                "progress": progress,
            }

        _set_onu_delete_progress(
            onu_id,
            1,
            "Exclusao enfileirada",
            status="running",
            steps=_build_onu_delete_steps(active_key="lookup" if live else "local_delete", live=live),
        )

        def _runner():
            try:
                delete_onu(onu_id, live=live, progress_enabled=True)
            finally:
                with ASYNC_ONU_DELETE_LOCK:
                    current = ASYNC_ONU_DELETE_THREADS.get(onu_id)
                    if current is threading.current_thread():
                        ASYNC_ONU_DELETE_THREADS.pop(onu_id, None)

        thread = threading.Thread(
            target=_runner,
            name=f"delete-onu-{onu_id}",
            daemon=True,
        )
        ASYNC_ONU_DELETE_THREADS[onu_id] = thread
        thread.start()

    return {
        "onu_id": onu_id,
        "status": "started",
        "message": "Exclusao iniciada em segundo plano.",
    }


def _run_huawei_commands_for_onu(onu, connection, commands):
    host = onu.get("olt_host") or connection.get("olt_host")
    username = (connection.get("username") or "").strip()
    password = connection.get("password")
    if not host or not username:
        raise CollectorError("Host/usuario da OLT nao configurados.")

    transport_type = (connection.get("transport_type") or "ssh").strip().lower()
    command_timeout = int(connection.get("command_timeout_sec") or 30)
    extra = connection.get("extra_config") or {}
    if transport_type == "ssh":
        return run_huawei_commands_native(
            host=host,
            username=username,
            password=password,
            port=int(connection.get("port") or 22),
            timeout=max(20, command_timeout),
            key_path=extra.get("ssh_key_path"),
            commands=commands,
        )
    if transport_type == "telnet":
        return run_huawei_commands_over_telnet(
            host=host,
            username=username,
            password=password,
            port=int(connection.get("port") or 23),
            timeout=max(25, command_timeout),
            command_timeout=int(extra.get("telnet_command_timeout_sec") or max(25, command_timeout)),
            commands=commands,
        )
    raise CollectorError("Acao da ONU suporta apenas SSH/Telnet para Huawei native.")


def _first_successful_huawei_action(onu, connection, command_groups):
    attempts = []
    for commands in command_groups:
        try:
            outputs = _run_huawei_commands_for_onu(onu, connection, commands)
        except Exception as error:
            attempts.append({"commands": commands, "output": str(error)})
            continue
        last = outputs[-1] if outputs else {"command": "", "output": ""}
        output = (last.get("output") or "").strip()
        if output and not _looks_like_huawei_command_failure(output):
            return {
                "status": "ok",
                "command": last.get("command") or "",
                "output": output,
                "attempts": attempts,
            }
        attempts.append({"commands": commands, "output": output})
    raise CollectorError(
        "Falha ao executar comando da ONU. "
        + "; ".join(
            f"{' | '.join(item['commands'])}: {(item.get('output') or '')[:120]}"
            for item in attempts
        )
    )


def _to_mbps(value, unit):
    try:
        numeric = float(value)
    except Exception:
        return None
    normalized = (unit or "mbps").strip().lower()
    if normalized in {"kbps", "kbit/s", "kbitps", "k"}:
        return round(numeric / 1000.0, 3)
    if normalized in {"gbps", "gbit/s", "gbitps", "g"}:
        return round(numeric * 1000.0, 3)
    return round(numeric, 3)


def _parse_huawei_traffic_output(text):
    output = str(text or "")
    patterns = [
        # Downstream current : 1234 kbps
        r"(?is)(downstream|downlink|rx)[^\n:]{0,40}[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*(k|m|g)(?:bps|bit/s)",
        r"(?is)(upstream|uplink|tx)[^\n:]{0,40}[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*(k|m|g)(?:bps|bit/s)",
    ]
    down = None
    up = None
    for match in re.finditer(patterns[0], output):
        down = _to_mbps(match.group(2), f'{(match.group(3) or "m")}bps')
        if down is not None:
            break
    for match in re.finditer(patterns[1], output):
        up = _to_mbps(match.group(2), f'{(match.group(3) or "m")}bps')
        if up is not None:
            break

    return down, up


def _extract_onu_traffic_from_output(output, onu):
    try:
        table = parse_traffic(output or "")
    except Exception:
        table = {}
    key = (
        str(onu.get("board_slot") or ""),
        str(onu.get("port_name") or ""),
        int(onu.get("pon_position") or 0),
    )
    row = table.get(key) or {}
    down = row.get("traffic_down_mbps")
    up = row.get("traffic_up_mbps")
    if down is not None or up is not None:
        try:
            return (float(down) if down is not None else None), (float(up) if up is not None else None)
        except Exception:
            pass
    return _parse_huawei_traffic_output(output)


def _build_huawei_onu_command_context(onu):
    port_name = str(onu.get("port_name") or "")
    try:
        port_number = int(port_name.split()[-1])
        port_index = max(0, port_number - 1)
    except Exception:
        port_index = 0
    try:
        frame_id, slot_id = [int(item) for item in str(onu.get("board_slot") or "0/0").split("/")[:2]]
    except Exception:
        frame_id, slot_id = 0, 0
    return {
        "frame_id": frame_id,
        "slot_id": slot_id,
        "port_index": port_index,
        "ont_id": int(onu.get("pon_position") or 0),
        "serial": str(onu.get("serial") or "").strip(),
    }


def _pick_huawei_command_output(outputs, command_fragment):
    fragment = str(command_fragment or "").strip().lower()
    for item in outputs or []:
        command = str(item.get("command") or "").strip().lower()
        if fragment and fragment not in command:
            continue
        return str(item.get("output") or "").strip()
    return ""


def _looks_like_huawei_alarm_empty(output):
    text = str(output or "").strip().lower()
    if not text:
        return False
    markers = [
        "no active alarm",
        "active alarm info does not exist",
        "active alarm does not exist",
        "alarm info does not exist",
        "does not have active alarm",
    ]
    return any(marker in text for marker in markers)


def _find_huawei_output_line(text, matcher):
    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").splitlines():
        stripped = raw_line.strip()
        if stripped and matcher(stripped.lower()):
            return stripped
    return ""


def _extract_huawei_run_state(text):
    match = re.search(r"(?im)^\s*run\s*state\s*:\s*([^\n]+)$", str(text or ""))
    if not match:
        return ""
    return match.group(1).strip()


def _extract_huawei_last_down_cause(text):
    match = re.search(r"(?im)^\s*last\s+down\s+cause\s*:\s*([^\n]+)$", str(text or ""))
    if not match:
        return ""
    return match.group(1).strip()


def _is_huawei_run_state_online(value):
    text = str(value or "").strip().lower()
    if not text:
        return False
    markers = ["online", "up", "working", "normal"]
    return any(marker in text for marker in markers)


def _find_huawei_power_alarm_line(text):
    markers = ["dying gasp", "dying-gasp", "dgi", "power off", "power failure", "power fail", "powerfail"]
    return _find_huawei_output_line(text, lambda line: any(marker in line for marker in markers))


def _find_huawei_fiber_alarm_line(text):
    return _find_huawei_output_line(
        text,
        lambda line: "ethernet" not in line and (
            "loss of signal" in line
            or "loss of frame" in line
            or re.search(r"\b(los|losi|lof|lofi|lobi)\b", line)
        ),
    )


def _find_huawei_ethernet_alarm_line(text):
    return _find_huawei_output_line(
        text,
        lambda line: "ethernet" in line and ("signal loss" in line or "loss of signal" in line),
    )


def _parse_huawei_optical_metrics(output):
    text = str(output or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text:
        return {}

    def _extract(patterns, validator=None):
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
            if not match:
                continue
            try:
                value = round(float(match.group(1)), 2)
            except Exception:
                continue
            if validator and not validator(value):
                continue
            return value
        return None

    metrics = {}
    signal_dbm = _extract(
        [
            r"^\s*(?:rx(?:\s+optical)?\s+power(?:\s+current)?|ont\s+rx\s+optical\s+power|rxpower)\s*(?:\(dbm\))?\s*[:=]\s*(-?[\d.]+)",
            r"^\s*rx/tx\s+power(?:\(dbm\))?\s*[:=]\s*(-?[\d.]+)\s*/\s*-?[\d.]+",
            r"^\s*\d+/\d+/\d+\s+\d+\s+(-?[\d.]+)\s+(?:-?[\d.]+)\s*$",
        ],
        validator=_is_valid_onu_signal_dbm,
    )
    if signal_dbm is not None:
        metrics["signal_dbm"] = signal_dbm

    signal_tx_dbm = _extract(
        [
            r"^\s*(?:tx(?:\s+optical)?\s+power(?:\s+current)?|ont\s+tx\s+optical\s+power|txpower)\s*(?:\(dbm\))?\s*[:=]\s*(-?[\d.]+)",
            r"^\s*rx/tx\s+power(?:\(dbm\))?\s*[:=]\s*-?[\d.]+\s*/\s*(-?[\d.]+)",
        ],
        validator=_is_valid_onu_signal_tx_dbm,
    )
    if signal_tx_dbm is not None:
        metrics["signal_tx_dbm"] = signal_tx_dbm

    signal_olt_rx_dbm = _extract(
        [
            r"^\s*(?:olt\s+rx(?:\s+ont)?\s+optical\s+power|onu\s*->\s*olt(?:\s+return)?\s+signal|return\s+signal)\s*(?:\(dbm\))?\s*[:=]\s*(-?[\d.]+)",
        ],
        validator=_is_valid_onu_signal_dbm,
    )
    if signal_olt_rx_dbm is not None:
        metrics["signal_olt_rx_dbm"] = signal_olt_rx_dbm

    temperature_c = _extract(
        [
            r"^\s*(?:temperature|ont\s+temperature)\s*(?:\([^)]+\))?\s*[:=]\s*(-?[\d.]+)",
            r"^\s*\d+/\d+/\d+\s+\d+\s+-?[\d.]+\s+(-?[\d.]+)\s*$",
        ],
        validator=_is_valid_onu_temperature_c,
    )
    if temperature_c is not None:
        metrics["temperature_c"] = temperature_c

    return metrics


def _collect_huawei_onu_optical_metrics(onu, connection):
    context = _build_huawei_onu_command_context(onu)
    command_groups = [
        [
            "config",
            f"interface gpon {context['frame_id']}/{context['slot_id']}",
            f"display ont optical-info {context['port_index']} {context['ont_id']}",
            "quit",
            "quit",
        ],
        ["enable", f"display ont optical-info {context['port_index']} {context['ont_id']}"],
        ["enable", f"display ont info by-sn {context['serial']}"] if context["serial"] else None,
        ["enable", f"display ont info {context['port_index']} {context['ont_id']}"],
    ]
    for commands in command_groups:
        if not commands:
            continue
        try:
            outputs = _run_huawei_commands_for_onu(onu, connection, commands)
        except Exception:
            continue
        output = ""
        for command_hint in ("display ont optical-info", "display ont info by-sn", "display ont info"):
            candidate = _pick_huawei_command_output(outputs, command_hint)
            if candidate:
                output = candidate
                break
        if not output or _looks_like_huawei_command_failure(output):
            continue
        metrics = _parse_huawei_optical_metrics(output)
        if metrics:
            return metrics
    return {}


def _build_physical_state_entry(state, label, detail="", source=""):
    return {
        "state": state,
        "label": label,
        "detail": detail or "",
        "source": source or "",
    }


def _build_huawei_disconnect_reason(
    online,
    power_alarm,
    fiber_alarm,
    ethernet_alarm,
    last_down_cause,
    run_state,
    alarm_output_available=False,
    has_optical_signal=False,
    optical_signal_detail="",
):
    if online:
        detail = f"Run state: {run_state}" if run_state else "ONU online."
        return _build_physical_state_entry("online", "ONU online", detail, "cli")
    if power_alarm:
        return _build_physical_state_entry(
            "probable-power-off",
            "Provavel sem energia",
            power_alarm,
            "cli",
        )
    if fiber_alarm:
        return _build_physical_state_entry(
            "probable-fiber-cut",
            "Provavel rompimento/perda de fibra",
            fiber_alarm,
            "cli",
        )
    if ethernet_alarm:
        return _build_physical_state_entry(
            "probable-ethernet-down",
            "Provavel falha no RJ45",
            ethernet_alarm,
            "cli",
        )
    if has_optical_signal:
        detail = optical_signal_detail or "ONU apresenta sinal optico, sem evidencias de DGi/LOS/LOFi."
        return _build_physical_state_entry(
            "online",
            "ONU com sinal optico",
            detail,
            "signal",
        )
    if last_down_cause:
        return _build_physical_state_entry(
            "unconfirmed",
            "Sem conclusao da OLT",
            f"Last down cause: {last_down_cause}",
            "cli",
        )
    return _build_physical_state_entry(
        "unconfirmed",
        "Sem conclusao da OLT",
        (
            "alarm-state respondeu, mas sem DGi/LOS/LOFi conclusivos."
            if alarm_output_available
            else "Sem resposta conclusiva de alarm-state e sem last down cause."
        ),
        "cli",
    )


def _collect_huawei_onu_physical_status(onu, connection, info_output=""):
    context = _build_huawei_onu_command_context(onu)
    normalized_info_output = str(info_output or "").strip()
    if normalized_info_output and not (
        re.search(r"(?im)^\s*run\s*state\s*:", normalized_info_output)
        or re.search(r"(?im)^\s*last\s+down\s+cause\s*:", normalized_info_output)
    ):
        normalized_info_output = ""

    if not normalized_info_output:
        info_groups = [
            ["enable", f"display ont info by-sn {context['serial']}"] if context["serial"] else None,
            ["enable", f"display ont info {context['port_index']} {context['ont_id']}"],
        ]
        for commands in info_groups:
            if not commands:
                continue
            try:
                outputs = _run_huawei_commands_for_onu(onu, connection, commands)
            except Exception:
                continue
            candidate = _pick_huawei_command_output(outputs, "display ont info")
            if candidate and not _looks_like_huawei_command_failure(candidate):
                normalized_info_output = candidate
                break

    alarm_output = ""
    alarm_groups = [
        [
            "config",
            f"interface gpon {context['frame_id']}/{context['slot_id']}",
            f"display ont alarm-state {context['port_index']} {context['ont_id']}",
            "quit",
            "quit",
        ],
        ["enable", f"display ont alarm-state {context['port_index']} {context['ont_id']}"],
    ]
    for commands in alarm_groups:
        try:
            outputs = _run_huawei_commands_for_onu(onu, connection, commands)
        except Exception:
            continue
        candidate = _pick_huawei_command_output(outputs, "display ont alarm-state")
        if not candidate:
            continue
        if _looks_like_huawei_alarm_empty(candidate) or not _looks_like_huawei_command_failure(candidate):
            alarm_output = candidate
            break

    run_state = _extract_huawei_run_state(normalized_info_output)
    last_down_cause = _extract_huawei_last_down_cause(normalized_info_output)
    online = _is_huawei_run_state_online(run_state)
    power_alarm = _find_huawei_power_alarm_line(alarm_output)
    fiber_alarm = _find_huawei_fiber_alarm_line(alarm_output)
    ethernet_alarm = _find_huawei_ethernet_alarm_line(alarm_output)
    if not online:
        power_alarm = power_alarm or _find_huawei_power_alarm_line(last_down_cause)
        fiber_alarm = fiber_alarm or _find_huawei_fiber_alarm_line(last_down_cause)
        ethernet_alarm = ethernet_alarm or _find_huawei_ethernet_alarm_line(last_down_cause)
    normalized_status = str(onu.get("status") or "").strip().lower()

    signal_dbm = onu.get("signal_dbm")
    try:
        signal_dbm = float(signal_dbm) if signal_dbm is not None else None
    except Exception:
        signal_dbm = None
    if signal_dbm is not None and not _is_valid_onu_signal_dbm(signal_dbm):
        signal_dbm = None
    signal_olt_rx_dbm = onu.get("signal_olt_rx_dbm")
    try:
        signal_olt_rx_dbm = float(signal_olt_rx_dbm) if signal_olt_rx_dbm is not None else None
    except Exception:
        signal_olt_rx_dbm = None
    if signal_olt_rx_dbm is not None and not _is_valid_onu_signal_dbm(signal_olt_rx_dbm):
        signal_olt_rx_dbm = None
    traffic_down = 0.0
    traffic_up = 0.0
    try:
        traffic_down = float(onu.get("traffic_down_mbps") or 0.0)
    except Exception:
        traffic_down = 0.0
    try:
        traffic_up = float(onu.get("traffic_up_mbps") or 0.0)
    except Exception:
        traffic_up = 0.0
    has_traffic = traffic_down > 0.01 or traffic_up > 0.01
    alarm_query_ran = bool(alarm_output)
    has_optical_signal = signal_dbm is not None or signal_olt_rx_dbm is not None
    optical_signal_detail = (
        f"RX {signal_dbm:.2f} dBm"
        if signal_dbm is not None
        else f"ONU->OLT {signal_olt_rx_dbm:.2f} dBm"
        if signal_olt_rx_dbm is not None
        else ""
    )

    power = _build_physical_state_entry("unconfirmed", "Sem confirmacao", "OLT nao confirma energia com a ONU offline.", "cli")
    if online or normalized_status == "active":
        detail = f"Run state: {run_state}" if run_state else "ONU online."
        power = _build_physical_state_entry("on", "Ligada", detail, "cli")
    elif has_optical_signal and not power_alarm:
        power = _build_physical_state_entry(
            "on",
            "Ligada (inferido)",
            f"{optical_signal_detail}. Sinal optico implica ONU energizada.",
            "signal",
        )
    elif power_alarm:
        power = _build_physical_state_entry("probable-off", "Provavel sem energia", power_alarm, "cli")
    elif last_down_cause:
        power = _build_physical_state_entry(
            "unconfirmed",
            "Sem confirmacao",
            f"Ultimo evento: {last_down_cause}",
            "cli",
        )

    fiber = _build_physical_state_entry(
        "unconfirmed",
        "Sem confirmacao",
        "OLT nao confirma se existe ONU energizada na fibra enquanto estiver offline.",
        "cli",
    )
    if online or has_optical_signal:
        detail = (
            f"RX {signal_dbm:.2f} dBm"
            if signal_dbm is not None
            else f"ONU->OLT {signal_olt_rx_dbm:.2f} dBm"
            if signal_olt_rx_dbm is not None
            else (f"Run state: {run_state}" if run_state else "Enlace optico ativo.")
        )
        fiber_source = "cli" if online else "signal"
        fiber_label = "UP" if online else "UP (inferido)"
        fiber = _build_physical_state_entry("up", fiber_label, detail, fiber_source)
    elif fiber_alarm:
        fiber = _build_physical_state_entry("probable-loss", "Provavel LOSS", fiber_alarm, "cli")
    elif last_down_cause:
        fiber = _build_physical_state_entry(
            "unconfirmed",
            "Sem confirmacao",
            f"Ultimo evento: {last_down_cause}",
            "cli",
        )

    ethernet = _build_physical_state_entry(
        "unconfirmed",
        "Sem confirmacao",
        "OLT nao confirma o RJ45 desta ONU enquanto ela estiver offline.",
        "cli",
    )
    if has_traffic and (online or normalized_status == "active" or has_optical_signal):
        ethernet = _build_physical_state_entry(
            "up",
            "UP",
            f"Down {traffic_down:.3f} Mbps / Up {traffic_up:.3f} Mbps",
            "metrics",
        )
    elif online and ethernet_alarm:
        ethernet = _build_physical_state_entry("down", "DOWN", ethernet_alarm, "cli")
    elif ethernet_alarm:
        ethernet = _build_physical_state_entry("probable-down", "Provavel DOWN", ethernet_alarm, "cli")
    elif online and alarm_query_ran and not _looks_like_huawei_alarm_empty(alarm_output):
        ethernet = _build_physical_state_entry("up", "UP", "Sem alarme ativo de Ethernet.", "cli")
    elif online and _looks_like_huawei_alarm_empty(alarm_output):
        ethernet = _build_physical_state_entry("up", "UP", "Sem alarmes ativos na ONU.", "cli")
    disconnect_reason = _build_huawei_disconnect_reason(
        online,
        power_alarm,
        fiber_alarm,
        ethernet_alarm,
        last_down_cause,
        run_state,
        alarm_output_available=bool(alarm_output),
        has_optical_signal=has_optical_signal,
        optical_signal_detail=optical_signal_detail,
    )

    return {
        "power": power,
        "fiber": fiber,
        "ethernet": ethernet,
        "disconnect_reason": disconnect_reason,
        "meta": {
            "run_state": run_state,
            "last_down_cause": last_down_cause,
            "alarm_output_available": bool(alarm_output),
            "optical_signal_evidence": has_optical_signal,
            "optical_signal_detail": optical_signal_detail,
        },
    }


def _persist_onu_live_status_snapshot(onu, *, status=None, traffic_down_mbps=None, traffic_up_mbps=None):
    payload = {
        "collected_at": db.utc_now(),
        "olt_metrics": {},
        "boards": [],
        "ports": [],
        "onus": [
            {
                "serial": onu["serial"],
                "model": onu.get("model") or "Desconhecido",
                "status": status if status is not None else onu.get("status"),
                "traffic_down_mbps": traffic_down_mbps,
                "traffic_up_mbps": traffic_up_mbps,
                "board_slot": onu.get("board_slot"),
                "port_name": onu.get("port_name"),
                "pon_position": onu.get("pon_position"),
                "vlan_id": onu.get("vlan_id"),
                "description": onu.get("client_name"),
            }
        ],
        "authorization_requests": [],
        "events": [],
    }
    db.apply_collection(int(onu["olt_id"]), payload)
    return db.fetch_onu_by_id(int(onu["id"]))


def run_onu_action(onu_id, action):
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {"status", "running", "swinfo", "live"}:
        raise CollectorError("Acao da ONU invalida.")

    onu = db.fetch_onu_by_id(int(onu_id))
    connection = db.fetch_connection_for_olt(int(onu["olt_id"]))
    brand = (onu.get("olt_brand") or "").strip().lower()
    protocol = (connection.get("protocol") or "").strip().lower()
    if brand != "huawei" or protocol != "native":
        raise CollectorError("Acoes de ONU suportadas apenas para Huawei native.")

    port_name = str(onu.get("port_name") or "")
    try:
        port_number = int(port_name.split()[-1])
        port_index = max(0, port_number - 1)
    except Exception:
        port_index = 0
    ont_id = int(onu.get("pon_position") or 0)
    serial = str(onu.get("serial") or "").strip()

    base = ["enable"]
    by_sn = f"display ont info by-sn {serial}" if serial else ""
    status_groups = [
        [*base, by_sn] if by_sn else [*base, f"display ont info {port_index} {ont_id}"],
        [*base, f"display ont info {port_index} {ont_id}"],
        [*base, f"display ont optical-info {port_index} {ont_id}"],
    ]
    running_groups = [
        [*base, f"display current-configuration | include {serial}"] if serial else [*base, "display current-configuration"],
        [*base, f"display service-port all | include {serial}"] if serial else [*base, "display service-port all"],
        [*base, f"display ont info {port_index} {ont_id}"],
    ]
    try:
        frame_id = int(str(onu.get("board_slot") or "0/0").split("/")[0])
    except Exception:
        frame_id = 0
    live_groups = [
        [*base, f"display ont traffic {frame_id} all"],
        [*base, f"display ont info by-sn {serial}"] if serial else [*base, f"display ont info {port_index} {ont_id}"],
    ]

    live_collection = None
    swinfo_collection = None
    physical_status = None
    if normalized_action == "live":
        status_probe = None
        live_allowed = str(onu.get("status") or "").strip().lower() == "active"
        try:
            status_probe = _first_successful_huawei_action(onu, connection, status_groups)
            physical_status = _collect_huawei_onu_physical_status(
                onu,
                connection,
                info_output=status_probe.get("output") or "",
            )
            run_state = str((physical_status.get("meta") or {}).get("run_state") or "").strip()
            if run_state:
                live_allowed = _is_huawei_run_state_online(run_state)
            else:
                power_state = str((physical_status.get("power") or {}).get("state") or "").strip().lower()
                fiber_state = str((physical_status.get("fiber") or {}).get("state") or "").strip().lower()
                has_optical_signal = bool((physical_status.get("meta") or {}).get("optical_signal_evidence"))
                if power_state in {"off", "probable-off"} or fiber_state in {"loss", "down", "probable-loss"}:
                    live_allowed = False
                elif power_state in {"on"} or fiber_state in {"up"} or has_optical_signal:
                    live_allowed = True
        except Exception:
            status_probe = None
        if not live_allowed:
            updated_onu = _persist_onu_live_status_snapshot(
                onu,
                status="warning",
                traffic_down_mbps=0.0,
                traffic_up_mbps=0.0,
            )
            blocked_field_meta = {
                "status": {
                    "source": "live-gate",
                    "updated_at": db.utc_now(),
                    "age_sec": 0,
                    "stale_after_sec": None,
                    "stale": False,
                    "confidence": "high",
                    "freshness": "live",
                    "detail": "LIVE bloqueado porque a ONU esta offline na OLT.",
                },
                "traffic": {
                    "source": "live-gate",
                    "updated_at": db.utc_now(),
                    "age_sec": 0,
                    "stale_after_sec": None,
                    "stale": False,
                    "confidence": "high",
                    "freshness": "live",
                    "detail": "Trafego zerado porque LIVE PON nao deve reutilizar consumo com ONU offline.",
                },
            }
            updated_onu = _merge_onu_field_meta(updated_onu, blocked_field_meta)
            return {
                "status": "ok",
                "onu_id": int(onu_id),
                "action": normalized_action,
                "command": status_probe.get("command") if status_probe else "live-blocked",
                "output": "LIVE indisponivel: ONU offline. Este botao consulta trafego da PON, nao trafego exclusivo desta ONU.",
                "updated_at": db.utc_now(),
                "live_available": False,
                "field_meta": blocked_field_meta,
                "physical_status": physical_status,
                "onu": updated_onu,
            }
        live_collection = collect_onu_live(
            int(onu_id),
            fields=[
                "signal",
                "signal_tx",
                "signal_olt_rx",
                "temperature",
                "vlan",
                "status",
                "profile",
                "traffic_down",
                "traffic_up",
            ],
        )
        updated_live_fields = set(live_collection.get("updated_fields") or [])
        live_onu = live_collection.get("onu") or {}
        live_down = live_onu.get("traffic_down_mbps")
        live_up = live_onu.get("traffic_up_mbps")
        if "traffic_down" in updated_live_fields or "traffic_up" in updated_live_fields:
            result = {
                "status": "ok",
                "command": "snmp-live",
                "output": f"Downstream: {live_down if live_down is not None else '-'} Mbps | Upstream: {live_up if live_up is not None else '-'} Mbps",
            }
        else:
            result = _first_successful_huawei_action(onu, connection, live_groups)
    elif normalized_action == "status":
        result = _first_successful_huawei_action(onu, connection, status_groups)
    elif normalized_action == "running":
        result = _first_successful_huawei_action(onu, connection, running_groups)
    elif normalized_action == "swinfo":
        swinfo_collection = collect_onu_live(int(onu_id), fields=["profile"])
        current_onu = db.fetch_onu_by_id(int(onu_id))
        result = {
            "status": "ok",
            "command": "local-swinfo",
            "output": (
                f"Serial: {current_onu.get('serial') or '-'}\n"
                f"Modelo: {current_onu.get('model') or '-'}\n"
                f"Perfil: {current_onu.get('profile_name') or 'default'}\n"
                f"VLAN: {current_onu.get('vlan_id') or '-'}\n"
                f"Status: {current_onu.get('status') or '-'}\n"
                f"Porta: {current_onu.get('board_slot') or '-'}/{current_onu.get('port_name') or '-'}"
            ),
        }
    else:
        result = _first_successful_huawei_action(onu, connection, status_groups)

    response = {
        "status": "ok",
        "onu_id": int(onu_id),
        "action": normalized_action,
        "command": result.get("command") or "",
        "output": result.get("output") or "",
        "updated_at": db.utc_now(),
    }
    if live_collection is not None:
        live_field_meta = live_collection.get("field_meta") or {}
        updated_live_fields = set(live_collection.get("updated_fields") or [])
        live_onu = live_collection.get("onu") or {}
        live_down = live_onu.get("traffic_down_mbps")
        live_up = live_onu.get("traffic_up_mbps")
        if "traffic_down" in updated_live_fields or "traffic_up" in updated_live_fields:
            down_mbps = float(live_down) if live_down is not None else None
            up_mbps = float(live_up) if live_up is not None else None
        else:
            down_mbps, up_mbps = _extract_onu_traffic_from_output(result.get("output") or "", onu)
        if down_mbps is not None or up_mbps is not None:
            response["output"] = f"Downstream: {down_mbps if down_mbps is not None else '-'} Mbps | Upstream: {up_mbps if up_mbps is not None else '-'} Mbps"
        else:
            skipped = live_collection.get("skipped_fields") or {}
            down_reason = skipped.get("traffic_down")
            up_reason = skipped.get("traffic_up")
            if down_reason or up_reason:
                response["output"] = (
                    "Consumo em tempo real indisponivel: configure OIDs SNMP de trafego "
                    "(`snmp_traffic_down_oid` e `snmp_traffic_up_oid`) na conexao da OLT."
                )
            else:
                response["output"] = (result.get("output") or "")[:1200]
        if down_mbps is not None or up_mbps is not None:
            current_onu = db.fetch_onu_by_id(int(onu_id))
            if down_mbps is None:
                try:
                    down_mbps = float(current_onu.get("traffic_down_mbps"))
                except Exception:
                    down_mbps = 0.0
            if up_mbps is None:
                try:
                    up_mbps = float(current_onu.get("traffic_up_mbps"))
                except Exception:
                    up_mbps = 0.0
            payload = {
                "collected_at": db.utc_now(),
                "olt_metrics": {},
                "boards": [],
                "ports": [],
                "onus": [
                    {
                        "serial": current_onu["serial"],
                        "model": current_onu.get("model") or "Desconhecido",
                        "status": current_onu.get("status") or "active",
                        "signal_dbm": current_onu.get("signal_dbm"),
                        "signal_tx_dbm": current_onu.get("signal_tx_dbm"),
                        "signal_olt_rx_dbm": current_onu.get("signal_olt_rx_dbm"),
                        "traffic_down_mbps": down_mbps if down_mbps is not None else current_onu.get("traffic_down_mbps"),
                        "traffic_up_mbps": up_mbps if up_mbps is not None else current_onu.get("traffic_up_mbps"),
                        "temperature_c": current_onu.get("temperature_c"),
                        "board_slot": current_onu.get("board_slot"),
                        "port_name": current_onu.get("port_name"),
                        "pon_position": current_onu.get("pon_position"),
                        "vlan_id": current_onu.get("vlan_id"),
                        "description": current_onu.get("client_name"),
                    }
                ],
                "authorization_requests": [],
                "events": [],
            }
            db.apply_collection(int(current_onu["olt_id"]), payload)
            response["traffic"] = {"down_mbps": down_mbps, "up_mbps": up_mbps}
        response["live_collection"] = live_collection
        response["onu"] = db.fetch_onu_by_id(int(onu_id))
        if live_field_meta:
            response["field_meta"] = live_field_meta
            response["onu"] = _merge_onu_field_meta(response["onu"], live_field_meta)
        if physical_status is not None:
            response["physical_status"] = physical_status
        response["live_available"] = True
    elif swinfo_collection is not None:
        response["swinfo_collection"] = swinfo_collection
        response["onu"] = db.fetch_onu_by_id(int(onu_id))
    elif normalized_action == "status":
        response["physical_status"] = _collect_huawei_onu_physical_status(
            db.fetch_onu_by_id(int(onu_id)),
            connection,
            info_output=result.get("output") or "",
        )
    return response


def _normalize_onu_live_fields(fields):
    aliases = {
        "signal": "signal",
        "rx": "signal",
        "signal_rx": "signal",
        "signal_tx": "signal_tx",
        "tx": "signal_tx",
        "signal_olt_rx": "signal_olt_rx",
        "signal_return": "signal_olt_rx",
        "return": "signal_olt_rx",
        "olt_rx": "signal_olt_rx",
        "temperature": "temperature",
        "temp": "temperature",
        "vlan": "vlan",
        "status": "status",
        "profile": "profile",
        "traffic": "traffic",
        "traffic_down": "traffic_down",
        "traffic_up": "traffic_up",
        "down": "traffic_down",
        "up": "traffic_up",
        "power": "power",
        "energy": "power",
        "energia": "power",
        "fiber": "fiber",
        "fibra": "fiber",
        "optical": "fiber",
        "ethernet": "ethernet",
        "eth": "ethernet",
        "rj45": "ethernet",
        "lan": "ethernet",
    }
    if not fields:
        return [
            "signal",
            "signal_tx",
            "signal_olt_rx",
            "temperature",
            "vlan",
            "status",
            "profile",
            "traffic_down",
            "traffic_up",
        ]
    normalized = []
    for item in fields:
        key = aliases.get(str(item or "").strip().lower())
        if key and key not in normalized:
            normalized.append(key)
    if not normalized:
        raise CollectorError("Nenhum campo valido solicitado para coleta da ONU.")
    return normalized


def _build_oid_with_suffix(base_oid, suffix):
    base = str(base_oid or "").strip().strip(".")
    if not base:
        return ""
    if not isinstance(suffix, tuple):
        suffix = (suffix,)
    suffix_text = ".".join(str(int(part)) for part in suffix)
    if not suffix_text:
        return base
    return f"{base}.{suffix_text}"


def _build_onu_snmp_candidates(onu):
    candidates = []
    for item in _onu_index_candidates(onu):
        if item and item not in candidates:
            candidates.append(item)
        for expanded in _expand_metric_index_suffix(item):
            if expanded and expanded not in candidates:
                candidates.append(expanded)

    serial = snmp_client.normalize_serial(onu.get("serial"))
    with SNMP_INDEX_CACHE_LOCK:
        cached = dict(SNMP_INDEX_CACHE.get(int(onu.get("olt_id") or 0)) or {})
    cached_suffix = cached.get(serial)
    if cached_suffix is not None:
        if not isinstance(cached_suffix, tuple):
            cached_suffix = tuple(cached_suffix) if isinstance(cached_suffix, (list, tuple)) else (cached_suffix,)
        if cached_suffix not in candidates:
            candidates.insert(0, cached_suffix)
        for expanded in _expand_metric_index_suffix(cached_suffix):
            if expanded not in candidates:
                candidates.insert(0, expanded)
    return candidates


def _snmp_get_value_for_candidates(
    host,
    community,
    base_oid,
    candidates,
    *,
    port=161,
    timeout=3,
    version="2c",
    retries=1,
):
    for suffix in candidates:
        try:
            full_oid = _build_oid_with_suffix(base_oid, suffix)
            if not full_oid:
                continue
            _, value = snmp_client.get(
                host,
                community,
                full_oid,
                port=port,
                timeout=timeout,
                version=version,
                retries=retries,
            )
            return value, suffix
        except Exception:
            continue
    return None, None


def _parse_oid_parts(oid_text):
    parts = [chunk.strip() for chunk in str(oid_text or "").strip().strip(".").split(".") if chunk.strip()]
    parsed = []
    for part in parts:
        if not part.isdigit():
            return None
        parsed.append(int(part))
    return tuple(parsed)


def _normalize_ifname(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return "".join(ch for ch in text if not ch.isspace())


def _extract_huawei_location_from_ifname(value):
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"(?i)\bgpon\s+(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\b", text)
    if not match:
        return None
    frame = int(match.group(1))
    slot = int(match.group(2))
    port_index = int(match.group(3))
    return {
        "board_slot": f"{frame}/{slot}",
        "port_name": f"PON {port_index + 1}",
    }


def _build_gpon_ifname_candidates_from_onu(onu):
    board_slot = str(onu.get("board_slot") or "").strip()
    port_name = str(onu.get("port_name") or "").strip().upper()
    if "/" not in board_slot:
        return []
    try:
        frame, slot = [int(item) for item in board_slot.split("/")[:2]]
    except Exception:
        return []
    try:
        pon_number = int(port_name.split()[-1])
    except Exception:
        return []
    pon_index = max(0, pon_number - 1)
    # Some Huawei profiles expose slot in ifName shifted by +1 (e.g. board 0/0 => GPON 0/1/x).
    candidates = [
        f"GPON {frame}/{slot}/{pon_index}",
        f"GPON {frame}/{slot + 1}/{pon_index}",
    ]
    # Keep insertion order and remove duplicates.
    dedup = []
    seen = set()
    for item in candidates:
        key = _normalize_ifname(item)
        if key and key not in seen:
            seen.add(key)
            dedup.append(item)
    return dedup


def _resolve_ifindex_for_onu(onu, connection):
    olt_id = int(onu.get("olt_id") or 0)
    ifname_candidates = _build_gpon_ifname_candidates_from_onu(onu)
    if not ifname_candidates:
        return None
    normalized_candidates = [_normalize_ifname(item) for item in ifname_candidates if _normalize_ifname(item)]
    with IFINDEX_CACHE_LOCK:
        cached = dict(IFINDEX_CACHE.get(olt_id) or {})
    for candidate in normalized_candidates:
        if candidate in cached:
            return cached[candidate]

    extra = connection.get("extra_config") or {}
    host = onu.get("olt_host") or connection.get("olt_host")
    community = (
        extra.get("snmp_read_community")
        or extra.get("snmp_community")
        or connection.get("password")
        or ""
    ).strip()
    if not host or not community:
        return None

    ifname_oid = (extra.get("snmp_ifname_oid") or "1.3.6.1.2.1.31.1.1.1.1").strip()
    oid_parts = _parse_oid_parts(ifname_oid)
    if not oid_parts:
        return None
    try:
        rows = snmp_client.walk(
            host,
            community,
            ifname_oid,
            port=int(extra.get("snmp_port") or 161),
            timeout=min(5, int(extra.get("snmp_timeout_sec") or 3)),
            version=(extra.get("snmp_version") or "2c").strip().lower(),
            retries=min(1, int(extra.get("snmp_retries") or 1)),
            max_rows=min(300, int(extra.get("snmp_max_rows") or 300)),
            max_repetitions=min(25, int(extra.get("snmp_bulk_repetitions") or 25)),
        )
    except Exception:
        return None

    discovered = {}
    for oid, value in rows:
        suffix = oid[len(oid_parts) :]
        if len(suffix) != 1:
            continue
        normalized_name = _normalize_ifname(value)
        if not normalized_name:
            continue
        try:
            discovered[normalized_name] = int(suffix[0])
        except Exception:
            continue
    with IFINDEX_CACHE_LOCK:
        current = dict(IFINDEX_CACHE.get(olt_id) or {})
        current.update(discovered)
        IFINDEX_CACHE[olt_id] = current
    for candidate in normalized_candidates:
        if candidate in discovered:
            return discovered[candidate]
    return None


def _snmp_get_traffic_counter_for_ifindex(
    *,
    host,
    community,
    oid_text,
    ifindex,
    port=161,
    timeout=3,
    version="2c",
    retries=1,
):
    oid = str(oid_text or "").strip()
    if not oid:
        return None
    if "[ifindex]" in oid.lower():
        # Preserve user formatting; replace any case variation.
        for token in ("[ifIndex]", "[ifindex]", "[IFINDEX]"):
            oid = oid.replace(token, str(int(ifindex)))
    else:
        parsed = _parse_oid_parts(oid)
        if not parsed:
            return None
        std_in = _parse_oid_parts("1.3.6.1.2.1.2.2.1.10")
        std_out = _parse_oid_parts("1.3.6.1.2.1.2.2.1.16")
        if parsed in {std_in, std_out}:
            oid = f"{oid}.{int(ifindex)}"
    _, value = snmp_client.get(
        host,
        community,
        oid,
        port=port,
        timeout=timeout,
        version=version,
        retries=retries,
    )
    try:
        return int(value)
    except Exception:
        return None


def _calc_mbps_from_counter_delta(cache_key, current_value, now_ts):
    if current_value is None:
        return None
    with TRAFFIC_COUNTER_CACHE_LOCK:
        previous = TRAFFIC_COUNTER_CACHE.get(cache_key)
        TRAFFIC_COUNTER_CACHE[cache_key] = (int(current_value), float(now_ts))
    if not previous:
        return None
    prev_value, prev_ts = previous
    elapsed = float(now_ts) - float(prev_ts)
    if elapsed <= 0:
        return None
    curr = int(current_value)
    prev = int(prev_value)
    if curr >= prev:
        delta = curr - prev
    else:
        # 32-bit counter wraparound for ifInOctets/ifOutOctets.
        delta = curr + (2**32 - prev)
    return round((delta * 8.0) / elapsed / 1_000_000.0, 3)


def _build_live_field_meta(updated_fields, collected_at, detail="Atualizado sob demanda na OLT.", field_sources=None):
    alias_map = {
        "signal": ("signal", "live-snmp"),
        "signal_tx": ("signal", "live-snmp"),
        "signal_olt_rx": ("signal", "live-snmp"),
        "status": ("status", "live-snmp"),
        "temperature": ("temperature", "live-snmp"),
        "traffic": ("traffic", "live-pon-snmp"),
        "traffic_down": ("traffic", "live-pon-snmp"),
        "traffic_up": ("traffic", "live-pon-snmp"),
        "profile": ("profile", "live-profile"),
        "vlan": ("vlan", "live-snmp"),
    }
    meta = {}
    for field in updated_fields or []:
        target = alias_map.get(field)
        if not target:
            continue
        key, default_source = target
        source = (field_sources or {}).get(field) or default_source
        meta[key] = {
            "source": source,
            "updated_at": collected_at,
            "age_sec": 0,
            "stale_after_sec": None,
            "stale": False,
            "confidence": "high",
            "freshness": "live",
            "detail": detail,
        }
    return meta


def _merge_onu_field_meta(onu_data, field_meta):
    if not onu_data:
        return onu_data
    merged = dict(onu_data)
    current_meta = dict(merged.get("field_meta") or {})
    for key, value in (field_meta or {}).items():
        current_meta[key] = {**dict(current_meta.get(key) or {}), **dict(value or {})}
    if current_meta:
        merged["field_meta"] = current_meta
    quality = dict(merged.get("data_quality") or {})
    freshness_keys = {"status", "signal", "traffic", "temperature"}
    latest_live = None
    for key, value in (field_meta or {}).items():
        if key not in freshness_keys:
            continue
        updated_at = (value or {}).get("updated_at")
        if updated_at and (latest_live is None or str(updated_at) > str(latest_live)):
            latest_live = updated_at
    if latest_live:
        quality["source"] = "mixed-live"
        quality["updated_at"] = latest_live
        quality["age_sec"] = 0
        quality["stale"] = False
        quality["confidence"] = "high"
        quality["freshness"] = "live"
        quality["detail"] = "Campos principais atualizados sob demanda."
        merged["data_quality"] = quality
    return merged


def collect_onu_live(onu_id, fields=None):
    onu = db.fetch_onu_by_id(int(onu_id))
    requested_fields = _normalize_onu_live_fields(fields)
    physical_fields = [field for field in requested_fields if field in {"power", "fiber", "ethernet"}]
    if requested_fields == ["profile"]:
        return {
            "status": "ok",
            "onu_id": int(onu_id),
            "collected_at": db.utc_now(),
            "updated_fields": ["profile"],
            "skipped_fields": {},
            "onu": db.fetch_onu_by_id(int(onu_id)),
        }

    connection = db.fetch_connection_for_olt(int(onu["olt_id"]))
    if not connection.get("enabled"):
        raise CollectorError("Coleta da OLT desabilitada.")
    protocol = (connection.get("protocol") or "").strip().lower()
    if protocol != "native":
        raise CollectorError("Coleta sob demanda da ONU suporta apenas protocolo native.")
    if (onu.get("olt_brand") or "").strip().lower() != "huawei":
        raise CollectorError("Coleta sob demanda da ONU disponivel apenas para OLT Huawei.")

    extra = connection.get("extra_config") or {}
    host = onu.get("olt_host")
    community = (
        extra.get("snmp_read_community")
        or extra.get("snmp_community")
        or connection.get("password")
        or ""
    ).strip()
    if not community:
        raise CollectorError("SNMP community nao configurada para a OLT.")

    snmp_version = (extra.get("snmp_version") or "2c").strip().lower()
    snmp_port = int(extra.get("snmp_port") or 161)
    timeout = min(5, int(extra.get("snmp_timeout_sec") or 3))
    retries = min(1, int(extra.get("snmp_retries") or 1))
    signal_scale = float(extra.get("snmp_signal_multiplier") or 1.0)
    signal_offset = float(extra.get("snmp_signal_offset") or 0.0)
    signal_tx_scale = float(extra.get("snmp_signal_tx_multiplier") or signal_scale)
    signal_tx_offset = float(extra.get("snmp_signal_tx_offset") or signal_offset)
    temp_scale = float(extra.get("snmp_temperature_multiplier") or 1.0)
    temp_offset = float(extra.get("snmp_temperature_offset") or 0.0)
    traffic_down_scale = float(extra.get("snmp_traffic_down_multiplier") or 1.0)
    traffic_down_offset = float(extra.get("snmp_traffic_down_offset") or 0.0)
    traffic_up_scale = float(extra.get("snmp_traffic_up_multiplier") or 1.0)
    traffic_up_offset = float(extra.get("snmp_traffic_up_offset") or 0.0)

    oid_by_field = {
        "signal": (extra.get("snmp_signal_oid") or "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4").strip(),
        "signal_tx": (extra.get("snmp_signal_tx_oid") or "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3").strip(),
        "signal_olt_rx": (extra.get("snmp_signal_olt_rx_oid") or "").strip(),
        "temperature": (extra.get("snmp_temperature_oid") or "").strip(),
        "vlan": (extra.get("snmp_vlan_oid") or extra.get("snmp_onu_vlan_oid") or "").strip(),
        "status": (extra.get("snmp_status_oid") or "").strip(),
        "traffic_down": (extra.get("snmp_traffic_down_oid") or "1.3.6.1.2.1.2.2.1.10").strip(),
        "traffic_up": (extra.get("snmp_traffic_up_oid") or "1.3.6.1.2.1.2.2.1.16").strip(),
        "traffic": (extra.get("snmp_traffic_oid") or "").strip(),
    }

    candidates = _build_onu_snmp_candidates(onu)
    if not candidates:
        raise CollectorError("Nao foi possivel montar indices SNMP para a ONU selecionada.")

    skipped_fields = {}
    updated_fields = []
    persisted_fields_updated = []
    field_sources = {}
    physical_status = None
    onu_payload = {
        "serial": onu["serial"],
        "model": onu.get("model") or "Desconhecido",
        "status": onu.get("status") or "warning",
        "signal_dbm": onu.get("signal_dbm"),
        "signal_tx_dbm": onu.get("signal_tx_dbm"),
        "signal_olt_rx_dbm": onu.get("signal_olt_rx_dbm"),
        "traffic_down_mbps": onu.get("traffic_down_mbps"),
        "traffic_up_mbps": onu.get("traffic_up_mbps"),
        "temperature_c": onu.get("temperature_c"),
        "board_slot": onu.get("board_slot"),
        "port_name": onu.get("port_name"),
        "pon_position": onu.get("pon_position"),
        "vlan_id": onu.get("vlan_id"),
        "description": onu.get("client_name"),
    }

    for field in requested_fields:
        if field in {"power", "fiber", "ethernet"}:
            continue
        if field == "profile":
            updated_fields.append("profile")
            continue
        oid = oid_by_field.get(field, "")
        if not oid:
            skipped_fields[field] = "OID nao configurado"
            continue
        if field in {"traffic_down", "traffic_up"}:
            ifindex = _resolve_ifindex_for_onu(onu, connection)
            if ifindex is None:
                skipped_fields[field] = "ifIndex da PON nao encontrado"
                continue
            counter_value = _snmp_get_traffic_counter_for_ifindex(
                host=host,
                community=community,
                oid_text=oid,
                ifindex=ifindex,
                port=snmp_port,
                timeout=timeout,
                version=snmp_version,
                retries=retries,
            )
            if counter_value is None:
                skipped_fields[field] = "Sem resposta SNMP para contador de trafego"
                continue
            cache_key = (int(onu.get("olt_id") or 0), int(ifindex), field)
            now_ts = time.time()
            rate_mbps = _calc_mbps_from_counter_delta(cache_key, counter_value, now_ts)
            if rate_mbps is None:
                # Primeira leitura: coleta segunda amostra curta para já exibir taxa.
                time.sleep(1.0)
                counter_value_2 = _snmp_get_traffic_counter_for_ifindex(
                    host=host,
                    community=community,
                    oid_text=oid,
                    ifindex=ifindex,
                    port=snmp_port,
                    timeout=timeout,
                    version=snmp_version,
                    retries=retries,
                )
                rate_mbps = _calc_mbps_from_counter_delta(cache_key, counter_value_2, time.time())
            if rate_mbps is None:
                skipped_fields[field] = "Aguardando segunda amostra de contador"
                continue
            if field == "traffic_down":
                onu_payload["traffic_down_mbps"] = round(float(rate_mbps) * traffic_down_scale + traffic_down_offset, 3)
            else:
                onu_payload["traffic_up_mbps"] = round(float(rate_mbps) * traffic_up_scale + traffic_up_offset, 3)
            updated_fields.append(field)
            continue

        value, matched_suffix = _snmp_get_value_for_candidates(
            host,
            community,
            oid,
            candidates,
            port=snmp_port,
            timeout=timeout,
            version=snmp_version,
            retries=retries,
        )
        if value is None:
            skipped_fields[field] = "Sem resposta SNMP para os indices testados"
            continue

        if field == "signal":
            converted_signal = round(float(value) * signal_scale + signal_offset, 2) if _is_valid_snmp_metric(value) else None
            if converted_signal is not None and _is_valid_onu_signal_dbm(converted_signal):
                onu_payload["signal_dbm"] = converted_signal
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "signal_tx":
            converted_signal_tx = round(float(value) * signal_tx_scale + signal_tx_offset, 2) if _is_valid_snmp_metric(value) else None
            if converted_signal_tx is not None and _is_valid_onu_signal_tx_dbm(converted_signal_tx):
                onu_payload["signal_tx_dbm"] = converted_signal_tx
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "signal_olt_rx":
            converted_signal_olt_rx = _convert_signal_olt_rx_dbm(value, signal_scale, signal_offset)
            if converted_signal_olt_rx is not None:
                onu_payload["signal_olt_rx_dbm"] = converted_signal_olt_rx
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "temperature":
            converted_temp = round(float(value) * temp_scale + temp_offset, 2) if _is_valid_snmp_metric(value) else None
            if converted_temp is not None and _is_valid_onu_temperature_c(converted_temp):
                onu_payload["temperature_c"] = converted_temp
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "vlan":
            try:
                vlan_value = int(value)
                if 1 <= vlan_value <= 4094:
                    onu_payload["vlan_id"] = vlan_value
                    updated_fields.append(field)
                    persisted_fields_updated.append(field)
                    field_sources[field] = "live-snmp"
                else:
                    skipped_fields[field] = "VLAN fora da faixa valida"
            except Exception:
                skipped_fields[field] = "VLAN invalida"
        elif field == "status":
            try:
                status_code = int(value)
                onu_payload["status"] = "active" if status_code == 1 else "warning"
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-snmp"
            except Exception:
                skipped_fields[field] = "Status invalido"
        elif field == "traffic_down":
            if _is_valid_snmp_metric(value):
                onu_payload["traffic_down_mbps"] = round(float(value) * traffic_down_scale + traffic_down_offset, 3)
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-pon-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "traffic_up":
            if _is_valid_snmp_metric(value):
                onu_payload["traffic_up_mbps"] = round(float(value) * traffic_up_scale + traffic_up_offset, 3)
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-pon-snmp"
            else:
                skipped_fields[field] = "Valor invalido"
        elif field == "traffic":
            if _is_valid_snmp_metric(value):
                throughput = round(float(value), 3)
                onu_payload["traffic_down_mbps"] = throughput
                onu_payload["traffic_up_mbps"] = throughput
                updated_fields.append(field)
                persisted_fields_updated.append(field)
                field_sources[field] = "live-pon-snmp"
            else:
                skipped_fields[field] = "Valor invalido"

        serial = snmp_client.normalize_serial(onu.get("serial"))
        if serial and isinstance(matched_suffix, tuple):
            with SNMP_INDEX_CACHE_LOCK:
                cache_for_olt = dict(SNMP_INDEX_CACHE.get(int(onu.get("olt_id") or 0)) or {})
                cache_for_olt[serial] = matched_suffix
                SNMP_INDEX_CACHE[int(onu.get("olt_id") or 0)] = cache_for_olt

    optical_fallback_fields = [
        field
        for field in ("signal", "signal_tx", "signal_olt_rx", "temperature")
        if field in requested_fields and field not in updated_fields
    ]
    if optical_fallback_fields:
        optical_metrics = _collect_huawei_onu_optical_metrics({**onu, **onu_payload}, connection)
        mapping = {
            "signal": "signal_dbm",
            "signal_tx": "signal_tx_dbm",
            "signal_olt_rx": "signal_olt_rx_dbm",
            "temperature": "temperature_c",
        }
        for field in optical_fallback_fields:
            payload_key = mapping[field]
            if optical_metrics.get(payload_key) is None:
                continue
            onu_payload[payload_key] = optical_metrics[payload_key]
            if field not in updated_fields:
                updated_fields.append(field)
            if field not in persisted_fields_updated:
                persisted_fields_updated.append(field)
            field_sources[field] = "live-cli"
            skipped_fields.pop(field, None)

    if (
        "status" in requested_fields
        and "status" not in updated_fields
        and any(field in updated_fields for field in ("signal", "signal_olt_rx"))
        and _has_optical_signal_evidence(onu_payload)
    ):
        onu_payload["status"] = "active"
        updated_fields.append("status")
        persisted_fields_updated.append("status")
        field_sources["status"] = "signal"
        skipped_fields.pop("status", None)

    if physical_fields:
        physical_status = _collect_huawei_onu_physical_status({**onu, **onu_payload}, connection)
        for field in physical_fields:
            item = physical_status.get(field) or {}
            if item.get("state") and item.get("state") != "unknown":
                updated_fields.append(field)
            else:
                skipped_fields[field] = item.get("detail") or "Sem leitura da porta fisica."
        if "status" in requested_fields and "status" not in updated_fields:
            run_state = str((physical_status.get("meta") or {}).get("run_state") or "").strip()
            run_state_lower = run_state.lower()
            disconnect_state = str((physical_status.get("disconnect_reason") or {}).get("state") or "").strip().lower()
            has_optical_signal = bool((physical_status.get("meta") or {}).get("optical_signal_evidence"))
            can_infer_online_from_signal = (
                has_optical_signal
                and run_state_lower in {"", "-", "unknown"}
                and disconnect_state in {"", "unconfirmed"}
            )
            has_offline_evidence = run_state_lower in {"offline", "down"} or disconnect_state in {
                "probable-power-off",
                "probable-fiber-cut",
                "probable-ethernet-down",
            }
            if _is_huawei_run_state_online(run_state) or disconnect_state == "online" or can_infer_online_from_signal:
                onu_payload["status"] = "active"
                updated_fields.append("status")
                persisted_fields_updated.append("status")
                field_sources["status"] = "live-cli" if _is_huawei_run_state_online(run_state) else "signal"
                skipped_fields.pop("status", None)
            elif has_offline_evidence:
                onu_payload["status"] = "warning"
                updated_fields.append("status")
                persisted_fields_updated.append("status")
                field_sources["status"] = "live-cli"
                skipped_fields.pop("status", None)
                # Com offline confirmado pela OLT, limpa sinal optico nao confirmado
                # para evitar manter leitura antiga no painel.
                signal_mapping = {
                    "signal": ("signal_dbm", 0.0),
                    "signal_tx": ("signal_tx_dbm", 0.0),
                    "signal_olt_rx": ("signal_olt_rx_dbm", 0.0),
                }
                for signal_field, payload_info in signal_mapping.items():
                    if signal_field not in requested_fields or signal_field in updated_fields:
                        continue
                    payload_key, fallback_value = payload_info
                    onu_payload[payload_key] = fallback_value
                    updated_fields.append(signal_field)
                    persisted_fields_updated.append(signal_field)
                    field_sources[signal_field] = "live-cli"
                    skipped_fields.pop(signal_field, None)

    if not updated_fields and "profile" not in requested_fields and not physical_status:
        raise CollectorError("Nao foi possivel atualizar nenhum campo da ONU via SNMP.")

    collected_at = db.utc_now()
    if persisted_fields_updated:
        payload = {
            "collected_at": collected_at,
            "olt_metrics": {},
            "boards": [],
            "ports": [],
            "onus": [onu_payload],
            "authorization_requests": [],
            "events": [
                {
                    "level": "info",
                    "message": f'Coleta sob demanda da ONU {onu.get("serial")}',
                    "details": {
                        "mode": "onu-live",
                        "onu_id": int(onu_id),
                        "updated_fields": updated_fields,
                        "skipped_fields": skipped_fields,
                    },
                }
            ],
        }
        db.apply_collection(int(onu["olt_id"]), payload)
    response = {
        "status": "ok",
        "onu_id": int(onu_id),
        "collected_at": collected_at,
        "updated_fields": updated_fields,
        "skipped_fields": skipped_fields,
        "onu": db.fetch_onu_by_id(int(onu_id)),
    }
    field_meta = _build_live_field_meta(updated_fields, collected_at, field_sources=field_sources)
    if field_meta:
        response["field_meta"] = field_meta
        response["onu"] = _merge_onu_field_meta(response["onu"], field_meta)
    if physical_status:
        response["physical_status"] = physical_status
    return response
