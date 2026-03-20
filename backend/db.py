import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.secrets import decrypt_secret, encrypt_secret


DB_PATH = Path(__file__).resolve().parent.parent / "conectaolt.db"
PASSWORD_HASH_ITERATIONS = 210_000
SESSION_DURATION_SEC = 12 * 60 * 60
PERMISSION_CATALOG = [
    {"key": "dashboard_view", "label": "Dashboard (visualizar)"},
    {"key": "olts_view", "label": "OLTs (visualizar)"},
    {"key": "olts_manage", "label": "OLTs (gerenciar)"},
    {"key": "onus_view", "label": "ONUs (visualizar)"},
    {"key": "onus_manage", "label": "ONUs (gerenciar)"},
    {"key": "requests_view", "label": "Solicitacoes (visualizar)"},
    {"key": "requests_manage", "label": "Solicitacoes (gerenciar)"},
    {"key": "collection_view", "label": "Coleta (visualizar)"},
    {"key": "collection_manage", "label": "Coleta (executar/editar)"},
    {"key": "users_view", "label": "Usuarios (visualizar)"},
    {"key": "users_manage", "label": "Usuarios (gerenciar)"},
]
PERMISSION_KEYS = tuple(item["key"] for item in PERMISSION_CATALOG)
LEGACY_PERMISSION_MAP = {
    "dashboard": ("dashboard_view",),
    "olts": ("olts_view", "olts_manage"),
    "onus": ("onus_view", "onus_manage"),
    "requests": ("requests_view", "requests_manage"),
    "collection": ("collection_view", "collection_manage"),
    "users": ("users_view", "users_manage"),
}

TEMPLATE_EXTRA_KEYS = {
    "snmp_version",
    "snmp_community",
    "snmp_read_community",
    "snmp_write_community",
    "snmp_port",
    "snmp_timeout_sec",
    "snmp_retries",
    "snmp_max_rows",
    "snmp_bulk_repetitions",
    "snmp_fast_mode",
    "snmp_fast_max_rows",
    "snmp_fast_retries",
    "snmp_fast_timeout_sec",
    "snmp_use_cached_serial_index",
    "snmp_serial_oid",
    "snmp_signal_oid",
    "snmp_signal_tx_oid",
    "snmp_signal_olt_rx_oid",
    "snmp_temperature_oid",
    "snmp_status_oid",
    "snmp_distance_oid",
    "snmp_vlan_oid",
    "snmp_port_status_oid",
    "snmp_port_count_oid",
    "snmp_parallel_walks",
    "snmp_signal_multiplier",
    "snmp_signal_offset",
    "snmp_signal_tx_multiplier",
    "snmp_signal_tx_offset",
    "snmp_temperature_multiplier",
    "snmp_temperature_offset",
    "snmp_traffic_down_oid",
    "snmp_traffic_up_oid",
    "snmp_traffic_oid",
    "snmp_traffic_down_multiplier",
    "snmp_traffic_down_offset",
    "snmp_traffic_up_multiplier",
    "snmp_traffic_up_offset",
    "snmp_ifname_oid",
    "snmp_live_alert_mbps",
    "live_pon_alert_mbps",
    "force_full_inventory",
    "fast_poll_enabled",
    "allow_empty_onu_inventory",
    "full_inventory_interval_sec",
    "fast_partial_onu_updates",
    "telnet_command_timeout_sec",
    "telnet_allow_partial",
    "command_overrides",
    "ssh_key_path",
    "provision_inbound_traffic_table",
    "provision_outbound_traffic_table",
    "provision_gemport",
    "provision_tag_transform",
    "provision_native_vlan_eth_port",
    "collector_profile",
    "collector_profile_detected",
}
TEMPLATE_COMMAND_OVERRIDE_KEYS = ("ont_summary", "service_port", "vlan_inventory")
TEMPLATE_DEFAULT_KEYS = {
    "protocol",
    "transport_type",
    "username",
    "password",
    "api_base_url",
    "api_token",
    "source_path",
    "command_line",
    "port",
    "poll_interval_sec",
    "command_timeout_sec",
    "verify_tls",
    "enabled",
    "status",
    "board_model",
    "board_slots",
    "ports_per_board",
    "capacity_onu",
}
TEMPLATE_SECRET_DEFAULT_KEYS = {"password", "api_token"}

BUILTIN_CONNECTION_TEMPLATES = [
    {
        "brand": "huawei",
        "model": "*",
        "firmware": "*",
        "extra_config": {
            "snmp_version": "2c",
            "snmp_port": 161,
            "snmp_timeout_sec": 4,
            "snmp_retries": 2,
            "snmp_max_rows": 8192,
            "snmp_bulk_repetitions": 25,
            "snmp_fast_mode": True,
            "snmp_use_cached_serial_index": True,
            "snmp_signal_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
            "snmp_signal_tx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3",
            "snmp_signal_olt_rx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6",
            "snmp_traffic_down_oid": "1.3.6.1.2.1.2.2.1.10",
            "snmp_traffic_up_oid": "1.3.6.1.2.1.2.2.1.16",
            "snmp_ifname_oid": "1.3.6.1.2.1.31.1.1.1.1",
            "snmp_live_alert_mbps": 200,
            "fast_poll_enabled": True,
            "full_inventory_interval_sec": 1800,
            "fast_partial_onu_updates": True,
        },
    },
    {
        "brand": "huawei",
        "model": "MA5600",
        "firmware": "V800R018",
        "extra_config": {
            "snmp_version": "2c",
            "snmp_port": 161,
            "snmp_timeout_sec": 4,
            "snmp_retries": 2,
            "snmp_max_rows": 8192,
            "snmp_bulk_repetitions": 25,
            "snmp_fast_mode": True,
            "snmp_use_cached_serial_index": True,
            "snmp_signal_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
            "snmp_signal_tx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3",
            "snmp_signal_olt_rx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6",
            "snmp_traffic_down_oid": "1.3.6.1.2.1.2.2.1.10",
            "snmp_traffic_up_oid": "1.3.6.1.2.1.2.2.1.16",
            "snmp_ifname_oid": "1.3.6.1.2.1.31.1.1.1.1",
            "snmp_live_alert_mbps": 200,
            "fast_poll_enabled": True,
            "full_inventory_interval_sec": 1800,
            "fast_partial_onu_updates": True,
        },
    },
    {
        "brand": "huawei",
        "model": "Huawei-MA5683T",
        "firmware": "R015",
        "defaults": {
            "protocol": "native",
            "transport_type": "telnet",
            "port": 23,
            "poll_interval_sec": 300,
            "command_timeout_sec": 20,
            "enabled": True,
            "status": "online",
            "board_model": "GPON",
            "board_slots": "0/0,0/1,0/2,0/3,0/4,0/5",
            "ports_per_board": 16,
            "capacity_onu": 128,
        },
        "extra_config": {
            "collector_profile": "huawei_ma56xx",
            "fast_poll_enabled": True,
            "full_inventory_interval_sec": 1800,
            "fast_partial_onu_updates": True,
            "snmp_fast_mode": True,
            "snmp_use_cached_serial_index": True,
            "snmp_fast_timeout_sec": 5,
            "snmp_fast_retries": 1,
            "snmp_fast_max_rows": 4096,
            "snmp_parallel_walks": 2,
            "snmp_signal_multiplier": 0.01,
            "snmp_signal_offset": 0,
            "snmp_signal_tx_multiplier": 0.01,
            "snmp_signal_tx_offset": 0,
            "snmp_temperature_multiplier": 1,
            "snmp_temperature_offset": 0,
            "snmp_temperature_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.1",
            "snmp_serial_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3",
            "snmp_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15",
            "snmp_distance_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20",
            "snmp_vlan_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.2",
            "snmp_port_count_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.16",
            "snmp_port_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.10",
            "telnet_command_timeout_sec": 90,
            "telnet_allow_partial": True,
            "command_overrides": {
                "ont_summary": "display ont info 0",
                "service_port": "display current-configuration | include service-port",
                "vlan_inventory": "display current-configuration | include vlan",
            },
        },
    },
    {
        "brand": "huawei",
        "model": "Huawei-MA5683T",
        "firmware": "R018",
        "defaults": {
            "protocol": "native",
            "transport_type": "telnet",
            "port": 23,
            "poll_interval_sec": 300,
            "command_timeout_sec": 20,
            "enabled": True,
            "status": "online",
            "board_model": "GPON",
            "board_slots": "0/0,0/1,0/2,0/3",
            "ports_per_board": 16,
            "capacity_onu": 128,
        },
        "extra_config": {
            "collector_profile": "huawei_ma56xx",
            "fast_poll_enabled": True,
            "full_inventory_interval_sec": 1800,
            "fast_partial_onu_updates": True,
            "snmp_fast_mode": True,
            "snmp_use_cached_serial_index": True,
            "snmp_fast_timeout_sec": 5,
            "snmp_fast_retries": 1,
            "snmp_fast_max_rows": 4096,
            "snmp_parallel_walks": 2,
            "snmp_signal_multiplier": 0.01,
            "snmp_signal_offset": 0,
            "snmp_signal_tx_multiplier": 0.01,
            "snmp_signal_tx_offset": 0,
            "snmp_temperature_multiplier": 1,
            "snmp_temperature_offset": 0,
            "snmp_temperature_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.1",
            "snmp_serial_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3",
            "snmp_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15",
            "snmp_distance_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20",
            "snmp_vlan_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.2",
            "snmp_port_count_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.16",
            "snmp_port_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.21.1.10",
            "telnet_command_timeout_sec": 90,
            "telnet_allow_partial": True,
            "command_overrides": {
                "ont_summary": "display ont info 0",
                "service_port": "display current-configuration | include service-port",
                "vlan_inventory": "display current-configuration | include vlan",
            },
        },
    },
    {
        "brand": "huawei",
        "model": "Huawei-MA5800-X7",
        "firmware": "R018",
        "defaults": {
            "protocol": "native",
            "transport_type": "telnet",
            "port": 23,
            "poll_interval_sec": 300,
            "command_timeout_sec": 20,
            "enabled": True,
            "status": "online",
            "board_model": "GPON",
            "board_slots": "0/1,0/2,0/3,0/4,0/5,0/6,0/7",
            "ports_per_board": 16,
            "capacity_onu": 128,
        },
        "extra_config": {
            "collector_profile": "huawei_ma5800",
            "command_overrides": {
                "ont_summary": "display ont info summary",
                "service_port": "display current-configuration | include service-port",
                "vlan_inventory": "display current-configuration | include vlan",
            },
            "snmp_signal_multiplier": 0.01,
            "snmp_signal_offset": 0,
            "snmp_signal_tx_multiplier": 0.01,
            "snmp_signal_tx_offset": 0,
            "snmp_temperature_multiplier": 1,
            "snmp_temperature_offset": 0,
            "snmp_parallel_walks": 2,
            "snmp_temperature_oid": "1.3.6.1.4.1.6527.3.1.2.2.1.8.1.18",
            "snmp_distance_oid": "1.3.6.1.4.1.2011.5.14.6.1.1.15",
            "snmp_port_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9",
        },
    },
    {
        "brand": "huawei",
        "model": "Huawei-MA5800-X15",
        "firmware": "R018",
        "defaults": {
            "protocol": "native",
            "transport_type": "telnet",
            "port": 23,
            "poll_interval_sec": 300,
            "command_timeout_sec": 20,
            "enabled": True,
            "status": "online",
            "board_model": "GPON",
            "board_slots": "0/1,0/2,0/3,0/4,0/5,0/6,0/7,0/10,0/11,0/12,0/13,0/14,0/15,0/16,0/17",
            "ports_per_board": 16,
            "capacity_onu": 128,
        },
        "extra_config": {
            "collector_profile": "huawei_ma5800",
            "command_overrides": {
                "ont_summary": "display ont info summary",
                "service_port": "display current-configuration | include service-port",
                "vlan_inventory": "display current-configuration | include vlan",
            },
            "snmp_signal_multiplier": 0.01,
            "snmp_signal_offset": 0,
            "snmp_signal_tx_multiplier": 0.01,
            "snmp_signal_tx_offset": 0,
            "snmp_temperature_multiplier": 1,
            "snmp_temperature_offset": 0,
            "snmp_parallel_walks": 2,
            "snmp_temperature_oid": "1.3.6.1.4.1.6527.3.1.2.2.1.8.1.18",
            "snmp_distance_oid": "1.3.6.1.4.1.2011.5.14.6.1.1.15",
            "snmp_port_status_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9",
        },
    }
]


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value, now=None):
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return max(0, int((reference.astimezone(timezone.utc) - parsed).total_seconds()))


def _confidence_from_age(age_sec, poll_interval_sec, stale_after_sec):
    if age_sec is None:
        return "low"
    if age_sec <= max(1, int(poll_interval_sec)):
        return "high"
    if age_sec <= max(1, int(stale_after_sec)):
        return "medium"
    return "low"


def _freshness_from_age(age_sec, poll_interval_sec, stale_after_sec):
    if age_sec is None:
        return "unknown"
    if age_sec <= max(1, int(poll_interval_sec)):
        return "fresh"
    if age_sec <= max(1, int(stale_after_sec)):
        return "aging"
    return "stale"


def _build_onu_field_meta(source, updated_at, age_sec, stale_after_sec, confidence, freshness, detail):
    return {
        "source": source or "",
        "updated_at": updated_at,
        "age_sec": age_sec,
        "stale_after_sec": stale_after_sec,
        "stale": freshness == "stale",
        "confidence": confidence,
        "freshness": freshness,
        "detail": detail or "",
    }


def _decorate_onu_runtime_state(item, now=None):
    normalized = dict(item or {})
    poll_interval_raw = normalized.pop("poll_interval_sec", 300)
    try:
        poll_interval_sec = max(60, int(poll_interval_raw or 300))
    except Exception:
        poll_interval_sec = 300
    stale_after_sec = max(180, min(1800, poll_interval_sec * 2))
    age_sec = _age_seconds(normalized.get("updated_at"), now=now)
    confidence = _confidence_from_age(age_sec, poll_interval_sec, stale_after_sec)
    freshness = _freshness_from_age(age_sec, poll_interval_sec, stale_after_sec)
    detail = (
        "Ultima leitura acima da janela esperada da OLT."
        if freshness == "stale"
        else "Leitura ainda valida, mas fora do ultimo ciclo do poll."
        if freshness == "aging"
        else "Leitura dentro da janela esperada do poll."
        if freshness == "fresh"
        else "Sem horario de coleta confiavel."
    )
    normalized["data_quality"] = {
        "source": "poll",
        "updated_at": normalized.get("updated_at"),
        "age_sec": age_sec,
        "poll_interval_sec": poll_interval_sec,
        "stale_after_sec": stale_after_sec,
        "stale": freshness == "stale",
        "confidence": confidence,
        "freshness": freshness,
        "detail": detail,
    }
    normalized["field_meta"] = {
        "status": _build_onu_field_meta(
            "poll",
            normalized.get("updated_at"),
            age_sec,
            stale_after_sec,
            confidence,
            freshness,
            detail,
        ),
        "signal": _build_onu_field_meta(
            "poll-snmp" if normalized.get("signal_dbm") is not None else "",
            normalized.get("updated_at"),
            age_sec,
            stale_after_sec,
            confidence,
            freshness,
            detail,
        ),
        "traffic": _build_onu_field_meta(
            "poll-pon",
            normalized.get("updated_at"),
            age_sec,
            stale_after_sec,
            confidence,
            freshness,
            detail,
        ),
        "temperature": _build_onu_field_meta(
            "poll-snmp" if normalized.get("temperature_c") is not None else "",
            normalized.get("updated_at"),
            age_sec,
            stale_after_sec,
            confidence,
            freshness,
            detail,
        ),
    }
    return normalized


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS olt (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                brand TEXT NOT NULL,
                model TEXT NOT NULL,
                host TEXT NOT NULL,
                status TEXT NOT NULL,
                firmware TEXT,
                temperature_c REAL NOT NULL,
                cpu_usage REAL NOT NULL,
                memory_usage REAL NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS board (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL REFERENCES olt(id) ON DELETE CASCADE,
                slot TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,
                ports_total INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pon_port (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                board_id INTEGER NOT NULL REFERENCES board(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                capacity_onu INTEGER NOT NULL,
                alert_threshold_pct INTEGER NOT NULL DEFAULT 80
            );

            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand TEXT NOT NULL,
                name TEXT NOT NULL,
                onu_model TEXT NOT NULL,
                vlan_default INTEGER NOT NULL,
                line_profile TEXT,
                service_profile TEXT
            );

            CREATE TABLE IF NOT EXISTS onu (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                model TEXT NOT NULL,
                client_name TEXT NOT NULL,
                neighborhood TEXT NOT NULL,
                city TEXT NOT NULL,
                vlan_id INTEGER NOT NULL,
                profile_id INTEGER REFERENCES profile(id),
                onu_mode TEXT NOT NULL DEFAULT 'bridge',
                status TEXT NOT NULL,
                signal_dbm REAL NOT NULL,
                signal_tx_dbm REAL,
                signal_olt_rx_dbm REAL,
                traffic_down_mbps REAL NOT NULL,
                traffic_up_mbps REAL NOT NULL,
                temperature_c REAL NOT NULL,
                olt_id INTEGER NOT NULL REFERENCES olt(id),
                board_id INTEGER NOT NULL REFERENCES board(id),
                port_id INTEGER NOT NULL REFERENCES pon_port(id),
                pon_position INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authorization_request (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial TEXT NOT NULL,
                detected_model TEXT NOT NULL,
                olt_id INTEGER NOT NULL REFERENCES olt(id),
                board_id INTEGER NOT NULL REFERENCES board(id),
                port_id INTEGER NOT NULL REFERENCES pon_port(id),
                requested_signal_dbm REAL,
                requested_temperature_c REAL,
                requested_at TEXT NOT NULL,
                status TEXT NOT NULL,
                notes TEXT,
                resolved_onu_id INTEGER REFERENCES onu(id)
            );

            CREATE TABLE IF NOT EXISTS olt_connection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL UNIQUE REFERENCES olt(id) ON DELETE CASCADE,
                protocol TEXT NOT NULL,
                transport_type TEXT NOT NULL DEFAULT 'ssh',
                enabled INTEGER NOT NULL DEFAULT 1,
                username TEXT,
                password TEXT,
                api_base_url TEXT,
                api_token TEXT,
                source_path TEXT,
                command_line TEXT,
                port INTEGER,
                poll_interval_sec INTEGER NOT NULL DEFAULT 300,
                command_timeout_sec INTEGER NOT NULL DEFAULT 20,
                verify_tls INTEGER NOT NULL DEFAULT 0,
                extra_config TEXT,
                last_poll_status TEXT,
                last_poll_at TEXT,
                last_error TEXT,
                last_connect_status TEXT,
                last_connect_at TEXT,
                last_connect_message TEXT
            );

            CREATE TABLE IF NOT EXISTS olt_metric_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL REFERENCES olt(id) ON DELETE CASCADE,
                collected_at TEXT NOT NULL,
                temperature_c REAL NOT NULL,
                cpu_usage REAL NOT NULL,
                memory_usage REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS onu_metric_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                onu_id INTEGER NOT NULL REFERENCES onu(id) ON DELETE CASCADE,
                collected_at TEXT NOT NULL,
                signal_dbm REAL NOT NULL,
                traffic_down_mbps REAL NOT NULL,
                traffic_up_mbps REAL NOT NULL,
                temperature_c REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS port_metric_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER NOT NULL REFERENCES pon_port(id) ON DELETE CASCADE,
                collected_at TEXT NOT NULL,
                used_onu INTEGER NOT NULL,
                capacity_onu INTEGER NOT NULL,
                usage_pct REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS collector_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL REFERENCES olt(id) ON DELETE CASCADE,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                details_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS olt_vlan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL REFERENCES olt(id) ON DELETE CASCADE,
                vlan_id INTEGER NOT NULL,
                name TEXT,
                description TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                updated_at TEXT NOT NULL,
                UNIQUE(olt_id, vlan_id)
            );

            CREATE TABLE IF NOT EXISTS olt_profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                olt_id INTEGER NOT NULL REFERENCES olt(id) ON DELETE CASCADE,
                profile_kind TEXT NOT NULL,
                profile_ref INTEGER NOT NULL,
                name TEXT NOT NULL,
                binding_times INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'cli',
                updated_at TEXT NOT NULL,
                UNIQUE(olt_id, profile_kind, profile_ref)
            );

            CREATE TABLE IF NOT EXISTS olt_connection_template (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand TEXT NOT NULL,
                model TEXT NOT NULL,
                firmware TEXT NOT NULL,
                extra_config TEXT NOT NULL,
                defaults_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL,
                UNIQUE(brand, model, firmware)
            );

            CREATE TABLE IF NOT EXISTS app_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_admin INTEGER NOT NULL DEFAULT 0,
                permissions_json TEXT NOT NULL DEFAULT '{}',
                last_login_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            );
            """
        )
        ensure_connection_columns(connection)
        ensure_onu_columns(connection)
        ensure_auth_columns(connection)
        ensure_connection_template_columns(connection)
        ensure_connection_templates(connection)
        ensure_phase2_records(connection)


def seed_history(connection, now):
    usage = _port_usage(connection)
    olt_rows = connection.execute(
        "SELECT id, temperature_c, cpu_usage, memory_usage FROM olt"
    ).fetchall()
    for olt in olt_rows:
        connection.execute(
            """
            INSERT INTO olt_metric_history (
                olt_id, collected_at, temperature_c, cpu_usage, memory_usage
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (olt["id"], now, olt["temperature_c"], olt["cpu_usage"], olt["memory_usage"]),
        )

    onu_rows = connection.execute(
        """
        SELECT id, signal_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c
        FROM onu
        """
    ).fetchall()
    for onu in onu_rows:
        connection.execute(
            """
            INSERT INTO onu_metric_history (
                onu_id, collected_at, signal_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                onu["id"],
                now,
                onu["signal_dbm"],
                onu["traffic_down_mbps"],
                onu["traffic_up_mbps"],
                onu["temperature_c"],
            ),
        )

    for port_id, data in usage.items():
        usage_pct = 0 if not data["capacity_onu"] else round(data["used_onu"] * 100 / data["capacity_onu"], 1)
        connection.execute(
            """
            INSERT INTO port_metric_history (
                port_id, collected_at, used_onu, capacity_onu, usage_pct
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (port_id, now, data["used_onu"], data["capacity_onu"], usage_pct),
        )


def ensure_phase2_records(connection):
    existing_connections = connection.execute(
        "SELECT COUNT(*) FROM olt_connection"
    ).fetchone()[0]
    if not existing_connections:
        olts = connection.execute("SELECT id, brand FROM olt ORDER BY id").fetchall()
        rows = []
        for olt in olts:
            rows.append(
                (
                    olt["id"],
                    _default_collection_protocol(olt["brand"], "ssh"),
                    "ssh",
                    1,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    22,
                    300,
                    20,
                    0,
                    json.dumps({"vendor_hint": olt["brand"]}),
                    "idle",
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            )
        connection.executemany(
            """
            INSERT INTO olt_connection (
                olt_id, protocol, transport_type, enabled, username, password, api_base_url, api_token,
                source_path, command_line, port, poll_interval_sec, command_timeout_sec,
                verify_tls, extra_config, last_poll_status, last_poll_at, last_error,
                last_connect_status, last_connect_at, last_connect_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    history_count = connection.execute(
        "SELECT COUNT(*) FROM olt_metric_history"
    ).fetchone()[0]
    if not history_count:
        seed_history(connection, utc_now())
        connection.commit()


def ensure_connection_columns(connection):
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(olt_connection)").fetchall()
    }
    migrations = [
        ("transport_type", "ALTER TABLE olt_connection ADD COLUMN transport_type TEXT NOT NULL DEFAULT 'ssh'"),
        ("last_connect_status", "ALTER TABLE olt_connection ADD COLUMN last_connect_status TEXT"),
        ("last_connect_at", "ALTER TABLE olt_connection ADD COLUMN last_connect_at TEXT"),
        ("last_connect_message", "ALTER TABLE olt_connection ADD COLUMN last_connect_message TEXT"),
    ]
    for column_name, statement in migrations:
        if column_name not in existing_columns:
            connection.execute(statement)
    connection.execute(
        """
        UPDATE olt_connection
        SET protocol = 'native'
        WHERE protocol = 'mock'
          AND olt_id IN (
            SELECT id
            FROM olt
            WHERE LOWER(brand) = 'huawei'
          )
          AND LOWER(COALESCE(transport_type, 'ssh')) IN ('ssh', 'telnet')
        """
    )
    connection.commit()


def ensure_connection_template_columns(connection):
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(olt_connection_template)").fetchall()
    }
    if "defaults_json" not in existing_columns:
        connection.execute(
            "ALTER TABLE olt_connection_template ADD COLUMN defaults_json TEXT NOT NULL DEFAULT '{}'"
        )
    connection.commit()


def ensure_onu_columns(connection):
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(onu)").fetchall()
    }
    if "signal_tx_dbm" not in existing_columns:
        connection.execute("ALTER TABLE onu ADD COLUMN signal_tx_dbm REAL")
    if "signal_olt_rx_dbm" not in existing_columns:
        connection.execute("ALTER TABLE onu ADD COLUMN signal_olt_rx_dbm REAL")
    if "line_profile" not in existing_columns:
        connection.execute("ALTER TABLE onu ADD COLUMN line_profile TEXT")
    if "service_profile" not in existing_columns:
        connection.execute("ALTER TABLE onu ADD COLUMN service_profile TEXT")
    if "onu_mode" not in existing_columns:
        connection.execute("ALTER TABLE onu ADD COLUMN onu_mode TEXT NOT NULL DEFAULT 'bridge'")
    connection.commit()


def ensure_auth_columns(connection):
    existing_user_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(app_user)").fetchall()
    }
    user_migrations = [
        ("display_name", "ALTER TABLE app_user ADD COLUMN display_name TEXT NOT NULL DEFAULT ''"),
        ("password_hash", "ALTER TABLE app_user ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''"),
        ("is_active", "ALTER TABLE app_user ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"),
        ("is_admin", "ALTER TABLE app_user ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"),
        ("permissions_json", "ALTER TABLE app_user ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '{}'"),
        ("last_login_at", "ALTER TABLE app_user ADD COLUMN last_login_at TEXT"),
        ("created_at", "ALTER TABLE app_user ADD COLUMN created_at TEXT"),
        ("updated_at", "ALTER TABLE app_user ADD COLUMN updated_at TEXT"),
    ]
    for column_name, statement in user_migrations:
        if column_name not in existing_user_columns:
            connection.execute(statement)

    existing_session_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(app_session)").fetchall()
    }
    session_migrations = [
        ("last_seen_at", "ALTER TABLE app_session ADD COLUMN last_seen_at TEXT"),
        ("expires_at", "ALTER TABLE app_session ADD COLUMN expires_at TEXT"),
        ("ip_address", "ALTER TABLE app_session ADD COLUMN ip_address TEXT"),
        ("user_agent", "ALTER TABLE app_session ADD COLUMN user_agent TEXT"),
    ]
    for column_name, statement in session_migrations:
        if column_name not in existing_session_columns:
            connection.execute(statement)

    now = utc_now()
    connection.execute(
        """
        UPDATE app_user
        SET display_name = CASE
                WHEN TRIM(COALESCE(display_name, '')) = '' THEN username
                ELSE display_name
            END,
            created_at = COALESCE(created_at, ?),
            updated_at = COALESCE(updated_at, ?),
            permissions_json = CASE
                WHEN TRIM(COALESCE(permissions_json, '')) = '' THEN '{}'
                ELSE permissions_json
            END
        """,
        (now, now),
    )
    connection.execute(
        """
        UPDATE app_session
        SET last_seen_at = COALESCE(last_seen_at, created_at, ?),
            expires_at = COALESCE(expires_at, ?)
        """,
        (now, _utc_after_seconds(SESSION_DURATION_SEC)),
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_app_session_user_id ON app_session(user_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_app_session_expires_at ON app_session(expires_at)")
    connection.commit()


def get_permission_catalog():
    return [dict(item) for item in PERMISSION_CATALOG]


def _utc_after_seconds(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=int(seconds))).replace(microsecond=0).isoformat()


def _normalize_username(value):
    return (value or "").strip().lower()


def _normalize_permissions(raw_permissions, is_admin=False):
    normalized = {key: False for key in PERMISSION_KEYS}
    source = raw_permissions
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except Exception:
            source = {}
    if isinstance(source, list):
        source = {str(item): True for item in source}
    if isinstance(source, dict):
        for legacy_key, mapped_keys in LEGACY_PERMISSION_MAP.items():
            if bool(source.get(legacy_key)):
                for mapped in mapped_keys:
                    normalized[mapped] = True
        for key in PERMISSION_KEYS:
            normalized[key] = normalized[key] or bool(source.get(key))
    if normalized.get("olts_manage"):
        normalized["olts_view"] = True
    if normalized.get("onus_manage"):
        normalized["onus_view"] = True
    if normalized.get("requests_manage"):
        normalized["requests_view"] = True
    if normalized.get("collection_manage"):
        normalized["collection_view"] = True
    if normalized.get("users_manage"):
        normalized["users_view"] = True
    if is_admin:
        for key in PERMISSION_KEYS:
            normalized[key] = True
    return normalized


def _deserialize_permissions(value, is_admin=False):
    if isinstance(value, dict):
        return _normalize_permissions(value, is_admin=is_admin)
    try:
        payload = json.loads(value or "{}")
    except Exception:
        payload = {}
    return _normalize_permissions(payload, is_admin=is_admin)


def _hash_password(raw_password):
    password = str(raw_password or "")
    if len(password) < 6:
        raise ValueError("Senha deve ter pelo menos 6 caracteres.")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return (
        "pbkdf2_sha256$"
        f"{PASSWORD_HASH_ITERATIONS}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def _verify_password(raw_password, password_hash):
    password = str(raw_password or "")
    parts = str(password_hash or "").split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
    except Exception:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(digest, expected)


def _public_user_from_row(row):
    item = dict(row)
    is_admin = bool(item.get("is_admin"))
    return {
        "id": int(item["id"]),
        "username": item.get("username") or "",
        "display_name": item.get("display_name") or item.get("username") or "",
        "is_active": bool(item.get("is_active")),
        "is_admin": is_admin,
        "permissions": _deserialize_permissions(item.get("permissions_json"), is_admin=is_admin),
        "last_login_at": item.get("last_login_at"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _has_any_user(connection):
    return int(connection.execute("SELECT COUNT(*) FROM app_user").fetchone()[0]) > 0


def _create_session_for_user(connection, user_id, ip_address=None, user_agent=None):
    now = utc_now()
    token = secrets.token_urlsafe(36)
    connection.execute(
        """
        INSERT INTO app_session (token, user_id, created_at, last_seen_at, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token,
            int(user_id),
            now,
            now,
            _utc_after_seconds(SESSION_DURATION_SEC),
            (ip_address or "").strip() or None,
            (user_agent or "").strip() or None,
        ),
    )
    return token


def _delete_expired_sessions(connection):
    now = utc_now()
    connection.execute("DELETE FROM app_session WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))


def has_permission(session_payload, permission_key):
    if not isinstance(session_payload, dict):
        return False
    user = session_payload.get("user") or {}
    if user.get("is_admin"):
        return True
    permissions = session_payload.get("permissions") or {}
    if permission_key in LEGACY_PERMISSION_MAP:
        return any(bool(permissions.get(mapped)) for mapped in LEGACY_PERMISSION_MAP[permission_key])
    return bool(permissions.get(permission_key))


def fetch_auth_session(token=None):
    with connect() as connection:
        _delete_expired_sessions(connection)
        bootstrap_required = not _has_any_user(connection)
        if not token:
            connection.commit()
            return {
                "authenticated": False,
                "bootstrap_required": bootstrap_required,
                "permission_catalog": get_permission_catalog(),
                "user": None,
                "permissions": _normalize_permissions({}),
            }

        row = connection.execute(
            """
            SELECT
                session.id AS session_id,
                session.user_id,
                user.id,
                user.username,
                user.display_name,
                user.is_active,
                user.is_admin,
                user.permissions_json,
                user.last_login_at,
                user.created_at,
                user.updated_at
            FROM app_session session
            JOIN app_user user ON user.id = session.user_id
            WHERE session.token = ?
              AND user.is_active = 1
              AND session.expires_at > ?
            LIMIT 1
            """,
            (token, utc_now()),
        ).fetchone()
        if not row:
            connection.commit()
            return {
                "authenticated": False,
                "bootstrap_required": bootstrap_required,
                "permission_catalog": get_permission_catalog(),
                "user": None,
                "permissions": _normalize_permissions({}),
            }

        now = utc_now()
        connection.execute(
            """
            UPDATE app_session
            SET last_seen_at = ?
            WHERE id = ?
            """,
            (now, int(row["session_id"])),
        )
        connection.commit()
        user = _public_user_from_row(row)
        return {
            "authenticated": True,
            "bootstrap_required": False,
            "permission_catalog": get_permission_catalog(),
            "user": user,
            "permissions": user["permissions"],
        }


def authenticate_user(username, password, ip_address=None, user_agent=None):
    identity = _normalize_username(username)
    if not identity:
        raise ValueError("Informe usuario e senha.")
    with connect() as connection:
        _delete_expired_sessions(connection)
        row = connection.execute(
            """
            SELECT id, username, display_name, password_hash, is_active, is_admin,
                   permissions_json, last_login_at, created_at, updated_at
            FROM app_user
            WHERE username = ?
            LIMIT 1
            """,
            (identity,),
        ).fetchone()
        if not row or not bool(row["is_active"]):
            raise ValueError("Usuario ou senha invalidos.")
        if not _verify_password(password, row["password_hash"]):
            raise ValueError("Usuario ou senha invalidos.")
        token = _create_session_for_user(
            connection,
            int(row["id"]),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        now = utc_now()
        connection.execute(
            """
            UPDATE app_user
            SET last_login_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (now, now, int(row["id"])),
        )
        refreshed = connection.execute(
            """
            SELECT id, username, display_name, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            WHERE id = ?
            """,
            (int(row["id"]),),
        ).fetchone()
        connection.commit()
        user = _public_user_from_row(refreshed)
        return {
            "token": token,
            "user": user,
            "permissions": user["permissions"],
            "authenticated": True,
            "bootstrap_required": False,
            "permission_catalog": get_permission_catalog(),
        }


def logout_session(token):
    if not token:
        return {"status": "ok"}
    with connect() as connection:
        connection.execute("DELETE FROM app_session WHERE token = ?", (token,))
        connection.commit()
    return {"status": "ok"}


def bootstrap_admin_user(payload, ip_address=None, user_agent=None):
    payload = payload or {}
    username = _normalize_username(payload.get("username"))
    display_name = (payload.get("display_name") or "").strip() or username
    password = str(payload.get("password") or "")
    if not username:
        raise ValueError("Informe o usuario administrador.")
    if len(password) < 6:
        raise ValueError("Senha deve ter pelo menos 6 caracteres.")
    now = utc_now()
    with connect() as connection:
        if _has_any_user(connection):
            raise ValueError("Bootstrap ja realizado. Faça login.")
        cursor = connection.execute(
            """
            INSERT INTO app_user (
                username, display_name, password_hash, is_active, is_admin,
                permissions_json, last_login_at, created_at, updated_at
            ) VALUES (?, ?, ?, 1, 1, ?, NULL, ?, ?)
            """,
            (
                username,
                display_name,
                _hash_password(password),
                json.dumps(_normalize_permissions({}, is_admin=True)),
                now,
                now,
            ),
        )
        token = _create_session_for_user(
            connection,
            cursor.lastrowid,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        connection.execute(
            "UPDATE app_user SET last_login_at = ? WHERE id = ?",
            (now, int(cursor.lastrowid)),
        )
        row = connection.execute(
            """
            SELECT id, username, display_name, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            WHERE id = ?
            """,
            (int(cursor.lastrowid),),
        ).fetchone()
        connection.commit()
        user = _public_user_from_row(row)
        return {
            "token": token,
            "authenticated": True,
            "bootstrap_required": False,
            "permission_catalog": get_permission_catalog(),
            "user": user,
            "permissions": user["permissions"],
        }


def fetch_users():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, username, display_name, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            ORDER BY username
            """
        ).fetchall()
        return [_public_user_from_row(row) for row in rows]


def create_user(payload, actor_user_id=None):
    payload = payload or {}
    username = _normalize_username(payload.get("username"))
    display_name = (payload.get("display_name") or "").strip() or username
    password = str(payload.get("password") or "")
    is_active = bool(payload.get("is_active", True))
    is_admin = bool(payload.get("is_admin", False))
    permissions = _normalize_permissions(payload.get("permissions") or {}, is_admin=is_admin)
    if not username:
        raise ValueError("Usuario e obrigatorio.")
    if len(password) < 6:
        raise ValueError("Senha deve ter pelo menos 6 caracteres.")
    now = utc_now()
    with connect() as connection:
        duplicate = connection.execute(
            "SELECT id FROM app_user WHERE username = ?",
            (username,),
        ).fetchone()
        if duplicate:
            raise ValueError("Ja existe um usuario com esse login.")
        cursor = connection.execute(
            """
            INSERT INTO app_user (
                username, display_name, password_hash, is_active, is_admin,
                permissions_json, last_login_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                username,
                display_name,
                _hash_password(password),
                1 if is_active else 0,
                1 if is_admin else 0,
                json.dumps(permissions),
                now,
                now,
            ),
        )
        row = connection.execute(
            """
            SELECT id, username, display_name, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            WHERE id = ?
            """,
            (int(cursor.lastrowid),),
        ).fetchone()
        connection.commit()
        return _public_user_from_row(row)


def update_user(user_id, payload, actor_user_id=None):
    payload = payload or {}
    user_id = int(user_id)
    now = utc_now()
    with connect() as connection:
        row = connection.execute(
            """
            SELECT id, username, display_name, password_hash, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        if not row:
            raise ValueError("Usuario nao encontrado.")

        current = _public_user_from_row(row)
        username = _normalize_username(payload.get("username") if "username" in payload else current["username"])
        display_name = (
            (payload.get("display_name") if "display_name" in payload else current["display_name"]) or ""
        ).strip() or username
        is_active = bool(payload.get("is_active")) if "is_active" in payload else current["is_active"]
        is_admin = bool(payload.get("is_admin")) if "is_admin" in payload else current["is_admin"]
        permissions_source = payload.get("permissions") if "permissions" in payload else current["permissions"]
        permissions = _normalize_permissions(permissions_source, is_admin=is_admin)
        password = payload.get("password")

        if not username:
            raise ValueError("Usuario e obrigatorio.")
        duplicate = connection.execute(
            "SELECT id FROM app_user WHERE username = ? AND id <> ?",
            (username, user_id),
        ).fetchone()
        if duplicate:
            raise ValueError("Ja existe um usuario com esse login.")

        if not is_admin and current["is_admin"]:
            remaining_admins = connection.execute(
                """
                SELECT COUNT(*)
                FROM app_user
                WHERE is_admin = 1
                  AND is_active = 1
                  AND id <> ?
                """,
                (user_id,),
            ).fetchone()[0]
            if int(remaining_admins) == 0:
                raise ValueError("Nao e permitido remover o ultimo administrador ativo.")
        if not is_active and current["is_admin"]:
            remaining_admins = connection.execute(
                """
                SELECT COUNT(*)
                FROM app_user
                WHERE is_admin = 1
                  AND is_active = 1
                  AND id <> ?
                """,
                (user_id,),
            ).fetchone()[0]
            if int(remaining_admins) == 0:
                raise ValueError("Nao e permitido desativar o ultimo administrador ativo.")

        password_hash = row["password_hash"]
        if password is not None and str(password) != "":
            password_hash = _hash_password(password)

        connection.execute(
            """
            UPDATE app_user
            SET username = ?, display_name = ?, password_hash = ?, is_active = ?, is_admin = ?,
                permissions_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                username,
                display_name,
                password_hash,
                1 if is_active else 0,
                1 if is_admin else 0,
                json.dumps(permissions),
                now,
                user_id,
            ),
        )
        if not is_active:
            connection.execute("DELETE FROM app_session WHERE user_id = ?", (user_id,))
        updated = connection.execute(
            """
            SELECT id, username, display_name, is_active, is_admin, permissions_json,
                   last_login_at, created_at, updated_at
            FROM app_user
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        connection.commit()
        return _public_user_from_row(updated)


def delete_user(user_id, actor_user_id=None):
    user_id = int(user_id)
    with connect() as connection:
        row = connection.execute(
            """
            SELECT id, username, is_admin, is_active
            FROM app_user
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        if not row:
            raise ValueError("Usuario nao encontrado.")
        if actor_user_id is not None and int(actor_user_id) == user_id:
            raise ValueError("Nao e permitido excluir o proprio usuario logado.")
        if bool(row["is_admin"]) and bool(row["is_active"]):
            remaining_admins = connection.execute(
                """
                SELECT COUNT(*)
                FROM app_user
                WHERE is_admin = 1
                  AND is_active = 1
                  AND id <> ?
                """,
                (user_id,),
            ).fetchone()[0]
            if int(remaining_admins) == 0:
                raise ValueError("Nao e permitido excluir o ultimo administrador ativo.")

        connection.execute("DELETE FROM app_user WHERE id = ?", (user_id,))
        connection.commit()
        return {"status": "deleted", "id": user_id, "username": row["username"]}


def _normalize_identity(value):
    return (value or "").strip().lower()


def _is_meaningful_template_value(value):
    if value in (False, 0):
        return True
    if value in (None, "", []):
        return False
    if isinstance(value, dict):
        return bool(value)
    return True


def _normalize_template_extra_value(key, value):
    if key == "command_overrides":
        if not isinstance(value, dict):
            return None
        normalized = {}
        for command_key in TEMPLATE_COMMAND_OVERRIDE_KEYS:
            command = str(value.get(command_key) or "").strip()
            if command:
                normalized[command_key] = command
        return normalized or None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return value


def _normalize_template_default_value(key, value, encrypt_secrets=False):
    if key not in TEMPLATE_DEFAULT_KEYS:
        return None
    if key in TEMPLATE_SECRET_DEFAULT_KEYS:
        if encrypt_secrets:
            stripped = str(value or "").strip()
            return encrypt_secret(stripped or None) if stripped else None
        return value if value not in (None, "", []) else None
    if key in {"verify_tls", "enabled"}:
        if value is None:
            return None
        return bool(value)
    if key in {"port", "poll_interval_sec", "command_timeout_sec", "ports_per_board", "capacity_onu"}:
        if value in (None, "", []):
            return None
        try:
            return int(value)
        except Exception:
            return None
    if key == "board_slots":
        if isinstance(value, (list, tuple)):
            joined = ",".join(str(item).strip() for item in value if str(item).strip())
            return joined or None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return value


def _filter_template_extra(extra_config):
    filtered = {}
    source = extra_config or {}
    for key, raw_value in source.items():
        if key not in TEMPLATE_EXTRA_KEYS:
            continue
        value = _normalize_template_extra_value(key, raw_value)
        if not _is_meaningful_template_value(value):
            continue
        filtered[key] = value
    return filtered


def _filter_template_defaults(defaults, encrypt_secrets=False):
    filtered = {}
    source = defaults or {}
    for key, raw_value in source.items():
        if key not in TEMPLATE_DEFAULT_KEYS:
            continue
        value = _normalize_template_default_value(key, raw_value, encrypt_secrets=encrypt_secrets)
        if not _is_meaningful_template_value(value):
            continue
        filtered[key] = value
    return filtered


def _merge_missing_template_values(current_extra, template_extra):
    merged = dict(template_extra or {})
    merged.update({k: v for k, v in (current_extra or {}).items() if v not in (None, "", [])})
    # Keep explicit false/zero values provided by current config.
    for key, value in (current_extra or {}).items():
        if value in (False, 0):
            merged[key] = value
    return merged


def _merge_missing_template_defaults(current_defaults, template_defaults):
    merged = dict(template_defaults or {})
    merged.update({k: v for k, v in (current_defaults or {}).items() if v not in (None, "", [])})
    for key, value in (current_defaults or {}).items():
        if value in (False, 0):
            merged[key] = value
    return merged


def _public_template_defaults(defaults):
    public = dict(defaults or {})
    for key in TEMPLATE_SECRET_DEFAULT_KEYS:
        public[key] = decrypt_secret(public.get(key))
    return public


def _fetch_connection_template_bundle(connection, brand, model, firmware):
    brand_n = _normalize_identity(brand)
    model_n = _normalize_identity(model)
    firmware_n = _normalize_identity(firmware)
    candidates = [
        (brand_n, "*", "*"),
        (brand_n, model_n, "*"),
        (brand_n, model_n, firmware_n),
    ]
    merged_extra = {}
    merged_defaults = {}
    for current_brand, current_model, current_firmware in candidates:
        if not current_brand:
            continue
        row = connection.execute(
            """
            SELECT extra_config, defaults_json
            FROM olt_connection_template
            WHERE brand = ? AND model = ? AND firmware = ?
            """,
            (current_brand, current_model or "*", current_firmware or "*"),
        ).fetchone()
        if row:
            current_extra = _deserialize_extra(row["extra_config"])
            current_defaults = _deserialize_extra(row["defaults_json"])
            for key, value in current_extra.items():
                if value not in (None, "", []):
                    merged_extra[key] = value
            for key, value in current_defaults.items():
                if value not in (None, "", []):
                    merged_defaults[key] = value
    return {
        "extra_config": merged_extra,
        "defaults": merged_defaults,
    }


def _fetch_connection_template(connection, brand, model, firmware):
    return _fetch_connection_template_bundle(connection, brand, model, firmware).get("extra_config") or {}


def _extract_template_defaults_from_existing(connection, olt_id, row):
    row_data = dict(row or {})
    board_rows = connection.execute(
        """
        SELECT board.slot, board.model, board.ports_total, pon_port.capacity_onu
        FROM board
        LEFT JOIN pon_port ON pon_port.board_id = board.id
        WHERE board.olt_id = ?
        ORDER BY board.slot, pon_port.id
        """,
        (int(olt_id),),
    ).fetchall()
    board_slots = []
    board_model = None
    ports_per_board = None
    capacity_onu = None
    for board in board_rows:
        slot = str(board["slot"] or "").strip()
        if slot and slot not in board_slots:
            board_slots.append(slot)
        if board_model is None and board["model"]:
            board_model = str(board["model"]).strip() or None
        if ports_per_board is None and board["ports_total"] is not None:
            try:
                ports_per_board = int(board["ports_total"])
            except Exception:
                ports_per_board = None
        if capacity_onu is None and board["capacity_onu"] is not None:
            try:
                capacity_onu = int(board["capacity_onu"])
            except Exception:
                capacity_onu = None
    return _filter_template_defaults(
        {
            "protocol": row_data.get("protocol"),
            "transport_type": row_data.get("transport_type"),
            "username": row_data.get("username"),
            "password": row_data.get("password"),
            "api_base_url": row_data.get("api_base_url"),
            "api_token": row_data.get("api_token"),
            "source_path": row_data.get("source_path"),
            "command_line": row_data.get("command_line"),
            "port": row_data.get("port"),
            "poll_interval_sec": row_data.get("poll_interval_sec"),
            "command_timeout_sec": row_data.get("command_timeout_sec"),
            "verify_tls": bool(row_data.get("verify_tls")),
            "enabled": bool(row_data.get("enabled")),
            "status": row_data.get("olt_status"),
            "board_model": board_model,
            "board_slots": ",".join(board_slots),
            "ports_per_board": ports_per_board,
            "capacity_onu": capacity_onu,
        }
    )


def _upsert_connection_template(connection, brand, model, firmware, extra_config, defaults=None):
    identity = (
        _normalize_identity(brand),
        _normalize_identity(model),
        _normalize_identity(firmware),
    )
    if not all(identity):
        return
    filtered = _filter_template_extra(extra_config)
    filtered_defaults = _filter_template_defaults(defaults or {})
    if not filtered and not filtered_defaults:
        return
    now = utc_now()
    connection.execute(
        """
        INSERT INTO olt_connection_template (brand, model, firmware, extra_config, defaults_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(brand, model, firmware) DO UPDATE SET
            extra_config = excluded.extra_config,
            defaults_json = excluded.defaults_json,
            updated_at = excluded.updated_at
        """,
        (*identity, json.dumps(filtered), json.dumps(filtered_defaults), now),
    )


def ensure_connection_templates(connection):
    for item in BUILTIN_CONNECTION_TEMPLATES:
        _upsert_connection_template(
            connection,
            item.get("brand"),
            item.get("model"),
            item.get("firmware"),
            item.get("extra_config") or {},
            item.get("defaults") or {},
        )
    existing_rows = connection.execute(
        """
        SELECT
            olt.id AS olt_id,
            olt.brand,
            olt.model,
            olt.firmware,
            olt.status AS olt_status,
            connection.protocol,
            connection.transport_type,
            connection.enabled,
            connection.username,
            connection.password,
            connection.api_base_url,
            connection.api_token,
            connection.source_path,
            connection.command_line,
            connection.port,
            connection.poll_interval_sec,
            connection.command_timeout_sec,
            connection.verify_tls,
            connection.extra_config
        FROM olt_connection connection
        JOIN olt ON olt.id = connection.olt_id
        """
    ).fetchall()
    for row in existing_rows:
        row_dict = dict(row)
        _upsert_connection_template(
            connection,
            row_dict["brand"],
            row_dict["model"],
            row_dict["firmware"],
            _deserialize_extra(row_dict["extra_config"]),
            _extract_template_defaults_from_existing(connection, row_dict["olt_id"], row_dict),
        )
    connection.commit()


def fetch_vendors_for_brand(connection, brand):
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT id, name, onu_model, vlan_default, line_profile, service_profile
            FROM profile
            WHERE brand = ?
            ORDER BY name
            """,
            (brand,),
        ).fetchall()
    ]


def fetch_profiles():
    with connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, brand, name, onu_model, vlan_default, line_profile, service_profile
                FROM profile
                ORDER BY brand, name
                """
            ).fetchall()
        ]


def _fetch_olt_profiles_for_kind(connection, olt_id, profile_kind):
    kind = (profile_kind or "").strip().lower()
    if kind not in {"line", "service"}:
        raise ValueError("Tipo de profile invalido.")
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT profile_kind, profile_ref, name, binding_times, source, updated_at
            FROM olt_profile
            WHERE olt_id = ? AND profile_kind = ?
            ORDER BY binding_times DESC, name, profile_ref
            """,
            (int(olt_id), kind),
        ).fetchall()
    ]


def fetch_olt_profiles(olt_id, profile_kind=None):
    with connect() as connection:
        if profile_kind:
            return _fetch_olt_profiles_for_kind(connection, olt_id, profile_kind)
        return {
            "olt_id": int(olt_id),
            "line_profiles": _fetch_olt_profiles_for_kind(connection, olt_id, "line"),
            "service_profiles": _fetch_olt_profiles_for_kind(connection, olt_id, "service"),
        }


def replace_olt_profiles(olt_id, profiles_by_kind, source="cli", collected_at=None):
    profiles_by_kind = profiles_by_kind or {}
    now = collected_at or utc_now()
    with connect() as connection:
        exists = connection.execute(
            "SELECT id FROM olt WHERE id = ?",
            (int(olt_id),),
        ).fetchone()
        if not exists:
            raise ValueError("OLT nao encontrada.")
        for kind in ("line", "service"):
            items = profiles_by_kind.get(kind)
            if items is None:
                continue
            connection.execute(
                "DELETE FROM olt_profile WHERE olt_id = ? AND profile_kind = ?",
                (int(olt_id), kind),
            )
            for item in items:
                profile_name = str(item.get("name") or "").strip()
                if not profile_name:
                    continue
                try:
                    profile_ref = int(item.get("profile_ref"))
                except Exception:
                    continue
                binding_times = int(item.get("binding_times") or 0)
                connection.execute(
                    """
                    INSERT INTO olt_profile (
                        olt_id, profile_kind, profile_ref, name, binding_times, source, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(olt_id),
                        kind,
                        profile_ref,
                        profile_name,
                        binding_times,
                        str(item.get("source") or source or "cli"),
                        str(item.get("updated_at") or now),
                    ),
                )
        connection.commit()


def fetch_onus():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                onu.id,
                onu.serial,
                onu.model,
                onu.client_name,
                onu.neighborhood,
                onu.city,
                onu.vlan_id,
                onu.onu_mode,
                onu.status,
                onu.line_profile,
                onu.service_profile,
                onu.signal_dbm,
                onu.signal_tx_dbm,
                onu.signal_olt_rx_dbm,
                onu.traffic_down_mbps,
                onu.traffic_up_mbps,
                onu.temperature_c,
                onu.pon_position,
                onu.updated_at,
                olt.name AS olt_name,
                olt.brand AS olt_brand,
                board.slot AS board_slot,
                pon_port.name AS port_name,
                profile.name AS profile_name,
                olt_connection.poll_interval_sec
            FROM onu
            JOIN olt ON olt.id = onu.olt_id
            JOIN board ON board.id = onu.board_id
            JOIN pon_port ON pon_port.id = onu.port_id
            LEFT JOIN profile ON profile.id = onu.profile_id
            LEFT JOIN olt_connection ON olt_connection.olt_id = onu.olt_id
            ORDER BY olt.name, board.slot, pon_port.name, onu.pon_position
            """
        ).fetchall()
        return [
            {
                **_decorate_onu_runtime_state(dict(row)),
                "onu_mode": _normalize_onu_mode(
                    row["onu_mode"],
                    _infer_onu_mode_from_profiles(row["line_profile"], row["service_profile"], "bridge"),
                ),
            }
            for row in rows
        ]


def _fetch_olt_vlan_inventory(connection, olt_id):
    rows = connection.execute(
        """
        SELECT vlan_id, name, description, source, updated_at
        FROM olt_vlan
        WHERE olt_id = ?
        ORDER BY vlan_id
        """,
        (olt_id,),
    ).fetchall()
    result = {int(row["vlan_id"]): dict(row) for row in rows}

    observed_rows = connection.execute(
        """
        SELECT vlan_id, MAX(updated_at) AS updated_at
        FROM onu
        WHERE olt_id = ? AND vlan_id IS NOT NULL
        GROUP BY vlan_id
        ORDER BY vlan_id
        """,
        (olt_id,),
    ).fetchall()
    for row in observed_rows:
        vlan_id = int(row["vlan_id"])
        if vlan_id not in result:
            result[vlan_id] = {
                "vlan_id": vlan_id,
                "name": "",
                "description": "",
                "source": "observed",
                "updated_at": row["updated_at"] or utc_now(),
            }
    return sorted(result.values(), key=lambda item: item["vlan_id"])


def fetch_olt_vlans(olt_id):
    with connect() as connection:
        olt = connection.execute(
            "SELECT id FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not olt:
            raise ValueError("OLT nao encontrada.")

        return _fetch_olt_vlan_inventory(connection, olt_id)


def save_olt_vlan(olt_id, payload):
    payload = payload or {}
    vlan_id = int(payload.get("vlan_id") or 0)
    if vlan_id < 1 or vlan_id > 4094:
        raise ValueError("VLAN invalida. Informe um valor entre 1 e 4094.")
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip()
    source = (payload.get("source") or "manual").strip().lower() or "manual"
    now = utc_now()

    with connect() as connection:
        exists = connection.execute(
            "SELECT id FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not exists:
            raise ValueError("OLT nao encontrada.")
        connection.execute(
            """
            INSERT INTO olt_vlan (olt_id, vlan_id, name, description, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(olt_id, vlan_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                source = excluded.source,
                updated_at = excluded.updated_at
            """,
            (olt_id, vlan_id, name, description, source, now),
        )
        connection.commit()
    return {"status": "ok", "olt_id": olt_id, "vlan_id": vlan_id}


def delete_olt_vlan(olt_id, vlan_id):
    vlan_id = int(vlan_id)
    with connect() as connection:
        exists = connection.execute(
            "SELECT id FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not exists:
            raise ValueError("OLT nao encontrada.")
        connection.execute(
            "DELETE FROM olt_vlan WHERE olt_id = ? AND vlan_id = ?",
            (olt_id, vlan_id),
        )
        connection.commit()
    return {"status": "ok", "olt_id": olt_id, "vlan_id": vlan_id}


def delete_onu(onu_id):
    onu_id = int(onu_id)
    with connect() as connection:
        row = connection.execute(
            "SELECT id, olt_id, serial FROM onu WHERE id = ?",
            (onu_id,),
        ).fetchone()
        if not row:
            raise ValueError("ONU nao encontrada.")
        connection.execute(
            """
            UPDATE authorization_request
            SET resolved_onu_id = NULL
            WHERE resolved_onu_id = ?
            """,
            (onu_id,),
        )
        connection.execute("DELETE FROM onu WHERE id = ?", (onu_id,))
        connection.commit()
    return {"status": "ok", "onu_id": onu_id, "olt_id": row["olt_id"], "serial": row["serial"]}


def fetch_onu_by_id(onu_id):
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                onu.id,
                onu.serial,
                onu.model,
                onu.client_name,
                onu.neighborhood,
                onu.city,
                onu.vlan_id,
                onu.onu_mode,
                onu.status,
                onu.line_profile,
                onu.service_profile,
                onu.signal_dbm,
                onu.signal_tx_dbm,
                onu.signal_olt_rx_dbm,
                onu.traffic_down_mbps,
                onu.traffic_up_mbps,
                onu.temperature_c,
                onu.pon_position,
                onu.updated_at,
                onu.olt_id,
                olt.name AS olt_name,
                olt.brand AS olt_brand,
                olt.host AS olt_host,
                board.slot AS board_slot,
                pon_port.name AS port_name,
                profile.name AS profile_name,
                olt_connection.poll_interval_sec
            FROM onu
            JOIN olt ON olt.id = onu.olt_id
            JOIN board ON board.id = onu.board_id
            JOIN pon_port ON pon_port.id = onu.port_id
            LEFT JOIN profile ON profile.id = onu.profile_id
            LEFT JOIN olt_connection ON olt_connection.olt_id = onu.olt_id
            WHERE onu.id = ?
            LIMIT 1
            """,
            (onu_id,),
        ).fetchone()
        if not row:
            raise ValueError("ONU nao encontrada.")
        item = _decorate_onu_runtime_state(dict(row))
        item["onu_mode"] = _normalize_onu_mode(
            item.get("onu_mode"),
            _infer_onu_mode_from_profiles(item.get("line_profile"), item.get("service_profile"), "bridge"),
        )
        return item


def _port_usage(connection):
    rows = connection.execute(
        """
        SELECT
            pon_port.id AS port_id,
            pon_port.capacity_onu,
            pon_port.alert_threshold_pct,
            COUNT(onu.id) AS used_onu
        FROM pon_port
        LEFT JOIN onu ON onu.port_id = pon_port.id AND onu.status IN ('active', 'warning')
        GROUP BY pon_port.id, pon_port.capacity_onu, pon_port.alert_threshold_pct
        """
    ).fetchall()
    return {
        row["port_id"]: {
            "used_onu": row["used_onu"],
            "capacity_onu": row["capacity_onu"],
            "alert_threshold_pct": row["alert_threshold_pct"],
        }
        for row in rows
    }


def _alert_level(percent, threshold):
    if percent >= 100:
        return "full"
    if percent >= 90:
        return "critical"
    if percent >= threshold:
        return "warning"
    return "ok"


def fetch_olts():
    with connect() as connection:
        usage = _port_usage(connection)
        olt_rows = connection.execute(
            """
            SELECT id, name, brand, model, host, status, firmware, temperature_c,
                   cpu_usage, memory_usage, updated_at
            FROM olt
            ORDER BY name
            """
        ).fetchall()
        board_rows = connection.execute(
            """
            SELECT id, olt_id, slot, model, status, ports_total
            FROM board
            ORDER BY olt_id, slot
            """
        ).fetchall()
        port_rows = connection.execute(
            """
            SELECT id, board_id, name, capacity_onu, alert_threshold_pct
            FROM pon_port
            ORDER BY board_id, name
            """
        ).fetchall()

        boards_by_olt = {}
        for board in board_rows:
            boards_by_olt.setdefault(board["olt_id"], []).append(
                {
                    "id": board["id"],
                    "slot": board["slot"],
                    "model": board["model"],
                    "status": board["status"],
                    "ports_total": board["ports_total"],
                    "ports": [],
                }
            )

        board_lookup = {}
        for olt_boards in boards_by_olt.values():
            for board in olt_boards:
                board_lookup[board["id"]] = board

        for port in port_rows:
            stats = usage[port["id"]]
            percent = 0 if not stats["capacity_onu"] else round(stats["used_onu"] * 100 / stats["capacity_onu"], 1)
            board_lookup[port["board_id"]]["ports"].append(
                {
                    "id": port["id"],
                    "name": port["name"],
                    "capacity_onu": port["capacity_onu"],
                    "used_onu": stats["used_onu"],
                    "usage_pct": percent,
                    "alert_level": _alert_level(percent, port["alert_threshold_pct"]),
                }
            )

        result = []
        for olt in olt_rows:
            boards = boards_by_olt.get(olt["id"], [])
            total_capacity = sum(port["capacity_onu"] for board in boards for port in board["ports"])
            total_used = sum(port["used_onu"] for board in boards for port in board["ports"])
            result.append(
                {
                    **dict(olt),
                    "summary": {
                        "boards": len(boards),
                        "ports": sum(len(board["ports"]) for board in boards),
                        "total_capacity": total_capacity,
                        "used_onu": total_used,
                        "usage_pct": 0 if not total_capacity else round(total_used * 100 / total_capacity, 1),
                    },
                    "boards_data": boards,
                }
            )
        return result


def fetch_authorization_requests():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                req.id,
                req.serial,
                req.detected_model,
                req.requested_signal_dbm,
                req.requested_temperature_c,
                req.requested_at,
                req.status,
                req.notes,
                olt.id AS olt_id,
                olt.name AS olt_name,
                olt.brand AS olt_brand,
                board.id AS board_id,
                board.slot AS board_slot,
                pon_port.id AS port_id,
                pon_port.name AS port_name
            FROM authorization_request req
            JOIN olt ON olt.id = req.olt_id
            JOIN board ON board.id = req.board_id
            JOIN pon_port ON pon_port.id = req.port_id
            WHERE req.status = 'pending'
            ORDER BY req.requested_at DESC, req.id DESC
            """
        ).fetchall()

        result = []
        olt_vlan_cache = {}
        for row in rows:
            item = dict(row)
            olt_id = int(row["olt_id"])
            if olt_id not in olt_vlan_cache:
                olt_vlan_cache[olt_id] = _fetch_olt_vlan_inventory(connection, olt_id)
            duplicate = connection.execute(
                """
                SELECT
                    onu.id,
                    onu.client_name,
                    onu.status,
                    onu.vlan_id,
                    onu.onu_mode,
                    onu.line_profile,
                    onu.service_profile,
                    onu.signal_dbm,
                    olt.name AS olt_name,
                    board.slot AS board_slot,
                    pon_port.name AS port_name
                FROM onu
                JOIN olt ON olt.id = onu.olt_id
                JOIN board ON board.id = onu.board_id
                JOIN pon_port ON pon_port.id = onu.port_id
                WHERE onu.serial = ?
                LIMIT 1
                """,
                (row["serial"],),
            ).fetchone()
            if duplicate:
                existing_onu = dict(duplicate)
                existing_onu["onu_mode"] = _normalize_onu_mode(
                    existing_onu.get("onu_mode"),
                    _infer_onu_mode_from_profiles(
                        existing_onu.get("line_profile"),
                        existing_onu.get("service_profile"),
                        "bridge",
                    ),
                )
                item["existing_onu"] = existing_onu
            else:
                item["existing_onu"] = None
            item["suggested_action"] = "move" if duplicate else "authorize"
            item["profiles"] = fetch_vendors_for_brand(connection, row["olt_brand"])
            item["olt_line_profiles"] = _fetch_olt_profiles_for_kind(connection, row["olt_id"], "line")
            item["olt_service_profiles"] = _fetch_olt_profiles_for_kind(connection, row["olt_id"], "service")
            item["olt_vlans"] = olt_vlan_cache.get(olt_id, [])
            result.append(item)
        return result


def fetch_dashboard():
    with connect() as connection:
        port_usage = _port_usage(connection)
        summary = {
            "olts": connection.execute("SELECT COUNT(*) FROM olt").fetchone()[0],
            "active_onus": connection.execute(
                "SELECT COUNT(*) FROM onu WHERE status IN ('active', 'warning')"
            ).fetchone()[0],
            "pending_requests": connection.execute(
                "SELECT COUNT(*) FROM authorization_request WHERE status = 'pending'"
            ).fetchone()[0],
            "ports_near_capacity": sum(
                1
                for data in port_usage.values()
                if data["capacity_onu"] and data["used_onu"] * 100 / data["capacity_onu"] >= data["alert_threshold_pct"]
            ),
        }

        alerts = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    olt.name AS olt_name,
                    board.slot AS board_slot,
                    pon_port.name AS port_name,
                    pon_port.capacity_onu,
                    COUNT(onu.id) AS used_onu
                FROM pon_port
                JOIN board ON board.id = pon_port.board_id
                JOIN olt ON olt.id = board.olt_id
                LEFT JOIN onu ON onu.port_id = pon_port.id AND onu.status IN ('active', 'warning')
                GROUP BY olt.name, board.slot, pon_port.name, pon_port.capacity_onu
                HAVING (COUNT(onu.id) * 100.0 / pon_port.capacity_onu) >= 80
                ORDER BY (COUNT(onu.id) * 100.0 / pon_port.capacity_onu) DESC
                LIMIT 6
                """
            ).fetchall()
        ]
        for alert in alerts:
            usage = round(alert["used_onu"] * 100 / alert["capacity_onu"], 1)
            alert["usage_pct"] = usage
            alert["level"] = _alert_level(usage, 80)

        traffic_chart = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    olt.name AS label,
                    ROUND(SUM(onu.traffic_down_mbps), 1) AS down_mbps,
                    ROUND(SUM(onu.traffic_up_mbps), 1) AS up_mbps
                FROM onu
                JOIN olt ON olt.id = onu.olt_id
                GROUP BY olt.name
                ORDER BY olt.name
                """
            ).fetchall()
        ]

        signal_chart = []
        buckets = [
            ("Excelente", -20.0, 999.0),
            ("Bom", -23.0, -20.01),
            ("Atencao", -26.0, -23.01),
            ("Critico", -999.0, -26.01),
        ]
        for label, lower, upper in buckets:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM onu
                WHERE signal_dbm >= ? AND signal_dbm <= ?
                """,
                (lower, upper),
            ).fetchone()[0]
            signal_chart.append({"label": label, "count": count})

        return {
            "summary": summary,
            "alerts": alerts,
            "traffic_chart": traffic_chart,
            "signal_chart": signal_chart,
        }


def _fetch_request(connection, request_id):
    row = connection.execute(
        """
        SELECT
            req.id,
            req.serial,
            req.detected_model,
            req.olt_id,
            req.board_id,
            req.port_id,
            req.status,
            olt.name AS olt_name,
            olt.brand AS olt_brand,
            olt.host AS olt_host,
            board.slot AS board_slot,
            pon_port.name AS port_name
        FROM authorization_request req
        JOIN olt ON olt.id = req.olt_id
        JOIN board ON board.id = req.board_id
        JOIN pon_port ON pon_port.id = req.port_id
        WHERE req.id = ?
        """,
        (request_id,),
    ).fetchone()
    if not row:
        raise ValueError("Solicitacao nao encontrada.")
    if row["status"] != "pending":
        raise ValueError("Solicitacao ja processada.")
    return row


def _find_duplicate_onu(connection, serial):
    return connection.execute(
        """
        SELECT id, olt_id, board_id, port_id, client_name, profile_id, vlan_id, onu_mode, line_profile, service_profile
        FROM onu
        WHERE serial = ?
        LIMIT 1
        """,
        (serial,),
    ).fetchone()


def _resolve_profile(connection, request_row, profile_id, allow_missing=False):
    if profile_id:
        row = connection.execute(
            """
            SELECT id, vlan_default, line_profile, service_profile
            FROM profile
            WHERE id = ?
            """,
            (profile_id,),
        ).fetchone()
        if row:
            return row
    fallback = connection.execute(
        """
        SELECT id, vlan_default, line_profile, service_profile
        FROM profile
        WHERE brand = ? AND onu_model = ?
        ORDER BY id
        LIMIT 1
        """,
        (request_row["olt_brand"], request_row["detected_model"]),
    ).fetchone()
    if not fallback:
        if allow_missing:
            return None
        raise ValueError("Nenhum profile compativel encontrado.")
    return fallback


def _find_profile_for_brand_model(connection, brand, model):
    if not brand or not model:
        return None
    return connection.execute(
        """
        SELECT id, vlan_default, line_profile, service_profile
        FROM profile
        WHERE brand = ? AND onu_model = ?
        ORDER BY id
        LIMIT 1
        """,
        (brand, model),
    ).fetchone()


def _resolve_olt_profile_name(connection, olt_id, profile_kind, requested_name=None, fallback_name=None):
    kind = (profile_kind or "").strip().lower()
    if kind not in {"line", "service"}:
        return None
    value = str(requested_name or "").strip() or str(fallback_name or "").strip()
    if not value:
        return None
    row = connection.execute(
        """
        SELECT name
        FROM olt_profile
        WHERE olt_id = ? AND profile_kind = ? AND lower(name) = lower(?)
        LIMIT 1
        """,
        (int(olt_id), kind, value),
    ).fetchone()
    if row:
        return row["name"]
    has_catalog = connection.execute(
        """
        SELECT 1
        FROM olt_profile
        WHERE olt_id = ? AND profile_kind = ?
        LIMIT 1
        """,
        (int(olt_id), kind),
    ).fetchone()
    if has_catalog:
        label = "Line profile" if kind == "line" else "Service profile"
        raise ValueError(f"{label} nao encontrado no catalogo da OLT.")
    return value


def _resolve_olt_profile_entry(connection, olt_id, profile_kind, requested_name=None, fallback_name=None):
    resolved_name = _resolve_olt_profile_name(
        connection,
        olt_id,
        profile_kind,
        requested_name=requested_name,
        fallback_name=fallback_name,
    )
    if not resolved_name:
        return None
    row = connection.execute(
        """
        SELECT profile_kind, profile_ref, name, binding_times, source, updated_at
        FROM olt_profile
        WHERE olt_id = ? AND profile_kind = ? AND lower(name) = lower(?)
        LIMIT 1
        """,
        (int(olt_id), str(profile_kind or "").strip().lower(), resolved_name),
    ).fetchone()
    if row:
        return dict(row)
    return {
        "profile_kind": str(profile_kind or "").strip().lower(),
        "profile_ref": None,
        "name": resolved_name,
        "binding_times": None,
        "source": "manual",
        "updated_at": utc_now(),
    }


def _normalize_onu_mode(value, fallback="bridge"):
    normalized = str(value or "").strip().lower()
    if normalized in {"route", "router", "routing"}:
        return "route"
    if normalized in {"bridge", "bridging"}:
        return "bridge"
    return str(fallback or "bridge").strip().lower() or "bridge"


def _infer_onu_mode_from_profiles(line_profile=None, service_profile=None, fallback="bridge"):
    names = " ".join(
        str(value or "").strip().lower()
        for value in (line_profile, service_profile)
        if str(value or "").strip()
    )
    if not names:
        return _normalize_onu_mode(fallback)
    if "router" in names or "route" in names:
        return "route"
    if "bridge" in names or "smartolt" in names or "generic_" in names:
        return "bridge"
    return _normalize_onu_mode(fallback)


def _parse_port_index_from_name(port_name):
    try:
        return max(0, int(str(port_name or "").split()[-1]) - 1)
    except Exception:
        return 0


def _resolve_collected_model(collected_model, current_model):
    value = (collected_model or "").strip()
    if value and value.lower() not in {"desconhecido", "unknown", "n/a", "-"}:
        return value
    existing = (current_model or "").strip()
    if existing:
        return existing
    return "Desconhecido"


def _guess_model_from_serial(serial):
    raw = "".join(ch for ch in str(serial or "").upper() if ch.isalnum())
    if len(raw) < 8:
        return "Desconhecido"
    prefix = raw[:8]
    try:
        vendor = bytes.fromhex(prefix).decode("ascii", errors="ignore").strip()
        vendor = "".join(ch for ch in vendor if ch.isalnum())
    except Exception:
        vendor = ""
    if vendor:
        return f"ONU-{vendor}"
    return f"ONU-{prefix}"


def _normalize_serial_token(serial):
    return "".join(ch for ch in str(serial or "").upper() if ch.isalnum())


def _is_generic_model_name(model):
    value = str(model or "").strip()
    if not value:
        return True
    lowered = value.lower()
    if lowered in {"desconhecido", "unknown", "n/a", "-"}:
        return True
    if value.upper().startswith("ONU-"):
        return True
    return False


def suggest_detected_onu_model(serial, detected_model=None, min_samples=3, dominance_threshold=0.6):
    current_model = str(detected_model or "").strip() or "Desconhecido"
    if not _is_generic_model_name(current_model):
        return {"model": current_model, "source": "reported"}

    normalized_serial = _normalize_serial_token(serial)
    if not normalized_serial:
        return {"model": current_model, "source": "fallback"}

    with connect() as connection:
        exact_row = connection.execute(
            """
            SELECT model
            FROM onu
            WHERE upper(replace(serial, '-', '')) = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 1
            """,
            (normalized_serial,),
        ).fetchone()
        if exact_row and not _is_generic_model_name(exact_row["model"]):
            return {"model": exact_row["model"], "source": "serial-exact"}

        if len(normalized_serial) < 8:
            return {"model": current_model, "source": "fallback"}

        prefix = normalized_serial[:8]
        rows = connection.execute(
            """
            SELECT model, COUNT(*) AS qty
            FROM onu
            WHERE upper(substr(replace(serial, '-', ''), 1, 8)) = ?
            GROUP BY model
            ORDER BY qty DESC, model
            """,
            (prefix,),
        ).fetchall()

    specific_rows = [row for row in rows if not _is_generic_model_name(row["model"])]
    if not specific_rows:
        return {"model": current_model, "source": "fallback"}

    top = specific_rows[0]
    total_specific = sum(int(row["qty"] or 0) for row in specific_rows)
    top_qty = int(top["qty"] or 0)
    if top_qty < max(1, int(min_samples)):
        return {"model": current_model, "source": "fallback"}
    if not total_specific or (top_qty / total_specific) < float(dominance_threshold):
        return {"model": current_model, "source": "fallback"}

    return {"model": top["model"], "source": "serial-prefix"}


def _resolve_collected_client_name(collected_description, current_client_name):
    desc = (collected_description or "").strip()
    if desc:
        return desc
    current = (current_client_name or "").strip()
    if current:
        return current
    return "Nao identificado"


def _resolve_collected_vlan(collected_vlan, current_vlan=None):
    if collected_vlan is not None and str(collected_vlan).strip() != "":
        try:
            vlan_id = int(collected_vlan)
            if 1 <= vlan_id <= 4094:
                return vlan_id
        except Exception:
            pass
    if current_vlan is not None:
        try:
            vlan_id = int(current_vlan)
            if 1 <= vlan_id <= 4094:
                return vlan_id
        except Exception:
            pass
    return 0


def _next_pon_position(connection, port_id):
    current = connection.execute(
        "SELECT COALESCE(MAX(pon_position), 0) FROM onu WHERE port_id = ?",
        (port_id,),
    ).fetchone()[0]
    return current + 1


def authorize_request(request_id, payload, pon_position=None):
    payload = payload or {}
    with connect() as connection:
        request_row = _fetch_request(connection, request_id)
        duplicate = _find_duplicate_onu(connection, request_row["serial"])
        if duplicate:
            raise ValueError("ONU ja cadastrada em outra porta. Use a acao de mover.")

        profile = _resolve_profile(connection, request_row, payload.get("profile_id"), allow_missing=True)
        raw_vlan_id = payload.get("vlan_id")
        if raw_vlan_id in (None, ""):
            if not profile:
                raise ValueError("Informe a VLAN ou cadastre um profile global compativel.")
            raw_vlan_id = profile["vlan_default"]
        vlan_id = int(raw_vlan_id or 0)
        if vlan_id < 1 or vlan_id > 4094:
            raise ValueError("VLAN invalida. Informe um valor entre 1 e 4094.")
        line_profile = _resolve_olt_profile_name(
            connection,
            request_row["olt_id"],
            "line",
            payload.get("line_profile"),
            profile["line_profile"] if profile else None,
        )
        service_profile = _resolve_olt_profile_name(
            connection,
            request_row["olt_id"],
            "service",
            payload.get("service_profile"),
            profile["service_profile"] if profile else None,
        )
        onu_mode = _normalize_onu_mode(
            payload.get("onu_mode"),
            _infer_onu_mode_from_profiles(line_profile, service_profile, "bridge"),
        )
        client_name = (payload.get("client_name") or "").strip() or "Cliente sem nome"
        neighborhood = (payload.get("neighborhood") or "").strip() or "Nao informado"
        city = (payload.get("city") or "").strip() or "Nao informado"
        now = utc_now()
        resolved_pon_position = _next_pon_position(connection, request_row["port_id"])
        if pon_position is not None:
            resolved_pon_position = int(pon_position)
        cursor = connection.execute(
            """
            INSERT INTO onu (
                serial, mac_address, model, client_name, neighborhood, city, vlan_id,
                profile_id, line_profile, service_profile, onu_mode, status, signal_dbm, traffic_down_mbps, traffic_up_mbps,
                temperature_c, olt_id, board_id, port_id, pon_position, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_row["serial"],
                "",
                request_row["detected_model"],
                client_name,
                neighborhood,
                city,
                vlan_id,
                profile["id"] if profile else None,
                line_profile,
                service_profile,
                onu_mode,
                "active",
                payload.get("signal_dbm", -21.0),
                payload.get("traffic_down_mbps", 0.0),
                payload.get("traffic_up_mbps", 0.0),
                payload.get("temperature_c", 44.0),
                request_row["olt_id"],
                request_row["board_id"],
                request_row["port_id"],
                resolved_pon_position,
                now,
            ),
        )
        onu_id = cursor.lastrowid
        connection.execute(
            """
            UPDATE authorization_request
            SET status = 'authorized', resolved_onu_id = ?
            WHERE id = ?
            """,
            (onu_id, request_id),
        )
        connection.commit()
        return {"status": "authorized", "onu_id": onu_id}


def prepare_request_provisioning_context(request_id, payload):
    payload = payload or {}
    with connect() as connection:
        request_row = _fetch_request(connection, request_id)
        duplicate = _find_duplicate_onu(connection, request_row["serial"])
        action = "move" if duplicate else "authorize"
        profile_id = payload.get("profile_id") or (duplicate["profile_id"] if duplicate else None)
        profile = _resolve_profile(connection, request_row, profile_id, allow_missing=True)

        if action == "move":
            raw_vlan_id = payload.get("vlan_id") or duplicate["vlan_id"] or (profile["vlan_default"] if profile else 0)
        else:
            raw_vlan_id = payload.get("vlan_id")
            if raw_vlan_id in (None, ""):
                if not profile:
                    raise ValueError("Informe a VLAN ou cadastre um profile global compativel.")
                raw_vlan_id = profile["vlan_default"]
        vlan_id = int(raw_vlan_id or 0)
        if action != "move" and (vlan_id < 1 or vlan_id > 4094):
            raise ValueError("VLAN invalida. Informe um valor entre 1 e 4094.")

        line_profile_entry = _resolve_olt_profile_entry(
            connection,
            request_row["olt_id"],
            "line",
            payload.get("line_profile"),
            (duplicate["line_profile"] if duplicate else None) or (profile["line_profile"] if profile else None),
        )
        service_profile_entry = _resolve_olt_profile_entry(
            connection,
            request_row["olt_id"],
            "service",
            payload.get("service_profile"),
            (duplicate["service_profile"] if duplicate else None) or (profile["service_profile"] if profile else None),
        )
        onu_mode = _normalize_onu_mode(
            payload.get("onu_mode"),
            (duplicate["onu_mode"] if duplicate else None)
            or _infer_onu_mode_from_profiles(
                line_profile_entry["name"] if line_profile_entry else None,
                service_profile_entry["name"] if service_profile_entry else None,
                "bridge",
            ),
        )

        client_name = (payload.get("client_name") or "").strip()
        if not client_name:
            client_name = duplicate["client_name"] if duplicate else "Cliente sem nome"
        neighborhood = (payload.get("neighborhood") or "").strip() or "Nao informado"
        city = (payload.get("city") or "").strip() or "Nao informado"

        return {
            "request_id": int(request_id),
            "action": action,
            "serial": request_row["serial"],
            "detected_model": request_row["detected_model"],
            "olt_id": int(request_row["olt_id"]),
            "olt_name": request_row["olt_name"],
            "olt_brand": request_row["olt_brand"],
            "olt_host": request_row["olt_host"],
            "board_id": int(request_row["board_id"]),
            "board_slot": request_row["board_slot"],
            "port_id": int(request_row["port_id"]),
            "port_name": request_row["port_name"],
            "port_index": _parse_port_index_from_name(request_row["port_name"]),
            "fsp": f'{request_row["board_slot"]}/{_parse_port_index_from_name(request_row["port_name"])}',
            "profile_id": profile["id"] if profile else None,
            "onu_mode": onu_mode,
            "vlan_id": vlan_id,
            "line_profile": line_profile_entry,
            "service_profile": service_profile_entry,
            "client_name": client_name,
            "neighborhood": neighborhood,
            "city": city,
            "existing_onu": dict(duplicate) if duplicate else None,
        }


def move_request(request_id, payload):
    payload = payload or {}
    with connect() as connection:
        request_row = _fetch_request(connection, request_id)
        duplicate = _find_duplicate_onu(connection, request_row["serial"])
        if not duplicate:
            raise ValueError("Nenhuma ONU existente encontrada para mover.")

        profile_id = payload.get("profile_id") or duplicate["profile_id"]
        profile = _resolve_profile(connection, request_row, profile_id, allow_missing=True)
        vlan_id = int(
            payload.get("vlan_id")
            or duplicate["vlan_id"]
            or (profile["vlan_default"] if profile else 0)
        )
        line_profile = _resolve_olt_profile_name(
            connection,
            request_row["olt_id"],
            "line",
            payload.get("line_profile"),
            duplicate["line_profile"] or (profile["line_profile"] if profile else None),
        )
        service_profile = _resolve_olt_profile_name(
            connection,
            request_row["olt_id"],
            "service",
            payload.get("service_profile"),
            duplicate["service_profile"] or (profile["service_profile"] if profile else None),
        )
        onu_mode = _normalize_onu_mode(
            payload.get("onu_mode"),
            duplicate["onu_mode"] or _infer_onu_mode_from_profiles(line_profile, service_profile, "bridge"),
        )
        now = utc_now()
        connection.execute(
            """
            UPDATE onu
            SET olt_id = ?, board_id = ?, port_id = ?, profile_id = ?, vlan_id = ?,
                line_profile = ?, service_profile = ?, onu_mode = ?,
                pon_position = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                request_row["olt_id"],
                request_row["board_id"],
                request_row["port_id"],
                profile_id,
                vlan_id,
                line_profile,
                service_profile,
                onu_mode,
                _next_pon_position(connection, request_row["port_id"]),
                now,
                duplicate["id"],
            ),
        )
        connection.execute(
            """
            UPDATE authorization_request
            SET status = 'moved', resolved_onu_id = ?
            WHERE id = ?
            """,
            (duplicate["id"], request_id),
        )
        connection.commit()
        return {"status": "moved", "onu_id": duplicate["id"]}


def sync_metrics():
    with connect() as connection:
        onus = connection.execute(
            "SELECT id, signal_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c FROM onu"
        ).fetchall()
        for onu in onus:
            connection.execute(
                """
                UPDATE onu
                SET signal_dbm = ?, traffic_down_mbps = ?, traffic_up_mbps = ?,
                    temperature_c = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    round(max(-29.5, min(-18.0, onu["signal_dbm"] + random.uniform(-0.8, 0.8))), 1),
                    round(max(5.0, onu["traffic_down_mbps"] + random.uniform(-60.0, 80.0)), 1),
                    round(max(1.0, onu["traffic_up_mbps"] + random.uniform(-20.0, 40.0)), 1),
                    round(max(38.0, min(64.0, onu["temperature_c"] + random.uniform(-1.2, 1.4))), 1),
                    utc_now(),
                    onu["id"],
                ),
            )

        olts = connection.execute(
            "SELECT id, temperature_c, cpu_usage, memory_usage FROM olt"
        ).fetchall()
        for olt in olts:
            connection.execute(
                """
                UPDATE olt
                SET temperature_c = ?, cpu_usage = ?, memory_usage = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    round(max(33.0, min(58.0, olt["temperature_c"] + random.uniform(-1.0, 1.3))), 1),
                    round(max(12.0, min(93.0, olt["cpu_usage"] + random.uniform(-4.0, 6.0))), 1),
                    round(max(24.0, min(96.0, olt["memory_usage"] + random.uniform(-4.0, 5.0))), 1),
                    utc_now(),
                    olt["id"],
                ),
            )

        connection.commit()
        return {"status": "ok", "updated_at": utc_now()}


def _deserialize_extra(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _default_port_for_transport(transport_type):
    transport = (transport_type or "ssh").lower()
    defaults = {
        "ssh": 22,
        "telnet": 23,
        "snmp": 161,
        "api": 443,
    }
    return defaults.get(transport, 22)


def _default_collection_protocol(brand, transport_type):
    normalized_brand = (brand or "").strip().lower()
    normalized_transport = (transport_type or "ssh").strip().lower()
    if normalized_brand == "huawei" and normalized_transport in {"ssh", "telnet"}:
        return "native"
    return "mock"


def _prefer_payload_or_template(value, template_value, fallback=None, default_markers=None):
    markers = tuple(default_markers or ())
    if value in (None, "", []):
        return template_value if template_value not in (None, "", []) else fallback
    if template_value not in (None, "", []) and markers and value in markers:
        return template_value
    return value


def fetch_olt_context(olt_id):
    with connect() as connection:
        olt = connection.execute(
            """
            SELECT id, name, brand, model, host, status, firmware, temperature_c,
                   cpu_usage, memory_usage, updated_at
            FROM olt
            WHERE id = ?
            """,
            (olt_id,),
        ).fetchone()
        if not olt:
            raise ValueError("OLT nao encontrada.")

        boards = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, slot, model, status, ports_total
                FROM board
                WHERE olt_id = ?
                ORDER BY slot
                """,
                (olt_id,),
            ).fetchall()
        ]
        ports = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    pon_port.id,
                    board.slot AS board_slot,
                    pon_port.name,
                    pon_port.capacity_onu,
                    pon_port.alert_threshold_pct
                FROM pon_port
                JOIN board ON board.id = pon_port.board_id
                WHERE board.olt_id = ?
                ORDER BY board.slot, pon_port.name
                """,
                (olt_id,),
            ).fetchall()
        ]
        onus = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    onu.id,
                    onu.serial,
                    onu.model,
                    onu.status,
                    onu.signal_dbm,
                    onu.traffic_down_mbps,
                    onu.traffic_up_mbps,
                    onu.temperature_c,
                    onu.vlan_id,
                    onu.profile_id,
                    onu.pon_position,
                    board.slot AS board_slot,
                    pon_port.name AS port_name
                FROM onu
                JOIN board ON board.id = onu.board_id
                JOIN pon_port ON pon_port.id = onu.port_id
                WHERE onu.olt_id = ?
                ORDER BY board.slot, pon_port.name, onu.pon_position
                """,
                (olt_id,),
            ).fetchall()
        ]
        pending_requests = [
            dict(row)
            for row in connection.execute(
                """
                SELECT
                    req.id,
                    req.serial,
                    req.detected_model,
                    req.requested_signal_dbm,
                    req.requested_temperature_c,
                    board.slot AS board_slot,
                    pon_port.name AS port_name
                FROM authorization_request req
                JOIN board ON board.id = req.board_id
                JOIN pon_port ON pon_port.id = req.port_id
                WHERE req.olt_id = ? AND req.status = 'pending'
                ORDER BY req.id
                """,
                (olt_id,),
            ).fetchall()
        ]
        return {
            "olt": dict(olt),
            "boards": boards,
            "ports": ports,
            "onus": onus,
            "pending_requests": pending_requests,
        }


def fetch_connection_for_olt(olt_id):
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                connection.*,
                olt.name AS olt_name,
                olt.brand AS olt_brand,
                olt.model AS olt_model,
                olt.firmware AS olt_firmware,
                olt.host AS olt_host
            FROM olt_connection connection
            JOIN olt ON olt.id = connection.olt_id
            WHERE connection.olt_id = ?
            """,
            (olt_id,),
        ).fetchone()
        if not row:
            raise ValueError("Conexao da OLT nao encontrada.")
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["verify_tls"] = bool(item["verify_tls"])
        current_extra = _deserialize_extra(item["extra_config"])
        template_extra = _fetch_connection_template(
            connection,
            item.get("olt_brand"),
            item.get("olt_model"),
            item.get("olt_firmware"),
        )
        item["extra_config"] = _merge_missing_template_values(current_extra, template_extra)
        item["password"] = decrypt_secret(item.get("password"))
        item["api_token"] = decrypt_secret(item.get("api_token"))
        return item


def fetch_connections():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                connection.*,
                olt.name AS olt_name,
                olt.brand AS olt_brand,
                olt.model AS olt_model,
                olt.firmware AS olt_firmware,
                olt.host AS olt_host
            FROM olt_connection connection
            JOIN olt ON olt.id = connection.olt_id
            ORDER BY olt.name
            """
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["verify_tls"] = bool(item["verify_tls"])
            current_extra = _deserialize_extra(item["extra_config"])
            template_extra = _fetch_connection_template(
                connection,
                item.get("olt_brand"),
                item.get("olt_model"),
                item.get("olt_firmware"),
            )
            item["extra_config"] = _merge_missing_template_values(current_extra, template_extra)
            item["password"] = decrypt_secret(item.get("password"))
            item["api_token"] = decrypt_secret(item.get("api_token"))
            items.append(item)
        return items


def fetch_connection_templates():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, brand, model, firmware, extra_config, defaults_json, updated_at
            FROM olt_connection_template
            ORDER BY brand, model, firmware
            """
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["extra_config"] = _deserialize_extra(item.get("extra_config"))
            item["defaults"] = _public_template_defaults(_deserialize_extra(item.get("defaults_json")))
            items.append(item)
        return items


def save_connection_template(payload):
    payload = payload or {}
    brand = _normalize_identity(payload.get("brand"))
    model = _normalize_identity(payload.get("model"))
    firmware = _normalize_identity(payload.get("firmware"))
    if not brand or not model or not firmware:
        raise ValueError("Template exige marca, modelo e firmware.")
    extra_config = _filter_template_extra(payload.get("extra_config") or {})
    defaults = _filter_template_defaults(payload.get("defaults") or {}, encrypt_secrets=True)
    if not extra_config and not defaults:
        raise ValueError("Template sem configuracao valida.")

    with connect() as connection:
        if payload.get("id"):
            existing = connection.execute(
                "SELECT id FROM olt_connection_template WHERE id = ?",
                (int(payload["id"]),),
            ).fetchone()
            if not existing:
                raise ValueError("Template nao encontrado.")
        _upsert_connection_template(connection, brand, model, firmware, extra_config, defaults)
        row = connection.execute(
            """
            SELECT id, brand, model, firmware, extra_config, defaults_json, updated_at
            FROM olt_connection_template
            WHERE brand = ? AND model = ? AND firmware = ?
            """,
            (brand, model, firmware),
        ).fetchone()
        connection.commit()
    item = dict(row)
    item["extra_config"] = _deserialize_extra(item.get("extra_config"))
    item["defaults"] = _public_template_defaults(_deserialize_extra(item.get("defaults_json")))
    return item


def delete_connection_template(template_id):
    with connect() as connection:
        row = connection.execute(
            "SELECT id, brand, model, firmware FROM olt_connection_template WHERE id = ?",
            (int(template_id),),
        ).fetchone()
        if not row:
            raise ValueError("Template nao encontrado.")
        connection.execute("DELETE FROM olt_connection_template WHERE id = ?", (int(template_id),))
        connection.commit()
        return {
            "status": "deleted",
            "id": int(row["id"]),
            "brand": row["brand"],
            "model": row["model"],
            "firmware": row["firmware"],
        }


def create_olt(payload):
    payload = payload or {}
    name = (payload.get("name") or "").strip()
    brand = (payload.get("brand") or "").strip()
    model = (payload.get("model") or "").strip()
    host = (payload.get("host") or "").strip()
    if not all([name, brand, model, host]):
        raise ValueError("Nome, marca, modelo e host sao obrigatorios.")

    with connect() as connection:
        template_bundle = _fetch_connection_template_bundle(
            connection,
            brand,
            model,
            (payload.get("firmware") or "").strip() or "N/A",
        )
        template_defaults = template_bundle.get("defaults") or {}
        firmware = (
            _prefer_payload_or_template(
                (payload.get("firmware") or "").strip(),
                template_defaults.get("firmware"),
                "N/A",
            )
            or "N/A"
        )
        board_slots_raw = _prefer_payload_or_template(
            payload.get("board_slots"),
            template_defaults.get("board_slots"),
            "0/1",
            default_markers=("0/1",),
        )
        board_slots = [
            slot.strip()
            for slot in str(board_slots_raw or "").split(",")
            if slot.strip()
        ]
        if not board_slots:
            raise ValueError("Informe ao menos um slot de placa.")

        board_model = (
            _prefer_payload_or_template(
                (payload.get("board_model") or "").strip(),
                template_defaults.get("board_model"),
                "GPON",
                default_markers=("GPON",),
            )
            or "GPON"
        )
        ports_per_board = int(
            _prefer_payload_or_template(
                payload.get("ports_per_board"),
                template_defaults.get("ports_per_board"),
                4,
                default_markers=(4, "4"),
            )
            or 4
        )
        capacity_onu = int(
            _prefer_payload_or_template(
                payload.get("capacity_onu"),
                template_defaults.get("capacity_onu"),
                128,
                default_markers=(128, "128"),
            )
            or 128
        )
        status = (
            _prefer_payload_or_template(
                (payload.get("status") or "").strip(),
                template_defaults.get("status"),
                "online",
                default_markers=("online",),
            )
            or "online"
        )
        transport_type = (
            _prefer_payload_or_template(
                (payload.get("transport_type") or "").strip().lower(),
                template_defaults.get("transport_type"),
                "ssh",
                default_markers=("ssh",),
            )
            or "ssh"
        )
        connection_port = int(
            _prefer_payload_or_template(
                payload.get("port"),
                template_defaults.get("port"),
                _default_port_for_transport(transport_type),
                default_markers=(22, "22", 23, "23"),
            )
            or _default_port_for_transport(transport_type)
        )
        connection_protocol = (
            _prefer_payload_or_template(
                (payload.get("protocol") or "").strip().lower(),
                template_defaults.get("protocol"),
                _default_collection_protocol(brand, transport_type),
            )
            or _default_collection_protocol(brand, transport_type)
        )
        username = (
            _prefer_payload_or_template(
                (payload.get("username") or "").strip(),
                template_defaults.get("username"),
                None,
            )
            or None
        )
        raw_password = (payload.get("password") or "").strip()
        password = (
            encrypt_secret(raw_password or None)
            if raw_password
            else template_defaults.get("password")
        )
        poll_interval_sec = int(
            _prefer_payload_or_template(
                payload.get("poll_interval_sec"),
                template_defaults.get("poll_interval_sec"),
                300,
                default_markers=(300, "300"),
            )
            or 300
        )
        command_timeout_sec = int(
            _prefer_payload_or_template(
                payload.get("command_timeout_sec"),
                template_defaults.get("command_timeout_sec"),
                20,
                default_markers=(20, "20"),
            )
            or 20
        )
        enabled = bool(
            _prefer_payload_or_template(
                payload.get("enabled"),
                template_defaults.get("enabled"),
                True,
                default_markers=(True, "true", "1", 1),
            )
        )
        verify_tls = bool(
            _prefer_payload_or_template(
                payload.get("verify_tls"),
                template_defaults.get("verify_tls"),
                False,
            )
        )
        api_base_url = (
            _prefer_payload_or_template(
                (payload.get("api_base_url") or "").strip(),
                template_defaults.get("api_base_url"),
                None,
            )
            or None
        )
        raw_api_token = (payload.get("api_token") or "").strip()
        api_token = (
            encrypt_secret(raw_api_token or None)
            if raw_api_token
            else template_defaults.get("api_token")
        )
        source_path = (
            _prefer_payload_or_template(
                (payload.get("source_path") or "").strip(),
                template_defaults.get("source_path"),
                None,
            )
            or None
        )
        command_line = (
            _prefer_payload_or_template(
                (payload.get("command_line") or "").strip(),
                template_defaults.get("command_line"),
                None,
            )
            or None
        )
        now = utc_now()
        template_extra = template_bundle.get("extra_config") or {}
        merged_extra_config = _merge_missing_template_values(
            {"vendor_hint": brand},
            template_extra,
        )
        duplicate = connection.execute(
            "SELECT id FROM olt WHERE name = ? OR host = ?",
            (name, host),
        ).fetchone()
        if duplicate:
            raise ValueError("Ja existe uma OLT com esse nome ou host.")

        cursor = connection.execute(
            """
            INSERT INTO olt (
                name, brand, model, host, status, firmware, temperature_c,
                cpu_usage, memory_usage, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, brand, model, host, status, firmware, 0.0, 0.0, 0.0, now),
        )
        olt_id = cursor.lastrowid

        board_rows = []
        for slot in board_slots:
            board_rows.append((olt_id, slot, board_model, status, ports_per_board))
        connection.executemany(
            "INSERT INTO board (olt_id, slot, model, status, ports_total) VALUES (?, ?, ?, ?, ?)",
            board_rows,
        )

        inserted_boards = connection.execute(
            "SELECT id, slot FROM board WHERE olt_id = ? ORDER BY slot",
            (olt_id,),
        ).fetchall()
        port_rows = []
        for board in inserted_boards:
            for port_index in range(1, ports_per_board + 1):
                port_rows.append((board["id"], f"PON {port_index}", capacity_onu, 80))
        connection.executemany(
            "INSERT INTO pon_port (board_id, name, capacity_onu, alert_threshold_pct) VALUES (?, ?, ?, ?)",
            port_rows,
        )

        connection.execute(
            """
            INSERT INTO olt_connection (
                olt_id, protocol, enabled, username, password, api_base_url, api_token,
                transport_type, source_path, command_line, port, poll_interval_sec, command_timeout_sec,
                verify_tls, extra_config, last_poll_status, last_poll_at, last_error,
                last_connect_status, last_connect_at, last_connect_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'idle', NULL, NULL, NULL, NULL, NULL)
            """,
            (
                olt_id,
                connection_protocol,
                1 if enabled else 0,
                username,
                password,
                api_base_url,
                api_token,
                transport_type,
                source_path,
                command_line,
                connection_port,
                poll_interval_sec,
                command_timeout_sec,
                1 if verify_tls else 0,
                json.dumps(merged_extra_config),
            ),
        )

        _upsert_connection_template(
            connection,
            brand,
            model,
            firmware,
            merged_extra_config,
            _filter_template_defaults(
                {
                    "protocol": connection_protocol,
                    "transport_type": transport_type,
                    "username": username,
                    "password": password,
                    "api_base_url": api_base_url,
                    "api_token": api_token,
                    "source_path": source_path,
                    "command_line": command_line,
                    "port": connection_port,
                    "poll_interval_sec": poll_interval_sec,
                    "command_timeout_sec": command_timeout_sec,
                    "verify_tls": verify_tls,
                    "enabled": enabled,
                    "status": status,
                    "board_model": board_model,
                    "board_slots": ",".join(board_slots),
                    "ports_per_board": ports_per_board,
                    "capacity_onu": capacity_onu,
                }
            ),
        )

        connection.execute(
            """
            INSERT INTO olt_metric_history (
                olt_id, collected_at, temperature_c, cpu_usage, memory_usage
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (olt_id, now, 0.0, 0.0, 0.0),
        )
        connection.commit()
    return {"status": "created", "olt_id": olt_id, "olts": fetch_olts()}


def update_olt(olt_id, payload):
    payload = payload or {}
    name = (payload.get("name") or "").strip()
    brand = (payload.get("brand") or "").strip()
    model = (payload.get("model") or "").strip()
    host = (payload.get("host") or "").strip()
    if not all([name, brand, model, host]):
        raise ValueError("Nome, marca, modelo e host sao obrigatorios.")

    board_slots_raw = payload.get("board_slots") or "0/1"
    board_slots = [
        slot.strip()
        for slot in str(board_slots_raw).split(",")
        if slot.strip()
    ]
    if not board_slots:
        raise ValueError("Informe ao menos um slot de placa.")

    board_model = (payload.get("board_model") or "GPON").strip()
    ports_per_board = int(payload.get("ports_per_board") or 4)
    capacity_onu = int(payload.get("capacity_onu") or 128)
    firmware = (payload.get("firmware") or "").strip() or "N/A"
    status = (payload.get("status") or "online").strip() or "online"
    transport_type = (payload.get("transport_type") or "ssh").strip().lower() or "ssh"
    connection_port = int(payload.get("port") or _default_port_for_transport(transport_type))
    connection_protocol = _default_collection_protocol(brand, transport_type)
    username = (payload.get("username") or "").strip() or None
    password = encrypt_secret((payload.get("password") or "").strip() or None)
    now = utc_now()

    with connect() as connection:
        current = connection.execute(
            "SELECT id FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not current:
            raise ValueError("OLT nao encontrada.")

        duplicate = connection.execute(
            "SELECT id FROM olt WHERE (name = ? OR host = ?) AND id <> ?",
            (name, host, olt_id),
        ).fetchone()
        if duplicate:
            raise ValueError("Ja existe outra OLT com esse nome ou host.")

        current_connection = connection.execute(
            """
            SELECT extra_config
                 , protocol
                 , enabled
                 , api_base_url
                 , api_token
                 , source_path
                 , command_line
                 , poll_interval_sec
                 , command_timeout_sec
                 , verify_tls
            FROM olt_connection
            WHERE olt_id = ?
            """,
            (olt_id,),
        ).fetchone()
        current_extra = _deserialize_extra(current_connection["extra_config"]) if current_connection else {}
        current_extra["vendor_hint"] = brand
        template_extra = _fetch_connection_template(connection, brand, model, firmware)
        merged_extra_config = _merge_missing_template_values(current_extra, template_extra)

        connection.execute(
            """
            UPDATE olt
            SET name = ?, brand = ?, model = ?, host = ?, firmware = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, brand, model, host, firmware, status, now, olt_id),
        )

        existing_boards = {
            row["slot"]: row["id"]
            for row in connection.execute(
                "SELECT id, slot FROM board WHERE olt_id = ?",
                (olt_id,),
            ).fetchall()
        }
        desired_slots = set(board_slots)
        current_slots = set(existing_boards.keys())

        slots_to_remove = current_slots - desired_slots
        for slot in slots_to_remove:
            board_id = existing_boards[slot]
            has_onus = connection.execute(
                "SELECT COUNT(*) FROM onu WHERE board_id = ?",
                (board_id,),
            ).fetchone()[0]
            if has_onus:
                raise ValueError(f"Nao e possivel remover a placa {slot}: existem ONUs vinculadas.")
            connection.execute("DELETE FROM board WHERE id = ?", (board_id,))

        slots_to_add = desired_slots - current_slots
        for slot in sorted(slots_to_add):
            cursor = connection.execute(
                "INSERT INTO board (olt_id, slot, model, status, ports_total) VALUES (?, ?, ?, ?, ?)",
                (olt_id, slot, board_model, status, ports_per_board),
            )
            existing_boards[slot] = cursor.lastrowid
            for port_index in range(1, ports_per_board + 1):
                connection.execute(
                    """
                    INSERT INTO pon_port (board_id, name, capacity_onu, alert_threshold_pct)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cursor.lastrowid, f"PON {port_index}", capacity_onu, 80),
                )

        for slot in sorted(desired_slots):
            board_id = existing_boards[slot]
            connection.execute(
                """
                UPDATE board
                SET model = ?, status = ?, ports_total = ?
                WHERE id = ?
                """,
                (board_model, status, ports_per_board, board_id),
            )

            existing_ports = {
                row["name"]: row["id"]
                for row in connection.execute(
                    "SELECT id, name FROM pon_port WHERE board_id = ?",
                    (board_id,),
                ).fetchall()
            }
            desired_port_names = {f"PON {index}" for index in range(1, ports_per_board + 1)}

            for port_name, port_id in list(existing_ports.items()):
                if port_name in desired_port_names:
                    continue
                has_onus = connection.execute(
                    "SELECT COUNT(*) FROM onu WHERE port_id = ?",
                    (port_id,),
                ).fetchone()[0]
                if has_onus:
                    raise ValueError(
                        f"Nao e possivel remover a porta {slot} {port_name}: existem ONUs vinculadas."
                    )
                connection.execute("DELETE FROM pon_port WHERE id = ?", (port_id,))

            for port_name in sorted(desired_port_names):
                if port_name not in existing_ports:
                    connection.execute(
                        """
                        INSERT INTO pon_port (board_id, name, capacity_onu, alert_threshold_pct)
                        VALUES (?, ?, ?, ?)
                        """,
                        (board_id, port_name, capacity_onu, 80),
                    )

            connection.execute(
                """
                UPDATE pon_port
                SET capacity_onu = ?, alert_threshold_pct = 80
                WHERE board_id = ?
                """,
                (capacity_onu, board_id),
            )

        connection.execute(
            """
            UPDATE olt_connection
            SET username = ?, password = ?, transport_type = ?, port = ?, extra_config = ?,
                protocol = CASE WHEN protocol = 'mock' THEN ? ELSE protocol END
            WHERE olt_id = ?
            """,
            (
                username,
                password,
                transport_type,
                connection_port,
                json.dumps(merged_extra_config),
                connection_protocol,
                olt_id,
            ),
        )
        current_connection_dict = dict(current_connection) if current_connection else {}
        effective_protocol = (
            connection_protocol
            if str(current_connection_dict.get("protocol") or "").strip().lower() == "mock"
            else current_connection_dict.get("protocol")
        ) or connection_protocol
        _upsert_connection_template(
            connection,
            brand,
            model,
            firmware,
            merged_extra_config,
            _filter_template_defaults(
                {
                    "protocol": effective_protocol,
                    "transport_type": transport_type,
                    "username": username,
                    "password": password,
                    "api_base_url": current_connection_dict.get("api_base_url"),
                    "api_token": current_connection_dict.get("api_token"),
                    "source_path": current_connection_dict.get("source_path"),
                    "command_line": current_connection_dict.get("command_line"),
                    "port": connection_port,
                    "poll_interval_sec": current_connection_dict.get("poll_interval_sec"),
                    "command_timeout_sec": current_connection_dict.get("command_timeout_sec"),
                    "verify_tls": bool(current_connection_dict.get("verify_tls")),
                    "enabled": bool(current_connection_dict.get("enabled", True)),
                    "status": status,
                    "board_model": board_model,
                    "board_slots": ",".join(sorted(desired_slots)),
                    "ports_per_board": ports_per_board,
                    "capacity_onu": capacity_onu,
                }
            ),
        )
        connection.commit()
    return {"status": "updated", "olt_id": olt_id, "olts": fetch_olts()}


def save_connection(olt_id, payload):
    payload = payload or {}
    with connect() as connection:
        exists = connection.execute(
            """
            SELECT
                connection.id,
                connection.protocol,
                connection.transport_type,
                connection.port,
                olt.brand,
                olt.model,
                olt.firmware
            FROM olt_connection connection
            JOIN olt ON olt.id = connection.olt_id
            WHERE connection.olt_id = ?
            """,
            (olt_id,),
        ).fetchone()
        extra_config = payload.get("extra_config") or {}
        fallback_protocol = _default_collection_protocol(
            exists["brand"] if exists else "",
            payload.get("transport_type") or (exists["transport_type"] if exists else "ssh"),
        )
        protocol = ((payload.get("protocol") or (exists["protocol"] if exists else fallback_protocol) or fallback_protocol).strip().lower())
        transport_type = (
            (payload.get("transport_type") or (exists["transport_type"] if exists else "ssh") or "ssh")
            .strip()
            .lower()
        )
        connection_port = int(payload.get("port") or (exists["port"] if exists else _default_port_for_transport(transport_type)) or _default_port_for_transport(transport_type))
        template_extra = _fetch_connection_template(
            connection,
            exists["brand"] if exists else "",
            exists["model"] if exists else "",
            exists["firmware"] if exists else "",
        )
        merged_extra_config = _merge_missing_template_values(extra_config, template_extra)
        row = (
            protocol,
            transport_type,
            1 if payload.get("enabled", True) else 0,
            (payload.get("username") or "").strip() or None,
            encrypt_secret((payload.get("password") or "").strip() or None),
            (payload.get("api_base_url") or "").strip() or None,
            encrypt_secret((payload.get("api_token") or "").strip() or None),
            (payload.get("source_path") or "").strip() or None,
            (payload.get("command_line") or "").strip() or None,
            connection_port,
            int(payload.get("poll_interval_sec") or 300),
            int(payload.get("command_timeout_sec") or 20),
            1 if payload.get("verify_tls") else 0,
            json.dumps(merged_extra_config),
        )
        if exists:
            connection.execute(
                """
                UPDATE olt_connection
                SET protocol = ?, transport_type = ?, enabled = ?, username = ?, password = ?,
                    api_base_url = ?, api_token = ?, source_path = ?, command_line = ?,
                    port = ?, poll_interval_sec = ?, command_timeout_sec = ?,
                    verify_tls = ?, extra_config = ?
                WHERE olt_id = ?
                """,
                (*row, olt_id),
            )
        else:
            connection.execute(
                """
                INSERT INTO olt_connection (
                    protocol, transport_type, enabled, username, password, api_base_url, api_token,
                    source_path, command_line, port, poll_interval_sec,
                    command_timeout_sec, verify_tls, extra_config, olt_id,
                    last_connect_status, last_connect_at, last_connect_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (*row, olt_id),
            )
        template_source = connection.execute(
            """
            SELECT
                olt.id AS olt_id,
                olt.brand,
                olt.model,
                olt.firmware,
                olt.status AS olt_status,
                connection.protocol,
                connection.transport_type,
                connection.enabled,
                connection.username,
                connection.password,
                connection.api_base_url,
                connection.api_token,
                connection.source_path,
                connection.command_line,
                connection.port,
                connection.poll_interval_sec,
                connection.command_timeout_sec,
                connection.verify_tls
            FROM olt_connection connection
            JOIN olt ON olt.id = connection.olt_id
            WHERE connection.olt_id = ?
            """,
            (int(olt_id),),
        ).fetchone()
        _upsert_connection_template(
            connection,
            exists["brand"] if exists else "",
            exists["model"] if exists else "",
            exists["firmware"] if exists else "",
            merged_extra_config,
            _extract_template_defaults_from_existing(connection, int(olt_id), dict(template_source) if template_source else {}),
        )
        connection.commit()
    return fetch_connection_for_olt(olt_id)


def apply_connection_template(olt_id, overwrite=True):
    with connect() as connection:
        row = connection.execute(
            """
            SELECT
                connection.olt_id,
                connection.protocol,
                connection.transport_type,
                connection.enabled,
                connection.username,
                connection.password,
                connection.api_base_url,
                connection.api_token,
                connection.source_path,
                connection.command_line,
                connection.port,
                connection.poll_interval_sec,
                connection.command_timeout_sec,
                connection.verify_tls,
                connection.extra_config,
                olt.brand,
                olt.model,
                olt.firmware
            FROM olt_connection connection
            JOIN olt ON olt.id = connection.olt_id
            WHERE connection.olt_id = ?
            """,
            (int(olt_id),),
        ).fetchone()
        if not row:
            raise ValueError("Conexao da OLT nao encontrada.")

        current_defaults = _filter_template_defaults(
            {
                "protocol": row["protocol"],
                "transport_type": row["transport_type"],
                "username": row["username"],
                "password": row["password"],
                "api_base_url": row["api_base_url"],
                "api_token": row["api_token"],
                "source_path": row["source_path"],
                "command_line": row["command_line"],
                "port": row["port"],
                "poll_interval_sec": row["poll_interval_sec"],
                "command_timeout_sec": row["command_timeout_sec"],
                "verify_tls": bool(row["verify_tls"]),
                "enabled": bool(row["enabled"]),
            }
        )
        current_extra = _deserialize_extra(row["extra_config"])
        template_bundle = _fetch_connection_template_bundle(
            connection,
            row["brand"],
            row["model"],
            row["firmware"],
        )
        template_extra = template_bundle.get("extra_config") or {}
        template_defaults = template_bundle.get("defaults") or {}
        if not template_extra:
            if not template_defaults:
                raise ValueError("Nenhum template encontrado para esta OLT.")

        if overwrite:
            merged_extra = dict(current_extra)
            for key, value in template_extra.items():
                merged_extra[key] = value
            merged_defaults = dict(current_defaults)
            for key, value in template_defaults.items():
                merged_defaults[key] = value
        else:
            merged_extra = _merge_missing_template_values(current_extra, template_extra)
            merged_defaults = _merge_missing_template_defaults(current_defaults, template_defaults)

        connection.execute(
            """
            UPDATE olt_connection
            SET protocol = ?, transport_type = ?, enabled = ?, username = ?, password = ?,
                api_base_url = ?, api_token = ?, source_path = ?, command_line = ?,
                port = ?, poll_interval_sec = ?, command_timeout_sec = ?, verify_tls = ?,
                extra_config = ?
            WHERE olt_id = ?
            """,
            (
                merged_defaults.get("protocol") or row["protocol"],
                merged_defaults.get("transport_type") or row["transport_type"],
                1 if bool(merged_defaults.get("enabled", row["enabled"])) else 0,
                merged_defaults.get("username"),
                merged_defaults.get("password"),
                merged_defaults.get("api_base_url"),
                merged_defaults.get("api_token"),
                merged_defaults.get("source_path"),
                merged_defaults.get("command_line"),
                int(merged_defaults.get("port") or row["port"] or 0),
                int(merged_defaults.get("poll_interval_sec") or row["poll_interval_sec"] or 300),
                int(merged_defaults.get("command_timeout_sec") or row["command_timeout_sec"] or 20),
                1 if bool(merged_defaults.get("verify_tls", row["verify_tls"])) else 0,
                json.dumps(merged_extra),
                int(olt_id),
            ),
        )
        connection.commit()
    return fetch_connection_for_olt(int(olt_id))


def delete_olt(olt_id):
    with connect() as connection:
        exists = connection.execute(
            "SELECT id, name FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not exists:
            raise ValueError("OLT nao encontrada.")
        connection.execute("DELETE FROM olt WHERE id = ?", (olt_id,))
        connection.commit()
        return {"status": "deleted", "olt_id": olt_id, "name": exists["name"]}


def list_due_connections():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT olt_id
            FROM olt_connection
            WHERE enabled = 1
              AND (
                    last_poll_at IS NULL
                    OR (strftime('%s', 'now') - strftime('%s', last_poll_at)) >= poll_interval_sec
                  )
            ORDER BY olt_id
            """
        ).fetchall()
        return [row["olt_id"] for row in rows]


def update_connection_poll_status(olt_id, status, error=None, polled_at=None):
    with connect() as connection:
        connection.execute(
            """
            UPDATE olt_connection
            SET last_poll_status = ?, last_poll_at = ?, last_error = ?
            WHERE olt_id = ?
            """,
            (status, polled_at or utc_now(), error, olt_id),
        )
        connection.commit()


def update_connection_connect_status(olt_id, status, message=None, connected_at=None):
    with connect() as connection:
        connection.execute(
            """
            UPDATE olt_connection
            SET last_connect_status = ?, last_connect_at = ?, last_connect_message = ?
            WHERE olt_id = ?
            """,
            (status, connected_at or utc_now(), message, olt_id),
        )
        connection.commit()


def update_connection_extra_config(olt_id, extra_updates):
    extra_updates = extra_updates or {}
    with connect() as connection:
        row = connection.execute(
            "SELECT extra_config FROM olt_connection WHERE olt_id = ?",
            (int(olt_id),),
        ).fetchone()
        if not row:
            return
        current = _deserialize_extra(row["extra_config"])
        for key, value in extra_updates.items():
            current[key] = value
        connection.execute(
            """
            UPDATE olt_connection
            SET extra_config = ?
            WHERE olt_id = ?
            """,
            (json.dumps(current), int(olt_id)),
        )
        connection.commit()


def add_collector_event(olt_id, level, message, details=None, created_at=None):
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO collector_event (olt_id, level, message, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                olt_id,
                level,
                message,
                json.dumps(details or {}),
                created_at or utc_now(),
            ),
        )
        connection.commit()


def _upsert_pending_request(connection, olt_id, board_id, port_id, item, collected_at):
    exists = connection.execute(
        """
        SELECT id
        FROM authorization_request
        WHERE serial = ? AND status = 'pending'
        LIMIT 1
        """,
        (item["serial"],),
    ).fetchone()
    if exists:
        connection.execute(
            """
            UPDATE authorization_request
            SET olt_id = ?, board_id = ?, port_id = ?, detected_model = ?,
                requested_signal_dbm = ?, requested_temperature_c = ?, requested_at = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                olt_id,
                board_id,
                port_id,
                item["detected_model"],
                item.get("requested_signal_dbm"),
                item.get("requested_temperature_c"),
                collected_at,
                item.get("notes"),
                exists["id"],
            ),
        )
        return exists["id"]
    cursor = connection.execute(
        """
        INSERT INTO authorization_request (
            serial, detected_model, olt_id, board_id, port_id, requested_signal_dbm,
            requested_temperature_c, requested_at, status, notes, resolved_onu_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)
        """,
        (
            item["serial"],
            item["detected_model"],
            olt_id,
            board_id,
            port_id,
            item.get("requested_signal_dbm"),
            item.get("requested_temperature_c"),
            collected_at,
            item.get("notes"),
        ),
    )
    return cursor.lastrowid


def _upsert_olt_vlan(connection, olt_id, vlan_id, source="observed", collected_at=None):
    if vlan_id is None:
        return
    try:
        vlan_id = int(vlan_id)
    except Exception:
        return
    if vlan_id < 1 or vlan_id > 4094:
        return
    now = collected_at or utc_now()
    connection.execute(
        """
        INSERT INTO olt_vlan (olt_id, vlan_id, name, description, source, updated_at)
        VALUES (?, ?, '', '', ?, ?)
        ON CONFLICT(olt_id, vlan_id) DO UPDATE SET
            source = CASE
                WHEN olt_vlan.source = 'manual' THEN olt_vlan.source
                ELSE excluded.source
            END,
            updated_at = excluded.updated_at
        """,
        (olt_id, vlan_id, source, now),
    )


def apply_collection(olt_id, payload):
    payload = payload or {}
    collected_at = payload.get("collected_at") or utc_now()
    events_added = []
    with connect() as connection:
        olt_row = connection.execute(
            "SELECT id, brand FROM olt WHERE id = ?",
            (olt_id,),
        ).fetchone()
        if not olt_row:
            raise ValueError("OLT nao encontrada.")

        olt_metrics = payload.get("olt_metrics") or {}
        if olt_metrics:
            connection.execute(
                """
                UPDATE olt
                SET temperature_c = ?, cpu_usage = ?, memory_usage = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    olt_metrics.get("temperature_c", 0.0),
                    olt_metrics.get("cpu_usage", 0.0),
                    olt_metrics.get("memory_usage", 0.0),
                    collected_at,
                    olt_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO olt_metric_history (
                    olt_id, collected_at, temperature_c, cpu_usage, memory_usage
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    olt_id,
                    collected_at,
                    olt_metrics.get("temperature_c", 0.0),
                    olt_metrics.get("cpu_usage", 0.0),
                    olt_metrics.get("memory_usage", 0.0),
                ),
            )

        board_lookup = {
            row["slot"]: row["id"]
            for row in connection.execute(
                "SELECT id, slot FROM board WHERE olt_id = ?",
                (olt_id,),
            ).fetchall()
        }
        for board in payload.get("boards", []):
            board_slot = board.get("slot")
            if not board_slot:
                continue
            board_id = board_lookup.get(board_slot)
            if not board_id:
                cursor = connection.execute(
                    """
                    INSERT INTO board (olt_id, slot, model, status, ports_total)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        olt_id,
                        board_slot,
                        board.get("model") or "GPON",
                        board.get("status") or "online",
                        int(board.get("ports_total") or 16),
                    ),
                )
                board_id = cursor.lastrowid
                board_lookup[board_slot] = board_id
            else:
                connection.execute(
                    """
                    UPDATE board
                    SET model = ?, status = ?, ports_total = ?
                    WHERE id = ?
                    """,
                    (
                        board.get("model") or "",
                        board.get("status") or "online",
                        int(board.get("ports_total") or 0),
                        board_id,
                    ),
                )

        port_lookup = {
            (row["slot"], row["name"]): row["id"]
            for row in connection.execute(
                """
                SELECT pon_port.id, board.slot, pon_port.name
                FROM pon_port
                JOIN board ON board.id = pon_port.board_id
                WHERE board.olt_id = ?
                """,
                (olt_id,),
            ).fetchall()
        }

        for port in payload.get("ports", []):
            board_slot = port.get("board_slot")
            port_name = port.get("name")
            if not board_slot or not port_name:
                continue
            board_id = board_lookup.get(board_slot)
            if not board_id:
                cursor = connection.execute(
                    """
                    INSERT INTO board (olt_id, slot, model, status, ports_total)
                    VALUES (?, ?, 'GPON', 'online', 16)
                    """,
                    (olt_id, board_slot),
                )
                board_id = cursor.lastrowid
                board_lookup[board_slot] = board_id
            port_id = port_lookup.get((board_slot, port_name))
            if not port_id:
                cursor = connection.execute(
                    """
                    INSERT INTO pon_port (board_id, name, capacity_onu, alert_threshold_pct)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        board_id,
                        port_name,
                        int(port.get("capacity_onu") or 128),
                        int(port.get("alert_threshold_pct") or 80),
                    ),
                )
                port_id = cursor.lastrowid
                port_lookup[(board_slot, port_name)] = port_id
            if not port_id:
                continue
            used_onu = int(port.get("used_onu") or 0)
            capacity_onu = int(port.get("capacity_onu") or 0)
            usage_pct = 0 if not capacity_onu else round(used_onu * 100 / capacity_onu, 1)
            connection.execute(
                """
                UPDATE pon_port
                SET capacity_onu = ?, alert_threshold_pct = ?
                WHERE id = ?
                """,
                (
                    capacity_onu,
                    int(port.get("alert_threshold_pct") or 80),
                    port_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO port_metric_history (
                    port_id, collected_at, used_onu, capacity_onu, usage_pct
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (port_id, collected_at, used_onu, capacity_onu, usage_pct),
            )
            if usage_pct >= int(port.get("alert_threshold_pct") or 80):
                message = (
                    f'Porta {port["board_slot"]} {port["name"]} em {usage_pct}% '
                    f'({used_onu}/{capacity_onu})'
                )
                connection.execute(
                    """
                    INSERT INTO collector_event (olt_id, level, message, details_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        olt_id,
                        _alert_level(usage_pct, int(port.get("alert_threshold_pct") or 80)),
                        message,
                        json.dumps(port),
                        collected_at,
                    ),
                )
                events_added.append(message)

        for item in payload.get("onus", []):
            board_slot = item.get("board_slot")
            port_name = item.get("port_name")
            if not board_slot or not port_name:
                continue
            board_id = board_lookup.get(board_slot)
            if not board_id:
                cursor = connection.execute(
                    """
                    INSERT INTO board (olt_id, slot, model, status, ports_total)
                    VALUES (?, ?, 'GPON', 'online', 16)
                    """,
                    (olt_id, board_slot),
                )
                board_id = cursor.lastrowid
                board_lookup[board_slot] = board_id
            port_id = port_lookup.get((board_slot, port_name))
            if not port_id:
                cursor = connection.execute(
                    """
                    INSERT INTO pon_port (board_id, name, capacity_onu, alert_threshold_pct)
                    VALUES (?, ?, 128, 80)
                    """,
                    (board_id, port_name),
                )
                port_id = cursor.lastrowid
                port_lookup[(board_slot, port_name)] = port_id

            onu_row = connection.execute(
                """
                SELECT
                    id, model, client_name, neighborhood, city, vlan_id, profile_id, onu_mode, line_profile, service_profile,
                    signal_dbm, signal_tx_dbm, signal_olt_rx_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c
                FROM onu
                WHERE serial = ?
                LIMIT 1
                """,
                (item["serial"],),
            ).fetchone()
            if not onu_row:
                raw_description = (item.get("description") or "").strip()
                client_name = raw_description or "Nao identificado"
                model_value = _resolve_collected_model(item.get("model"), None)
                if model_value == "Desconhecido":
                    model_value = _guess_model_from_serial(item.get("serial"))
                profile = _find_profile_for_brand_model(
                    connection,
                    olt_row["brand"],
                    model_value or "",
                )
                collected_vlan = _resolve_collected_vlan(item.get("vlan_id"))
                line_profile_value = profile["line_profile"] if profile else None
                service_profile_value = profile["service_profile"] if profile else None
                onu_mode_value = _infer_onu_mode_from_profiles(line_profile_value, service_profile_value, "bridge")
                cursor = connection.execute(
                    """
                    INSERT INTO onu (
                        serial, mac_address, model, client_name, neighborhood, city, vlan_id,
                        profile_id, line_profile, service_profile, onu_mode, status, signal_dbm, signal_tx_dbm, signal_olt_rx_dbm,
                        traffic_down_mbps, traffic_up_mbps, temperature_c, olt_id, board_id, port_id,
                        pon_position, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item["serial"],
                        "",
                        model_value or "Desconhecido",
                        client_name,
                        "Nao informado",
                        "Nao informado",
                        collected_vlan,
                        profile["id"] if profile else None,
                        line_profile_value,
                        service_profile_value,
                        onu_mode_value,
                        item.get("status") or "active",
                        item.get("signal_dbm") or 0.0,
                        item.get("signal_tx_dbm"),
                        item.get("signal_olt_rx_dbm"),
                        item.get("traffic_down_mbps") or 0.0,
                        item.get("traffic_up_mbps") or 0.0,
                        item.get("temperature_c") or 0.0,
                        olt_id,
                        board_id,
                        port_id,
                        int(item["pon_position"]) if item.get("pon_position") is not None else _next_pon_position(connection, port_id),
                        collected_at,
                    ),
                )
                onu_id = cursor.lastrowid
                _upsert_olt_vlan(
                    connection,
                    olt_id,
                    collected_vlan,
                    source="observed",
                    collected_at=collected_at,
                )
                connection.execute(
                    """
                    INSERT INTO onu_metric_history (
                        onu_id, collected_at, signal_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        onu_id,
                        collected_at,
                        item.get("signal_dbm") or 0.0,
                        item.get("traffic_down_mbps") or 0.0,
                        item.get("traffic_up_mbps") or 0.0,
                        item.get("temperature_c") or 0.0,
                    ),
                )
                connection.execute(
                    """
                    UPDATE authorization_request
                    SET status = 'authorized', resolved_onu_id = ?
                    WHERE serial = ? AND status = 'pending'
                    """,
                    (onu_id, item["serial"]),
                )
                continue

            connection.execute(
                """
                UPDATE onu
                SET model = ?, status = ?, signal_dbm = ?, traffic_down_mbps = ?,
                    signal_tx_dbm = ?, signal_olt_rx_dbm = ?, traffic_up_mbps = ?, temperature_c = ?, client_name = ?,
                    olt_id = ?, board_id = ?, port_id = ?, pon_position = ?,
                    vlan_id = ?, line_profile = ?, service_profile = ?, onu_mode = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    (
                        _guess_model_from_serial(item.get("serial"))
                        if _resolve_collected_model(item.get("model"), onu_row["model"]) == "Desconhecido"
                        else _resolve_collected_model(item.get("model"), onu_row["model"])
                    ),
                    item.get("status") or "active",
                    (
                        item["signal_dbm"]
                        if ("signal_dbm" in item and item.get("signal_dbm") is not None)
                        else onu_row["signal_dbm"]
                    ),
                    (
                        item["traffic_down_mbps"]
                        if ("traffic_down_mbps" in item and item.get("traffic_down_mbps") is not None)
                        else onu_row["traffic_down_mbps"]
                    ),
                    (
                        item["signal_tx_dbm"]
                        if ("signal_tx_dbm" in item and item.get("signal_tx_dbm") is not None)
                        else onu_row["signal_tx_dbm"]
                    ),
                    (
                        item["signal_olt_rx_dbm"]
                        if ("signal_olt_rx_dbm" in item and item.get("signal_olt_rx_dbm") is not None)
                        else onu_row["signal_olt_rx_dbm"]
                    ),
                    (
                        item["traffic_up_mbps"]
                        if ("traffic_up_mbps" in item and item.get("traffic_up_mbps") is not None)
                        else onu_row["traffic_up_mbps"]
                    ),
                    (
                        item["temperature_c"]
                        if ("temperature_c" in item and item.get("temperature_c") is not None)
                        else onu_row["temperature_c"]
                    ),
                    _resolve_collected_client_name(item.get("description"), onu_row["client_name"]),
                    olt_id,
                    board_id,
                    port_id,
                    int(item["pon_position"]) if item.get("pon_position") is not None else 0,
                    _resolve_collected_vlan(item.get("vlan_id"), onu_row["vlan_id"]),
                    onu_row["line_profile"],
                    onu_row["service_profile"],
                    _normalize_onu_mode(
                        onu_row["onu_mode"],
                        _infer_onu_mode_from_profiles(onu_row["line_profile"], onu_row["service_profile"], "bridge"),
                    ),
                    collected_at,
                    onu_row["id"],
                ),
            )
            _upsert_olt_vlan(
                connection,
                olt_id,
                _resolve_collected_vlan(item.get("vlan_id"), onu_row["vlan_id"]),
                source="observed",
                collected_at=collected_at,
            )
            connection.execute(
                """
                INSERT INTO onu_metric_history (
                    onu_id, collected_at, signal_dbm, traffic_down_mbps, traffic_up_mbps, temperature_c
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    onu_row["id"],
                    collected_at,
                    (
                        item["signal_dbm"]
                        if ("signal_dbm" in item and item.get("signal_dbm") is not None)
                        else onu_row["signal_dbm"]
                    ),
                    (
                        item["traffic_down_mbps"]
                        if ("traffic_down_mbps" in item and item.get("traffic_down_mbps") is not None)
                        else onu_row["traffic_down_mbps"]
                    ),
                    (
                        item["traffic_up_mbps"]
                        if ("traffic_up_mbps" in item and item.get("traffic_up_mbps") is not None)
                        else onu_row["traffic_up_mbps"]
                    ),
                    (
                        item["temperature_c"]
                        if ("temperature_c" in item and item.get("temperature_c") is not None)
                        else onu_row["temperature_c"]
                    ),
                ),
            )
            connection.execute(
                """
                UPDATE authorization_request
                SET status = 'authorized', resolved_onu_id = ?
                WHERE serial = ? AND status = 'pending'
                """,
                (onu_row["id"], item["serial"]),
            )

        for vlan_item in payload.get("olt_vlans", []):
            _upsert_olt_vlan(
                connection,
                olt_id,
                vlan_item.get("vlan_id"),
                source=(vlan_item.get("source") or "observed"),
                collected_at=collected_at,
            )

        for item in payload.get("authorization_requests", []):
            board_id = board_lookup.get(item["board_slot"])
            port_id = port_lookup.get((item["board_slot"], item["port_name"]))
            if not board_id or not port_id:
                continue
            _upsert_pending_request(connection, olt_id, board_id, port_id, item, collected_at)

        for event in payload.get("events", []):
            connection.execute(
                """
                INSERT INTO collector_event (olt_id, level, message, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    olt_id,
                    event.get("level") or "info",
                    event.get("message") or "Evento de coleta",
                    json.dumps(event.get("details") or {}),
                    collected_at,
                ),
            )

        connection.commit()
    return {"status": "applied", "collected_at": collected_at, "events_added": events_added}


def fetch_history_dashboard(limit=12):
    with connect() as connection:
        olt_rows = connection.execute(
            "SELECT id, name FROM olt ORDER BY name"
        ).fetchall()
        olt_history = []
        for olt in olt_rows:
            points = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT collected_at, temperature_c, cpu_usage, memory_usage
                    FROM olt_metric_history
                    WHERE olt_id = ?
                    ORDER BY collected_at DESC
                    LIMIT ?
                    """,
                    (olt["id"], limit),
                ).fetchall()
            ]
            points.reverse()
            olt_history.append(
                {
                    "olt_id": olt["id"],
                    "label": olt["name"],
                    "points": points,
                }
            )

        tracked_onus = connection.execute(
            """
            SELECT id, serial, client_name
            FROM onu
            ORDER BY updated_at DESC, id DESC
            LIMIT 5
            """
        ).fetchall()
        onu_history = []
        for onu in tracked_onus:
            points = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT collected_at, signal_dbm, temperature_c, traffic_down_mbps, traffic_up_mbps
                    FROM onu_metric_history
                    WHERE onu_id = ?
                    ORDER BY collected_at DESC
                    LIMIT ?
                    """,
                    (onu["id"], limit),
                ).fetchall()
            ]
            points.reverse()
            onu_history.append(
                {
                    "onu_id": onu["id"],
                    "label": f'{onu["client_name"]} ({onu["serial"]})',
                    "points": points,
                }
            )

        return {"olt_history": olt_history, "onu_history": onu_history}


def fetch_onu_history(onu_id, limit=24):
    with connect() as connection:
        onu = connection.execute(
            "SELECT id, serial, client_name FROM onu WHERE id = ?",
            (onu_id,),
        ).fetchone()
        if not onu:
            raise ValueError("ONU nao encontrada.")
        points = [
            dict(row)
            for row in connection.execute(
                """
                SELECT collected_at, signal_dbm, temperature_c, traffic_down_mbps, traffic_up_mbps
                FROM onu_metric_history
                WHERE onu_id = ?
                ORDER BY collected_at DESC
                LIMIT ?
                """,
                (onu_id, limit),
            ).fetchall()
        ]
        points.reverse()
        return {
            "onu_id": onu["id"],
            "label": f'{onu["client_name"]} ({onu["serial"]})',
            "points": points,
        }


def fetch_events(limit=20):
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                event.id,
                event.level,
                event.message,
                event.details_json,
                event.created_at,
                olt.name AS olt_name
            FROM collector_event event
            JOIN olt ON olt.id = event.olt_id
            ORDER BY event.created_at DESC, event.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["details"] = _deserialize_extra(item.pop("details_json"))
            items.append(item)
        return items
