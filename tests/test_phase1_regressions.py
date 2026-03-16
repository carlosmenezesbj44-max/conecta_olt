import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from backend import db
from backend.collectors import service
from backend.collectors import huawei_telnet


class Phase1RegressionTests(unittest.TestCase):
    def test_zero_dbm_is_not_treated_as_valid_onu_rx_signal(self):
        self.assertFalse(service._is_valid_onu_signal_dbm(0))
        self.assertFalse(service._is_valid_onu_signal_dbm(0.0))
        self.assertTrue(service._is_valid_onu_signal_dbm(-21.5))

    def test_parse_huawei_optical_metrics_extracts_rx_tx_and_temperature(self):
        output = """
        Rx optical power(dBm)        : -23.41
        Tx optical power(dBm)        : 2.77
        OLT Rx ONT optical power(dBm): -21.52
        Temperature(C)               : 49.6
        """

        metrics = service._parse_huawei_optical_metrics(output)

        self.assertEqual(metrics["signal_dbm"], -23.41)
        self.assertEqual(metrics["signal_tx_dbm"], 2.77)
        self.assertEqual(metrics["signal_olt_rx_dbm"], -21.52)
        self.assertEqual(metrics["temperature_c"], 49.6)

    def test_telnet_collector_requests_optical_file(self):
        optical_command = next(command for filename, command in huawei_telnet.HUAWEI_TELNET_COMMANDS if filename == "optical.txt")
        self.assertEqual(optical_command, "display ont optical-info 0 all")

    def test_telnet_prompt_pattern_accepts_gpon_interface_prompt(self):
        prompt = "OLT-HW-BJM-CEN-01(config-if-gpon-0/1)#"
        self.assertTrue(huawei_telnet.PROMPT_PATTERN.search(prompt))

    def test_huawei_command_failure_detector_ignores_config_state_failed(self):
        output = """
        Run state               : online
        Config state            : failed
        Match state             : match
        """
        self.assertFalse(service._looks_like_huawei_command_failure(output))

    def test_physical_status_ignores_zero_dbm_and_uses_return_signal(self):
        status = service._collect_huawei_onu_physical_status(
            {
                "serial": "ABC123",
                "board_slot": "0/1",
                "port_name": "PON 1",
                "pon_position": 3,
                "status": "active",
                "signal_dbm": 0.0,
                "signal_olt_rx_dbm": -21.33,
            },
            {},
            info_output="Run state : online\nLast down cause : -\n",
        )

        self.assertEqual(status["fiber"]["state"], "up")
        self.assertIn("ONU->OLT -21.33 dBm", status["fiber"]["detail"])

    def test_huawei_disconnect_reason_classifies_dying_gasp_as_power_loss(self):
        reason = service._build_huawei_disconnect_reason(
            False,
            "DGi: dying gasp reported by ONU",
            "",
            "",
            "DGi: dying gasp reported by ONU",
            "offline",
        )

        self.assertEqual(reason["state"], "probable-power-off")
        self.assertIn("energia", reason["label"].lower())

    def test_huawei_fiber_alarm_detects_lofi(self):
        line = service._find_huawei_fiber_alarm_line("LOFi: loss of frame on optical channel")
        self.assertIn("lofi", line.lower())

    def test_huawei_disconnect_reason_marks_inconclusive_olt_when_no_evidence(self):
        reason = service._build_huawei_disconnect_reason(
            False,
            "",
            "",
            "",
            "",
            "offline",
            alarm_output_available=False,
        )

        self.assertEqual(reason["state"], "unconfirmed")
        self.assertEqual(reason["label"], "Sem conclusao da OLT")
        self.assertIn("alarm-state", reason["detail"].lower())

    def test_decorate_onu_runtime_state_marks_stale_after_threshold(self):
        now = datetime(2026, 3, 15, 21, 0, 0, tzinfo=timezone.utc)
        decorated = db._decorate_onu_runtime_state(
            {
                "updated_at": "2026-03-15T20:40:00+00:00",
                "poll_interval_sec": 300,
                "status": "active",
                "signal_dbm": -24.6,
                "temperature_c": 41.0,
            },
            now=now,
        )

        self.assertTrue(decorated["data_quality"]["stale"])
        self.assertEqual(decorated["data_quality"]["confidence"], "low")
        self.assertEqual(decorated["field_meta"]["signal"]["source"], "poll-snmp")
        self.assertEqual(decorated["field_meta"]["traffic"]["source"], "poll-pon")

    def test_build_live_field_meta_prefers_live_sources(self):
        meta = service._build_live_field_meta(
            ["signal", "status", "traffic_down", "traffic_up"],
            "2026-03-15T21:05:00+00:00",
        )

        self.assertEqual(meta["signal"]["source"], "live-snmp")
        self.assertEqual(meta["status"]["confidence"], "high")
        self.assertEqual(meta["traffic"]["source"], "live-pon-snmp")
        self.assertFalse(meta["traffic"]["stale"])

    def test_fast_snapshot_marks_missing_onus_warning_when_coverage_is_sufficient(self):
        serial_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3"
        signal_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
        serial_base = tuple(int(part) for part in serial_oid.split("."))
        signal_base = tuple(int(part) for part in signal_oid.split("."))
        payload = {
            "onus": [
                {
                    "serial": "ABC123",
                    "status": "active",
                    "traffic_down_mbps": 12.0,
                    "traffic_up_mbps": 1.0,
                },
                {
                    "serial": "DEF456",
                    "status": "active",
                    "traffic_down_mbps": 18.0,
                    "traffic_up_mbps": 2.0,
                },
            ],
            "ports": [],
            "boards": [],
            "events": [
                {
                    "level": "info",
                    "message": "Coleta rapida: inventario CLI reutilizado.",
                    "details": {"mode": "fast"},
                }
            ],
        }
        olt = {"id": 1, "host": "127.0.0.1"}
        connection = {
            "password": "public",
            "extra_config": {
                "snmp_fast_mode": True,
                "fast_partial_onu_updates": True,
                "snmp_serial_oid": serial_oid,
                "snmp_signal_oid": signal_oid,
                "snmp_signal_tx_oid": "",
                "snmp_signal_olt_rx_oid": "",
                "snmp_temperature_oid": "",
                "snmp_port_status_oid": "",
                "snmp_port_count_oid": "",
                "snmp_ifname_oid": "",
            },
        }

        def fake_walk(_host, _community, oid_value, **_kwargs):
            if oid_value == serial_oid:
                return [
                    (serial_base + (11,), "ABC123"),
                    (serial_base + (12,), "DEF456"),
                ]
            if oid_value == signal_oid:
                return [
                    (signal_base + (11,), -24.1),
                ]
            return []

        with patch.dict(service.SNMP_INDEX_CACHE, {}, clear=True):
            with patch.object(service.snmp_client, "walk", side_effect=fake_walk):
                service._enrich_huawei_payload_with_snmp(payload, olt, connection)

        self.assertEqual(payload["onus"][0]["status"], "active")
        self.assertEqual(payload["onus"][1]["status"], "warning")
        self.assertEqual(payload["onus"][1]["traffic_down_mbps"], 0.0)
        self.assertEqual(payload["onus"][1]["traffic_up_mbps"], 0.0)

        coverage_event = next(
            event for event in payload["events"] if (event.get("details") or {}).get("mode") == "fast-stale-onu-reset"
        )
        self.assertEqual(coverage_event["details"]["stale_onus"], 1)
        self.assertEqual(coverage_event["details"]["coverage_ratio"], 0.5)

    def test_snmp_enrichment_promotes_warning_to_active_when_status_oid_is_missing_but_signal_is_fresh(self):
        serial_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3"
        signal_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
        serial_base = tuple(int(part) for part in serial_oid.split("."))
        signal_base = tuple(int(part) for part in signal_oid.split("."))
        payload = {
            "onus": [
                {
                    "serial": "ABC123",
                    "status": "warning",
                    "signal_dbm": None,
                    "traffic_down_mbps": 2.0,
                    "traffic_up_mbps": 1.0,
                }
            ],
            "ports": [],
            "boards": [],
            "events": [
                {
                    "level": "info",
                    "message": "Coleta rapida: inventario CLI reutilizado.",
                    "details": {"mode": "fast"},
                }
            ],
        }
        olt = {"id": 1, "host": "127.0.0.1"}
        connection = {
            "password": "public",
            "extra_config": {
                "snmp_fast_mode": True,
                "fast_partial_onu_updates": True,
                "snmp_serial_oid": serial_oid,
                "snmp_signal_oid": signal_oid,
                "snmp_status_oid": "",
                "snmp_signal_tx_oid": "",
                "snmp_signal_olt_rx_oid": "",
                "snmp_temperature_oid": "",
                "snmp_port_status_oid": "",
                "snmp_port_count_oid": "",
                "snmp_ifname_oid": "",
            },
        }

        def fake_walk(_host, _community, oid_value, **_kwargs):
            if oid_value == serial_oid:
                return [(serial_base + (11,), "ABC123")]
            if oid_value == signal_oid:
                return [(signal_base + (11,), -23.7)]
            return []

        with patch.dict(service.SNMP_INDEX_CACHE, {}, clear=True):
            with patch.object(service.snmp_client, "walk", side_effect=fake_walk):
                service._enrich_huawei_payload_with_snmp(payload, olt, connection)

        self.assertEqual(payload["onus"][0]["status"], "active")
        self.assertAlmostEqual(payload["onus"][0]["signal_dbm"], -23.7, places=2)

    def test_run_onu_action_live_blocks_offline_onu(self):
        onu = {
            "id": 77,
            "serial": "ABC123",
            "model": "HG8245Q2",
            "client_name": "Cliente Teste",
            "status": "warning",
            "olt_id": 1,
            "olt_brand": "huawei",
            "board_slot": "0/1",
            "port_name": "GPON 0/1/1",
            "pon_position": 5,
            "vlan_id": 700,
        }
        persisted_onu = {
            **onu,
            "traffic_down_mbps": 0.0,
            "traffic_up_mbps": 0.0,
            "field_meta": {},
            "data_quality": {},
        }

        with patch.object(service.db, "fetch_onu_by_id", return_value=onu):
            with patch.object(service.db, "fetch_connection_for_olt", return_value={"protocol": "native"}):
                with patch.object(
                    service,
                    "_first_successful_huawei_action",
                    return_value={"command": "display ont info", "output": "Run state : offline"},
                ):
                    with patch.object(
                        service,
                        "_collect_huawei_onu_physical_status",
                        return_value={
                            "power": {"state": "probable-off"},
                            "fiber": {"state": "unconfirmed"},
                            "meta": {"run_state": "offline"},
                        },
                    ):
                        with patch.object(
                            service,
                            "_persist_onu_live_status_snapshot",
                            return_value=persisted_onu,
                        ) as persist_snapshot:
                            result = service.run_onu_action(77, "live")

        persist_snapshot.assert_called_once()
        self.assertFalse(result["live_available"])
        self.assertEqual(result["onu"]["field_meta"]["traffic"]["source"], "live-gate")
        self.assertIn("offline", result["output"].lower())
        self.assertEqual(persist_snapshot.call_args.kwargs["traffic_down_mbps"], 0.0)
        self.assertEqual(persist_snapshot.call_args.kwargs["traffic_up_mbps"], 0.0)

    def test_collect_onu_live_offline_evidence_sets_warning_and_clears_optical_values(self):
        onu = {
            "id": 99,
            "serial": "ABC123",
            "model": "HG8245Q2",
            "client_name": "Cliente Teste",
            "status": "active",
            "signal_dbm": -19.8,
            "signal_tx_dbm": 2.7,
            "signal_olt_rx_dbm": -24.2,
            "traffic_down_mbps": 0.2,
            "traffic_up_mbps": 0.1,
            "temperature_c": 45.0,
            "olt_id": 1,
            "olt_brand": "huawei",
            "olt_host": "127.0.0.1",
            "board_slot": "0/1",
            "port_name": "PON 1",
            "pon_position": 3,
            "vlan_id": 700,
        }
        updated_onu = {
            **onu,
            "status": "warning",
            "signal_dbm": 0.0,
            "signal_tx_dbm": 0.0,
            "signal_olt_rx_dbm": 0.0,
        }
        connection = {
            "enabled": True,
            "protocol": "native",
            "extra_config": {
                "snmp_read_community": "public",
                "snmp_signal_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
                "snmp_signal_tx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.3",
                "snmp_signal_olt_rx_oid": "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6",
                "snmp_status_oid": "",
            },
        }

        fetch_counter = {"count": 0}

        def fake_fetch_onu_by_id(_onu_id):
            fetch_counter["count"] += 1
            return onu if fetch_counter["count"] == 1 else updated_onu

        with patch.object(service.db, "fetch_onu_by_id", side_effect=fake_fetch_onu_by_id):
            with patch.object(service.db, "fetch_connection_for_olt", return_value=connection):
                with patch.object(service, "_build_onu_snmp_candidates", return_value=[(1,)]):
                    with patch.object(service, "_snmp_get_value_for_candidates", return_value=(None, None)):
                        with patch.object(service, "_collect_huawei_onu_optical_metrics", return_value={}):
                            with patch.object(
                                service,
                                "_collect_huawei_onu_physical_status",
                                return_value={
                                    "power": {"state": "probable-off", "detail": "dying-gasp"},
                                    "fiber": {"state": "up", "detail": "sinal legado"},
                                    "ethernet": {"state": "down", "detail": "sem link"},
                                    "disconnect_reason": {"state": "probable-power-off"},
                                    "meta": {"run_state": "offline", "optical_signal_evidence": True},
                                },
                            ):
                                with patch.object(service.db, "apply_collection") as apply_collection:
                                    result = service.collect_onu_live(
                                        99,
                                        fields=["status", "signal", "signal_tx", "signal_olt_rx", "power", "fiber", "ethernet"],
                                    )

        persisted_payload = apply_collection.call_args.args[1]
        persisted_onu = persisted_payload["onus"][0]
        self.assertEqual(persisted_onu["status"], "warning")
        self.assertEqual(persisted_onu["signal_dbm"], 0.0)
        self.assertEqual(persisted_onu["signal_tx_dbm"], 0.0)
        self.assertEqual(persisted_onu["signal_olt_rx_dbm"], 0.0)
        self.assertIn("status", result["updated_fields"])
        self.assertIn("signal", result["updated_fields"])


if __name__ == "__main__":
    unittest.main()
