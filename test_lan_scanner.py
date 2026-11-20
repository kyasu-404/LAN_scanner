import csv
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import LAN_scaner as scanner


HOST_XML = """
<host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="HP Inc."/>
    <hostnames><hostname name="lab &amp; office"/></hostnames>
    <ports>
        <port protocol="tcp" portid="3389"><state state="open"/></port>
        <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds" product="SMB" version="3"/>
        </port>
        <port protocol="tcp" portid="22"><state state="filtered"/></port>
    </ports>
</host>
"""


def nmap_xml(*hosts):
    return ("<nmaprun>" + "".join(hosts) +
            '<runstats><finished exit="success"/></runstats></nmaprun>').encode()


class ScannerTests(unittest.TestCase):
    def test_profiles_and_port_validation(self):
        self.assertEqual(scanner.parse_ports("022, 443, 8000 - 8005"), "22,443,8000-8005")
        for value in ("0", "65536", "81-80", "80,", "http", "80 81"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner.parse_ports(value)
        self.assertEqual(scanner.parse_network("192.0.2.10/24"), "192.0.2.0/24")
        with self.assertRaises(ValueError):
            scanner.parse_network("2001:db8::/64")

        basic, _ = scanner.scan_args("1", "", False, False)
        explicit, _ = scanner.scan_args("1", "443", True, True)
        self.assertIn("-F", basic)
        self.assertNotIn("-sV", basic)
        self.assertEqual(explicit[-4:], ["-p", "443", "-sV", "-O"])

    def test_parse_report_and_classify_without_vendor_override(self):
        run = scanner.parse_nmap(nmap_xml(HOST_XML))
        self.assertFalse(run.error)
        host, = scanner.collect_results([scanner.Host("192.0.2.10")], run)
        self.assertEqual(host.device_type, "Windows host")
        self.assertEqual(host.vendor, "HP Inc.")
        self.assertEqual([port.port for port in host.ports], [445, 3389])
        self.assertEqual(host.ports[0].version, "3")

        host.ports.extend([scanner.Port(9100), scanner.Port(631)])
        device, evidence = scanner.classify_device(host)
        self.assertEqual(device, "Unknown")
        self.assertEqual(len(evidence), 2)

    def test_batch_timeout_keeps_completed_hosts_and_discovery_metadata(self):
        cutoff = ("<nmaprun>" + HOST_XML + "<host>").encode()
        timed_out = subprocess.TimeoutExpired("nmap", 60, output=cutoff)
        with patch.object(scanner.subprocess, "run", side_effect=timed_out):
            run = scanner.run_nmap("nmap", [], ["192.0.2.10", "192.0.2.11"], 60)
        targets = [
            scanner.Host("192.0.2.10"),
            scanner.Host("192.0.2.11", mac="00:11:22:33:44:66", vendor="Vendor"),
        ]
        first, second = scanner.collect_results(targets, run)
        self.assertEqual(first.status, "partial")
        self.assertEqual(first.ports[0].service, "microsoft-ds")
        self.assertEqual(second.status, "timeout")
        self.assertEqual(second.vendor, "Vendor")

    def test_group_failures_keep_other_batches(self):
        second = HOST_XML.replace("192.0.2.10", "192.0.2.11")
        discovery = scanner.parse_nmap(nmap_xml(
            HOST_XML, second, HOST_XML.replace("192.0.2.10", "192.0.2.12"),
            HOST_XML.replace("192.0.2.10", "198.51.100.8"),
        ))
        first_batch = scanner.parse_nmap(nmap_xml(HOST_XML, second))
        with patch.object(scanner, "run_nmap", side_effect=[
            discovery, first_batch, scanner.ScanRun(error="Nmap завершился с ошибкой"),
        ]) as run:
            results, discovery_failed = scanner.scan_network("nmap", "192.0.2.0/24", 2, [], 60)
        self.assertFalse(discovery_failed)
        self.assertEqual([host.status for host in results], ["ok", "ok", "error"])
        self.assertEqual(
            [call.args[2] for call in run.call_args_list],
            [["192.0.2.0/24"], ["192.0.2.10", "192.0.2.11"], ["192.0.2.12"]],
        )

    def test_native_timeout_and_failed_discovery_are_distinct(self):
        xml = HOST_XML.replace("<host>", '<host timedout="true">')
        host = scanner.parse_nmap(nmap_xml(xml)).hosts["192.0.2.10"]
        self.assertEqual(host.status, "timeout")
        finished = b'<nmaprun><runstats><finished exit="error" errormsg="permission denied"/></runstats></nmaprun>'
        error = scanner.parse_nmap(finished)
        self.assertEqual(error.error, "permission denied")
        with patch.object(scanner, "run_nmap", return_value=error) as run:
            results, discovery_failed = scanner.scan_network("nmap", "192.0.2.0/24", 32, [], 60)
        self.assertTrue(discovery_failed)
        self.assertEqual(results, [])
        run.assert_called_once()

    def test_reports_include_services_and_escape_html(self):
        item = scanner.Host(
            "192.0.2.10", hostname="<lab & office>",
            ports=[scanner.Port(443, "https", "Web server", "2.0")],
        )
        empty = scanner.Host("192.0.2.11", status="timeout")
        with TemporaryDirectory() as directory:
            stem = Path(directory) / "scan_results"
            exported = scanner.export_results([item, empty], "html", stem)
            content = exported.read_text(encoding="utf-8")
            self.assertIn("&lt;lab &amp; office&gt;", content)
            self.assertIn("<td>2.0</td>", content)

            exported = scanner.export_results([item, empty], "json", stem)
            data = json.loads(exported.read_text(encoding="utf-8"))
            self.assertEqual(data[0]["ports"][0]["port"], 443)
            self.assertEqual(data[1]["status"], "timeout")

            exported = scanner.export_results([item, empty], "csv", stem)
            with exported.open(encoding="utf-8-sig", newline="") as stream:
                first, second = csv.DictReader(stream)
            self.assertEqual(first["TCP Port"], "443")
            self.assertEqual(first["Service"], "https")
            self.assertEqual(second["TCP Port"], "")


if __name__ == "__main__":
    unittest.main()
