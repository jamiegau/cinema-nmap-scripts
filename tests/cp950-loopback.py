"""Real Nmap/HTTP/XML tests with synthetic Dolby SOAP responses; no hardware.

Run: python3 tests/cp950-loopback.py
Only scans an OS-assigned port owned by this fixture on 127.0.0.1.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import threading
import unittest
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
BASE = "http://www.dolby.com/cp/ws/smi/"
PATH = "/cp/ws/smi/v1/services/SystemManagement"
OPS = {"getDeviceInfo": "v1_0", "getSerialNumber": "v1_1", "getSystemVersions": "v1_1"}


def pair(key, value):
    return f"<keyValuePair><key>{escape(key)}</key><value>{escape(value)}</value></keyValuePair>"


def envelope(op, payload, prefix="d"):
    return (f'<s:Envelope xmlns:s="{SOAP}" xmlns:{prefix}="{BASE}{OPS[op]}">'
            f'<s:Body><{prefix}:{op}Response>{payload}</{prefix}:{op}Response>'
            '</s:Body></s:Envelope>')


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass  # Nmap's initial TCP connect scan closes without an HTTP request.

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            root = ET.fromstring(raw)
            self.server.case.assertEqual(root.tag, f"{{{SOAP}}}Envelope")
            body = root.find(f"{{{SOAP}}}Body")
            self.server.case.assertEqual(len(body), 1)
            request = body[0]
            op = request.tag.split("}", 1)[-1].removesuffix("Request")
            self.server.case.assertIn(op, OPS, "read-only operation allowlist")
            self.server.case.assertEqual(request.tag, f"{{{BASE}{OPS[op]}}}{op}Request")
            self.server.case.assertEqual(len(request), 0)
            self.server.case.assertEqual(self.path, PATH)
            self.server.case.assertEqual(self.headers.get("SOAPAction"), f'"{BASE}v1/{op}"')
            self.server.case.assertIsNone(self.headers.get("Authorization"))
            self.server.case.calls.append(op)
            status, reply = self.server.case.responses[op]
            self.send_response(status)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(reply.encode())))
            if status == 302:
                self.send_header("Location", "http://127.0.0.1:1/do-not-follow")
            self.end_headers()
            self.wfile.write(reply.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected when Nmap enforces its body-size cap.
        except Exception as exc:
            self.server.case.errors.append(exc)


class DiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.case = self
        self.calls, self.errors = [], []
        self.responses = {
            "getDeviceInfo": (200, envelope("getDeviceInfo", pair("Product Name", "CP950"))),
            "getSerialNumber": (200, envelope("getSerialNumber", "<serialNumber>TEST-123</serialNumber>")),
            "getSystemVersions": (200, envelope("getSystemVersions", pair("Main Software Version", "2.2.0.13"))),
        }

    def discover(self):
        port = self.server.server_port
        result = subprocess.run([
            "nmap", "-n", "-Pn", "-sT", f"-p{port}", "--script",
            str(ROOT / "cinema-dolby-cp950.nse"), "--script-args",
            f"cinema-dolby-cp950.soap-port={port}", "-oX", "-", "127.0.0.1",
        ], capture_output=True, text=True, timeout=20, check=True)
        self.assertFalse(self.errors, self.errors)
        self.assertNotIn("ERROR", result.stdout + result.stderr)
        xml = ET.fromstring(result.stdout)
        return {e.attrib["key"]: e.text for e in xml.findall(
            ".//script[@id='cinema-dolby-cp950']/elem")}

    def test_cp950_complete_identity(self):
        self.assertEqual(self.discover(), dict(classification="sound-processor", vendor="Dolby",
            productName="CP950", serialNumber="TEST-123", version="2.2.0.13"))
        self.assertEqual(self.calls, list(OPS))

    def test_cp950a_inline_metadata(self):
        payload = pair("Model Name", "CP950A") + pair("Chassis Serial Number", "CHASSIS-1")
        payload += pair("Main Software Version", "2.4.0.1") + pair("CAT1710 Serial Number", "NOT-CHASSIS")
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", payload))
        out = self.discover()
        self.assertEqual(out["productName"], "CP950A")
        self.assertEqual(out["serialNumber"], "CHASSIS-1")
        self.assertEqual(out["version"], "2.4.0.1")
        self.assertEqual(self.calls, ["getDeviceInfo"])

    def test_namespace_prefix_is_not_fixed(self):
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", pair("productName", "Dolby CP950A"), "other"))
        self.assertEqual(self.discover()["productName"], "CP950A")

    def test_entities_and_cdata(self):
        payload = '<keyValuePair><key>Model</key><value><![CDATA[CP950A]]></value></keyValuePair>'
        payload += pair("Chassis Serial Number", "TEST&123")
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", payload))
        self.assertEqual(self.discover()["serialNumber"], "TEST&123")

    def test_other_models_not_misidentified(self):
        for model in ["CP850", "CP750", "CP9500", "CP950/CP950A", "Unknown"]:
            with self.subTest(model=model):
                self.calls.clear()
                self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", pair("Product Name", model)))
                self.assertEqual(self.discover(), {})
                self.assertEqual(self.calls, ["getDeviceInfo"])

    def test_model_in_arbitrary_text_not_identity(self):
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", pair("Hostname", "CP950")))
        self.assertEqual(self.discover(), {})

    def test_conflicting_model_keys(self):
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", pair("Product Name", "CP950") + pair("Model", "CP950A")))
        self.assertEqual(self.discover(), {})

    def test_conflicting_duplicate_keys_stay_rejected(self):
        payload = pair("Model", "CP950") + pair("Model", "CP950A") + pair("Model", "CP950")
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", payload))
        self.assertEqual(self.discover(), {})

    def test_unauthorized_redirect_and_http_failures(self):
        for status in [401, 403, 302, 404, 500]:
            with self.subTest(status=status):
                self.calls.clear()
                _, body = self.responses["getDeviceInfo"]
                self.responses["getDeviceInfo"] = (status, body)
                self.assertEqual(self.discover(), {})
                self.assertEqual(self.calls, ["getDeviceInfo"])

    def test_optional_fields_missing_or_faulted(self):
        self.responses["getSerialNumber"] = (500, "fault")
        self.responses["getSystemVersions"] = (200, envelope("getSystemVersions", pair("CAT1710 Version", "4.0")))
        out = self.discover()
        self.assertEqual(out["productName"], "CP950")
        self.assertNotIn("serialNumber", out)
        self.assertNotIn("version", out)

    def test_board_serial_never_replaces_chassis(self):
        payload = pair("Model", "CP950A") + pair("CAT1700 Serial Number", "BOARD-1")
        self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", payload))
        self.responses["getSerialNumber"] = (200, envelope("getSerialNumber", "<serialNumber>Unknown</serialNumber>"))
        self.assertNotIn("serialNumber", self.discover())

    def test_fault_namespace_and_wrong_operation_rejected(self):
        for body in [
            '<s:Envelope xmlns:s="'+SOAP+'"><s:Body><s:Fault>CP950</s:Fault></s:Body></s:Envelope>',
            envelope("getDeviceInfo", pair("Model", "CP950")).replace(BASE, "http://other/"),
            envelope("getSystemVersions", pair("Model", "CP950")),
            '<html><title>Dolby CP950</title></html>',
        ]:
            with self.subTest(body=body):
                self.responses["getDeviceInfo"] = (200, body)
                self.assertEqual(self.discover(), {})

    def test_malformed_truncated_and_dtd_rejected(self):
        valid = envelope("getDeviceInfo", pair("Model", "CP950"))
        for body in [valid[:-13], valid.replace('</value>', '</wrong>'), '<!DOCTYPE x>'+valid,
                     valid+valid, valid.replace('<key>', '<key><nested>')]:
            with self.subTest(body=body):
                self.responses["getDeviceInfo"] = (200, body)
                self.assertEqual(self.discover(), {})

    def test_oversized_and_deep_xml_rejected(self):
        for payload in ["x"*33000, '<x>'*20+pair("Model", "CP950")+'</x>'*20]:
            self.responses["getDeviceInfo"] = (200, envelope("getDeviceInfo", payload))
            self.assertEqual(self.discover(), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
