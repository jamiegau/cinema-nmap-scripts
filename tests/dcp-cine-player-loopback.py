"""Real Nmap/HTTP discovery tests against a local simulator; no player hardware."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading
import unittest
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PATH = '/api/player/v1/discovery'


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass  # Nmap's TCP port probe closes without sending an HTTP request.

    def log_message(self, *_):
        pass

    def do_GET(self):
        case = self.server.case
        case.calls.append((self.command, self.path))
        try:
            case.assertEqual(self.path, PATH, 'Only the anonymous discovery endpoint is probed')
            case.assertIsNone(self.headers.get('Authorization'))
            case.assertIsNone(self.headers.get('Cookie'))
            case.assertEqual(self.headers.get('Accept'), 'application/json')
            body = case.body if case.body is not None else json.dumps(case.identity)
            self.send_response(case.status)
            self.send_header('Content-Type', case.content_type)
            self.send_header('Content-Length', str(len(body.encode())))
            self.send_header('Cache-Control', 'no-store')
            if case.status == 302:
                self.send_header('Location', '/must-not-follow')
            self.end_headers()
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected for a bounded oversized response.
        except Exception as exc:
            case.errors.append(exc)


class DiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
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
        self.body, self.status, self.content_type = None, 200, 'application/json; charset=utf-8'
        self.identity = {
            'schema': 'd-cine.player-api.discovery.v1', 'product': 'dcp-cine-player', 'version': '4.2.20',
            'device_id': 'urn:uuid:c81d38db-8d1b-4db6-afa2-2e7ee6f2118e', 'serial_number': 'PRODUCT-123',
            'recipient_certificate': {'certificate_serial_number': 'CERT-456',
                'fingerprint_sha256': 'a' * 64,
                'not_before_utc': '2026-09-02T08:20:38Z', 'not_after_utc': '2036-07-02T00:14:11Z',
                'pem': '-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----\n'},
            'endpoints': {'device_info': '/api/player/v1/device-info'}, 'warnings': [],
        }

    def discover(self, getcerts=False):
        args = f'cinema-dcp-cine-player.port={self.server.server_port}'
        if getcerts:
            args += ',cinema-dcp-cine-player.getcerts=true'
        result = subprocess.run([
            'nmap', '-n', '-Pn', '-sT', f'-p{self.server.server_port}', '--script',
            str(ROOT / 'cinema-dcp-cine-player.nse'), '--script-args', args, '-oX', '-', '127.0.0.1',
        ], capture_output=True, text=True, timeout=15, check=True)
        self.assertFalse(self.errors, self.errors)
        self.assertNotIn('ERROR', result.stdout + result.stderr)
        xml = ET.fromstring(result.stdout)
        script = xml.find(".//script[@id='cinema-dcp-cine-player']")
        output = {} if script is None else {e.attrib['key']: e.text for e in script.findall('elem')}
        self.assertEqual(self.calls, [('GET', PATH)], 'One anonymous GET per discovery attempt')
        return output, script

    def test_registered_identity(self):
        out, script = self.discover()
        self.assertEqual(out['classification'], 'dci-player')
        self.assertEqual(out['vendor'], 'D-Cine')
        self.assertEqual(out['productName'], 'dcp-cine-player')
        self.assertEqual(out['version'], '4.2.20')
        self.assertEqual(out['mainSoftwareVersion'], '4.2.20')
        self.assertEqual(out['serialNumber'], 'PRODUCT-123')
        self.assertEqual(out['deviceId'], self.identity['device_id'])
        self.assertEqual(out['recipientCertificateSerialNumber'], 'CERT-456')
        self.assertIsNone(script.find("table[@key='CertInfo']"))

    def test_demo_null_identity_and_certificate(self):
        self.identity.update(serial_number=None, device_id=None, recipient_certificate=None)
        out, _ = self.discover()
        self.assertEqual(out['productName'], 'dcp-cine-player')
        self.assertNotIn('serialNumber', out)
        self.assertNotIn('deviceId', out)
        self.assertNotIn('recipientCertificateSerialNumber', out)

    def test_demo_certificate_serial_is_not_product_serial(self):
        self.identity['serial_number'] = None
        out, _ = self.discover()
        self.assertNotIn('serialNumber', out)
        self.assertEqual(out['recipientCertificateSerialNumber'], 'CERT-456')

    def test_opt_in_certificate_and_no_extra_requests(self):
        out, script = self.discover(getcerts=True)
        pem = script.find("table[@key='CertInfo']/table/elem[@key='cert']")
        self.assertEqual(pem.text, self.identity['recipient_certificate']['pem'])

    def test_private_key_and_multiple_certificates_are_not_exported(self):
        for suffix in ('-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n',
                       self.identity['recipient_certificate']['pem']):
            with self.subTest(suffix=suffix[:25]):
                self.calls.clear()
                original = copy.deepcopy(self.identity)
                self.identity['recipient_certificate']['pem'] += suffix
                _, script = self.discover(getcerts=True)
                self.assertIsNone(script.find("table[@key='CertInfo']"))
                self.identity = original

    def test_wrong_schema_product_or_json_shape(self):
        for body in ('{}', '[]', 'null', '{"product":"dcp-cine-player","schema":"wrong"}',
                     '{"product":"other","schema":"d-cine.player-api.discovery.v1"}', '{bad json'):
            with self.subTest(body=body):
                self.calls.clear()
                self.body = body
                self.assertEqual(self.discover()[0], {})

    def test_failure_and_redirect_are_not_followed(self):
        for status in (302, 401, 404, 503):
            with self.subTest(status=status):
                self.calls.clear()
                self.status = status
                self.assertEqual(self.discover()[0], {})

    def test_html_and_oversized_response_are_not_detected(self):
        self.content_type = 'text/html'
        self.assertEqual(self.discover()[0], {})
        self.calls.clear()
        self.content_type = 'application/json'
        self.body = json.dumps({**self.identity, 'untrusted_extra': 'x' * 140000})
        self.assertEqual(self.discover()[0], {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
