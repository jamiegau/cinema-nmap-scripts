"""Real Nmap against a local TLS SMS simulator using the bundled Barco 1.11 WSDL.

Synthetic product data, not a capture or claim of hardware validation. Each
HTTP handler owns the login state so a reconnect per SOAP call cannot pass.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
SOAP = 'http://www.w3.org/2003/05/soap-envelope'
API = 'http://www.barco.com/sms/sms_1'


def envelope(operation, contents='', code=0):
    return f'<env:Envelope xmlns:env="{SOAP}"><env:Body><{operation}Response xmlns="{API}"><{operation}Result>{code}</{operation}Result>{contents}</{operation}Response></env:Body></env:Envelope>'


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(2)
        try:
            tls = self.context.wrap_socket(sock, server_side=True)
        except Exception:
            sock.close()
            raise
        self.case.connections += 1
        return tls, addr


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def handle(self):
        self.logged_in = False
        try:
            super().handle()
        except (ConnectionResetError, ssl.SSLError):
            pass

    def do_POST(self):
        case = self.server.case
        try:
            root = ET.fromstring(self.rfile.read(int(self.headers['Content-Length'])))
            operation = root.find(f'{{{SOAP}}}Body')[0]
            name = operation.tag.removeprefix(f'{{{API}}}')
            case.assertIn(name, ('Login', 'GetProductInformation', 'Logout'))
            case.assertEqual(self.path, '/')
            case.assertIn('application/soap+xml', self.headers['Content-Type'])
            case.assertIn(f'action="{API}/{name}"', self.headers['Content-Type'])
            case.calls.append(name)
            if name == 'Login':
                case.assertEqual(operation.findtext(f'{{{API}}}userName'), case.username)
                case.assertEqual(operation.findtext(f'{{{API}}}password'), case.password)
                case.assertIsNotNone(operation.find(f'{{{API}}}sessionInfo'))
                self.logged_in = True
            else:
                case.assertTrue(self.logged_in, 'Login must be on this TLS connection')
                case.assertEqual(len(operation), 0)
            status, body = case.responses[name]
            if name == 'GetProductInformation' and case.raw_response:
                self.wfile.write(case.raw_response)
                self.close_connection = True
                return
            self.send_response(status)
            self.send_header('Content-Type', 'application/soap+xml')
            if status == 302:
                self.send_header('Location', 'https://127.0.0.1:1/do-not-follow')
            data = body.encode()
            if case.chunked:
                self.send_header('Transfer-Encoding', 'chunked')
            else:
                self.send_header('Content-Length', str(len(data)))
            if name == 'Login' and case.close_after_login:
                self.send_header('Connection', 'close')
                self.close_connection = True
            self.end_headers()
            if case.chunked:
                for offset in range(0, len(data), 29):
                    chunk = data[offset:offset+29]
                    self.wfile.write(f'{len(chunk):x};fixture=yes\r\n'.encode() + chunk + b'\r\n')
                self.wfile.write(b'0\r\nX-Fixture: done\r\n\r\n')
            else:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        except Exception as exc:
            case.errors.append(exc)
            self.close_connection = True


class BarcoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='barco-nmap-test-')
        cert, key = Path(cls.temp.name)/'cert.pem', Path(cls.temp.name)/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost'], check=True, capture_output=True)
        cls.server = Server(('127.0.0.1', 0), Handler)
        cls.server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server.context.load_cert_chain(cert, key)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def setUp(self):
        self.server.case = self
        self.calls, self.errors, self.connections = [], [], 0
        self.chunked = self.close_after_login = False
        self.raw_response = None
        self.username, self.password = 'Monitor', 'Monitor1234'
        self.responses = {'Login': (200, envelope('Login')), 'Logout': (200, envelope('Logout'))}
        self.product()

    def product(self, name='ICMP', model='R-test', version='1.2.3', serial='TEST-123', extra=''):
        fields = dict(ProductName=name, Model=model, Version=version, SerialNumber=serial,
                      Hostname='cinema-one', ProjectorModel='SP2K-9S', ProjectorHostname='projector-one')
        data = ''.join(f'<{key}>{escape(value)}</{key}>' for key, value in fields.items())
        self.responses['GetProductInformation'] = 200, envelope('GetProductInformation', f'<productInfo>{data}{extra}</productInfo>')

    def discover(self, args=''):
        port = self.server.server_port
        result = subprocess.run(['nmap', '-n', '-Pn', '-sT', f'-p{port}', '--script',
            str(ROOT/'cinema-barco-player.nse'), '--script-args',
            f'cinema-barco-player.soap-port={port}{args}', '-oX', '-', '127.0.0.1'],
            capture_output=True, text=True, check=True, timeout=45)
        self.assertFalse(self.errors, self.errors)
        self.assertNotIn('ERROR', result.stdout + result.stderr)
        return {e.attrib['key']: e.text for e in ET.fromstring(result.stdout).findall('.//script[@id="cinema-barco-player"]/elem')}

    def test_identity_uses_one_tls_connection_and_three_read_only_calls(self):
        out = self.discover()
        self.assertEqual(out['classification'], 'dci-player')
        self.assertEqual(out['vendor'], 'Barco')
        self.assertEqual(out['productName'], 'ICMP')
        self.assertEqual(out['serialNumber'], 'TEST-123')
        self.assertEqual(out['version'], 'Software: 1.2.3')
        self.assertEqual(out['mainSoftwareVersion'], '1.2.3')
        self.assertEqual(out['projectorModel'], 'SP2K-9S')
        self.assertNotIn('mainFirmwareVersion', out)
        self.assertNotIn('securityManagerVersion', out)
        self.assertEqual(self.calls, ['Login', 'GetProductInformation', 'Logout'])
        self.assertEqual(self.connections, 1)

    def test_chunked_responses_keep_connection(self):
        self.chunked = True
        self.assertEqual(self.discover()['productName'], 'ICMP')
        self.assertEqual(self.connections, 1)

    def test_model_aliases_and_xml_entities(self):
        for name in ('ICMP', 'ICMP-X', 'Barco Alchemy'):
            self.product(name=name, serial='TEST&123')
            self.assertEqual(self.discover()['serialNumber'], 'TEST&123')
        self.product(name='Media server', model='ICMP')
        self.assertEqual(self.discover()['productName'], 'ICMP')

    def test_projector_or_hostname_cannot_prove_player_identity(self):
        for name in ('SP2K-9S', 'Unknown', 'ICMP999', 'Not an ICMP'):
            self.product(name=name, extra='<NewField>ICMP</NewField>')
            self.assertEqual(self.discover(), {})

    def test_unknown_optional_fields_and_missing_versions(self):
        self.product(version='', serial='', extra='<NewField><Nested>future extension</Nested></NewField>')
        out = self.discover()
        self.assertEqual(out['version'], 'Software: Not reported')
        self.assertNotIn('serialNumber', out)
        self.assertNotIn('mainSoftwareVersion', out)

    def test_invalid_login_stops_without_retries(self):
        self.responses['Login'] = 200, envelope('Login', code=10508)
        self.assertEqual(self.discover(), {})
        self.assertEqual(self.calls, ['Login'])
        self.assertEqual(self.connections, 1)

    def test_closed_connection_after_login_does_not_reconnect(self):
        self.close_after_login = True
        self.assertEqual(self.discover(), {})
        self.assertEqual(self.connections, 1)

    def test_product_failure_still_logs_out(self):
        self.responses['GetProductInformation'] = 200, envelope('GetProductInformation', code=10508)
        self.assertEqual(self.discover(), {})
        self.assertEqual(self.calls, ['Login', 'GetProductInformation', 'Logout'])

    def test_credentials_are_namespaced_and_xml_escaped(self):
        self.username, self.password = 'monitor&test', 'test<password'
        self.assertEqual(self.discover(',cinema-barco-player.username=monitor&test,cinema-barco-player.password=test<password')['productName'], 'ICMP')

    def test_malformed_faulted_wrong_namespace_or_oversized_xml_rejected(self):
        valid = self.responses['GetProductInformation'][1]
        for reply in ('<broken', '<!DOCTYPE x>' + valid, valid.replace(API, 'urn:wrong'),
                      envelope('Fault'), 'x'*66000,
                      valid.replace('<ProductName>ICMP</ProductName>', '<ProductName>ICMP</ProductName><ProductName>Alchemy</ProductName>')):
            self.responses['GetProductInformation'] = 200, reply
            self.assertEqual(self.discover(), {})

    def test_redirect_and_http_errors_not_followed(self):
        for status in (302, 401, 403, 500):
            self.responses['Login'] = status, envelope('Login')
            self.assertEqual(self.discover(), {})
        self.assertEqual(self.calls, ['Login']*4)
        self.assertEqual(self.connections, 4)

    def test_bad_http_framing_rejected(self):
        for raw in (b'HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!',
                    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nGG\r\n',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort'):
            self.raw_response = raw
            self.assertEqual(self.discover(), {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
