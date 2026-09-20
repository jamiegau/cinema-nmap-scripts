"""Real Nmap against a localhost SOAP simulator; no cinema network access.

Fixtures follow the SystemInformation/SessionManagement WSDL in Catcher.
Includes the MD software title captured in the repository's IMS2000 example;
other firmware-specific aliases are synthetic. Hardware versions and unknown
package versions must never be SM. No live player verification is implied.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import threading
import unittest
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
API = 'http://www.doremilabs.com/dc/dcp/ws/v1_0'
SYS = 'http://www.doremilabs.com/dc/dcp/ws/v1/schemas/systeminformation'


def envelope(operation, body):
    return f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:d="{API}" xmlns:other="{SYS}"><soap:Body><d:{operation}Response>{body}</d:{operation}Response></soap:Body></soap:Envelope>'


def part(title, version):
    return f'<other:softwarePart><other:title>{escape(title)}</other:title><other:type>Firmware</other:type><other:vendor>Dolby</other:vendor><other:version>{escape(version)}</other:version></other:softwarePart>'


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        # Nmap's preliminary connect scan closes without an HTTP request.
        try:
            super().handle()
        except ConnectionResetError:
            pass

    def log_message(self, *_):
        pass

    def do_POST(self):
        case = self.server.case
        try:
            request = ET.fromstring(self.rfile.read(int(self.headers['Content-Length'])))
            operation = request.find(f'{{{SOAP}}}Body')[0]
            name = operation.tag.split('}')[-1]
            case.calls.append(name)
            if name == 'Login':
                case.assertEqual(operation.findtext('username'), case.username)
                case.assertEqual(operation.findtext('password'), case.password)
            else:
                case.assertEqual(operation.findtext('sessionId'), 'fixture-session')
            service = 'SessionManagement' if name in ('Login', 'Logout') else 'SystemInformation'
            case.assertEqual(self.path, f'/dc/dcp/ws/v1/{service}')
            status, body = case.responses[name]
            self.send_response(status)
            if status == 302:
                self.send_header('Location', 'http://127.0.0.1:1/do-not-follow')
            self.send_header('Content-Type', 'text/xml')
            self.send_header('Content-Length', str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            case.errors.append(exc)


class DolbyPlayerTests(unittest.TestCase):
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
        self.username, self.password = 'manager', 'password'
        self.product = '<productInformation><other:productName>IMS2000</other:productName><other:serialNumber>TEST-123</other:serialNumber><other:mainSoftwareVersion>2.8.52</other:mainSoftwareVersion><other:mainFirmwareVersion>4.6.12</other:mainFirmwareVersion><other:bundleVersion>bundle-test</other:bundleVersion></productInformation>'
        self.responses = {
            'Login': (200, envelope('Login', '<sessionId>fixture-session</sessionId>')),
            'Logout': (200, envelope('Logout', '')),
            'GetProductInformation': (200, envelope('GetProductInformation', self.product)),
            'GetSoftwareInventoryList': (200, envelope('GetSoftwareInventoryList', '<softwarePartList>' + part('Security Manager', '6.2.1') + part('Unrelated library', '99.1') + '</softwarePartList>')),
            'GetHardwareInventoryList': (200, envelope('GetHardwareInventoryList', '<hardwarePartList><other:hardwarePart><other:title>Media block</other:title><other:vendor>Component vendor</other:vendor><other:version>BOARD-99</other:version></other:hardwarePart></hardwarePartList>')),
            'GetHostname': (200, envelope('GetHostname', '<hostname>test-player</hostname><screenName>Screen 1</screenName>')),
            'GetCertificateList': (200, envelope('GetCertificateList', '<certificateList><other:certificate><other:title>Test</other:title><other:cert>test certificate</other:cert></other:certificate></certificateList>')),
        }

    def discover(self, extra_args=''):
        port = self.server.server_port
        result = subprocess.run([
            'nmap', '-n', '-Pn', '-sT', f'-p{port}', '--script',
            str(ROOT / 'cinema-dolby-player.nse'), '--script-args',
            f'cinema-dolby-player.soap-port={port}' + extra_args, '-oX', '-', '127.0.0.1',
        ], text=True, capture_output=True, timeout=20, check=True)
        self.assertFalse(self.errors, self.errors)
        self.assertNotIn('ERROR', result.stdout + result.stderr)
        self.script = ET.fromstring(result.stdout).find('.//script[@id="cinema-dolby-player"]')
        return {} if self.script is None else {e.attrib['key']: e.text for e in self.script.findall('elem')}

    def set_software(self, contents):
        self.responses['GetSoftwareInventoryList'] = (200, envelope('GetSoftwareInventoryList', '<softwarePartList>' + contents + '</softwarePartList>'))

    def test_three_labelled_versions_and_first_inventory_entry(self):
        out = self.discover()
        self.assertEqual(out['version'], 'Software: 2.8.52; Firmware: 4.6.12; SM: 6.2.1')
        self.assertEqual(out['mainSoftwareVersion'], '2.8.52')
        self.assertEqual(out['mainFirmwareVersion'], '4.6.12')
        self.assertEqual(out['securityManagerVersion'], '6.2.1')
        self.assertEqual(out['vendor'], 'Dolby')
        self.assertEqual(out['bundleVersion'], 'bundle-test')
        self.assertEqual(self.script.find('./table[@key="SoftwareInfo"]/table/elem[@key="title"]').text, 'Security Manager')
        self.assertEqual(self.calls[-1], 'Logout')
        self.assertEqual(len(self.calls), 6)

    def test_sm_titles_and_inventory_order(self):
        for label in ('SM', 'SecurityManager', 'SM Firmware', 'Dolby Security Manager', 'Security Manager (SM)'):
            with self.subTest(label=label):
                self.set_software(part('Other library', 'bad') + part(label, '6.2.1'))
                self.assertEqual(self.discover()['securityManagerVersion'], '6.2.1')

    def test_missing_or_unknown_sm_is_not_guessed(self):
        for inventory in ('', part('Unrelated firmware', '4.6.12'), part('SM', 'unknown'), part('SM', '')):
            self.set_software(inventory)
            self.assertEqual(self.discover()['securityManagerVersion'], 'Not reported')

    def test_captured_ims2000_md_software_is_sm_not_md_firmware(self):
        self.set_software(part('MD firmware', '4.6.10-0') + part('MD software', '6.1.135-0') + part('BIOS', 'unrelated'))
        out = self.discover()
        self.assertEqual(out['securityManagerVersion'], '6.1.135-0')
        self.assertEqual(out['mainFirmwareVersion'], '4.6.12')

    def test_conflicting_sm_versions_are_not_selected(self):
        self.set_software(part('SM', '6.2.1') + part('Security Manager', '6.1.0'))
        self.assertEqual(self.discover()['securityManagerVersion'], 'Not reported')

    def test_matching_sm_duplicates_are_accepted(self):
        self.set_software(part('SM', '6.2.1') + part('Security Manager', '6.2.1'))
        self.assertEqual(self.discover()['securityManagerVersion'], '6.2.1')

    def test_inventory_failure_preserves_product_identity(self):
        self.responses['GetSoftwareInventoryList'] = (500, '')
        out = self.discover()
        self.assertEqual(out['productName'], 'IMS2000')
        self.assertEqual(out['securityManagerVersion'], 'Not reported')
        self.assertEqual(out['mainFirmwareVersion'], '4.6.12')
        self.assertEqual(self.calls[-1], 'Logout')

    def test_missing_main_firmware_is_explicit(self):
        self.responses['GetProductInformation'] = (200, envelope('GetProductInformation', self.product.replace('<other:mainFirmwareVersion>4.6.12</other:mainFirmwareVersion>', '')))
        self.assertEqual(self.discover()['mainFirmwareVersion'], 'Not reported')

    def test_prefix_change_and_entities(self):
        self.responses['GetProductInformation'] = (200, envelope('GetProductInformation', self.product).replace('other:', 'different:').replace('xmlns:other=', 'xmlns:different=').replace('TEST-123', 'TEST&amp;123'))
        self.assertEqual(self.discover()['serialNumber'], 'TEST&123')

    def test_truncated_faulted_and_oversized_product_response(self):
        for status, body in ((200, '<s:Envelope'), (200, '<!DOCTYPE x>' + envelope('GetProductInformation', self.product)), (200, envelope('Fault', '')), (200, 'x'*270000), (302, 'redirect')):
            self.responses['GetProductInformation'] = status, body
            self.assertEqual(self.discover(), {})
            self.assertEqual(self.calls[-1], 'Logout')

    def test_failed_or_empty_login_stops_without_queries(self):
        for status, body in ((403, ''), (200, envelope('Login', '<sessionId/>'))):
            self.calls.clear()
            self.responses['Login'] = status, body
            self.assertEqual(self.discover(), {})
            self.assertEqual(self.calls, ['Login'])

    def test_credentials_are_xml_escaped(self):
        self.username, self.password = 'manager&test', 'p<&test'
        out = self.discover(',cinema-dolby-player.username=manager&test,cinema-dolby-player.password=p<&test')
        self.assertEqual(out['productName'], 'IMS2000')

    def test_legacy_credentials_and_opt_in_certificates(self):
        self.username, self.password = 'custom', 'secret'
        self.discover(',username=custom,password=secret,getcerts=true')
        self.assertIn('GetCertificateList', self.calls)
        self.assertEqual(self.script.find('./table[@key="CertInfo"]/table/elem[@key="cert"]').text, 'test certificate')


if __name__ == '__main__':
    unittest.main(verbosity=2)
