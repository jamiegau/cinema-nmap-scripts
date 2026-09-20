"""Optional real-Nmap transport test, using ONLY a locally owned TCP fixture.

Run: python3 tests/christie-loopback.py
Uses an OS-assigned local TCP port; does not contact cinema equipment.
These are synthetic fixtures, not captured Christie hardware responses.
"""
import pathlib
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPLIES = {
    b"(PNG?)": b"(PNG!71 001 000 001)",
    b"(SST+SERI?)": (
        b'(SST+SERI!000 001 "IMB-999" "IMB Serial Number")'
        b'(SST+SERI!001 001 "TEST-123" "Projector S/N")'
        b'(SST+SERI!"---END---")'
    ),
    b"(SST+SYST?)": (
        b'(SST+SYST!000 001 "CP4420-RGB" "Projector Model")'
        b'(SST+SYST!"---END---")'
    ),
}
requests = []
errors = []
stop = threading.Event()


def serve(listener):
    try:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(5)
                pending = b""
                while True:
                    try:
                        data = conn.recv(4096)
                    except ConnectionResetError:
                        break  # A connect scan can close with RST rather than FIN.
                    if not data:
                        break  # Nmap's initial connect scan has no payload.
                    pending += data
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        command = line.strip()
                        requests.append(command)
                        assert command in REPLIES, f"Unexpected command: {command!r}"
                        response = REPLIES[command]
                        conn.sendall(response[:5])
                        conn.sendall(response[5:] + b"\r\n")
    except Exception as exc:
        errors.append(exc)


with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen()
    listener.settimeout(0.2)
    thread = threading.Thread(target=serve, args=(listener,), daemon=True)
    thread.start()
    try:
        result = subprocess.run([
            "nmap", "-n", "-Pn", "-sT", f"-p{port}", "--script",
            str(ROOT / "cinema-christie-projector.nse"), "--script-args",
            f"cinema-christie-projector.port={port}", "-oX", "-", "127.0.0.1",
        ], text=True, capture_output=True, timeout=20, check=True)
    finally:
        stop.set()
        thread.join(timeout=6)
    assert not thread.is_alive(), "Fixture server failed to stop"
    assert not errors, errors
    document = ET.fromstring(result.stdout)
    fields = {e.attrib["key"]: e.text for e in document.findall(
        ".//script[@id='cinema-christie-projector']/elem")}
    assert fields.get("vendor") == "Christie", (fields, result.stderr)
    assert fields.get("classification") == "dci-projector", fields
    assert fields.get("productName") == "CP4420-RGB", fields
    assert fields.get("serialNumber") == "TEST-123", fields
    assert fields.get("version") == "1.0.1", fields
    assert requests == list(REPLIES), requests
    print("PASS: real Nmap -> loopback TCP fixture -> Catcher-compatible XML fields")
