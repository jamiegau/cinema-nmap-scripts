"""Real Nmap against localhost only; never contacts cinema equipment.

Response fields captured from a Senior 1.1.3 read-only PowerShell query.
TCP fragmentation and error variants below are simulated, not hardware tests.
"""
import pathlib
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPLY = (b"Version 1.1.3\r\nIP Adr 010.120.246.031\r\n"
         b"Subnet 255.255.255.000\r\nRouter 010.120.246.254\r\ncommand.ack\r\n")


def run_case(name, direct=True, response=REPLY, expected=True):
    connections, commands, errors = [], [], []
    stop = threading.Event()

    def serve(listener):
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                connections.append(True)
                with conn:
                    conn.settimeout(5)
                    data = b""
                    while b"\n" not in data:
                        try:
                            chunk = conn.recv(4096)
                        except ConnectionResetError:
                            break  # The -sT port scan opens then closes.
                        if not chunk:
                            break
                        data += chunk
                    if not data:
                        continue
                    commands.append(data)
                    assert data == b"get.ip\n", data
                    if response:
                        for part in (response[:3], response[3:50], response[50:]):
                            conn.sendall(part)
                            time.sleep(0.03)
                    # Script must close after ack or bounded timeout, with no
                    # second query or configuration command on this connection.
                    assert conn.recv(4096) == b"", "Unexpected extra query"
        except Exception as exc:
            errors.append(exc)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.listen()
        listener.settimeout(0.1)
        thread = threading.Thread(target=serve, args=(listener,), daemon=True)
        thread.start()
        arguments = ["nmap", "-n", "-Pn", "--disable-arp-ping"]
        arguments += ["-sn"] if direct else ["-sT", f"-p{port}"]
        script_args = f"cinema-edge-senior-io.port={port}"
        if direct:
            script_args += ",cinema-edge-senior-io.direct=true"
        try:
            result = subprocess.run(arguments + [
                "--script", str(ROOT / "cinema-edge-senior-io.nse"),
                "--script-args", script_args, "-oX", "-", "127.0.0.1",
            ], text=True, capture_output=True, timeout=15, check=True)
        finally:
            stop.set()
            thread.join(timeout=6)
        assert not thread.is_alive(), "Fixture server failed to stop"
        assert not errors, errors
        document = ET.fromstring(result.stdout)
        fields = {e.attrib["key"]: e.text for e in document.findall(
            ".//script[@id='cinema-edge-senior-io']/elem")}
        if expected:
            assert fields == dict(classification="automation-io", vendor="Edge",
                                  productName="Senior-IO", version="1.1.3"), fields
            path = ".//hostscript/script" if direct else ".//port/script"
            assert document.find(path) is not None
        else:
            assert not fields, fields
        assert commands == [b"get.ip\n"], commands
        assert len(connections) == (1 if direct else 2), connections
        if direct:
            assert document.find("scaninfo") is None, "Unexpected port scan"
        print(f"PASS: {name}")


run_case("direct mode: one connection, one query, fragmented captured response")
run_case("port mode: one query after port scan", direct=False)
run_case("invalid identity rejected", response=REPLY.replace(b"IP Adr", b"OtherX"), expected=False)
run_case("silent device times out and closes without retry", response=None, expected=False)
print("4 Senior real-Nmap loopback tests passed")
