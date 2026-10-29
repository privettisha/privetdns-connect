"""Self-contained DNS/DoT transport tests: python3 -m unittest -v test_splitdns.py"""
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest

import splitdns

SNI = "a" * 32 + ".dot.privetdns.ru"


def query(name, edns=False):
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split("."))
    opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
    return struct.pack("!HHHHHH", 0x12ab, 0x0100, 1, 0, 0, int(edns)) + labels + b"\0\0\1\0\1" + opt


def answer(q):
    return q[:2] + b"\x81\x80" + q[4:6] + b"\0\0\0\0" + q[10:]


class Datagram(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class Stream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class FakeUDP(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.seen.append(self.request[0])
        self.request[1].sendto(answer(self.request[0]), self.client_address)


class FakeTCP(socketserver.BaseRequestHandler):
    def handle(self):
        length = int.from_bytes(splitdns.exact(self.request, 2), "big")
        q = splitdns.exact(self.request, length)
        self.server.seen.append(q)
        a = answer(q)
        self.request.sendall(struct.pack("!H", len(a)) + a)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificate_dir = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.certificate_dir.name) / "test-cert.pem"
        cls.key = Path(cls.certificate_dir.name) / "test-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                        "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
                        "-subj", "/CN=PrivetDNS test", "-addext", "subjectAltName=DNS:" + SNI],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.certificate_dir.cleanup()

    def setUp(self):
        self.udp = Datagram(("127.0.0.1", 0), FakeUDP)
        self.udp.seen = []
        self.udp_thread = threading.Thread(target=self.udp.serve_forever, daemon=True)
        self.udp_thread.start()
        self.direct = splitdns.Resolver(frozenset({"example.com"}), "127.0.0.1", 1,
                                        SNI, ["127.0.0.1"], self.udp.server_address[1], 0.25)

    def tearDown(self):
        self.udp.shutdown()
        self.udp.server_close()
        self.udp_thread.join()

    def test_match_and_sibling(self):
        self.assertTrue(splitdns.matches("EXAMPLE.COM.", self.direct.domains))
        self.assertTrue(splitdns.matches("a.example.com", self.direct.domains))
        self.assertFalse(splitdns.matches("badexample.com", self.direct.domains))
        self.assertFalse(splitdns.matches("example.com.evil", self.direct.domains))

    def test_unmatched_udp_never_dot(self):
        q = query("badexample.com", True)
        self.assertEqual(self.direct.resolve(q), answer(q))
        self.assertEqual(self.udp.seen, [q])

    def test_matched_authenticated_dot_never_dhcp(self):
        cert = self.cert
        key = self.key
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        seen = []
        def serve():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with server_context.wrap_socket(conn, server_side=True) as tls:
                        size = int.from_bytes(splitdns.exact(tls, 2), "big")
                        wire = splitdns.exact(tls, size)
                        seen.append(wire)
                        reply = answer(wire)
                        tls.sendall(struct.pack("!H", len(reply)) + reply)
            except OSError:
                pass
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        resolver = splitdns.Resolver(self.direct.domains, "127.0.0.1", listener.getsockname()[1],
                                     SNI, ["127.0.0.1"], self.udp.server_address[1], 1, str(cert))
        q = query("www.example.com", True)
        self.assertEqual(resolver.resolve(q), answer(q))
        worker.join(timeout=2)
        self.assertEqual(seen, [q])
        self.assertEqual(self.udp.seen, [])

    def test_matched_failure_never_dhcp(self):
        q = query("www.example.com")
        self.assertEqual(self.direct.resolve(q)[3] & 15, 2)
        self.assertEqual(self.udp.seen, [])

    def test_invalid_questions_rejected_without_network(self):
        invalid = [query("example.com")[:14], query("example.com") + b"junk",
                   query("example.com").replace(b"\x07example", b"\xc0example"),
                   query("example.com")[:4] + b"\0\2" + query("example.com")[6:]]
        for q in invalid:
            self.assertEqual(self.direct.resolve(q)[3] & 15, 1)
        self.assertEqual(self.udp.seen, [])

    def test_domains_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains"
            for contents in ["example.com\nEXAMPLE.COM.\n", "example.com\n*.example.com\n",
                             "example.com\nexample.com.evil/\n"]:
                path.write_text(contents)
                with self.assertRaises(ValueError):
                    splitdns.load_domains(path)

    def test_tcp_proxy(self):
        with splitdns.BoundedTCP(("127.0.0.1", 0), self.direct) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            # TCP proxy must use TCP upstream, not the UDP-only fake.
            with socket.create_connection(proxy.server_address, 1) as client:
                q = query("other.org")
                client.sendall(struct.pack("!H", len(q)) + q)
                size = int.from_bytes(splitdns.exact(client, 2), "big")
                self.assertEqual(splitdns.exact(client, size)[3] & 15, 2)
            proxy.shutdown()
            thread.join()

    def test_root_config_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"personal_sni": SNI, "dhcp_dns": ["127.0.0.1"]}))
            path.chmod(0o644)
            with self.assertRaises(PermissionError):
                splitdns.load_config(path)
            if os.geteuid() == 0:
                path.chmod(0o600)
                resolver, port = splitdns.load_config(path)
                self.assertEqual(port, 5300)
                self.assertEqual(resolver.dot_ip, "31.76.244.138")

    def test_multiple_dot_upstreams_are_loaded_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            domains = root / "domains"
            domains.write_text("example.com\n")
            path = root / "config.json"
            path.write_text(json.dumps({"personal_sni": SNI, "dot_ips": ["31.76.30.138", "31.76.244.138"],
                                        "dhcp_dns": ["192.0.2.53"], "domains_file": str(domains)}))
            path.chmod(0o600)
            if os.geteuid() == 0:
                resolver, _ = splitdns.load_config(path)
                self.assertEqual(resolver.dot_ips, ("31.76.30.138", "31.76.244.138"))


if __name__ == "__main__":
    unittest.main()
