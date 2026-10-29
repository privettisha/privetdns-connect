#!/usr/bin/env python3
"""Local, selective DNS wire proxy. No host DNS settings are changed.

Run as root with a root-owned 0600 JSON config (see README.md). DNS queries for
listed suffixes go only to authenticated DoT; all other queries go only to
explicit IPv4 DHCP resolver addresses. Errors never trigger cross-route fallback.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import stat
import struct
import threading

MAX_WIRE = 4096
MAX_CLIENT_WIRE = 4096
SNI_PATTERN = re.compile(r"[a-z2-7]{32}\.dot\.privetdns\.ru\Z")
LABEL_PATTERN = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")


class DNSFormatError(ValueError):
    pass


def domain_name(text):
    """Normalize an ASCII domain, rejecting wildcards, URLs and empty labels."""
    if not isinstance(text, str) or not text or text != text.strip():
        raise ValueError("invalid domain")
    text = text.lower().removesuffix(".")
    if len(text) > 253 or not text or any(not LABEL_PATTERN.fullmatch(label) for label in text.split(".")):
        raise ValueError("invalid domain")
    return text


def load_domains(path):
    domains = set()
    with open(path, encoding="ascii") as source:
        for lineno, line in enumerate(source, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Reject duplicates, rather than accidentally expanding policy via
            # cosmetically different domain spellings.
            try:
                name = domain_name(line)
            except ValueError as exc:
                raise ValueError("invalid domain-list entry at line %d" % lineno) from exc
            if name in domains:
                raise ValueError("duplicate domain-list entry at line %d" % lineno)
            domains.add(name)
    if not domains:
        raise ValueError("empty domain list")
    return frozenset(domains)


def matches(name, domains):
    name = domain_name(name)
    return any(name == suffix or name.endswith("." + suffix) for suffix in domains)


def ipv4_address(text):
    if not isinstance(text, str):
        raise ValueError("upstream must be an IPv4 literal")
    return str(ipaddress.IPv4Address(text))


def load_config(path):
    """Reject symlinks and non-root/non-private config before reading secrets."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise PermissionError("config must be root-owned regular file with mode 0600")
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            fd = -1
            data = json.load(source)
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(data, dict):
        raise ValueError("config must be an object")
    allowed = {"personal_sni", "dot_ip", "dot_ips", "dot_port", "dhcp_dns", "dns_port", "listen_port", "timeout", "domains_file", "ca_file"}
    if data.keys() - allowed:
        raise ValueError("unknown config keys")
    sni = data.get("personal_sni")
    if not isinstance(sni, str) or not SNI_PATTERN.fullmatch(sni):
        raise ValueError("invalid personal DoT hostname")
    if "dot_ip" in data and "dot_ips" in data:
        raise ValueError("use dot_ips, not both dot_ip and dot_ips")
    dot_values = data.get("dot_ips", [data.get("dot_ip", "31.76.244.138")])
    if not isinstance(dot_values, list) or not 1 <= len(dot_values) <= 8:
        raise ValueError("dot_ips must be a nonempty list")
    dot_ips = tuple(dict.fromkeys(ipv4_address(item) for item in dot_values))
    dhcp_dns = data.get("dhcp_dns")
    if not isinstance(dhcp_dns, list) or not dhcp_dns:
        raise ValueError("dhcp_dns must be a nonempty list of original DHCP IPv4 DNS addresses")
    dhcp_dns = tuple(ipv4_address(item) for item in dhcp_dns)
    def port(key, default):
        value = data.get(key, default)
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError("invalid port")
        return value
    timeout = data.get("timeout", 3.0)
    if type(timeout) not in (int, float) or not 0.1 <= timeout <= 10:
        raise ValueError("invalid timeout")
    listen_port = data.get("listen_port", 5300)
    if type(listen_port) is not int or not 0 <= listen_port <= 65535:
        raise ValueError("invalid listen_port")
    ca_file = data.get("ca_file")
    if ca_file is not None and (not isinstance(ca_file, str) or not ca_file):
        raise ValueError("invalid CA file")
    domain_path = data.get("domains_file", str(Path(__file__).with_name("smartdns-domains.txt")))
    if not isinstance(domain_path, str) or not domain_path:
        raise ValueError("invalid domain-list path")
    return Resolver(load_domains(domain_path), dot_ips, port("dot_port", 853), sni,
                    dhcp_dns, port("dns_port", 53), float(timeout), ca_file), listen_port


def question(message):
    """Accept exactly one ordinary question and optionally one EDNS(0) OPT RR."""
    if len(message) < 17 or len(message) > MAX_WIRE:
        raise DNSFormatError("invalid DNS length")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", message)
    if flags & 0xFA40 or qd != 1 or an or ns or ar > 1:
        # QR, opcode, TC and reserved Z must not be set in a query. RD, CD,
        # AD are retained in the wire request rather than reconstructed.
        raise DNSFormatError("invalid DNS header")
    offset = 12
    labels = []
    while True:
        if offset >= len(message):
            raise DNSFormatError("truncated question")
        count = message[offset]
        offset += 1
        if count == 0:
            break
        if count > 63 or offset + count > len(message):
            raise DNSFormatError("invalid DNS label")
        try:
            label = message[offset:offset + count].decode("ascii")
            labels.append(domain_name(label))
        except (UnicodeDecodeError, ValueError) as exc:
            raise DNSFormatError("invalid DNS label") from exc
        offset += count
    if not labels or sum(map(len, labels)) + len(labels) > 253 or offset + 4 > len(message):
        raise DNSFormatError("invalid DNS question")
    qname = ".".join(labels)
    offset += 4
    question_end = offset
    if ar:
        if offset + 11 > len(message) or message[offset] != 0:
            raise DNSFormatError("invalid EDNS record")
        rrtype, udp_size, ttl, rdlen = struct.unpack_from("!HHIH", message, offset + 1)
        if rrtype != 41 or ttl >> 16 & 255 or udp_size < 512 or rdlen > MAX_WIRE:
            raise DNSFormatError("unsupported EDNS record")
        offset += 11 + rdlen
    if offset != len(message):
        raise DNSFormatError("trailing DNS data")
    return qname, question_end


def error_reply(message, rcode):
    # Echo only a validated question, so malformed input cannot be reflected.
    try:
        _, end = question(message)
        q = message[12:end]
        qd = 1
    except DNSFormatError:
        q = b""
        qd = 0
    ident = message[:2] if len(message) >= 2 else b"\0\0"
    rd = (message[2] & 1) if len(message) >= 3 else 0
    return ident + struct.pack("!HHHHH", 0x8000 | (rd << 8) | rcode, qd, 0, 0, 0) + q


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        piece = sock.recv(size - len(result))
        if not piece:
            raise OSError("short upstream response")
        result.extend(piece)
    return bytes(result)


def check_reply(query, reply, qend):
    if len(reply) < qend or len(reply) > MAX_WIRE or reply[:2] != query[:2]:
        raise DNSFormatError("invalid upstream response")
    flags, qd = struct.unpack_from("!HH", reply, 2)
    if not flags & 0x8000 or qd != 1 or reply[12:qend] != query[12:qend]:
        raise DNSFormatError("upstream question mismatch")
    return reply


class Resolver:
    def __init__(self, domains, dot_ips, dot_port, personal_sni, dhcp_dns,
                 dns_port=53, timeout=3.0, ca_file=None):
        self.domains = domains
        if isinstance(dot_ips, str):
            dot_ips = (dot_ips,)
        self.dot_ips = tuple(dict.fromkeys(ipv4_address(item) for item in dot_ips))
        if not self.dot_ips:
            raise ValueError("no DoT upstreams")
        self.dot_ip = self.dot_ips[0]  # Compatibility for status and tests.
        self.dot_port = dot_port
        self.personal_sni = personal_sni
        self.dhcp_dns = tuple(ipv4_address(item) for item in dhcp_dns)
        self.dns_port = dns_port
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=ca_file)

    def dot(self, query):
        last = None
        for address in self.dot_ips:
            try:
                with socket.create_connection((address, self.dot_port), self.timeout) as conn:
                    conn.settimeout(self.timeout)
                    with self.context.wrap_socket(conn, server_hostname=self.personal_sni) as tls:
                        tls.sendall(struct.pack("!H", len(query)) + query)
                        length = struct.unpack("!H", exact(tls, 2))[0]
                        if not 12 <= length <= MAX_WIRE:
                            raise DNSFormatError("invalid DoT reply size")
                        return exact(tls, length)
            except (OSError, DNSFormatError, ssl.SSLError) as error:
                last = error
        raise OSError("all authenticated DoT upstreams unavailable") from last

    def ordinary(self, query, qend, tcp):
        for address in self.dhcp_dns:
            try:
                if tcp:
                    return self.direct_tcp(query, address)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(query, (address, self.dns_port))
                    reply, peer = sock.recvfrom(MAX_WIRE + 1)
                    if peer != (address, self.dns_port):
                        raise DNSFormatError("unexpected upstream")
                    check_reply(query, reply, qend)
                    if reply[2] & 2:  # UDP truncation: TCP to the SAME ordinary upstream.
                        return self.direct_tcp(query, address)
                    return reply
            except (OSError, DNSFormatError):
                continue
        raise OSError("ordinary upstream unavailable")

    def direct_tcp(self, query, address):
        with socket.create_connection((address, self.dns_port), self.timeout) as conn:
            conn.settimeout(self.timeout)
            conn.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", exact(conn, 2))[0]
            if not 12 <= length <= MAX_WIRE:
                raise DNSFormatError("invalid TCP DNS reply size")
            return exact(conn, length)

    def resolve(self, query, tcp=False):
        try:
            name, qend = question(query)
        except DNSFormatError:
            return error_reply(query, 1)  # FORMERR; never send invalid requests upstream.
        try:
            if matches(name, self.domains):
                reply = self.dot(query)  # DoT failure is terminal: no DHCP fallback.
            else:
                reply = self.ordinary(query, qend, tcp)
            check_reply(query, reply, qend)
            if not tcp and len(reply) > (min(struct.unpack_from("!H", query, qend + 3)[0], MAX_WIRE)
                                         if struct.unpack_from("!H", query, 10)[0] else 512):
                # Preserve ID/question and signal truncation; never emit oversized
                # UDP replies to clients without matching EDNS receive capacity.
                return reply[:2] + struct.pack("!HHHHH", (struct.unpack_from("!H", reply, 2)[0] | 0x0200), 1, 0, 0, 0) + query[12:qend]
            return reply
        except (OSError, ValueError, ssl.SSLError):
            return error_reply(query, 2)  # SERVFAIL, without logging name or secret.


class BoundedUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = MAX_CLIENT_WIRE + 1

    def __init__(self, address, resolver, limit=32):
        self.resolver = resolver
        self.slots = threading.BoundedSemaphore(limit)
        super().__init__(address, UDPHandler)

    def process_request(self, request, client_address):
        if self.slots.acquire(blocking=False):
            super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never log DNS queries or secret-bearing errors.


class BoundedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, resolver, limit=32):
        self.resolver = resolver
        self.slots = threading.BoundedSemaphore(limit)
        super().__init__(address, TCPHandler)

    def process_request(self, request, client_address):
        if self.slots.acquire(blocking=False):
            super().process_request(request, client_address)
        else:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        sock.sendto(self.server.resolver.resolve(query), self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(self.server.resolver.timeout)
        length = struct.unpack("!H", exact(self.request, 2))[0]
        if not 12 <= length <= MAX_CLIENT_WIRE:
            return
        answer = self.server.resolver.resolve(exact(self.request, length), tcp=True)
        self.request.sendall(struct.pack("!H", len(answer)) + answer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="root-owned 0600 JSON configuration file")
    args = parser.parse_args()
    resolver, port = load_config(args.config)
    with BoundedUDP(("127.0.0.1", port), resolver) as udp:
        with BoundedTCP(("127.0.0.1", udp.server_address[1]), resolver) as tcp:
            udp_thread = threading.Thread(target=udp.serve_forever, daemon=True)
            udp_thread.start()
            try:
                tcp.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                udp.shutdown()
                udp_thread.join()


if __name__ == "__main__":
    main()
