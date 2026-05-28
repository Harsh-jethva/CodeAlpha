#!/usr/bin/env python3
"""Live packet capture backend for the network sniffer dashboard.

Run:
    python packet_tracer_backend.py --interface any --port 8765

Then open:
    http://127.0.0.1:8765/
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

if os.name == "nt":
    try:
        import ctypes
    except Exception:
        ctypes = None


PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    41: "IPv6",
    89: "OSPF",
}

WELL_KNOWN_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

DEMO_PROTOS = ["TCP", "TCP", "UDP", "UDP", "ICMP", "OTHER"]
DEMO_SERVICES = {
    "TCP": [
        {"sp": 45231, "dp": 80, "svc": "HTTP"},
        {"sp": 55420, "dp": 443, "svc": "HTTPS"},
        {"sp": 22150, "dp": 22, "svc": "SSH"},
        {"sp": 50222, "dp": 3306, "svc": "MySQL"},
    ],
    "UDP": [
        {"sp": 49231, "dp": 53, "svc": "DNS"},
        {"sp": 58032, "dp": 67, "svc": "DHCP"},
        {"sp": 12345, "dp": 5353, "svc": "mDNS"},
    ],
    "ICMP": [{"sp": 0, "dp": 0, "svc": ""}],
    "OTHER": [{"sp": 0, "dp": 0, "svc": "OSPF"}],
}
DEMO_ICMP_TYPES = ["Echo Request", "Echo Reply", "Dest Unreachable", "Time Exceeded"]
DEMO_IPS = [
    "192.168.1.1",
    "192.168.1.42",
    "10.0.0.15",
    "10.0.0.1",
    "172.16.0.5",
    "8.8.8.8",
    "1.1.1.1",
    "142.250.80.46",
    "93.184.216.34",
    "104.16.132.229",
]
DEMO_PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: example.com",
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html",
    b"POST /api/data HTTP/1.1\r\n{\"key\":\"value\"}",
    b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
    b"SSH-2.0-OpenSSH_8.9",
    b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1",
    b"",
]


def format_mac(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02X}" for b in mac_bytes)


def guess_service(src_port: int, dst_port: int) -> str:
    return WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port) or ""


def safe_decode(payload: bytes, max_chars: int = 200) -> str:
    text = payload.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else "." for ch in text)
    return text[:max_chars] + ("..." if len(text) > max_chars else "")


def hex_dump(data: bytes, bytes_per_line: int = 16, max_bytes: int = 64) -> str:
    lines = []
    for i in range(0, min(len(data), max_bytes), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_part:<{bytes_per_line * 3}}  {ascii_part}")
    return "\n".join(lines) or "(empty)"


def parse_ethernet(raw: bytes):
    if len(raw) < 14:
        return None, raw
    dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", raw[:14])
    return {
        "dst_mac": format_mac(dst_mac),
        "src_mac": format_mac(src_mac),
        "eth_type": eth_type,
    }, raw[14:]


def parse_ipv4(raw: bytes):
    if len(raw) < 20:
        return None, raw
    ver_ihl = raw[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0xF) * 4
    ttl, proto, checksum = struct.unpack("!BBH", raw[8:12])
    src_ip = socket.inet_ntoa(raw[12:16])
    dst_ip = socket.inet_ntoa(raw[16:20])
    return {
        "version": version,
        "ihl": ihl,
        "ttl": ttl,
        "protocol": proto,
        "proto_name": PROTO_MAP.get(proto, f"UNKNOWN({proto})"),
        "checksum": f"0x{checksum:04X}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }, raw[ihl:]


def parse_tcp(raw: bytes):
    if len(raw) < 20:
        return None, raw
    src_port, dst_port, seq, ack_num = struct.unpack("!HHII", raw[:12])
    offset_flags = struct.unpack("!H", raw[12:14])[0]
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF
    window = struct.unpack("!H", raw[14:16])[0]

    flag_names = []
    if flags & 0x001:
        flag_names.append("FIN")
    if flags & 0x002:
        flag_names.append("SYN")
    if flags & 0x004:
        flag_names.append("RST")
    if flags & 0x008:
        flag_names.append("PSH")
    if flags & 0x010:
        flag_names.append("ACK")
    if flags & 0x020:
        flag_names.append("URG")

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack_num": ack_num,
        "flags": flag_names,
        "window": window,
        "service_hint": guess_service(src_port, dst_port),
    }, raw[offset:]


def parse_udp(raw: bytes):
    if len(raw) < 8:
        return None, raw
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw[:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": f"0x{checksum:04X}",
        "service_hint": guess_service(src_port, dst_port),
    }, raw[8:]


def parse_icmp(raw: bytes):
    if len(raw) < 8:
        return None, raw
    icmp_type, code, checksum = struct.unpack("!BBH", raw[:4])
    type_names = {
        0: "Echo Reply",
        3: "Dest Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
    }
    return {
        "type": icmp_type,
        "type_name": type_names.get(icmp_type, f"Type {icmp_type}"),
        "code": code,
        "checksum": f"0x{checksum:04X}",
    }, raw[8:]


def build_packet(raw_data: bytes, has_ethernet: bool):
    ethernet = None
    ip_raw = raw_data

    if has_ethernet:
        ethernet, ip_raw = parse_ethernet(raw_data)
        if ethernet is None or ethernet["eth_type"] != 0x0800:
            return None

    ip, transport_raw = parse_ipv4(ip_raw)
    if ip is None:
        return None

    transport = {}
    payload = transport_raw

    if ip["protocol"] == 6:
        transport, payload = parse_tcp(transport_raw)
    elif ip["protocol"] == 17:
        transport, payload = parse_udp(transport_raw)
    elif ip["protocol"] == 1:
        transport, payload = parse_icmp(transport_raw)

    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "frame_size": len(raw_data),
        "ethernet": ethernet,
        "ip": ip,
        "transport": transport or {},
        "payload_size": len(payload),
        "payload_preview": safe_decode(payload),
        "payload_hex": hex_dump(payload),
    }


def build_demo_packet(sequence_id: int):
    proto = random.choice(DEMO_PROTOS)
    service_info = random.choice(DEMO_SERVICES[proto])
    src_ip = random.choice(DEMO_IPS)
    dst_ip = random.choice([ip for ip in DEMO_IPS if ip != src_ip])
    payload = random.choice(DEMO_PAYLOADS)
    flags = []
    if proto == "TCP":
        flags = random.choice([
            ["SYN"],
            ["SYN", "ACK"],
            ["ACK"],
            ["PSH", "ACK"],
            ["FIN", "ACK"],
            ["RST"],
        ])

    transport = {
        "src_port": service_info["sp"],
        "dst_port": service_info["dp"],
        "service_hint": service_info["svc"],
        "flags": flags,
    }
    if proto == "TCP":
        transport.update(
            {
                "seq": random.randint(100000, 9999999),
                "ack_num": random.randint(100000, 9999999),
                "window": random.randint(1024, 65535),
            }
        )
    elif proto == "UDP":
        transport.update({"length": len(payload) + 8, "checksum": f"0x{random.randint(0, 0xFFFF):04X}"})
    elif proto == "ICMP":
        transport.update(
            {
                "type": random.randint(0, 15),
                "type_name": random.choice(DEMO_ICMP_TYPES),
                "code": random.randint(0, 3),
                "checksum": f"0x{random.randint(0, 0xFFFF):04X}",
            }
        )

    ip = {
        "version": 4,
        "ihl": 20,
        "ttl": random.randint(48, 128),
        "protocol": {"TCP": 6, "UDP": 17, "ICMP": 1, "OTHER": 89}[proto],
        "proto_name": proto,
        "checksum": f"0x{random.randint(0, 0xFFFF):04X}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }

    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "frame_size": random.randint(64, 1514),
        "ethernet": {
            "dst_mac": "AA:BB:CC:DD:EE:FF",
            "src_mac": "11:22:33:44:55:66",
            "eth_type": 0x0800,
        },
        "ip": ip,
        "transport": transport,
        "payload_size": len(payload),
        "payload_preview": safe_decode(payload),
        "payload_hex": hex_dump(payload),
        "demo_mode": True,
        "sequence_id": sequence_id,
    }


class PacketStore:
    def __init__(self, max_packets: int = 5000):
        self._lock = threading.Lock()
        self._packets = deque(maxlen=max_packets)
        self._next_id = 1
        self._total = 0
        self._total_bytes = 0
        self._by_proto = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self._started_at = time.time()
        self._interface = "any"
        self._capture_error = None
        self._capture_mode = "starting"

    def set_interface(self, interface: str):
        with self._lock:
            self._interface = interface

    def set_error(self, message: str | None):
        with self._lock:
            self._capture_error = message

    def set_mode(self, mode: str):
        with self._lock:
            self._capture_mode = mode

    def add(self, packet: dict):
        proto_name = packet.get("ip", {}).get("proto_name", "OTHER")
        if proto_name not in self._by_proto:
            proto_name = "OTHER"

        with self._lock:
            packet["id"] = self._next_id
            self._next_id += 1
            self._packets.append(packet)
            self._total += 1
            self._total_bytes += packet.get("frame_size", 0)
            self._by_proto[proto_name] += 1

    def snapshot(self, after_id: int = 0, limit: int = 200):
        with self._lock:
            packets = [packet for packet in self._packets if packet["id"] > after_id]
            return packets[:limit]

    def status(self):
        with self._lock:
            elapsed = max(time.time() - self._started_at, 0.001)
            return {
                "latest_id": self._next_id - 1,
                "total": self._total,
                "total_bytes": self._total_bytes,
                "by_proto": dict(self._by_proto),
                "rate": self._total / elapsed,
                "uptime": elapsed,
                "interface": self._interface,
                "capture_mode": self._capture_mode,
                "capture_error": self._capture_error,
            }


class CaptureManager:
    def __init__(self, store: PacketStore, interface: str):
        self.store = store
        self.interface = interface
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self.stop()
        self._stop_event = threading.Event()
        self.store.set_interface(self.interface)
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=1.5)

    def restart(self, interface: str):
        self.interface = interface
        self.start()

    def _create_socket(self):
        if os.name == "nt":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            local_ip = socket.gethostbyname(socket.gethostname())
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return sock, False

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if self.interface and self.interface != "any":
            sock.bind((self.interface, 0))
        return sock, True

    def _capture_loop(self):
        raw_sock = None
        self.store.set_mode("starting")
        try:
            raw_sock, has_ethernet = self._create_socket()
            raw_sock.settimeout(0.5)
            self.store.set_error(None)
            self.store.set_mode("live")
        except PermissionError:
            self.store.set_error(
                "Administrator/root privileges are required for raw socket capture. Running in demo mode until the backend is started elevated."
            )
            self.store.set_mode("demo")
            self._demo_loop()
            return
        except OSError as exc:
            self.store.set_error(f"{exc}. Running in demo mode.")
            self.store.set_mode("demo")
            self._demo_loop()
            return

        try:
            while not self._stop_event.is_set():
                try:
                    raw_data, _ = raw_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                packet = build_packet(raw_data, has_ethernet)
                if packet is not None:
                    self.store.add(packet)
        finally:
            try:
                if os.name == "nt" and raw_sock is not None:
                    raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            if raw_sock is not None:
                raw_sock.close()

    def _demo_loop(self):
        self.store.set_mode("demo")
        sequence_id = 1
        while not self._stop_event.is_set():
            self.store.add(build_demo_packet(sequence_id))
            sequence_id += 1
            time.sleep(0.4)


def is_elevated() -> bool:
    if os.name != "nt" or ctypes is None:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "PacketTracer/1.0"

    def _set_headers(self, status_code=200, content_type="application/json; charset=utf-8"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html", "/network_sniffer_dashboard.html"}:
            dashboard = Path(__file__).with_name("network_sniffer_dashboard.html")
            if not dashboard.exists():
                self._set_headers(404, "text/plain; charset=utf-8")
                self.wfile.write(b"Dashboard file not found.")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(dashboard.read_bytes())
            return

        if parsed.path == "/api/status":
            summary = self.server.store.status()
            self._set_headers()
            payload = {
                "ok": True,
                "capture_running": self.server.capture_manager._thread is not None and self.server.capture_manager._thread.is_alive(),
                "config": {"interface": self.server.capture_manager.interface},
                "summary": summary,
                "mode": summary.get("capture_mode", "starting"),
                "warning": summary.get("capture_error"),
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if parsed.path == "/api/packets":
            query = parse_qs(parsed.query)
            after_id = int(query.get("after", [0])[0])
            limit = int(query.get("limit", [200])[0])
            packets = self.server.store.snapshot(after_id=after_id, limit=limit)
            summary = self.server.store.status()
            payload = {
                "ok": True,
                "latest_id": summary["latest_id"],
                "packets": packets,
                "summary": summary,
            }
            self._set_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self._set_headers(404, "text/plain; charset=utf-8")
        self.wfile.write(b"Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/config":
            self._set_headers(404, "text/plain; charset=utf-8")
            self.wfile.write(b"Not found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            body = {}

        interface = body.get("interface") or self.server.capture_manager.interface
        self.server.capture_manager.restart(interface)

        self._set_headers()
        self.wfile.write(
            json.dumps(
                {
                    "ok": True,
                    "config": {"interface": interface},
                    "summary": self.server.store.status(),
                }
            ).encode("utf-8")
        )

    def log_message(self, format, *args):
        return


class PacketTracerServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, store, capture_manager):
        super().__init__(server_address, RequestHandlerClass)
        self.store = store
        self.capture_manager = capture_manager


def main():
    parser = argparse.ArgumentParser(description="Live packet capture backend")
    parser.add_argument("--interface", default="any", help="Network interface to capture on")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port for the dashboard and API")
    args = parser.parse_args()

    store = PacketStore()
    capture_manager = CaptureManager(store, args.interface)
    capture_manager.start()

    if store.status().get("capture_mode") == "demo":
        print("Warning: raw capture is not available. The backend is running in demo mode.")
    else:
        print("Raw capture is active.")

    server = PacketTracerServer(("127.0.0.1", args.port), DashboardHandler, store, capture_manager)
    print(f"Serving dashboard at http://127.0.0.1:{args.port}/")
    print(f"Capturing on interface: {args.interface}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        capture_manager.stop()
        server.server_close()


if __name__ == "__main__":
    main()