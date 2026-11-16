#!/usr/bin/env python3
"""Exercise Mihomo Personal lease cancellation with loopback only and TUN disabled."""
import argparse
import concurrent.futures
import http.client
import http.server
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("core", type=pathlib.Path)
parser.add_argument("transport", choices=("tcp", "udp"))
parser.add_argument("action", choices=("reject", "expiry", "reload", "manual"))
parser.add_argument("--lease-dns", action="store_true", help="Resolve Personal names through the leased selector")
args = parser.parse_args()
executable = args.core.resolve(strict=True)
revocable = args.action != "manual"
lease_path = "/proxies/PERSONAL/lumina-fallback"


def controller_ports():
    with socket.socket() as a, socket.socket() as b:
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        return a.getsockname()[1], b.getsockname()[1]


def udp_endpoint():
    item = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    item.bind(("127.0.0.1", 0))
    return item


dns_seen, dns_release, target_seen = threading.Event(), threading.Event(), threading.Event()


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        target_seen.set()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"late-personal-flow" if self.path == "/test" else b"ordinary-direct")

    def log_message(self, *args):
        pass


class PacketTarget(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        if payload == b"late-probe":
            target_seen.set()
            sock.sendto(b"late-personal-flow", self.client_address)


def serve_dns(udp):
    packet, peer = udp.recvfrom(2048)
    question_end = packet.index(b"\0", 12) + 5
    dns_seen.set()
    assert dns_release.wait(3)
    is_a = struct.unpack("!H", packet[question_end - 4:question_end - 2])[0] == 1
    result = packet[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if is_a else b"\x00\x00") + b"\x00\x00\x00\x00"
    result += packet[12:question_end]
    if is_a:
        result += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
    udp.sendto(result, peer)


secret = "ephemeral-loopback-fixture"
controller, mixed = controller_ports()
with tempfile.TemporaryDirectory(prefix="lumina-late-dial.") as directory:
    with udp_endpoint() as udp, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target) as target, \
            socketserver.ThreadingUDPServer(("127.0.0.1", 0), PacketTarget) as packet_target:
        root = pathlib.Path(directory)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        threading.Thread(target=packet_target.serve_forever, daemon=True).start()
        threading.Thread(target=serve_dns, args=(udp,), daemon=True).start()
        dns = "udp://127.0.0.1:" + str(udp.getsockname()[1])
        personal_dns = dns + ("#PERSONAL" if args.lease_dns else "#PHYSICAL")
        config = {
            "mixed-port": mixed, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
            "external-controller": "127.0.0.1:" + str(controller), "secret": secret, "log-level": "warning",
            "ipv6": False, "tun": {"enable": False}, "profile": {"store-selected": False, "store-fake-ip": False},
            "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "fake-ip-range": "198.19.0.1/16",
                    "default-nameserver": [dns], "nameserver": [dns + "#PHYSICAL"], "direct-nameserver": [dns + "#PHYSICAL"],
                    "direct-nameserver-follow-policy": True, "nameserver-policy": {"slow.personal.example": [personal_dns]}},
            "proxies": [{"name": "PHYSICAL-BOUND", "type": "direct"}],
            "proxy-groups": [
                {"name": "PHYSICAL", "type": "select", "proxies": ["REJECT", "PHYSICAL-BOUND"]},
                {"name": "PERSONAL", "type": "select", "proxies": ["REJECT", "PHYSICAL"]}],
            "rules": ["DOMAIN,slow.personal.example,PERSONAL", "MATCH,PHYSICAL"],
        }
        if revocable:
            config["proxy-groups"][1]["lumina-fallback-lease"] = True
        (root / "config.json").write_text(json.dumps(config))
        with (root / "core.log").open("w+") as log, subprocess.Popen(
            [str(executable), "-d", str(root), "-f", str(root / "config.json")],
            stdout=log, stderr=log,
        ) as child:
            def api(method, path, payload=None, expected=(200, 204)):
                conn = http.client.HTTPConnection("127.0.0.1", controller, timeout=2)
                try:
                    conn.request(method, path, None if payload is None else json.dumps(payload),
                                 {"Authorization": "Bearer " + secret, "Content-Type": "application/json"})
                    response = conn.getresponse()
                    result = response.read()
                    assert response.status in expected, (method, path, response.status, result)
                    return json.loads(result) if result else None
                finally:
                    conn.close()

            def socket_read(conn, size):
                result = b""
                while len(result) < size:
                    piece = conn.recv(size - len(result))
                    if not piece:
                        raise ConnectionError("closed fixture SOCKS connection")
                    result += piece
                return result

            def connect_packet(results):
                with socket.create_connection(("127.0.0.1", mixed), timeout=2) as control, udp_endpoint() as relay:
                    control.sendall(b"\x05\x01\x00")
                    assert socket_read(control, 2) == b"\x05\x00"
                    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                    assert socket_read(control, 4) == b"\x05\x00\x00\x01"
                    relay_host, relay_port = socket_read(control, 4), struct.unpack("!H", socket_read(control, 2))[0]
                    assert relay_host in (b"\x7f\x00\x00\x01", b"\x00\x00\x00\x00"), relay_host
                    name = b"slow.personal.example"
                    datagram = b"\x00\x00\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", packet_target.server_address[1]) + b"late-probe"
                    relay.sendto(datagram, ("127.0.0.1", relay_port))
                    relay.settimeout(2)
                    try:
                        data, _ = relay.recvfrom(2048)
                        results.append(data.endswith(b"late-personal-flow"))
                    except (TimeoutError, socket.timeout):
                        results.append(False)

            def connect_personal(results):
                conn = http.client.HTTPConnection("127.0.0.1", mixed, timeout=3)
                try:
                    conn.request("GET", "http://slow.personal.example:" + str(target.server_port) + "/test")
                    response = conn.getresponse()
                    results.append((response.status, response.read()))
                except OSError as exc:
                    results.append(str(exc))
                finally:
                    conn.close()

            try:
                for _ in range(50):
                    try:
                        api("GET", "/version")
                        break
                    except OSError:
                        time.sleep(0.05)
                assert api("GET", "/configs")["tun"]["enable"] is False
                api("PUT", "/proxies/PHYSICAL", {"name": "PHYSICAL-BOUND"})
                if revocable:
                    initial = api("GET", lease_path)
                    assert not initial["active"]
                    api("PUT", "/proxies/PERSONAL", {"name": "PHYSICAL"}, (409,))
                    request = {"revision": initial["revision"], "operation": "open",
                               "deadline_ms": initial["now_ms"] + (500 if args.action == "expiry" else 2500)}
                    api("PUT", lease_path, dict(request, deadline_ms=2**63 - 1), (400,))
                    opened = api("PUT", lease_path, request)
                    assert opened["revision"] != initial["revision"]
                    assert opened["active"] and opened["deadline_ms"] == request["deadline_ms"]
                    api("PUT", lease_path, request, (409,))
                else:
                    api("GET", lease_path, expected=(404,))
                    api("PUT", "/proxies/PERSONAL", {"name": "PHYSICAL"})
                results = []
                flow = threading.Thread(target=connect_packet if args.transport == "udp" else connect_personal, args=(results,))
                flow.start()
                assert dns_seen.wait(2), "did not enter a delayed real dial"
                assert not target_seen.is_set()
                tracked = api("GET", "/connections")["connections"] or []
                personal = [entry for entry in tracked if "PERSONAL" in entry["chains"]]
                if args.lease_dns:
                    assert personal and all(entry["metadata"]["type"] == "Inner" for entry in personal), personal
                else:
                    assert not personal, personal
                if args.action == "expiry":
                    time.sleep((opened["deadline_ms"] - opened["now_ms"]) / 1000 + 0.15)
                elif args.action == "reload":
                    renewal = {"revision": opened["revision"], "operation": "renew",
                               "deadline_ms": opened["deadline_ms"] + 1500}
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as thread:
                        attempted = thread.submit(api, "PUT", lease_path, renewal, (200, 409))
                        api("PUT", "/configs?force=true", {"path": str(root / "config.json")})
                        attempted.result()
                    api("PUT", "/proxies/PHYSICAL", {"name": "PHYSICAL-BOUND"})
                elif args.action == "reject":
                    api("PUT", "/proxies/PERSONAL", {"name": "REJECT"})
                # In the expiry case, release the dial before reading state so
                # the test cannot rely on a control request causing revocation.
                dns_release.set()
                flow.join(3)
                assert not flow.is_alive(), "fixture request did not finish"
                if revocable:
                    assert not target_seen.is_set(), results
                    if args.transport == "udp":
                        assert results == [False], results
                    assert api("GET", "/proxies/PERSONAL")["now"] == "REJECT"
                    revoked = api("GET", lease_path)
                    assert not revoked["active"] and revoked["revision"] != opened["revision"]
                    renewal = {"revision": opened["revision"], "operation": "renew",
                               "deadline_ms": opened["deadline_ms"] + 1500}
                    api("PUT", lease_path, renewal, (409,))
                    api("PUT", lease_path, dict(renewal, revision=revoked["revision"],
                                                deadline_ms=revoked["now_ms"] + 1500), (409,))
                else:
                    assert target_seen.is_set()
                    assert results == ([True] if args.transport == "udp" else [(200, b"late-personal-flow")]), results
                    assert api("GET", "/proxies/PERSONAL")["now"] == "PHYSICAL"
                conn = http.client.HTTPConnection("127.0.0.1", mixed, timeout=2)
                try:
                    conn.request("GET", "http://127.0.0.1:" + str(target.server_port) + "/ordinary")
                    ordinary = conn.getresponse()
                    assert ordinary.status == 200 and ordinary.read() == b"ordinary-direct"
                finally:
                    conn.close()
                print(f"{args.transport} {args.action}: passed")
            finally:
                dns_release.set()
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                target.shutdown()
                packet_target.shutdown()
