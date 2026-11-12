import argparse
import http.server
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import netcheck  # noqa: E402


def make_opts(**overrides):
    values = dict(threads=4, timeout=3.0, max_time=20.0, banner_wait=0.5, probe_timeout=1.0,
                  retries=0, method="HEAD", user_agent="test", insecure=False, no_redirect=False)
    values.update(overrides)
    return argparse.Namespace(**values)


class FakeServer:
    def __init__(self, handler):
        self.handler = handler
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(50)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            self.handler(conn)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


def banner(data):
    return lambda conn: conn.sendall(data)


def silent(conn):
    conn.settimeout(6)
    conn.recv(256)


def rdp(conn):
    conn.settimeout(6)
    if conn.recv(256)[:2] == b"\x03\x00":
        conn.sendall(bytes([3, 0, 0, 0x13, 0x0E, 0xD0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0]))


class WebHandler(http.server.BaseHTTPRequestHandler):
    def _reply(self):
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD = _reply

    def log_message(self, *args):
        pass


def check(entry, **overrides):
    opts = make_opts(**overrides)
    return netcheck.run(netcheck.parse_target(entry), opts, netcheck.build_opener(False, True))


class ParseTests(unittest.TestCase):
    def test_bare_host_defaults_to_https(self):
        self.assertEqual(netcheck.parse_target("Example.COM")["url"], "https://example.com")

    def test_trailing_slash_is_normalized(self):
        self.assertEqual(netcheck.parse_target("https://Example.com/")["url"], "https://example.com")

    def test_host_port_is_autodetected(self):
        target = netcheck.parse_target("10.0.0.1:2222")
        self.assertEqual((target["kind"], target["proto"], target["port"]), ("service", None, 2222))

    def test_scheme_default_port(self):
        target = netcheck.parse_target("ssh://example.com")
        self.assertEqual((target["proto"], target["port"]), ("ssh", 22))

    def test_host_port_with_path(self):
        self.assertEqual(netcheck.parse_target("10.0.0.1:8080/status")["path"], "/status")

    def test_blank_and_comment_lines_are_ignored(self):
        self.assertIsNone(netcheck.parse_target("   "))
        self.assertIsNone(netcheck.parse_target("# comment"))

    def test_bom_and_duplicates(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("\ufeffexample.com\nEXAMPLE.com/\n# c\n\n10.0.0.1:22\n")
        try:
            targets = netcheck.read_targets(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual([t["key"] for t in targets], ["https://example.com", "10.0.0.1:22"])


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = {
            "ssh": FakeServer(banner(b"SSH-2.0-OpenSSH_9.2\r\n")),
            "vnc": FakeServer(banner(b"RFB 003.008\n")),
            "telnet": FakeServer(banner(b"\xff\xfd\x18")),
            "bad_telnet": FakeServer(banner(b"\xff\x00\x01")),
            "smtp": FakeServer(banner(b"220 mail.example.com ESMTP\r\n")),
            "rdp": FakeServer(rdp),
            "silent": FakeServer(silent),
        }
        cls.web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WebHandler)
        threading.Thread(target=cls.web.serve_forever, daemon=True).start()
        cls.web_port = cls.web.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers.values():
            server.close()
        cls.web.shutdown()

    def addr(self, name):
        return "127.0.0.1:{}".format(self.servers[name].port)

    def test_banner_protocols(self):
        for name, proto in [("ssh", "ssh"), ("vnc", "vnc"), ("telnet", "telnet"), ("smtp", "smtp")]:
            res = check(self.addr(name))
            self.assertEqual((res["status"], res["proto"]), ("UP", proto), name)

    def test_non_telnet_binary_banner_is_not_telnet(self):
        res = check(self.addr("bad_telnet"))
        self.assertEqual(res["status"], "PORT_OPEN")
        self.assertEqual(res["proto"], "")

    def test_rdp_probe(self):
        res = check(self.addr("rdp"))
        self.assertEqual((res["status"], res["proto"]), ("UP", "rdp"))

    def test_http_detection(self):
        res = check("127.0.0.1:{}".format(self.web_port))
        self.assertEqual((res["status"], res["proto"], res["code"]), ("UP", "http", 200))

    def test_http_detection_with_path(self):
        res = check("127.0.0.1:{}/missing".format(self.web_port))
        self.assertEqual((res["status"], res["code"]), ("HTTP_ERR", 404))

    def test_silent_port_is_port_open(self):
        self.assertEqual(check(self.addr("silent"))["status"], "PORT_OPEN")

    def test_closed_port_is_down(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        res = check("127.0.0.1:{}".format(port))
        self.assertEqual(res["status"], "DOWN")
        self.assertIn("refused", res["detail"])

    def test_explicit_scheme_match_and_mismatch(self):
        port = self.servers["ssh"].port
        self.assertEqual(check("ssh://127.0.0.1:{}".format(port))["status"], "UP")
        self.assertEqual(check("vnc://127.0.0.1:{}".format(port))["status"], "PORT_OPEN")

    def test_explicit_web_url(self):
        res = check("http://127.0.0.1:{}/missing".format(self.web_port))
        self.assertEqual((res["status"], res["code"]), ("HTTP_ERR", 404))

    def test_time_budget_is_enforced(self):
        res = check(self.addr("silent"), max_time=0.3, banner_wait=2.0)
        self.assertEqual(res["status"], "PORT_OPEN")
        self.assertIn("budget", res["detail"])


@unittest.skipIf(os.name == "nt", "SIGINT handling differs on Windows")
class InterruptTests(unittest.TestCase):
    def test_ctrl_c_saves_partial_results(self):
        server = FakeServer(silent)
        with tempfile.TemporaryDirectory() as tmp:
            targets = os.path.join(tmp, "targets.txt")
            alive = os.path.join(tmp, "alive.txt")
            with open(targets, "w") as fh:
                fh.write("".join("127.0.0.1:{}/p{}\n".format(server.port, i) for i in range(6)))
            proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "netcheck.py"), targets,
                                     "-t", "1", "-b", "4", "-a", alive],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(1.5)
            proc.send_signal(signal.SIGINT)
            proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 130)
            self.assertTrue(os.path.exists(alive))
        server.close()


if __name__ == "__main__":
    unittest.main()
