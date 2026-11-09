#!/usr/bin/env python3
"""Helioform Relay 4.2 — site telemetry edge and compliance ledger.

Public customers speak HSP inside a WebSocket. On-box agents still speak the
pre-migration raw session protocol. Loopback services are catalogd, provd,
and recordd. recordd's replication port is only for the site collector.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))

ENV_DIR = "/etc/helioform"
RELAY_ENV = os.path.join(ENV_DIR, "relay.env")
COLLECTOR_ENV = os.path.join(ENV_DIR, "collector.env")
RUNBOOK_DIR = "/var/lib/helioform/runbooks"
TICKET_KEY = "mesh-ticket-factory-v4"

OP_HELLO = 0x01
OP_PING = 0x02
OP_SUBSCRIBE = 0x03
OP_DIAL = 0x10
OP_PEER_HELLO = 0x11
OP_TICKET = 0x20
OP_EXPORT = 0x30
OP_STATUS = 0x40
OP_BLOB = 0x17
OP_ERR = 0x7F
FLAG_RESP = 0x0001

MAX_FRAME = 262144
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.epoch = 7
        self.tip = hashlib.sha256(b"helioform-genesis").hexdigest()
        self.nonces = {}
        self.trace_until = 0.0
        self.trace = []
        self.runbook_output = "idle"
        self.runbook_seen = {}
        self.console_key = ""
        self.console_iss = ""
        self.console_aud = ""
        self.repl_key = ""
        self.peer = "relay-collector"
        self.interval = 5
        self.log_root = "/var/log/helioform/streams"


state = State()


def log(msg):
    print(msg, flush=True)


def load_env_file(path):
    out = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def load_config():
    env = load_env_file(RELAY_ENV)
    col = load_env_file(COLLECTOR_ENV)
    state.console_key = env["CONSOLE_MAC_KEY"]
    state.console_iss = env["CONSOLE_ISS"]
    state.console_aud = env["CONSOLE_AUD"]
    state.repl_key = env["REPLICATION_MAC_KEY"]
    state.peer = col["COLLECTOR_PEER"]
    state.interval = int(col["COLLECTOR_INTERVAL_SEC"])
    state.log_root = col["LOG_ROOT"]


def pack_frame(opcode, flags, body):
    body = body if isinstance(body, bytes) else body.encode()
    if len(body) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack("<4sHHI", b"HSP1", opcode, flags, len(body)) + body


def parse_frame(data):
    if len(data) < 12:
        raise ValueError("short frame")
    magic, opcode, flags, length = struct.unpack_from("<4sHHI", data)
    if magic != b"HSP1":
        raise ValueError("bad magic")
    if length > MAX_FRAME or len(data) != 12 + length:
        raise ValueError("length mismatch")
    return opcode, flags, data[12:]


class BufSock:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(max(4096, n - len(self.buf)))
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_until(self, marker, limit):
        while marker not in self.buf:
            if len(self.buf) > limit:
                raise ValueError("headers too large")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError
            self.buf += chunk
        index = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:index], self.buf[index:]
        return out


def tune(sock):
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(60)


def send_ws(sock, payload):
    n = len(payload)
    if n < 126:
        header = bytes([0x82, n])
    elif n < 65536:
        header = bytes([0x82, 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x82, 127]) + struct.pack(">Q", n)
    sock.sendall(header + payload)


def read_ws_message(buf):
    while True:
        head = buf.read_exact(2)
        opcode = head[0] & 0x0F
        masked = head[1] & 0x80
        length = head[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", buf.read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", buf.read_exact(8))[0]
        if length > MAX_FRAME + 64:
            raise ValueError("ws frame too large")
        mask = buf.read_exact(4) if masked else None
        data = buf.read_exact(length)
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:
            raise EOFError
        if opcode == 0x9:
            # pong, unmasked
            buf.sock.sendall(bytes([0x8A, len(data)]) + data)
            continue
        if opcode in (0x1, 0x2):
            return data
        # ignore continuation / other control traffic


def read_edge_frame(transport, buf):
    if transport == "ws":
        return parse_frame(read_ws_message(buf))
    header = buf.read_exact(12)
    magic, opcode, flags, length = struct.unpack("<4sHHI", header)
    if magic != b"HSP1":
        raise ValueError("bad magic")
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    body = buf.read_exact(length) if length else b""
    return opcode, flags, body


def send_edge(transport, buf, opcode, flags, body):
    frame = pack_frame(opcode, flags, body)
    if transport == "ws":
        send_ws(buf.sock, frame)
    else:
        buf.sock.sendall(frame)


def ok(opcode, body):
    return opcode, FLAG_RESP, body


def err(text):
    return OP_ERR, FLAG_RESP, text if isinstance(text, bytes) else text.encode()


def parse_kv(body):
    fields = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text):
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_ticket(nonce):
    mac = hmac.new(TICKET_KEY.encode(), nonce.encode(), hashlib.sha256).hexdigest()[:32]
    return "tkt.%s.%s" % (nonce, mac)


def verify_ticket(ticket):
    try:
        prefix, nonce, mac = ticket.split(".")
    except ValueError:
        return False
    if prefix != "tkt":
        return False
    with state.lock:
        exp = state.nonces.get(nonce, 0)
    if exp < time.time():
        return False
    expect = hmac.new(TICKET_KEY.encode(), nonce.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(expect, mac)


def ledger_bind(epoch, tip):
    msg = ("bind|%s|%s" % (epoch, tip)).encode()
    return hmac.new(state.repl_key.encode(), msg, hashlib.sha256).hexdigest()[:32]


def mac_hello(epoch, tip, peer):
    canonical = "hsp-repl/1|hello|%s|%s|%s" % (epoch, tip, peer)
    digest = hmac.new(state.repl_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return canonical, digest


def mac_blob(epoch, tip, bind, stream_id, body):
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "hsp-repl/1|blob|%s|%s|%s|%s|%s" % (epoch, tip, bind, stream_id, body_sha)
    digest = hmac.new(state.repl_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return canonical, digest, body_sha


def pack_peer_hello(peer, epoch, tip_hex, mac_hex):
    peer_b = peer.encode()
    return struct.pack("<H", len(peer_b)) + peer_b + struct.pack("<I", epoch) + bytes.fromhex(tip_hex) + bytes.fromhex(mac_hex)


def pack_commit_blob(stream_id, epoch, tip_hex, bind_hex, body, mac_hex):
    stream_b = stream_id.encode()
    return (
        struct.pack("<H", len(stream_b))
        + stream_b
        + bytes([1])
        + struct.pack("<I", epoch)
        + bytes.fromhex(tip_hex)
        + bytes.fromhex(bind_hex)
        + struct.pack("<I", len(body))
        + body
        + bytes.fromhex(mac_hex)
    )


def snapshot():
    with state.lock:
        epoch = state.epoch
        tip = state.tip
        bind = ledger_bind(epoch, tip)
    return epoch, tip, bind


def resolve_stream(stream_id):
    if not stream_id or len(stream_id) > 400 or "\x00" in stream_id or "\\" in stream_id:
        raise ValueError("stream id rejected")
    if any(part == ".." for part in stream_id.split("/")):
        raise ValueError("stream id rejected")
    # Absolute ids drop the log root. os.path.join does the same on POSIX.
    if stream_id.startswith("/"):
        return stream_id
    return state.log_root.rstrip("/") + "/" + stream_id


def trace_add(text):
    with state.lock:
        if time.time() > state.trace_until:
            return
        state.trace.append(text)
        del state.trace[:-40]


def http_response(sock, status, reason, body, content_type="text/html; charset=utf-8", extra=None):
    if isinstance(body, str):
        body = body.encode()
    headers = [
        "HTTP/1.1 %s %s" % (status, reason),
        "Server: helioform-relay/4.2",
        "Content-Type: %s" % content_type,
        "Content-Length: %s" % len(body),
        "Connection: close",
        "Cache-Control: no-store",
    ]
    if extra:
        headers.extend(extra)
    sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)


def page(title, body):
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s — Helioform Relay</title>
<style>
body { margin: 0; background: #f4f1ea; color: #1c1915; font: 15px/1.5 Georgia, "Iowan Old Style", serif; }
header { background: #1f3a34; color: #f4f1ea; padding: 16px 28px; }
header a { color: #d7ebe3; margin-right: 16px; text-decoration: none; }
main { max-width: 860px; margin: 0 auto; padding: 28px 20px 64px; }
h1, h2 { font-weight: normal; }
code, pre, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 13px; }
pre { background: #1c1915; color: #f3ecdf; padding: 14px 16px; overflow: auto; }
table { border-collapse: collapse; width: 100%%; }
th, td { border-bottom: 1px solid #d9d3c7; text-align: left; padding: 6px 8px; vertical-align: top; }
a { color: #1f3a34; }
</style>
</head>
<body>
<header>
<strong>Helioform Relay 4.2</strong>
<a href="/">Overview</a>
<a href="/docs/hsp">Mesh protocol</a>
<a href="/console/login">Console</a>
</header>
<main>
%s
</main>
</body>
</html>""" % (html.escape(title), body)


def admin_session(headers):
    raw = headers.get("cookie", "")
    token = ""
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("hsp_session="):
            token = part.split("=", 1)[1]
            break
    if "." not in token:
        return None
    payload_b64, mac_hex = token.split(".", 1)
    expect = hmac.new(state.console_key.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, mac_hex):
        return None
    try:
        data = json.loads(b64url_decode(payload_b64))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    exp = data.get("exp")
    if type(exp) is not int or exp < int(time.time()):
        return None
    if data.get("role") != "admin":
        return None
    if data.get("iss") != state.console_iss or data.get("aud") != state.console_aud:
        return None
    return data


HSP_DOC = page("Mesh protocol", """
<h1>HSP, the Helioform session protocol</h1>
<p>Relay 4.2 accepts the customer mesh on <code>GET /mesh</code>. The framing below is little-endian. Magic is four ASCII bytes, not an integer.</p>
<pre>offset  size  field
0       4     magic    HSP1
4       2     opcode
6       2     flags    bit 0 is set on a reply
8       4     body length
12      n     body</pre>
<p>A success reply repeats the request opcode with flags <code>0x0001</code>. An error is opcode <code>0x007F</code>, flags <code>0x0001</code>, and an ASCII reason.</p>
<h2>Customer websocket</h2>
<p>Request subprotocol <code>hsp.ws.1</code>. Each binary WebSocket message carries one HSP frame. The customer opcodes are:</p>
<table>
<tr><th>opcode</th><th>name</th><th>body</th></tr>
<tr><td>0x01</td><td>HELLO</td><td>optional client name</td></tr>
<tr><td>0x02</td><td>PING</td><td>empty</td></tr>
<tr><td>0x03</td><td>SUBSCRIBE</td><td>ignored; one telemetry line is returned</td></tr>
</table>
<h2>On-box agents</h2>
<p>Agents that cannot mask WebSocket frames request subprotocol <code>hsp.raw.1</code>. After the 101 response the socket is a raw HSP byte stream. The edge authenticates an agent before it can open a channel. Loopback services use this same 12-byte header. Their opcodes are not part of the customer contract.</p>
<p>A normal WebSocket client must not send <code>hsp.raw.1</code>. That subprotocol exists for the appliance agent.</p>
""")

SESSION_DOC = page("Console session", """
<h1>Factory console session</h1>
<p>Operator SSO is not enabled on this appliance. Break-glass access is a factory-signed cookie.</p>
<table>
<tr><th>cookie</th><td><code>hsp_session</code></td></tr>
<tr><th>value</th><td><code>payload_b64.mac_hex</code></td></tr>
<tr><th>payload_b64</th><td>base64url of the JSON object, padding removed</td></tr>
<tr><th>json</th><td>fields <code>iss</code>, <code>aud</code>, <code>role</code>, <code>exp</code>. <code>exp</code> is a unix second and must be in the future. <code>role</code> for an operator is <code>admin</code>.</td></tr>
<tr><th>iss, aud</th><td>must match the factory environment on this appliance</td></tr>
<tr><th>mac_hex</th><td><code>HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)</code> as lowercase hex. The key is the literal environment string, not hex-decoded.</td></tr>
</table>
<p>The signing key is installed by the provisioner. It is not in this document.</p>
""")


def landing():
    return page("Overview", """
<h1>Site relay</h1>
<p>Helioform Relay 4.2 sits at the edge of a generation site. Inverters publish samples onto the mesh. The compliance ledger keeps the audit record that the operator console reviews.</p>
<p>The customer mesh is a WebSocket at <code>/mesh</code>. Read the session notes before writing a client. The operator console is separate from the mesh and does not accept inverter traffic.</p>
<p>Protocol notes live at <a href="/docs/hsp">/docs/hsp</a>. The console is at <a href="/console/login">/console/login</a>.</p>
""")


def login_page(message=""):
    note = "<p>%s</p>" % html.escape(message) if message else ""
    return page("Console", note + """
<h1>Operator console</h1>
<p>Site SSO is not configured. Factory sessions are documented in <a href="/docs/session">the session notes</a>.</p>
<form method="post" action="/console/login">
<p><label>Operator<br><input name="user" autocomplete="username"></label></p>
<p><label>Password<br><input name="password" type="password" autocomplete="current-password"></label></p>
<p><button type="submit">Sign in</button></p>
</form>
""")


TRACE_LEGEND = """inspector: hsp-repl/1
mac: HMAC-SHA256 over mac_canonical, key is the replication cluster key, digest lowercase hex
integers on the wire are little-endian; tip is 32 raw bytes; bind is 16 raw bytes; mac is 32 raw bytes
peer hello body: u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
hello mac_canonical = hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}
commit blob body: u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16] | u32 body_len | body | mac[32]
mode 0x01 replaces the resolved stream file with body
blob mac_canonical = hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha256}
body_sha256 = lowercase hex SHA-256 of the raw body
"""


def automation_page():
    with state.lock:
        output = state.runbook_output
    body = """
<h1>Runbooks</h1>
<p>Compliance actions are files the scheduler executes as the relay user. Stdout and stderr from the last execution are kept here.</p>
<table>
<tr><th>Directory</th><td id="runbook-dir">%s</td></tr>
<tr><th>Header</th><td id="runbook-header">HSP-RUNBOOK</td></tr>
<tr><th>Interval</th><td>%ss, and whenever a new file is written</td></tr>
</table>
<h2>Last output</h2>
<pre id="runbook-output">%s</pre>
""" % (html.escape(RUNBOOK_DIR), state.interval, html.escape(output))
    return page("Runbooks", body)


def trace_page():
    with state.lock:
        lines = list(state.trace)
        armed = time.time() < state.trace_until
    live = "\n".join(lines) if lines else "(no frames yet)"
    status = "capturing" if armed else "idle"
    body = """
<h1>Peer trace</h1>
<p>Decodes the replication conversation between the site collector and recordd. The cluster key is not shown.</p>
<p>Status: <strong>%s</strong></p>
<form method="post" action="/console/trace"><button type="submit">Capture 45s</button></form>
<h2>Decoder</h2>
<pre>%s</pre>
<h2>Frames</h2>
<pre id="trace">%s</pre>
""" % (status, html.escape(TRACE_LEGEND), html.escape(live))
    return page("Peer trace", body)


def require_admin(headers, sock):
    if admin_session(headers) is None:
        http_response(sock, 401, "Unauthorized", page("Console", "<h1>Authentication required</h1><p><a href=\"/console/login\">Return to sign in</a></p>"))
        return False
    return True


def route(method, target, headers, req_body, buf):
    path = target.split("?", 1)[0]
    sock = buf.sock

    if method == "GET" and path == "/":
        http_response(sock, 200, "OK", landing())
        return
    if method == "GET" and path == "/healthz":
        http_response(sock, 200, "OK", "ok\n", "text/plain; charset=utf-8")
        return
    if method == "GET" and path == "/docs/hsp":
        http_response(sock, 200, "OK", HSP_DOC)
        return
    if method == "GET" and path == "/docs/session":
        http_response(sock, 200, "OK", SESSION_DOC)
        return
    if method == "GET" and path == "/console/login":
        http_response(sock, 200, "OK", login_page())
        return
    if method == "POST" and path == "/console/login":
        http_response(sock, 200, "OK", login_page("Invalid credentials."))
        return
    if path == "/console/trace":
        if not require_admin(headers, sock):
            return
        if method == "POST":
            with state.lock:
                state.trace_until = time.time() + 45
                state.trace = []
        http_response(sock, 200, "OK", trace_page())
        return
    if method == "GET" and path == "/console/automation":
        if not require_admin(headers, sock):
            return
        http_response(sock, 200, "OK", automation_page())
        return
    if method == "GET" and path == "/console":
        if not require_admin(headers, sock):
            return
        http_response(sock, 200, "OK", page("Console", "<h1>Mesh operator</h1><p><a href=\"/console/trace\">Peer trace</a></p><p><a href=\"/console/automation\">Runbooks</a></p>"))
        return
    if method == "GET" and path == "/mesh":
        handle_mesh(buf, headers)
        return
    http_response(sock, 404, "Not Found", page("Missing", "<h1>Not found</h1>"))


def ws_accept(key):
    digest = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def handle_mesh(buf, headers):
    upgrade = headers.get("upgrade", "").lower()
    if upgrade != "websocket" or "upgrade" not in headers.get("connection", "").lower():
        http_response(buf.sock, 400, "Bad Request", "expected websocket upgrade\n", "text/plain")
        return
    if headers.get("sec-websocket-version") != "13" or "sec-websocket-key" not in headers:
        http_response(buf.sock, 400, "Bad Request", "websocket key required\n", "text/plain")
        return
    offered = [p.strip() for p in headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
    if "hsp.raw.1" in offered:
        chosen = "hsp.raw.1"
        transport = "raw"
    elif "hsp.ws.1" in offered:
        chosen = "hsp.ws.1"
        transport = "ws"
    else:
        http_response(
            buf.sock,
            400,
            "Bad Request",
            "supported subprotocols: hsp.ws.1, hsp.raw.1\n",
            "text/plain",
        )
        return
    accept = ws_accept(headers["sec-websocket-key"])
    raw = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Sec-WebSocket-Protocol: %s\r\n"
        "\r\n"
    ) % (accept, chosen)
    buf.sock.sendall(raw.encode())
    edge_loop(buf, transport)


def proxy_authorize_legacy(upgraded):
    """CONNECT-proxy check kept for hsp.raw.1.

    A finished HTTP upgrade is treated as proof that proxy authentication
    already ran. On this public listener it has not.
    """
    return bool(upgraded)


def dial_error(transport, host):
    if host != "127.0.0.1":
        return "err: egress denied"
    if transport == "raw":
        if proxy_authorize_legacy(True):
            return None
        return "err: proxy auth required"
    return "err: scope edge.dial required"


def handle_edge(transport, body, opcode):
    if opcode == OP_HELLO:
        if transport == "raw":
            banner = (
                "hsp-edge/4.2 transport=raw auth=legacy-proxy\n"
                "commands=HELLO:0x01,PING:0x02,DIAL:0x10\n"
                "dial=host:port\n"
                "dial-ack=splices\n"
                "egress=127.0.0.1\n"
            )
        else:
            banner = (
                "hsp-edge/4.2 transport=websocket auth=session\n"
                "commands=HELLO:0x01,PING:0x02,SUBSCRIBE:0x03\n"
            )
        return ok(OP_HELLO, banner)
    if opcode == OP_PING:
        return ok(OP_PING, "pong\n")
    if opcode == OP_SUBSCRIBE and transport == "ws":
        return ok(OP_SUBSCRIBE, "site=north kw=14.2\n")
    if opcode == OP_DIAL:
        return do_dial(transport, body)
    return err("err: unknown opcode")


def do_dial(transport, body):
    try:
        text = body.decode().strip()
        host, sep, port_s = text.rpartition(":")
        port = int(port_s)
        if not sep or not host or not (1 <= port <= 65535):
            raise ValueError
    except Exception:
        return err("err: dial target required (host:port)")
    reason = dial_error(transport, host)
    if reason:
        return err(reason)
    try:
        remote = socket.create_connection((host, port), timeout=2)
        tune(remote)
    except Exception:
        return err("err: dial failed")
    log("dial %s:%s via %s" % (host, port, transport))
    return ("splice", remote)


def edge_loop(buf, transport):
    while True:
        opcode, _flags, body = read_edge_frame(transport, buf)
        reply = handle_edge(transport, body, opcode)
        if isinstance(reply, tuple) and reply and reply[0] == "splice":
            send_edge(transport, buf, *ok(OP_DIAL, "ok splice\n"))
            splice(buf, reply[1])
            return
        send_edge(transport, buf, *reply)


def splice(buf, remote):
    if buf.buf:
        remote.sendall(buf.buf)
        buf.buf = b""
    left = buf.sock

    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    worker = threading.Thread(target=pump, args=(remote, left), daemon=True)
    worker.start()
    pump(left, remote)
    try:
        remote.close()
    except Exception:
        pass


def catalog_hello():
    nonce = os.urandom(16).hex()
    with state.lock:
        state.nonces[nonce] = time.time() + 600
    text = (
        "nonce=%s\n"
        "ticket_opcode=0x20\n"
        "ticket_body=nonce\n"
        "export_opcode=0x30\n"
        "export_fields=ticket,path\n"
        "status_opcode=0x40\n"
        "status_fields=ticket\n"
        "body=key=value lines\n"
        "services:\n"
        "127.0.0.1:7710 catalogd\n"
        "127.0.0.1:7711 provd\n"
        "127.0.0.1:7712 recordd\n"
    ) % nonce
    return ok(OP_HELLO, text)


def serve_catalog(sock):
    buf = BufSock(sock)
    while True:
        opcode, _flags, body = read_edge_frame("raw", buf)
        if opcode == OP_HELLO:
            reply = catalog_hello()
        elif opcode == OP_TICKET:
            nonce = body.decode("utf-8", "replace").strip()
            with state.lock:
                known = nonce in state.nonces and state.nonces[nonce] >= time.time()
            if not known:
                reply = err("err: nonce mismatch")
            else:
                reply = ok(OP_TICKET, "ticket=%s\nttl=600\n" % issue_ticket(nonce))
        else:
            reply = err("err: unknown opcode")
        sock.sendall(pack_frame(*reply))


def export_env(body):
    fields = parse_kv(body)
    if not verify_ticket(fields.get("ticket", "")):
        return err("err: mesh ticket required")
    raw_path = fields.get("path", "")
    norm = os.path.normpath(raw_path)
    if not norm.endswith(".env"):
        return err("err: dotenv loader refuses non-env path")
    root = os.path.normpath(ENV_DIR)
    try:
        inside = os.path.commonpath([norm, root]) == root
    except ValueError:
        inside = False
    if not inside:
        return err("err: path outside provision root")
    if not os.path.isfile(norm):
        return err("err: no such env file")
    with open(norm, "rb") as handle:
        data = handle.read(65536)
    return ok(OP_EXPORT, data)


def serve_prov(sock):
    buf = BufSock(sock)
    while True:
        opcode, _flags, body = read_edge_frame("raw", buf)
        if opcode == OP_HELLO:
            reply = ok(OP_HELLO, "provd dotenv broker\nexport_opcode=0x30\nexport_fields=ticket,path\n")
        elif opcode == OP_EXPORT:
            reply = export_env(body)
        else:
            reply = err("err: unknown opcode")
        sock.sendall(pack_frame(*reply))


def serve_status(sock):
    buf = BufSock(sock)
    while True:
        opcode, _flags, body = read_edge_frame("raw", buf)
        if opcode == OP_HELLO:
            reply = ok(OP_HELLO, "recordd status\nstatus_opcode=0x40\nstatus_fields=ticket\nwrite=peer-only\n")
        elif opcode == OP_STATUS:
            fields = parse_kv(body)
            if not verify_ticket(fields.get("ticket", "")):
                reply = err("err: mesh ticket required")
            else:
                epoch, tip, bind = snapshot()
                text = "epoch=%s\ntip=%s\nbind=%s\nrepl_port=7713\nwrite=peer-only\n" % (epoch, tip, bind)
                reply = ok(OP_STATUS, text)
        elif opcode == OP_BLOB:
            reply = err("err: peer handshake required")
        else:
            reply = err("err: unknown opcode")
        sock.sendall(pack_frame(*reply))


def unpack_peer_hello(body):
    if len(body) < 2:
        raise ValueError("malformed peer hello")
    (n,) = struct.unpack_from("<H", body, 0)
    i = 2
    need = i + n + 4 + 32 + 32
    if n > 200 or len(body) != need:
        raise ValueError("malformed peer hello")
    peer = body[i:i + n].decode()
    i += n
    (epoch,) = struct.unpack_from("<I", body, i)
    i += 4
    tip = body[i:i + 32].hex()
    i += 32
    mac = body[i:i + 32].hex()
    return peer, epoch, tip, mac


def unpack_blob(body):
    if len(body) < 2:
        raise ValueError("malformed blob")
    (n,) = struct.unpack_from("<H", body, 0)
    i = 2
    if n > 400 or len(body) < i + n + 1 + 4 + 32 + 16 + 4:
        raise ValueError("malformed blob")
    stream_id = body[i:i + n].decode()
    i += n
    mode = body[i]
    i += 1
    (epoch,) = struct.unpack_from("<I", body, i)
    i += 4
    tip = body[i:i + 32].hex()
    i += 32
    bind = body[i:i + 16].hex()
    i += 16
    (blen,) = struct.unpack_from("<I", body, i)
    i += 4
    if blen > MAX_FRAME or len(body) != i + blen + 32:
        raise ValueError("malformed blob")
    blob = body[i:i + blen]
    mac = body[i + blen:i + blen + 32].hex()
    return stream_id, mode, epoch, tip, bind, blob, mac


def execute_runbook(path):
    real = os.path.realpath(path)
    if os.path.dirname(real) != os.path.realpath(RUNBOOK_DIR):
        return
    try:
        data = open(real, "rb").read()
    except OSError:
        return
    digest = hashlib.sha256(data).hexdigest()
    with state.lock:
        if state.runbook_seen.get(real) == digest:
            return
        state.runbook_seen[real] = digest
    if data.startswith(b"HSP-RUNBOOK\r\n"):
        code_bytes = data[len(b"HSP-RUNBOOK\r\n"):]
    elif data.startswith(b"HSP-RUNBOOK\n"):
        code_bytes = data[len(b"HSP-RUNBOOK\n"):]
    else:
        with state.lock:
            state.runbook_output = "rejected header"
        return
    try:
        code = code_bytes.decode()
    except UnicodeDecodeError:
        with state.lock:
            state.runbook_output = "rejected header"
        return
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            timeout=3,
            cwd="/tmp",
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONUNBUFFERED": "1"},
            start_new_session=True,
        )
        text = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        text = "timeout\n"
    except Exception as exc:
        text = "exec failed: %s\n" % exc
    with state.lock:
        state.runbook_output = text[-4000:]
    log("runbook %s bytes=%s" % (os.path.basename(real), len(data)))


def commit_blob(stream_id, mode, epoch, tip, bind, body, mac_hex):
    if mode != 1:
        return err("err: unsupported mode")
    try:
        path = resolve_stream(stream_id)
    except ValueError as exc:
        return err("err: " + str(exc))
    with state.lock:
        current_epoch = state.epoch
        current_tip = state.tip
        current_bind = ledger_bind(current_epoch, current_tip)
        fresh = epoch == current_epoch and tip == current_tip and bind == current_bind
        if fresh:
            canonical, digest, body_sha = mac_blob(epoch, tip, bind, stream_id, body)
        else:
            canonical, digest, body_sha = "", "", ""
    if not fresh:
        return err("err: stale tip")
    if not hmac.compare_digest(digest, mac_hex):
        return err("err: bad mac")
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        return err("err: open failed")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    except OSError:
        return err("err: open failed")
    with state.lock:
        if state.tip == tip:
            state.tip = hashlib.sha256(bytes.fromhex(tip) + stream_id.encode() + body).hexdigest()
    trace_add(
        "opcode=0x0017\nmac_canonical=%s\nstream_id=%s\nmode=0x01\nbody_sha256=%s\nresolved=%s\n"
        % (canonical, stream_id, body_sha, path)
    )
    execute_runbook(path)
    return ok(OP_BLOB, "ok path=%s\n" % path)


def serve_repl(sock):
    buf = BufSock(sock)
    hello_ok = False
    while True:
        opcode, _flags, body = read_edge_frame("raw", buf)
        if opcode == OP_PEER_HELLO:
            try:
                peer, epoch, tip, mac = unpack_peer_hello(body)
            except Exception:
                sock.sendall(pack_frame(*err("err: malformed peer hello")))
                continue
            if peer != state.peer:
                sock.sendall(pack_frame(*err("err: unknown peer")))
                continue
            with state.lock:
                fresh = epoch == state.epoch and tip == state.tip
            if not fresh:
                sock.sendall(pack_frame(*err("err: stale tip")))
                continue
            canonical, digest = mac_hello(epoch, tip, peer)
            if not hmac.compare_digest(digest, mac):
                sock.sendall(pack_frame(*err("err: bad mac")))
                continue
            hello_ok = True
            trace_add("opcode=0x0011\nmac_canonical=%s\npeer=%s\nepoch=%s\ntip=%s\n" % (canonical, peer, epoch, tip))
            sock.sendall(pack_frame(*ok(OP_PEER_HELLO, "ok\n")))
            continue
        if opcode == OP_BLOB:
            if not hello_ok:
                sock.sendall(pack_frame(*err("err: peer hello required")))
                continue
            try:
                stream_id, mode, epoch, tip, bind, blob, mac = unpack_blob(body)
            except Exception:
                sock.sendall(pack_frame(*err("err: malformed blob")))
                continue
            reply = commit_blob(stream_id, mode, epoch, tip, bind, blob, mac)
            sock.sendall(pack_frame(*reply))
            continue
        sock.sendall(pack_frame(*err("err: peer handshake required")))


def run_service(port, fn):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            tune(self.request)
            try:
                fn(self.request)
            except Exception:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log("listen 127.0.0.1:%s" % port)
    return server


def collector_loop():
    time.sleep(0.5)
    sample = b'{"event":"inverter.sample","site":"north","kw":14.2}\n'
    stream_id = "site-north-inverter-14.log"
    while True:
        try:
            epoch, tip, bind = snapshot()
            _canonical, digest = mac_hello(epoch, tip, state.peer)
            hello = pack_peer_hello(state.peer, epoch, tip, digest)
            _c2, blob_mac, _sha = mac_blob(epoch, tip, bind, stream_id, sample)
            blob = pack_commit_blob(stream_id, epoch, tip, bind, sample, blob_mac)
            sock = socket.create_connection(("127.0.0.1", 7713), timeout=3)
            tune(sock)
            link = BufSock(sock)
            sock.sendall(pack_frame(OP_PEER_HELLO, 0, hello))
            op, _flags, reply = read_edge_frame("raw", link)
            if op == OP_ERR:
                raise RuntimeError(reply.decode("utf-8", "replace"))
            sock.sendall(pack_frame(OP_BLOB, 0, blob))
            op, _flags, reply = read_edge_frame("raw", link)
            if op == OP_ERR:
                raise RuntimeError(reply.decode("utf-8", "replace"))
            sock.close()
        except Exception as exc:
            log("collector: %s" % exc)
        time.sleep(state.interval)


def runbook_loop():
    while True:
        time.sleep(state.interval)
        try:
            for name in os.listdir(RUNBOOK_DIR):
                path = os.path.join(RUNBOOK_DIR, name)
                if os.path.isfile(path):
                    execute_runbook(path)
        except Exception:
            pass


def serve_public():
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            tune(self.request)
            buf = BufSock(self.request)
            try:
                raw = buf.read_until(b"\r\n\r\n", 16384)
                text = raw.decode("iso-8859-1")
                head = text.split("\r\n\r\n", 1)[0]
                lines = head.split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers = {}
                for line in lines[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                length = int(headers.get("content-length", "0") or "0")
                if length > 65536:
                    http_response(self.request, 413, "Payload Too Large", "too large\n", "text/plain")
                    return
                req_body = buf.read_exact(length) if length else b""
                route(method, target, headers, req_body, buf)
            except EOFError:
                pass
            except Exception:
                traceback.print_exc()
            finally:
                try:
                    self.request.close()
                except Exception:
                    pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server((HOST, PORT), Handler)
    log("helioform relay listening on %s:%s" % (HOST, PORT))
    server.serve_forever()


def main():
    load_config()
    os.makedirs(state.log_root, exist_ok=True)
    os.makedirs(RUNBOOK_DIR, exist_ok=True)
    run_service(7710, serve_catalog)
    run_service(7711, serve_prov)
    run_service(7712, serve_status)
    run_service(7713, serve_repl)
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=runbook_loop, daemon=True).start()
    serve_public()


if __name__ == "__main__":
    main()
