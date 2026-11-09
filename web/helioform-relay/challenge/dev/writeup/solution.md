# Solution — Helioform Relay

## Prerequisites
- Python 3, standard library only
- Understanding of WebSocket upgrades and binary protocols
- Understanding of HMAC-SHA256

## Overview

The Helioform Relay 4.2 appliance runs a single Python service with:
- A public HTTP server with WebSocket mesh endpoint at `/mesh`
- Four internal loopback services: catalogd (7710), provd (7711), recordd (7712), replication (7713)
- An admin console protected by HMAC-SHA256 signed cookies
- A runbook scheduler that executes files beginning with `HSP-RUNBOOK`

The exploit chain has six phases.

## Step 1 — Enumerate the mesh protocol

Visit `/docs/hsp`. It documents the HSP binary framing (12-byte header: magic `HSP1`, u16le opcode, u16le flags, u32le body length) and two WebSocket subprotocols:
- `hsp.ws.1` — customer: HELLO, PING, SUBSCRIBE
- `hsp.raw.1` — on-box agents: raw HSP byte stream after upgrade, includes DIAL opcode

## Step 2 — Protocol downgrade to hsp.raw.1

Request `hsp.raw.1` on the WebSocket upgrade. The server accepts it because `proxy_authorize_legacy()` treats a completed HTTP upgrade as proof of proxy authentication. This gives access to the DIAL opcode (0x10), which splices the socket to an internal service.

## Step 3 — SSRF via DIAL to internal services

Send DIAL with body `127.0.0.1:7710` to reach catalogd. The HELLO response reveals:
- A nonce for ticket issuance
- The service catalog: catalogd (7710), provd (7711), recordd (7712)

Issue a mesh ticket by sending the nonce back on opcode 0x20 (ISSUE_TICKET).

## Step 4 — Exfiltrate factory environment from provd

DIAL to `127.0.0.1:7711` (provd). Send EXPORT (0x30) with `ticket=<ticket>\npath=/etc/helioform/relay.env`. The dotenv loader serves the file, revealing:
- `CONSOLE_MAC_KEY` — the HMAC signing key for admin sessions
- `CONSOLE_ISS` and `CONSOLE_AUD` — required claims
- `REPLICATION_MAC_KEY` — the key for the replication protocol

## Step 5 — Forge an admin session cookie

Visit `/docs/session` to learn the cookie format: `base64url(json).hmac_sha256_hex`. Forge a cookie:
```python
claims = {"iss": "helioform-factory", "aud": "relay-console", "role": "admin", "exp": int(time.time()) + 3600}
payload_b64 = base64url(json.dumps(claims))
mac = hmac.new(CONSOLE_MAC_KEY, payload_b64, sha256).hexdigest()
cookie = payload_b64 + "." + mac
```

Access `/console/automation` with the forged cookie to learn:
- The runbook directory path
- Files beginning with `HSP-RUNBOOK` are executed by the scheduler

## Step 6 — Arm the peer trace and learn the replication protocol

POST to `/console/trace` to capture a replication exchange from the built-in collector. The trace reveals the exact wire format for PEER_HELLO and COMMIT_BLOB opcodes, including the MAC canonical strings.

## Step 7 — Path traversal via replication COMMIT_BLOB

DIAL to `127.0.0.1:7712` (recordd) to get the current ledger state (epoch, tip, bind). Then DIAL to `127.0.0.1:7713` (replication port).

The `resolve_stream()` function checks for `..` components but allows absolute paths starting with `/`. Set `stream_id` to the runbook directory path + `/intake.py` to write directly into the runbook directory.

Construct the replication messages:
1. **PEER_HELLO** (0x11): peer name, epoch, tip, HMAC
2. **COMMIT_BLOB** (0x17): stream_id, mode=0x01, epoch, tip, bind, body, HMAC

The body is a Python script with the `HSP-RUNBOOK` header that reads `/flag`.

## Step 8 — Read the flag

The runbook scheduler executes the written file. Poll `/console/automation` with the forged cookie to read the output containing the flag.

## Expected output

```
CSCTF{hsp_raw_d0wngrade_pr0xy_dial_env_t4p_runb00k}
```

## Notes

Each step chains into the next — you can't skip ahead. The DIAL needs the downgrade, the forge needs the leaked key, the write needs the replication key, and the exec needs the runbook directory path from the console.
