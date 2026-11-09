# Creation Notes — Helioform Relay

## Architecture

The challenge is a single Python service (~1090 lines) that implements a complete appliance with HTTP, WebSocket, and four internal TCP services. No external dependencies beyond the Python standard library.

### Ground truth

- **Target:** Helioform Relay 4.2 (custom Python service)
- **Runtime:** Python 3.11-slim Docker image
- **Vulnerability chain:**
  1. Protocol downgrade: `hsp.raw.1` subprotocol bypasses session authentication via `proxy_authorize_legacy()` treating HTTP upgrade as proxy auth
  2. SSRF: DIAL opcode (0x10) splices the socket to internal loopback services
  3. Sensitive file read: provd EXPORT opcode serves any `.env` file under `/etc/helioform/`
  4. Session forgery: HMAC-SHA256 cookie with leaked `CONSOLE_MAC_KEY`, `ISS`, `AUD`
  5. Path traversal: `resolve_stream()` allows absolute `stream_id` paths (checks for `..` but not leading `/`)
  6. Code execution: runbook scheduler executes files beginning with `HSP-RUNBOOK` header

### Exploit chain summary

```
Phase 1: Protocol downgrade (hsp.ws.1 → hsp.raw.1)
Phase 2: SSRF via DIAL to loopback services
Phase 3: Environment exfiltration from provd
Phase 4: Admin session cookie forgery
Phase 5: Replication protocol abuse (PEER_HELLO + COMMIT_BLOB)
Phase 6: Path traversal + runbook execution → flag
```

## Build and generation

### Dependencies

- Docker
- Python 3.11+ (for solver)

### Deploy

```bash
cd docker
docker compose up --build -d
```

The flag is written to `/flag` in the container via the Dockerfile. For CTFd per-team deployment, inject via `FLAG` environment variable and write to `/flag` at container startup.

## Testing

Solver runs in ~8s, deterministic (no brute force). Docker image is ~150 MB.

The collector advances the ledger every 5s so the solver retries up to 8 times if the tip goes stale between the status read and the commit.
