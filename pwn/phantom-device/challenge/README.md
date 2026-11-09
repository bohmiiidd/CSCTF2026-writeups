# Phantom Device — Pwn (Hard, 500 pts)

> A captured drone from the Vostari military contains an intact mobile communication module. Intelligence analysts use standard extraction tools to pull data — but the device is not what it seems. Something on the wire is lying about packet sizes.

## Challenge overview

A remote service on port 1337 runs a vulnerable AFC client (libimobiledevice v1.3.0). When you connect, the client immediately starts making AFC requests over your TCP connection.

Write a malicious AFC server that exploits CVE-2026-116258 (heap overflow) + CVE-2026-116261 (uninitialized read) to get RCE on the client process and read `/flag.txt` from the container.

Players also get the client binary and libraries for local analysis/testing.

## Player files

| File | Description |
|------|-------------|
| `client` | Compiled victim binary (ELF x86-64, links libimobiledevice) |
| `libc.so.6` | glibc 2.39 — Ubuntu 24.04 |
| `ld-linux-x86-64.so.2` | Dynamic linker |
| `libimobiledevice-1.0.so.6` | Vulnerable library (v1.3.0) |
| `libplist-2.0.so.4` | Runtime dependency |

## Local testing (patchelf)

```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . client
chmod +x client
# Legacy outbound mode for local testing:
./client <your_server_host> <your_server_port>
```

## Local testing (Docker)

```bash
cd docker/
docker compose up -d --build

# Extract libc and ld from the container:
bash build_and_extract.sh

# Run the exploit (connects directly — no callback needed):
python3 solve.py localhost 1337
```

## Remote

```bash
# Connect directly and speak AFC protocol:
python3 exploit.py <challenge_host> 1337
```

## Difficulty

Hard. Expect 3-6 hours for first solve. Covers binary RE, heap exploitation on modern glibc, info leak development, and FSOP.

## Network model

The container accepts inbound connections only (one port in, nothing out). The player connects to port 1337 and the AFC protocol runs over that same TCP connection. No outbound connectivity is required.

## Structure

```
phantom-device/
├── challenge.yml           # CTFd metadata
├── README.md               # This file
├── files/                  # Player handout
│   ├── client
│   ├── libc.so.6
│   ├── ld-linux-x86-64.so.2
│   ├── libimobiledevice-1.0.so.6
│   ├── libplist-2.0.so.4
│   ├── Dockerfile
│   ├── handler.sh
│   └── entrypoint.sh
├── dev/
│   ├── writeup/
│   │   ├── description.md  # Player-facing description
│   │   ├── hints.md        # Progressive hints
│   │   ├── solution.md     # Full solve walkthrough
│   │   └── creation.md     # Author notes and anchors
│   └── src/
│       ├── client/
│       │   └── client.c    # Victim source
│       └── exploit/
│           ├── __init__.py
│           └── server.py   # Reference exploit (solution)
└── docker/
    ├── Dockerfile
    ├── docker-compose.yml
    ├── client.c            # Client source (compiled in container)
    ├── flag.txt
    ├── entrypoint.sh       # socat listener on port 1337
    ├── handler.sh          # Per-connection: exec client (uses stdin fd)
    ├── solve.py            # Local solver (extracts libs + runs exploit)
    ├── build_and_extract.sh  # Build image + extract libc/ld/libs
    ├── extract_libs.sh     # Extract libs from existing image
    └── run_exploit.sh      # Quick-run exploit with correct flags
```
