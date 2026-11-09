# Helioform Relay — Web (Hard, 500 pts)

> A site relay appliance sits at the edge of the Kovari National Grid. The operator console is locked, but the mesh protocol documentation is public. Somewhere between the legacy agent wire and the compliance ledger, there is a path the provisioner never closed.

## Challenge overview

Players interact with a Helioform Relay 4.2 appliance — a single Python service exposing an HTTP server with WebSocket mesh, internal loopback microservices, and an admin console. The flag is at `/flag` inside the container.

The exploit chain requires six distinct steps: protocol downgrade, SSRF via DIAL opcode, environment file exfiltration, HMAC session forging, replication protocol abuse, and path traversal to write a runbook that executes arbitrary code.

## Setup

```bash
cd docker
docker compose up --build -d
# Challenge available at http://localhost:8080
```

## Difficulty

Hard. Expect 2-4 hours for first solve. Covers WebSocket protocol analysis, SSRF, HMAC forgery, binary protocol RE, and path traversal.

## Structure

```
helioform-relay/
├── challenge.yml           # CTFd metadata
├── README.md               # This file
├── files/                  # Player handout (empty — no client-side files)
├── dev/
│   ├── writeup/
│   │   ├── description.md  # Player-facing description
│   │   ├── hints.md        # Progressive hints
│   │   ├── solution.md     # Full solve walkthrough
│   │   └── creation.md     # Author notes and anchors
│   └── src/
│       └── solve/
│           └── solve.py    # Reference solver
└── docker/
    ├── Dockerfile
    ├── docker-compose.yml
    ├── flag.txt
    ├── run.sh
    └── src/
        ├── relay.py        # Challenge server
        ├── relay.env       # Factory environment
        └── collector.env   # Collector identity
```
