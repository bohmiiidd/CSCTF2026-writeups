#!/bin/sh
# Runtime flag injection — CTF infrastructure sets FLAG env var
if [ -n "$FLAG" ]; then
    printf '%s\n' "$FLAG" > /flag
fi
chmod 0400 /flag 2>/dev/null
exec python3 -u /opt/helioform/relay.py
