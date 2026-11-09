# Creation Notes — Phantom Device

## Architecture

Direct-connect pwn: a remote service on port 1337 accepts connections via socat. The player's TCP socket is passed directly to the vulnerable AFC client as stdin. The player's exploit acts as a malicious AFC server, speaking the protocol over the same inbound connection. No outbound connectivity is required — the container operates in "one port in, nothing out" mode.

### Ground truth

- **Target:** libimobiledevice 1.3.0 (`libimobiledevice-1.0.so.6`) from Ubuntu 24.04
- **Runtime:** glibc 2.39 from Ubuntu 24.04
- **Vulnerabilities:**
  - CVE-2026-116258 (CWE-122): Heap overflow in `afc_receive_data()` — `entire_length` controls `malloc()`, `this_length` controls `recv()`, no bounds check
  - CVE-2026-116261 (CWE-908): Uninitialized heap read in `afc_file_open()` — `memcpy(handle, data, 8)` always copies 8 bytes regardless of actual body size
- **Technique:** Large Bin Attack via glibc 2.39 "smallest" insertion path + House of Apple 2 FSOP
- **ASLR defeat:** 1/256 brute force on safe-linked heap fd (8-bit uncertainty)

### Exploit chain summary

```
Phase 1: Heap grooming via AFC DIR response sizes
Phase 2: Info leaks via CVE-2026-116261 (libc + heap)
Phase 3: Large Bin Attack via CVE-2026-116258 (corrupt _IO_list_all)
Phase 4: House of Apple 2 FSOP → system("cat /flag* >&0")
```

### Network model

The client uses socat's stdin fd for AFC communication. stdout/stderr are redirected to /dev/null so printf debug output doesn't corrupt the binary protocol stream. The RCE command writes to fd 0 (the original socket) via `>&0`.

In legacy mode (`./client <host> <port>`), the client connects outbound for local patchelf testing.

## Build and generation

### Dependencies

- Ubuntu 24.04 (or Docker image `ubuntu:24.04`)
- `libimobiledevice-dev` 1.3.0 (Ubuntu 24.04 package)
- `gcc`, `pkg-config`
- glibc 2.39

### Compile the client

```bash
gcc -g -O0 -o client client.c \
    $(pkg-config --cflags --libs libimobiledevice-1.0) -lpthread
```

### Extract challenge files

```bash
# From a Docker build:
cd docker/
docker compose build
bash build_and_extract.sh
```

### Player setup

```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . client
chmod +x client
```

## References

- libimobiledevice 1.3.0 — CVE-2026-116258, CVE-2026-116261
- glibc 2.39 malloc — `malloc/malloc.c`
- [how2heap](https://github.com/shellphish/how2heap) — Large Bin Attack
- [House of Apple 2](https://roderick01.com/House-of-Apple-一种新的glibc中IO攻击方法)
- [Safe linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)

## Testing

Solver averages ~30s (128 attempts), worst case ~80s. Docker image ~280 MB.

```
Run 1:   62 attempts,  24.6s — libc=0x78f8d5200000
Run 2:  111 attempts,  17.3s — libc=0x78b86ea00000
Run 3:   97 attempts,  41.8s — libc=0x777e1b800000
```

### Local Docker testing

```bash
cd docker/
docker compose up -d --build
bash build_and_extract.sh      # extracts libc, ld, client, libs → docker/libs/
python3 solve.py localhost 1337
```

No callback IP needed — the exploit connects directly to port 1337.

**Libc extraction:** `main_arena` is not in the dynamic symbol table (`.dynsym`)
so `pwntools` can't resolve it. The exploit falls back to the hardcoded offset
`0x204ac0` which is correct for glibc 2.39 (Ubuntu 24.04). Other offsets
(`system`, `_IO_list_all`, `_IO_wfile_jumps`) resolve from the extracted libc.

## Flag injection

The flag is at `/flag.txt` in the container. The exploit runs `system("cat /flag* >&0")` and the output goes to fd 0 (the player's TCP socket). For CTFd per-team deployment, inject via `FLAG` environment variable and write to `/flag.txt` at container startup.

## Notes

Heap layout can shift across kernel versions / container runtimes. Tested on Ubuntu 24.04 with default Docker. Worst-case brute force is ~80s which fits well within the 60s per-connection timeout. The challenge requires zero outbound connectivity — all traffic flows over the single inbound TCP connection on port 1337.
