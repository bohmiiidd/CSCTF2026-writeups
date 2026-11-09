# CSCTF 2026

Challenge author writeups and source for **[CSCTF 2026](https://2026.chronos-security.ro/)** — a competitive CTF with **650+ teams** and **2,600+ players**.

<img width="1617" height="918" alt="image" src="https://github.com/user-attachments/assets/939f61b6-7e8e-4787-9e77-629b29651058" />


**Author:** [bohmiiidd](https://github.com/bohmiiidd)

---

## Challenges

### Pwn — [Phantom Device](https://2026.chronos-security.ro/challenges#Phantom%20Device-9164) (Hard, 900 pts) ~25 solve
<img width="987" height="547" alt="image" src="https://github.com/user-attachments/assets/58963299-7ae4-4a5d-8c29-bf2e80fd70e7" />

**Exploit chain:** Heap overflow in `afc_receive_data` (CVE-2026-116258) + uninitialized heap read in `afc_file_open` (CVE-2026-116261) in libimobiledevice 1.3.0 → Large Bin Attack → House of Apple 2 FSOP → `system()` RCE under glibc 2.39 (Full RELRO, PIE, NX, canaries, FORTIFY).

| | |
|---|---|
| Writeup | [pwn/phantom-device/README.md](pwn/phantom-device/README.md) |
| Optimized exploit | [pwn/phantom-device/solve.py](pwn/phantom-device/solve.py) |
| Full challenge source | [pwn/phantom-device/challenge/](pwn/phantom-device/challenge/) |

---

### Web — [Helioform Relay](https://2026.chronos-security.ro/challenges#Helioform%20Relay-9163) (Hard, 900 pts) 113 solve

<img width="982" height="552" alt="image" src="https://github.com/user-attachments/assets/28c3db7c-8fe2-4438-a3aa-67b5da06e643" />

**Exploit chain:** Protocol downgrade (`hsp.ws.1` → `hsp.raw.1`) → SSRF via DIAL opcode → environment exfiltration → HMAC session forgery → replication protocol abuse → path traversal via COMMIT_BLOB → runbook execution → flag.

| | |
|---|---|
| Writeup | [web/helioform-relay/README.md](web/helioform-relay/README.md) |
| Solve script | [web/helioform-relay/solve.py](web/helioform-relay/solve.py) |
| Full challenge source | [web/helioform-relay/challenge/](web/helioform-relay/challenge/) |

---
