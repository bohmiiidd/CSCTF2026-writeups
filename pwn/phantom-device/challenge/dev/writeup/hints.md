# Hints

## Hint 1 (free — reorientation)
The AFC protocol header has two length fields. What happens when they disagree?

## Hint 2 (-50 points)
`afc_file_open` copies 8 bytes from the response body — even when fewer arrived. Where do the extra bytes come from on a recycled chunk?

## Hint 3 (-100 points)
glibc 2.39 large bin insertion has two paths. The "smallest" path skips the `bk` integrity check. What can you write, and where?

## Hint 4 (-150 points)
`_IO_flush_all_lockp` walks `_IO_list_all` on `exit()`. If that pointer leads to your controlled heap data, the vtable dispatch chain is: `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `__doallocate`. The command string lives in `_flags`.
