# uUPX - The Ultimate *Un*Packer for eXecutables

```
             ooooo     ooo  ooooo     ooo  ooooooooo.  ooooooo  ooooo
             `888'     `8'  `888'     `8'  `888   `Y88. `8888    d8'
              888       8    888       8    888   .d88'   Y888..8P
              888       8    888       8    888ooo88P'     `8888'
              888       8    888       8    888           .8PY888.
              `88.    .8'    `88.    .8'    888          d8'  `888b
                `YbodP'        `YbodP'     o888o       o888o  o88888o
```

A fork of [UPX](https://github.com/upx/upx) for security research, focused on unpacking UPX-packed binaries that have had their metadata deliberately clobbered to resist static unpacking.

## Background

[UPX](https://upx.github.io) is a widely-used executable packer. Malware authors frequently use UPX to compress their payloads, then **tamper with the UPX metadata** (magic bytes, checksums, header fields) so that the standard `upx -d` refuses to unpack the binary. This forces analysts to resort to dynamic unpacking (running the binary in a sandbox and dumping at OEP), which has significant drawbacks.

uUPX adds a `--force-unpack` flag that bypasses all metadata validation and recovers the original binary by trusting only the compressed data blocks (`b_info` chain), which must remain intact for the binary to self-execute at runtime.

## Definition: what counts as "UPX-packed"

We consider a binary to be UPX-packed -- regardless of how much metadata has been corrupted -- as long as:

1. **The unpacking stub is unmodified.** The embedded decompression code (assembly entry point + C decompressor) that runs at load time has not been altered.
2. **The binary can unpack itself at runtime.** When executed, the stub successfully decompresses the original program and transfers control to it with full functionality preserved.

If these two conditions hold, then by definition all the information needed to statically recover the original binary is still present in the file. The runtime stub only reads the `b_info` block headers (compression method, block sizes) and the compressed data -- it never checks `UPX!` magic, checksums, `l_info`, `p_info`, or any of the other metadata that `upx -d` validates. Therefore, any metadata that the stub ignores can be freely clobbered without affecting our ability to unpack.

## Usage

```bash
# Standard UPX refuses to unpack a tampered binary
$ upx -d malware.packed -o malware.unpacked
upx: malware.packed: NotPackedException: not packed by UPX

# uUPX force-unpacks it
$ ./upx -d --force-unpack malware.packed -o malware.unpacked
    1032912 <-    407760   39.48%   linux/amd64   malware.unpacked
```

## Advantages over dynamic unpacking (dump at OEP)

When analysts unpack malware dynamically by running it and dumping memory at the original entry point, they lose important information:

- **Section headers are gone.** The runtime loader discards them. uUPX recovers the full section header table (`.text`, `.data`, `.rodata`, `.bss`, `.symtab`, etc.) because they are stored inside the compressed data.
- **Symbol tables are preserved.** If the original binary was not stripped, `uUPX` recovers the symbol table intact. A memory dump has no symbols.
- **Relocations and dynamic linking info are intact.** The GOT, PLT, and relocation tables are restored exactly. Memory dumps require manual IAT reconstruction.
- **Byte-identical output.** uUPX produces the exact original binary, byte-for-byte. No alignment issues, no page-granularity artifacts, no need to fix up PE/ELF headers manually.
- **No execution required.** The malware never runs. No sandbox, no risk of anti-analysis triggers, no network callbacks. Purely static analysis.
- **BuildID preserved.** The GNU BuildID (SHA-1 hash of the binary) is recovered, enabling correlation with debug symbols or known-binary databases.

## What metadata can be clobbered?

uUPX handles all of the following being zeroed, randomized, or scrambled:

| Field | Purpose | Clobbered? |
|-------|---------|-----------|
| `UPX!` magic (all occurrences) | Format detection | Handled |
| `l_info` (checksum, magic, lsize, version, format) | Loader metadata | Handled |
| `p_info` (filesize, blocksize) | Pack metadata | Handled |
| PackHeader (version, format, method, checksums, sizes) | Decompression parameters | Handled |
| `overlay_offset` (last 4 bytes of file) | Locates compressed data | Handled |
| EOF marker (`b_info` with `sz_cpr == UPX_MAGIC`) | End-of-blocks sentinel | Handled |
| Adler32 checksums | Integrity verification | Handled |
| Section names (`UPX0`, `UPX1`) | PE section identification | Handled |

The only data that must remain intact is the **`b_info` block chain** and the **compressed data** itself. This is the minimum required for the runtime decompression stub to function -- if the binary can still self-execute, uUPX can unpack it.

## How it works

The standard `upx -d` unpacker validates extensive metadata before decompressing:

1. Searches for `UPX!` magic to locate the PackHeader
2. Validates version, format, method, header checksum
3. Reads `l_info` and `p_info` for loader and size metadata
4. Verifies Adler32 checksums after decompression
5. Checks decompressed ELF headers match the packed wrapper

With `--force-unpack`, uUPX bypasses all of these and instead:

1. **Reads the PackHeader from the end of the file** (fixed position at `fsize - 36`), falling back to scanning for a valid `b_info` chain if the PackHeader is also scrambled
2. **Derives `blocksize` and `orig_file_size`** from the actual block sizes in the `b_info` chain
3. **Decompresses each block** using the method specified in the per-block `b_info` header
4. **Applies unfiltering** (reverses the x86 call/jump preprocessing) using the filter ID from `b_info`
5. **Writes the output** using the decompressed ELF/PE headers for layout

## Supported formats

- **Linux ELF x86-64 (amd64)** -- fully tested
- **Linux ELF x86 (i386)** -- fully tested
- **Windows PE x86-64** -- metadata bypass implemented, not yet tested against real samples
- **Windows PE x86** -- metadata bypass implemented, not yet tested against real samples

## Building

```bash
git submodule update --init
make build/release -j$(nproc)
# Binary at build/release/upx
```

## Testing

A comprehensive test suite is included that compiles test binaries, packs them with UPX, applies 9 different clobbering strategies, and verifies byte-identical recovery:

```bash
python3 test_force_unpack.py
```

```
Testing architecture: amd64   -- 9/9 passed
Testing architecture: i386    -- 9/9 passed
TOTAL: 18 passed, 0 failed
```

## Acknowledgments

Based on [UPX](https://github.com/upx/upx) by Markus Oberhumer, Laszlo Molnar & John Reiser.
