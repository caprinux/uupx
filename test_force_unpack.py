#!/usr/bin/env python3
"""
Rigorous test suite for --force-unpack.

Strategy:
  1. Compile a test program with known output
  2. Pack it with UPX
  3. Apply various metadata clobbering strategies
  4. Verify --force-unpack recovers the original byte-for-byte
  5. Verify the recovered binary executes correctly
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

UPX = "/root/upx/build/release/upx"
CC = "gcc"

# ── helpers ──────────────────────────────────────────────────────────

def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)
    return r

def compile_test_binary(src_path, bin_path, arch="amd64"):
    """Compile a static binary with deterministic, verifiable output."""
    with open(src_path, "w") as f:
        f.write(r"""
#include <stdio.h>
#include <string.h>

// Use enough code to exercise multiple compressed blocks
static const char data[4096] = "KNOWN_TEST_PAYLOAD_FOR_VERIFICATION";

int compute(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) sum += i * i;
    return sum;
}

int main() {
    printf("TEST_OUTPUT:%d:%zu\n", compute(100), strlen(data));
    return 42;
}
""")
    flags = [CC, "-o", bin_path, src_path, "-static", "-O2"]
    if arch == "i386":
        flags.append("-m32")
    r = run(flags)
    assert r.returncode == 0, f"compile failed ({arch}): {r.stderr}"

def pack(input_path, output_path):
    r = run([UPX, "-o", output_path, input_path])
    assert r.returncode == 0, f"pack failed: {r.stderr}{r.stdout}"

def unpack_normal(input_path, output_path):
    r = run([UPX, "-d", "-o", output_path, input_path])
    return r.returncode == 0

def unpack_force(input_path, output_path):
    r = run([UPX, "-d", "--force-unpack", "-o", output_path, input_path])
    return r.returncode == 0

def verify_execution(bin_path):
    """Run the binary and check its output + exit code."""
    try:
        os.chmod(bin_path, 0o755)
        r = run([bin_path])
        return r.returncode == 42 and "TEST_OUTPUT:328350:35" in r.stdout
    except OSError:
        return False

# ── clobbering strategies ────────────────────────────────────────────

def find_all(data, needle):
    """Find all offsets of needle in data."""
    positions = []
    i = 0
    while True:
        p = data.find(needle, i)
        if p < 0:
            break
        positions.append(p)
        i = p + 1
    return positions

def get_overlay_offset(data):
    """Read overlay_offset from last 4 bytes of (non-zero-padded) file."""
    fsize = len(data)
    return struct.unpack_from("<I", data, fsize - 4)[0]

def get_linfo_offset(data):
    """l_info is at overlay_offset - 12."""
    return get_overlay_offset(data) - 12

def clobber_upx_magic_zero(data):
    """Zero all UPX! magic bytes."""
    d = bytearray(data)
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    return bytes(d), "zero all UPX! magic"

def clobber_upx_magic_random(data):
    """Replace all UPX! magic with random bytes."""
    d = bytearray(data)
    replacements = [b"\xde\xad\xbe\xef", b"\x41\x41\x41\x41",
                    b"\xff\x00\xff\x00", b"\x13\x37\x13\x37"]
    for i, pos in enumerate(find_all(d, b"UPX!")):
        d[pos:pos+4] = replacements[i % len(replacements)]
    return bytes(d), "randomize all UPX! magic"

def clobber_linfo(data):
    """Zero out the entire l_info structure (12 bytes)."""
    d = bytearray(data)
    # Zero UPX! magic first
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    # Zero l_info
    li_off = get_linfo_offset(data)
    d[li_off:li_off+12] = b"\x00" * 12
    return bytes(d), "zero l_info + UPX! magic"

def clobber_pinfo(data):
    """Zero out p_info (p_filesize and p_blocksize)."""
    d = bytearray(data)
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    li_off = get_linfo_offset(data)
    d[li_off:li_off+12] = b"\x00" * 12
    pi_off = get_overlay_offset(data)
    d[pi_off:pi_off+12] = b"\x00" * 12
    return bytes(d), "zero l_info + p_info + UPX! magic"

def clobber_packheader(data):
    """Scramble the PackHeader at end of file but keep overlay_offset intact."""
    d = bytearray(data)
    fsize = len(d)
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    # Scramble the 32-byte PackHeader (but NOT the 4-byte overlay_offset after it)
    ph_start = fsize - 4 - 32
    for i in range(ph_start, ph_start + 32):
        d[i] = (d[i] ^ 0xAA) & 0xFF
    return bytes(d), "scramble PackHeader + zero UPX! magic"

def clobber_everything(data):
    """Clobber all metadata: l_info, p_info, PackHeader, EOF marker, all UPX! magic.
    Only b_info chain and compressed data remain intact."""
    d = bytearray(data)
    fsize = len(d)
    # Zero all UPX! magic
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    # Zero l_info
    li_off = get_linfo_offset(data)
    d[li_off:li_off+12] = b"\x00" * 12
    # Randomize p_info
    pi_off = get_overlay_offset(data)
    d[pi_off:pi_off+12] = b"\xca\xfe\xba\xbe" * 3
    # Scramble PackHeader at end
    ph_start = fsize - 4 - 32
    for i in range(ph_start, ph_start + 32):
        d[i] = (d[i] ^ 0x55) & 0xFF
    # Also clobber the overlay_offset at end (!) — force b_info scan
    d[fsize-4:fsize] = b"\xff\xff\xff\xff"
    return bytes(d), "clobber EVERYTHING (l_info, p_info, PackHeader, overlay_offset, UPX!)"

def clobber_section_names(data):
    """Replace UPX section names (PE-style, but also checks ELF)."""
    d = bytearray(data)
    for pos in find_all(d, b"UPX!"):
        d[pos:pos+4] = b"\x00\x00\x00\x00"
    for needle in [b"UPX0", b"UPX1", b"UPX2", b"UPX\x00"]:
        for pos in find_all(d, needle):
            d[pos:pos+len(needle)] = b"\x00" * len(needle)
    return bytes(d), "zero UPX! magic + section names"

def clobber_checksums_only(data):
    """Clobber only the adler32 checksums in the PackHeader.
    This is a subtle attack — everything else looks valid."""
    d = bytearray(data)
    fsize = len(d)
    ph_start = fsize - 4 - 32
    # u_adler at ph+8, c_adler at ph+12 (4 bytes each, LE)
    d[ph_start+8:ph_start+16] = b"\x00" * 8
    # Also clobber the adler fields stored in l_info.l_checksum
    li_off = get_linfo_offset(data)
    d[li_off:li_off+4] = b"\x00\x00\x00\x00"  # l_checksum
    return bytes(d), "zero checksums only (subtle)"

def clobber_version_format(data):
    """Change the version and format fields to invalid values."""
    d = bytearray(data)
    fsize = len(d)
    # PackHeader: version at ph+4, format at ph+5
    ph_start = fsize - 4 - 32
    d[ph_start+4] = 0xFF  # invalid version
    d[ph_start+5] = 0xFF  # invalid format
    return bytes(d), "invalid version + format in PackHeader"


STRATEGIES = [
    clobber_upx_magic_zero,
    clobber_upx_magic_random,
    clobber_linfo,
    clobber_pinfo,
    clobber_packheader,
    clobber_section_names,
    clobber_checksums_only,
    clobber_version_format,
    clobber_everything,
]

# ── main test runner ─────────────────────────────────────────────────

def run_arch_tests(arch, tmpdir):
    """Run all clobbering strategies for a given architecture. Returns (passed, failed)."""
    src = os.path.join(tmpdir, f"test_{arch}.c")
    original = os.path.join(tmpdir, f"test_{arch}_original")
    packed = os.path.join(tmpdir, f"test_{arch}_packed")

    # Step 1: Compile
    print(f"  Compiling {arch} test binary...", end=" ", flush=True)
    compile_test_binary(src, original, arch)
    orig_hash = sha256(original)
    orig_size = os.path.getsize(original)
    assert verify_execution(original), f"{arch} original binary doesn't produce expected output"
    print(f"OK ({orig_size} bytes, sha256={orig_hash[:16]}...)")

    # Step 2: Pack
    print(f"  Packing with UPX...", end=" ", flush=True)
    pack(original, packed)
    packed_size = os.path.getsize(packed)
    packed_data = open(packed, "rb").read()
    upx_count = len(find_all(packed_data, b"UPX!"))
    print(f"OK ({packed_size} bytes, {upx_count} UPX! magic occurrences)")

    # Step 3: Verify normal unpack works
    print(f"  Verifying normal unpack...", end=" ", flush=True)
    normal_out = os.path.join(tmpdir, f"test_{arch}_normal_unpack")
    assert unpack_normal(packed, normal_out), f"{arch} normal unpack failed"
    assert sha256(normal_out) == orig_hash, f"{arch} normal unpack hash mismatch"
    assert verify_execution(normal_out), f"{arch} normal unpack execution mismatch"
    print("OK (byte-identical, execution verified)")
    print()

    # Step 4: Run each clobbering strategy
    passed = 0
    failed = 0

    for i, strategy in enumerate(STRATEGIES):
        tampered_data, desc = strategy(packed_data)
        tampered_path = os.path.join(tmpdir, f"{arch}_tampered_{i}")
        recovered_path = os.path.join(tmpdir, f"{arch}_recovered_{i}")

        with open(tampered_path, "wb") as f:
            f.write(tampered_data)

        # Verify normal unpack fails
        normal_fail_out = os.path.join(tmpdir, f"{arch}_normal_fail_{i}")
        normal_works = unpack_normal(tampered_path, normal_fail_out)
        if os.path.exists(normal_fail_out):
            os.unlink(normal_fail_out)

        # Try force-unpack
        force_ok = unpack_force(tampered_path, recovered_path)

        # Check results
        hash_match = False
        exec_ok = False
        if force_ok and os.path.exists(recovered_path):
            hash_match = sha256(recovered_path) == orig_hash
            exec_ok = verify_execution(recovered_path)

        status = "PASS" if (force_ok and hash_match and exec_ok and not normal_works) else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1

        detail_parts = []
        if normal_works:
            detail_parts.append("normal-unpack-still-works(!)")
        if not force_ok:
            detail_parts.append("force-unpack-failed")
        if force_ok and not hash_match:
            detail_parts.append("hash-mismatch")
        if force_ok and hash_match and not exec_ok:
            detail_parts.append("execution-mismatch")
        detail = "; ".join(detail_parts) if detail_parts else "byte-identical, execution verified"

        print(f"    [{status}] Strategy {i+1}/{len(STRATEGIES)}: {desc}")
        print(f"           normal_unpack={'blocked' if not normal_works else 'STILL WORKS'}"
              f"  force_unpack={'OK' if force_ok else 'FAILED'}"
              f"  hash={'match' if hash_match else 'MISMATCH'}"
              f"  exec={'OK' if exec_ok else 'FAIL'}")
        if status == "FAIL":
            print(f"           reason: {detail}")

    return passed, failed

def main():
    tmpdir = tempfile.mkdtemp(prefix="upx_test_")
    print(f"Working directory: {tmpdir}")

    total_passed = 0
    total_failed = 0

    for arch in ["amd64", "i386"]:
        print(f"\n{'='*60}")
        print(f"  Testing architecture: {arch}")
        print(f"{'='*60}")
        passed, failed = run_arch_tests(arch, tmpdir)
        total_passed += passed
        total_failed += failed
        print(f"\n  {arch}: {passed} passed, {failed} failed")

    print(f"\n{'='*60}")
    print(f"TOTAL: {total_passed} passed, {total_failed} failed, "
          f"{total_passed + total_failed} total")
    print(f"{'='*60}")

    if total_failed:
        print(f"\nTest files preserved in: {tmpdir}")

    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
