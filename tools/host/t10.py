#!/usr/bin/env python3
"""Standalone T10: flash-journal boot recovery, end to end, on a fresh
session (the full suite's version only failed because a long session's
heap churn starved XMODEM's staging malloc -- since tuned)."""
import sys, os, time, zlib
sys.path.insert(0, os.path.dirname(__file__))
import bslink
from suite import PW, crypt_state, cli_password_unlock, fresh_link, reboot, srwp_write_all, parse_meta, R, check


def main():
    lk = fresh_link()
    print("port:", lk.port)
    assert lk.open_cli(), "no CLI"
    state, _ = crypt_state(lk)
    print("state:", state)
    if state == "locked":
        o, _, state = cli_password_unlock(lk, PW)
    assert state == "unlocked", "need unlocked encrypted FRAM to start"

    assert lk.sync_srwp(), "SRWP unreachable"
    img = lk.srwp_read(0, 8192, timeout=30)
    assert len(img) == 8192
    meta = parse_meta(img)
    assert meta["algo"] == 2, "expected PBKDF2 format on chip"

    # journal = the current healthy state; recovery replay must restore
    # exactly these bytes after we corrupt the chip
    bootctr = 1
    while True:
        m2 = bytearray(meta["raw"]); m2[124:128] = bootctr.to_bytes(4, "little")
        jr = b"LTSJ" + bytes(m2) + bytes(img[:7680])
        crc = zlib.crc32(jr) & 0xFFFFFFFF
        if (crc & 0xFF) not in (0x00, 0x1A):
            break
        bootctr += 1
    journal = jr + crc.to_bytes(4, "little")
    print("journal: %d bytes, crc tail 0x%02x" % (len(journal), crc & 0xFF))

    lk.cli_clear_line()
    lk.write_retry(b"xmodem_up fram_commit.jrn\r")
    ok, msg = lk.xmodem_send(journal)
    print("xmodem:", ok, msg)
    out = lk.drain(quiet=1.0, maxwait=10.0).decode("ascii", "replace")
    check("T10 journal uploaded", ok and "RECEIVED OK" in out, out.strip()[-40:])
    out = lk.cli("ls", timeout=8.0)
    check("T10 journal file on flash", "fram_commit.jrn" in out)

    assert lk.sync_srwp(), "SRWP lost"
    srwp_write_all(lk, 0, b"\xde\xad" * 512)      # trash 1KB of ciphertext
    trashed = lk.srwp_read(0, 1024, timeout=15)
    check("T10 corruption applied", trashed == b"\xde\xad" * 512)

    lk = reboot(lk)
    assert lk.open_cli(), "no CLI after recovery boot"
    out = lk.cli("info", timeout=8.0)
    check("T10 recovery reported at boot", "RECOVERED" in out)
    o, _, state = cli_password_unlock(lk, PW)
    check("T10 unlock works after recovery", state == "unlocked")
    assert lk.sync_srwp(), "SRWP lost post-recovery"
    img2 = lk.srwp_read(0, 8192, timeout=30)
    check("T10 ciphertext restored byte-exact", img2[:7680] == img[:7680])
    out = lk.cli("ls", timeout=8.0)
    check("T10 journal consumed after recovery", "fram_commit.jrn" not in out)

    print("\n==== T10 RESULTS ====")
    passed = sum(1 for _, okk in R if okk)
    for name, okk in R:
        print(" %s  %s" % ("PASS" if okk else "FAIL", name))
    print("%d/%d passed" % (passed, len(R)))
    lk.close()
    return 0 if passed == len(R) else 1


if __name__ == "__main__":
    sys.exit(main())
