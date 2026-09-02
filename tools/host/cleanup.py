#!/usr/bin/env python3
"""Restore the device to factory-clean state after the test suite:
plaintext, FRAM fully zeroed (metadata region included -- the firmware
re-initializes fresh plaintext metadata at next boot), no leftover
test files on flash. Also exercises the 2400-baud reboot as a final
check of the magic-baud recovery path.
"""
import sys, os, time, termios
sys.path.insert(0, os.path.dirname(__file__))
import bslink
from suite import PW, crypt_state, cli_password_unlock, fresh_link, reboot, srwp_write_all


def main():
    lk = fresh_link()
    print("port:", lk.port)

    # sync RAM state with chip, whatever the suite left behind
    lk = reboot(lk)
    assert lk.open_cli(), "no CLI"
    state, _ = crypt_state(lk)
    print("state after suite:", state)

    if state == "locked":
        o, _, state = cli_password_unlock(lk, PW)
        assert state == "unlocked", "unlock failed during cleanup"
    if state == "unlocked":
        lk.cli("disable_encryption", timeout=4.0)
        lk.write_retry(b"YES\r"); time.sleep(1.0)
        lk.drain(quiet=1.0, maxwait=10.0)
        state, _ = crypt_state(lk)
        assert state == "plaintext", "disable failed during cleanup"
    print("plaintext restored")

    # remove any leftover test files from flash
    out = lk.cli("ls", timeout=8.0)
    for fname in ("fram_commit.jrn", "fram_commit.jrn.tmp", "fram_snapshot.bin"):
        if fname in out:
            lk.cli("rm %s" % fname, timeout=4.0)
            lk.write_retry(b"YES\r"); time.sleep(0.5)
            lk.drain(quiet=0.5, maxwait=4.0)
            print("removed", fname)
    out = lk.cli("ls", timeout=8.0)
    print("flash files now:", out.strip().splitlines()[-1] if out.strip() else "?")

    # zero the ENTIRE chip, metadata included
    assert lk.sync_srwp(), "SRWP unreachable for wipe"
    srwp_write_all(lk, 0, b"\x00" * 8192)
    img = lk.srwp_read(0, 8192, timeout=30)
    assert img == b"\x00" * 8192, "wipe verification failed"
    print("FRAM fully zeroed (8192/8192 verified)")

    # magic-baud application reboot (2400) -- final feature check
    print("testing 2400-baud reboot...")
    port = lk.port
    fd = lk.fd
    a = termios.tcgetattr(fd)
    a[4] = termios.B2400; a[5] = termios.B2400
    termios.tcsetattr(fd, termios.TCSANOW, a)
    time.sleep(0.5)
    lk.close()
    time.sleep(2.0)
    ok = False
    t0 = time.time()
    while time.time() - t0 < 30:
        p = bslink.find_port()
        if p:
            ok = True
            break
        time.sleep(0.5)
    print("2400-baud reboot:", "PASS (device re-enumerated)" if ok else "FAIL")

    time.sleep(1.5)
    lk = bslink.Link()
    for _ in range(4):
        if not lk.drain(quiet=1.0, maxwait=5.0):
            break
    assert lk.open_cli(), "no CLI after final reboot"
    state, info = crypt_state(lk)
    print("final state:", state)
    fram_line = [l for l in info.splitlines() if "FRAM:" in l or "FIRMWARE" in l]
    for l in fram_line:
        print("  ", l.strip())
    img = lk.srwp_read(0, 7680, timeout=30)
    print("user area zeroed:", img == b"\x00" * 7680)
    lk.close()
    print("CLEANUP COMPLETE" if state == "plaintext" and ok else "CLEANUP INCOMPLETE")
    return 0 if state == "plaintext" else 1


if __name__ == "__main__":
    sys.exit(main())
