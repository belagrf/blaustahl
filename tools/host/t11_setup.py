#!/usr/bin/env python3
"""Put the device into the state T11 needs: encrypted with PW and locked."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bslink
from suite import PW, crypt_state, cli_password_unlock, fresh_link, reboot


def enable(lk):
    lk.cli_clear_line()
    lk.write_retry(b"password\r")
    seen = ""
    end = time.time() + 8
    while time.time() < end:
        seen += lk.drain(quiet=0.4, maxwait=2.0).decode("ascii", "replace")
        if "PASSWORD" in seen:
            break
    lk.write_retry(PW.encode() + b"\r"); time.sleep(0.4); lk.drain(quiet=0.5, maxwait=3.0)
    lk.write_retry(PW.encode() + b"\r")
    out = ""
    end = time.time() + 90
    while time.time() < end:
        out += lk.drain(quiet=0.7, maxwait=4.0).decode("ascii", "replace")
        if "ENCRYPTED AND UNLOCKED" in out or "FAILED" in out:
            break
    return out


lk = fresh_link()
lk = reboot(lk)
assert lk.open_cli(), "no CLI"
state, _ = crypt_state(lk)
print("start state:", state)
if state == "plaintext":
    print("enabling:", enable(lk).strip()[-40:])
    state, _ = crypt_state(lk)
if state == "unlocked":
    out = lk.cli("lock", timeout=8.0)
    print("lock:", out.strip()[-40:])
    state, _ = crypt_state(lk)
print("final state:", state)
lk.close()
sys.exit(0 if state == "locked" else 1)
