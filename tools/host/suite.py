#!/usr/bin/env python3
"""Full on-device verification suite for blaustahl v0.2.0-hardened.

Covers: encryption round-trip across a reboot, wrong-password
rejection, host interop (PBKDF2+ChaCha20-Poly1305 format), legacy
algo-1 migration with auto-upgrade, ciphertext corruption detection,
flash-journal boot recovery, and the lock command. Leaves the device
encrypted at the end only if a test failed; cleanup is a separate
script so a failure leaves evidence in place.
"""
import sys, os, time, struct, zlib, hashlib
sys.path.insert(0, os.path.dirname(__file__))
import bslink

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PW = "correct-horse-battery-staple-42"
MARKER = b"HARDENED-FIRMWARE-ROUND-TRIP-MARKER-2026"
AAD = b"\x00\x00\x00\x01"
R = []


def check(name, ok, detail=""):
    R.append((name, bool(ok)))
    print("  %s %s %s" % ("PASS" if ok else "FAIL", name, detail))


def wait_boot(lk):
    for _ in range(5):
        if not lk.drain(quiet=1.0, maxwait=5.0):
            break


def fresh_link():
    port = None
    t0 = time.time()
    while time.time() - t0 < 40:
        port = bslink.find_port()
        if port:
            break
        time.sleep(0.5)
    time.sleep(1.5)
    lk = bslink.Link(port)
    wait_boot(lk)
    return lk


def reboot(lk):
    assert lk.open_cli(), "no CLI for reboot"
    lk.write(b"reboot\r")
    time.sleep(3.0)
    lk.close()
    return fresh_link()


def parse_meta(img):
    m = img[7680:7808]
    return {
        "magic": m[0] | (m[1] << 8), "version": m[2], "algo": m[3],
        "desc": bytes(m[4:52]).split(b"\x00")[0],
        "salt": bytes(m[52:68]), "nonce": bytes(m[68:80]),
        "tag": bytes(m[92:108]),
        "kdf_iters": int.from_bytes(m[108:112], "little"),
        "raw": bytes(m),
    }


def pack_meta(version, algo, desc, salt, nonce, tag, kdf_iters, bootctr=1):
    m = bytearray(128)
    m[0:2] = (0x1F1E).to_bytes(2, "little")
    m[2] = version; m[3] = algo
    d = desc[:47]; m[4:4+len(d)] = d
    m[52:68] = salt; m[68:80] = nonce; m[92:108] = tag
    m[108:112] = kdf_iters.to_bytes(4, "little")
    m[124:128] = bootctr.to_bytes(4, "little")
    return bytes(m)


def srwp_write_all(lk, addr, data, chunk=512):
    for off in range(0, len(data), chunk):
        lk.srwp_write(addr + off, data[off:off+chunk])
    time.sleep(0.3)


def crypt_state(lk):
    """Ground truth from `info`: 'plaintext' | 'locked' | 'unlocked'.
    Re-enters the CLI first -- successful unlock/enable operations
    jump the UI to the grid editor (try_jump_to_fram), where typed
    commands would land in the grid instead of the prompt."""
    if not lk.open_cli():
        return "unknown", ""
    out = lk.cli("info", timeout=8.0)
    if "ENCRYPTED, UNLOCKED" in out:
        return "unlocked", out
    if "ENCRYPTED, LOCKED" in out:
        return "locked", out
    if "PLAINTEXT" in out:
        return "plaintext", out
    return "unknown", out


def cli_password_unlock(lk, pw, check_state=True):
    """Run `password` on a clean prompt, type pw at the prompt, return
    (visible_output, wall_seconds, state_after). With check_state=False
    the UI is left wherever the unlock put it (the grid on success) --
    used when the caller wants to inspect that screen before the state
    query navigates back to the CLI."""
    lk.cli_clear_line()
    lk.write_retry(b"password\r")
    # wait for the actual prompt text before typing the password
    seen = ""
    end = time.time() + 8
    while time.time() < end:
        seen += lk.drain(quiet=0.4, maxwait=2.0).decode("ascii", "replace")
        if "PASSWORD" in seen:
            break
    t0 = time.time()
    lk.write_retry(pw.encode() + b"\r")
    out = ""
    end = time.time() + 60      # legacy auto-upgrade adds a rekey +
                                # journal write; first-ever journal can
                                # even trigger a littlefs format
    while time.time() < end:
        out += lk.drain(quiet=0.7, maxwait=4.0).decode("ascii", "replace")
        if "UNLOCKED" in out or "INCORRECT" in out or "CANCELLED" in out:
            break
    dt = time.time() - t0
    if not check_state:
        return out, dt, "unchecked"
    state, _ = crypt_state(lk)
    return out, dt, state


def main():
    lk = fresh_link()
    print("port:", lk.port)

    # ---------- reset to known plaintext baseline ----------
    print("== baseline: ensure plaintext ==")
    assert lk.open_cli(), "no CLI"
    # a previous run may have written raw FRAM via SRWP underneath a
    # live session, leaving the firmware's cached metadata stale (the
    # documented SRWP hazard). Reboot first so RAM state == chip state.
    lk = reboot(lk)
    assert lk.open_cli(), "no CLI after baseline reboot"
    state, _ = crypt_state(lk)
    print("   current state:", state)
    if state == "locked":
        o, _, state = cli_password_unlock(lk, PW)
        assert state == "unlocked", "cannot unlock to reset baseline: %r" % o[-120:]
    if state == "unlocked":
        lk.cli("disable_encryption", timeout=4.0)
        lk.write_retry(b"YES\r"); time.sleep(1.0)
        out2 = lk.drain(quiet=1.0, maxwait=10.0).decode("ascii", "replace")
        print("   disable:", out2.strip()[-60:])
        state, _ = crypt_state(lk)
    assert state == "plaintext", "baseline reset failed (state=%s)" % state
    assert lk.sync_srwp(), "SRWP not reachable at baseline"

    # ---------- T3: plant marker plaintext ----------
    print("== T3: plant plaintext marker via SRWP ==")
    pattern = (MARKER + b" ") * (7680 // (len(MARKER) + 1) + 1)
    pattern = pattern[:7680]
    srwp_write_all(lk, 0, pattern)
    back = lk.srwp_read(0, 7680, timeout=30)
    check("T3 marker plaintext written+verified", back == pattern,
          "(%d bytes)" % len(back))

    # ---------- T4: enable encryption ----------
    print("== T4: enable encryption (PBKDF2) ==")
    assert lk.open_cli(), "no CLI"
    lk.cli_clear_line()
    lk.write_retry(b"password\r")
    seen = ""
    end = time.time() + 8
    while time.time() < end:
        seen += lk.drain(quiet=0.4, maxwait=2.0).decode("ascii", "replace")
        if "PASSWORD" in seen:
            break
    lk.write_retry(PW.encode() + b"\r")
    time.sleep(0.4); lk.drain(quiet=0.5, maxwait=3.0)   # CONFIRM prompt
    t0 = time.time()
    lk.write_retry(PW.encode() + b"\r")
    out = ""
    end = time.time() + 90      # first journal write may format littlefs
    while time.time() < end:
        out += lk.drain(quiet=0.7, maxwait=4.0).decode("ascii", "replace")
        if "ENCRYPTED AND UNLOCKED" in out or "FAILED" in out:
            break
    dt = time.time() - t0
    state, _ = crypt_state(lk)
    check("T4 enable succeeded", state == "unlocked",
          "(%.2fs incl. KDF, msg=%r)" % (dt, out.strip()[-40:]))

    assert lk.sync_srwp(), "SRWP lost after enable"
    img = lk.srwp_read(0, 8192, timeout=30)
    meta = parse_meta(img)
    check("T4 format algo=2/version=1", meta["algo"] == 2 and meta["version"] == 1,
          "(algo=%d ver=%d)" % (meta["algo"], meta["version"]))
    check("T4 kdf_iters=100000", meta["kdf_iters"] == 100000)
    check("T4 ciphertext != plaintext", img[:7680] != pattern)

    # ---------- T5: host interop ----------
    print("== T5: host-side format interop ==")
    key = PBKDF2HMAC(hashes.SHA256(), 32, meta["salt"], meta["kdf_iters"]
                     ).derive(PW.encode())
    try:
        pt = ChaCha20Poly1305(key).decrypt(meta["nonce"],
                                           bytes(img[:7680]) + meta["tag"], AAD)
        check("T5 host decrypt matches marker", pt == pattern)
    except Exception as e:
        check("T5 host decrypt matches marker", False, str(e))
    try:
        kb = PBKDF2HMAC(hashes.SHA256(), 32, meta["salt"], meta["kdf_iters"]
                        ).derive(b"wrong")
        ChaCha20Poly1305(kb).decrypt(meta["nonce"], bytes(img[:7680]) + meta["tag"], AAD)
        check("T5 wrong key rejected", False)
    except Exception:
        check("T5 wrong key rejected", True)

    # ---------- T6: reboot -> locked; wrong pw; correct pw ----------
    print("== T6: reboot / lock semantics ==")
    lk = reboot(lk)
    assert lk.open_cli(), "no CLI after reboot"
    state, _ = crypt_state(lk)
    check("T6 relocked after reboot", state == "locked")

    o, dt_bad, state = cli_password_unlock(lk, "definitely-wrong-password")
    check("T6 wrong password rejected", state == "locked", "(%.2fs)" % dt_bad)

    o, dt_ok, _ = cli_password_unlock(lk, PW, check_state=False)
    # unlock jumps the UI into the grid -- capture the decrypted view
    # BEFORE any state query navigates back to the CLI
    scr = lk.screen(settle=1.5)
    marker_visible = MARKER.decode() in scr.replace("\n", "")
    state, _ = crypt_state(lk)
    check("T6 correct password unlocks", state == "unlocked", "(%.2fs)" % dt_ok)
    check("T6 marker visible in grid after unlock", marker_visible)

    # ---------- T7: lock command ----------
    print("== T7: lock command ==")
    assert lk.open_cli(), "no CLI"
    out = lk.cli("lock", timeout=8.0)
    check("T7 lock reported", "LOCKED" in out)
    state, _ = crypt_state(lk)
    check("T7 info shows locked", state == "locked")
    o, _, state = cli_password_unlock(lk, PW)
    check("T7 unlock after lock", state == "unlocked")

    # ---------- T8: corruption detection ----------
    print("== T8: ciphertext corruption detection ==")
    assert lk.sync_srwp(), "SRWP lost"
    good = lk.srwp_read(0, 8192, timeout=30)
    lk.srwp_write(100, bytes([good[100] ^ 0xFF]))
    lk = reboot(lk)
    assert lk.open_cli(), "no CLI"
    o, _, state = cli_password_unlock(lk, PW)
    check("T8 corrupted ciphertext rejected", state == "locked")
    assert lk.sync_srwp(), "SRWP lost"
    lk.srwp_write(100, bytes([good[100]]))
    o, _, state = cli_password_unlock(lk, PW)
    check("T8 restored byte unlocks again", state == "unlocked")

    # ---------- T9: legacy algo-1 migration ----------
    print("== T9: legacy format migration ==")
    assert lk.open_cli(), "no CLI"
    lk.cli("disable_encryption", timeout=4.0)
    lk.write_retry(b"YES\r"); time.sleep(1.0)
    lk.drain(quiet=1.0, maxwait=10.0)
    state, _ = crypt_state(lk)
    assert state == "plaintext", "disable failed in T9 (state=%s)" % state
    assert lk.sync_srwp(), "SRWP lost after disable"
    back = lk.srwp_read(0, 7680, timeout=30)
    check("T9 disable restored plaintext", back == pattern)

    # craft legacy image on host: key = SHA256(pw[:32] padded to 32 || salt)
    salt = hashlib.sha256(b"legacy-salt-material").digest()[:16]
    pw_field = PW.encode()[:32].ljust(32, b"\x00")
    legacy_key = hashlib.sha256(pw_field + salt).digest()
    nonce = b"\x00" * 12
    ct = ChaCha20Poly1305(legacy_key).encrypt(nonce, pattern, AAD)
    legacy_meta = pack_meta(0, 1, b"SHA256(p||salt)+ChaCha20-Poly1305",
                            salt, nonce, ct[7680:7696], 0)
    srwp_write_all(lk, 0, ct[:7680])
    srwp_write_all(lk, 7680, legacy_meta)
    ver = lk.srwp_read(7680, 128, timeout=10)
    check("T9 legacy meta planted", ver == legacy_meta)

    lk = reboot(lk)
    assert lk.open_cli(), "no CLI"
    out = lk.cli("info", timeout=8.0)
    check("T9 legacy detected", "LEGACY KDF" in out)
    o, dt, state = cli_password_unlock(lk, PW)
    check("T9 legacy unlock + auto-upgrade message",
          state == "unlocked" and "UPGRADED" in o, "(%.2fs)" % dt)
    assert lk.sync_srwp(), "SRWP lost"
    img = lk.srwp_read(0, 8192, timeout=30)
    meta = parse_meta(img)
    check("T9 now algo=2 (PBKDF2)", meta["algo"] == 2)
    key = PBKDF2HMAC(hashes.SHA256(), 32, meta["salt"], meta["kdf_iters"]
                     ).derive(PW.encode())
    try:
        pt = ChaCha20Poly1305(key).decrypt(meta["nonce"],
                                           bytes(img[:7680]) + meta["tag"], AAD)
        check("T9 content survived migration", pt == pattern)
    except Exception as e:
        check("T9 content survived migration", False, str(e))

    # ---------- T10: journal boot recovery ----------
    print("== T10: flash journal boot recovery ==")
    # journal = the CURRENT healthy encrypted state; then corrupt FRAM
    # and let boot recovery repair it.
    jr = b"LTSJ" + meta["raw"] + bytes(img[:7680])
    crc = zlib.crc32(jr) & 0xFFFFFFFF
    # firmware trims trailing 0x1A/0x00 from the XMODEM upload's final
    # block; nudge bootctr in the meta copy until the CRC's last byte
    # is safe (content change -> different CRC, replay stays idempotent
    # because data + meta are replayed together)
    bootctr = 1
    while (crc & 0xFF) in (0x00, 0x1A):
        bootctr += 1
        m2 = bytearray(meta["raw"]); m2[124:128] = bootctr.to_bytes(4, "little")
        jr = b"LTSJ" + bytes(m2) + bytes(img[:7680])
        crc = zlib.crc32(jr) & 0xFFFFFFFF
    journal = jr + crc.to_bytes(4, "little")
    print("   journal: %d bytes, crc tail 0x%02x, bootctr nudge %d"
          % (len(journal), crc & 0xFF, bootctr))

    assert lk.open_cli(), "no CLI"
    lk.cli_clear_line()
    lk.write_retry(b"xmodem_up fram_commit.jrn\r")
    time.sleep(1.0)
    ok, msg = lk.xmodem_send(journal)
    print("   xmodem:", ok, msg)
    out = lk.drain(quiet=1.0, maxwait=8.0).decode("ascii", "replace")
    check("T10 journal uploaded", ok and "RECEIVED OK" in out, out.strip()[-40:])
    out = lk.cli("ls", timeout=8.0)
    check("T10 journal file present", "fram_commit.jrn" in out)

    # corrupt a big span of ciphertext
    assert lk.sync_srwp(), "SRWP lost"
    srwp_write_all(lk, 0, b"\xde\xad" * 512)   # 1KB of garbage
    lk = reboot(lk)
    assert lk.open_cli(), "no CLI after recovery boot"
    out = lk.cli("info", timeout=8.0)
    check("T10 recovery reported at boot", "RECOVERED" in out)
    o, _, state = cli_password_unlock(lk, PW)
    check("T10 unlock works after recovery", state == "unlocked")
    assert lk.sync_srwp(), "SRWP lost"
    img2 = lk.srwp_read(0, 8192, timeout=30)
    check("T10 FRAM ciphertext restored", img2[:7680] == img[:7680])
    out = lk.cli("ls", timeout=8.0)
    check("T10 journal consumed after recovery", "fram_commit.jrn" not in out)

    print("\n==== SUITE RESULTS ====")
    passed = sum(1 for _, ok in R if ok)
    for name, ok in R:
        print(" %s  %s" % ("PASS" if ok else "FAIL", name))
    print("%d/%d passed" % (passed, len(R)))
    lk.close()
    return 0 if passed == len(R) else 1


if __name__ == "__main__":
    sys.exit(main())
