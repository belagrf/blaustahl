#!/usr/bin/env python3
"""Hang reproduction lever for the Blaustahl core1 wedge.

Runs a profile of operations against the device, probing liveness
(SRWP CMD_SIZE) after every one, and writes one JSONL record per op:
    {"i": n, "op": name, "dt_s": seconds, "alive": bool, "note": str}
On the first probe failure it records the wedge, attempts a 2400-baud
recovery, and exits 3, so the sequence that produced the hang is the
artifact.

Profiles:
  io    cross-core USB traffic only, no heap churn: large SRWP echoes,
        8KB reads, keystroke bursts into the read-only grid.
  heap  heap churn with sparse I/O: CLI enter/exit (Scheme session
        alloc/free), xmodem_up start+cancel (32KB staging), tiny Scheme
        evals.
  mixed both, interleaved.
"""
import sys, os, time, json, argparse, termios, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bslink


def find_port_wait(timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        p = bslink.find_port()
        if p:
            return p
        time.sleep(0.4)
    return None


def magic_baud(port, baud):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[4] = baud; a[5] = baud
    termios.tcsetattr(fd, termios.TCSANOW, a)
    time.sleep(0.4)
    os.close(fd)


class Stress:
    def __init__(self, log_path):
        self.log = open(log_path, "a")
        self.lk = None
        self.i = 0

    def connect(self):
        port = find_port_wait()
        if not port:
            raise RuntimeError("no device")
        self.lk = bslink.Link(port)
        for _ in range(4):
            if not self.lk.drain(quiet=1.0, maxwait=5.0):
                break

    def record(self, op, dt, alive, note=""):
        rec = {"i": self.i, "op": op, "dt_s": round(dt, 3), "alive": alive, "note": note}
        self.log.write(json.dumps(rec) + "\n"); self.log.flush()
        print("%4d %-18s %6.2fs %s %s" % (self.i, op, dt, "ok" if alive else "WEDGED", note), flush=True)
        self.i += 1

    def alive(self):
        try:
            for _ in range(3):
                if self.lk.srwp_size() == 8192:
                    return True
                self.lk.drain(quiet=0.8, maxwait=3.0)
            return False
        except RuntimeError:
            return False

    # ---- ops ----
    def op_echo_1k(self):
        pat = bytes(range(256)) * 4
        r = self.lk.srwp_echo(pat, timeout=15.0)
        return "echo %d/%d" % (len(r), len(pat)), r == pat

    def op_read_8k(self):
        r = self.lk.srwp_read(0, 8192, timeout=20.0)
        return "read %d" % len(r), len(r) == 8192

    def op_keys_burst(self):
        # printable chars into the read-only grid + a refresh; every
        # byte crosses the core0->core1 RX path individually
        self.lk.write_retry((b"abcdefghij" * 20))
        self.lk.write_retry(b"\x0c")
        out = self.lk.drain(quiet=0.6, maxwait=6.0)
        return "burst redraw %dB" % len(out), len(out) > 0

    def op_cli_cycle(self):
        ok = self.lk.open_cli()
        self.lk.write_retry(b"\x14")           # menu from CLI
        time.sleep(0.4); self.lk.drain(quiet=0.4, maxwait=3.0)
        # LEFT x4 back to FRAM, enter -> grid (ends the Scheme session)
        for _ in range(4):
            self.lk.write_retry(b"\x1b[D"); time.sleep(0.25)
        self.lk.write_retry(b"\r"); time.sleep(0.6)
        self.lk.drain(quiet=0.6, maxwait=4.0)
        return "cli enter/exit", ok

    def op_scheme_eval(self):
        ok = self.lk.open_cli()
        out = self.lk.cli("(+ 1 2)", timeout=6.0)
        return "eval -> %r" % out.strip()[-12:], ok and "3" in out

    def op_xmodem_cancel(self):
        ok = self.lk.open_cli()
        self.lk.cli_clear_line()
        self.lk.write_retry(b"xmodem_up stress.tmp\r")
        # wait for an isolated 'C' poll, then cancel
        self.lk.drain(quiet=1.2, maxwait=10.0)
        got = self.lk.read_exact(1, timeout=6.0)
        self.lk.write_retry(b"\x18\x18")
        out = self.lk.drain(quiet=1.0, maxwait=8.0).decode("ascii", "replace")
        return "xmodem C=%r cancel=%s" % (got, "CANCELLED" in out), ok and got == b"C" and "CANCELLED" in out

    def op_overlap(self):
        # maximize core1 printf (full-screen redraw ~2KB) overlapping
        # with host->device traffic and a device->host read: CTRL-L
        # then, without waiting, a 512-byte keystroke burst, then an
        # SRWP read while the redraw may still be streaming
        self.lk.write_retry(b"\x0c" + b"klmnopqrst" * 51 + b"\x0c")
        r = self.lk.srwp_read(0, 4096, timeout=15.0)
        out = self.lk.drain(quiet=0.8, maxwait=8.0)
        return "overlap srwp=%d redraw=%dB" % (len(r), len(out)), True

    def op_help_flood(self):
        # CLI help text (printf-heavy) requested repeatedly while the
        # host keeps sending
        ok = self.lk.open_cli()
        for _ in range(3):
            self.lk.write_retry(b"help\r")
        out = self.lk.drain(quiet=0.8, maxwait=10.0)
        return "help x3 -> %dB" % len(out), ok and len(out) > 200

    PROFILES = {
        "io":      ["echo_1k", "read_8k", "keys_burst", "echo_1k", "read_8k"],
        "heap":    ["cli_cycle", "xmodem_cancel", "scheme_eval", "cli_cycle"],
        "mixed":   ["echo_1k", "cli_cycle", "read_8k", "xmodem_cancel", "keys_burst", "scheme_eval"],
        "overlap": ["overlap", "overlap", "help_flood", "overlap", "keys_burst"],
    }

    def diag_dump(self, port):
        """4800-baud touch -> core0 prints a DIAG line; capture it."""
        try:
            fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            a = termios.tcgetattr(fd); a[4] = termios.B4800; a[5] = termios.B4800
            a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL; a[3] = 0; a[0] = 0; a[1] = 0
            termios.tcsetattr(fd, termios.TCSANOW, a)
            end = time.time() + 4.0; buf = b""
            while time.time() < end:
                try:
                    buf += os.read(fd, 4096)
                except BlockingIOError:
                    time.sleep(0.05)
                if b"DIAG" in buf and b"\n" in buf[buf.find(b"DIAG"):]:
                    break
            os.close(fd)
            line = buf[buf.find(b"DIAG"):].split(b"\n")[0].decode("ascii", "replace") if b"DIAG" in buf else "(no DIAG line: %r)" % buf[-80:]
        except Exception as e:
            line = "diag failed: %s" % e
        print("DIAG:", line, flush=True)
        self.log.write(json.dumps({"i": self.i, "op": "diag", "line": line}) + "\n"); self.log.flush()
        return line

    def run(self, profile, rounds):
        ops = self.PROFILES[profile]
        for r in range(rounds):
            for name in ops:
                t0 = time.time()
                try:
                    note, ok = getattr(self, "op_" + name)()
                except Exception as e:
                    note, ok = "EXC %s" % e, False
                dt = time.time() - t0
                alive = self.alive()
                self.record(name, dt, alive, note if ok else "op-failed: " + note)
                if not alive:
                    return False
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("profile", choices=["io", "heap", "mixed", "overlap"])
    ap.add_argument("--diag", action="store_true", help="4800-baud DIAG dump on wedge (instrumented build)")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--log", default="stress.jsonl")
    args = ap.parse_args()

    s = Stress(args.log)
    s.connect()
    print("profile=%s rounds=%d port=%s" % (args.profile, args.rounds, s.lk.port))
    ok = s.run(args.profile, args.rounds)
    if ok:
        print("NO WEDGE after %d ops" % s.i)
        s.lk.close()
        return 0
    print("WEDGE at op %d" % (s.i - 1))
    port = s.lk.port
    try:
        s.lk.close()
    except Exception:
        pass
    if args.diag:
        s.diag_dump(port)
        time.sleep(0.5)
    print("attempting 2400-baud recovery")
    magic_baud(port, termios.B2400)
    p = find_port_wait(30)
    print("recovered:", bool(p))
    return 3


if __name__ == "__main__":
    sys.exit(main())
