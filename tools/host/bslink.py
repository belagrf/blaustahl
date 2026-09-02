"""Robust serial link + protocol helpers for Blaustahl testing.

Discipline learned the hard way against stock 0.1.0: never re-poke a
half-parsed command into the device; always drain to silence before a
fresh command; verify every reply length. The hardened firmware makes
most of this unnecessary, but the driver stays paranoid so it can also
talk to stock firmware safely.
"""

import os, termios, time, select, glob, re


def find_port():
    for p in sorted(glob.glob("/dev/ttyACM*")):
        try:
            path = os.path.realpath(
                "/sys/class/tty/%s/device" % os.path.basename(p))
            for probe in (path, os.path.dirname(path)):
                prod = os.path.join(probe, "..", "product")
                if os.path.exists(prod):
                    with open(prod) as f:
                        if "Blaustahl" in f.read():
                            return p
        except OSError:
            continue
    return None


class Link:
    def __init__(self, port=None):
        self.port = port or find_port()
        if not self.port:
            raise RuntimeError("no Blaustahl serial port found")
        self.fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        a = termios.tcgetattr(self.fd)
        a[0] = 0; a[1] = 0
        a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        a[3] = 0
        a[4] = termios.B115200; a[5] = termios.B115200
        termios.tcsetattr(self.fd, termios.TCSANOW, a)
        termios.tcflush(self.fd, termios.TCIOFLUSH)
        time.sleep(0.2)

    def close(self):
        os.close(self.fd)

    def write(self, data, timeout=15.0):
        # generous timeout: the device's core1 blocks completely during
        # PBKDF2 (~1s) and littlefs journal writes -- it stops reading
        # USB, its 64-byte RX FIFO fills, and host writes back up until
        # it comes around again. That's expected, not an error.
        end = time.time() + timeout; off = 0
        while off < len(data):
            if time.time() > end:
                raise RuntimeError("serial write stalled")
            _, w, _ = select.select([], [self.fd], [], 0.2)
            if w:
                try:
                    off += os.write(self.fd, data[off:])
                except BlockingIOError:
                    time.sleep(0.02)
        return True

    def sync_srwp(self, tries=8):
        """Wait until the device answers a clean CMD_SIZE: drains any
        UI output between attempts. Use after long CLI operations."""
        for i in range(tries):
            self.drain(quiet=0.8, maxwait=4.0)
            try:
                if self.srwp_size() == 8192:
                    return True
            except RuntimeError:
                time.sleep(2.0)
            time.sleep(0.5)
        return False

    def read_exact(self, n, timeout=5.0):
        out = b""; end = time.time() + timeout
        while len(out) < n and time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    c = os.read(self.fd, n - len(out))
                    if c: out += c
                except BlockingIOError:
                    pass
        return out

    def drain(self, quiet=0.6, maxwait=6.0):
        end = time.time() + maxwait; last = time.time(); buf = b""
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    c = os.read(self.fd, 4096)
                    buf += c; last = time.time()
                except BlockingIOError:
                    pass
            elif time.time() - last > quiet:
                break
        return buf

    # ---- SRWP ----

    def srwp_size(self):
        self.write(bytes([0x00, 0x0A]))
        r = self.read_exact(4, timeout=3.0)
        return int.from_bytes(r, "little") if len(r) == 4 else None

    def srwp_read(self, addr, length, timeout=30.0):
        cmd = bytes([0x00, 0x01]) + addr.to_bytes(4, "little") \
            + length.to_bytes(4, "little")
        self.write(cmd)
        return self.read_exact(length, timeout=timeout)

    def srwp_write(self, addr, data):
        cmd = bytes([0x00, 0x02]) + addr.to_bytes(4, "little") \
            + len(data).to_bytes(4, "little") + bytes(data)
        self.write(cmd)
        time.sleep(0.1)

    def srwp_echo(self, data, timeout=10.0):
        cmd = bytes([0x00, 0x00]) + len(data).to_bytes(4, "little") + bytes(data)
        self.write(cmd)
        return self.read_exact(len(data), timeout=timeout)

    # ---- VT100 UI ----

    def screen(self, settle=1.2):
        """CTRL-L redraw, return cleaned visible text."""
        self.drain(quiet=0.4, maxwait=3.0)
        self.write(b"\x0c")
        raw = self.drain(quiet=0.8, maxwait=max(3.0, settle + 2))
        txt = raw.decode("ascii", "replace")
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "\n", txt)

    def keys(self, data, gap=0.15):
        for i in range(len(data)):
            self.write(data[i:i+1])
            time.sleep(gap)

    def _menu_selected(self, raw):
        """Given raw VT100 output containing the menu bar, return the
        label rendered in reverse video (the cursor), or None. The
        firmware prints ESC[7m (+ optional ESC[4m) right before the
        selected [LABEL]."""
        best = None
        for label in ("FRAM", "SRAM", "VIEWER", "FILES", "CLI", "HELP",
                      "TEXT", "HEX"):
            tok = "[" + label + "]"
            i = raw.find(tok)
            while i != -1:
                if "[7m" in raw[max(0, i - 10):i]:
                    return label
                i = raw.find(tok, i + 1)
        return best

    def open_cli(self, verbose=False):
        """Feedback-driven CLI entry: look at what the device actually
        shows, act on it, repeat. Handles: already in CLI, grid editor,
        help screen, an already-open menu at any selection."""
        sample = self.drain(quiet=0.5, maxwait=2.5).decode("ascii", "replace")
        for step in range(16):
            if "blaustahl>" in sample:
                return True
            sel = self._menu_selected(sample)
            if sel == "CLI":
                self.write(b"\r"); time.sleep(0.7)
                sample = self.drain(quiet=0.5, maxwait=3.0).decode("ascii", "replace")
                continue
            if sel is not None:
                # menu open, wrong item: one step right, resample from
                # the redraw the move triggers
                self.write(b"\x1b[C"); time.sleep(0.35)
                sample = self.drain(quiet=0.4, maxwait=2.5).decode("ascii", "replace")
                continue
            # no menu visible: CTRL-L to identify where we are
            self.write(b"\x0c"); time.sleep(0.5)
            sample = self.drain(quiet=0.5, maxwait=3.0).decode("ascii", "replace")
            if "blaustahl>" in sample or self._menu_selected(sample):
                continue
            # grid/help/viewer: open the menu
            self.write_retry(b"\x14"); time.sleep(0.5)
            sample = self.drain(quiet=0.5, maxwait=2.5).decode("ascii", "replace")
            if verbose:
                print("open_cli step", step, repr(sample[:80]))
        return False

    # ---- XMODEM-CRC sender (matches the firmware's xmodem_up) ----

    @staticmethod
    def _crc16_xmodem(data):
        crc = 0
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) \
                    else (crc << 1) & 0xFFFF
        return crc

    def xmodem_send(self, payload, handshake_timeout=60.0):
        """Send `payload` to a device that was just told `xmodem_up`.
        CRITICAL ordering: the command's own banner text ("...VIA
        XMODEM/CRC -- START YOUR SENDER NOW...") contains 'C'
        characters -- drain ALL of it to silence first, and only then
        treat a received 'C' as the receiver's real CRC-mode poll.
        (Matching the banner's 'C' and blasting a frame early is how a
        previous run desynced the receiver.) The firmware trims
        trailing 0x1A/0x00 within the final block, so the caller must
        ensure the payload's last byte is neither."""
        self.drain(quiet=1.2, maxwait=10.0)     # absorb banner fully
        end = time.time() + handshake_timeout
        while time.time() < end:
            b1 = self.read_exact(1, timeout=3.0)
            if b1 == b"C":
                break
        else:
            return False, "no CRC handshake"
        blk = 1
        for off in range(0, len(payload), 128):
            chunk = payload[off:off+128]
            chunk = chunk + b"\x1a" * (128 - len(chunk))
            frame = bytes([0x01, blk & 0xFF, 0xFF - (blk & 0xFF)]) + chunk
            crc = self._crc16_xmodem(chunk)
            frame += bytes([crc >> 8, crc & 0xFF])
            for attempt in range(10):
                self.write_retry(frame)
                r = self.read_exact(1, timeout=8.0)
                if r == b"\x06":        # ACK
                    break
                if r == b"C" and blk == 1:
                    continue            # receiver still handshaking
                # NAK or noise -> retransmit
            else:
                return False, "block %d never ACKed" % blk
            blk += 1
        self.write_retry(b"\x04")       # EOT
        r = self.read_exact(1, timeout=8.0)
        return (r == b"\x06"), "done" if r == b"\x06" else "EOT not ACKed"

    def write_retry(self, data, tries=4):
        """write() that tolerates the device being CPU-busy (core1
        blocks during PBKDF2/flash writes and stops draining USB)."""
        for i in range(tries):
            try:
                return self.write(data)
            except RuntimeError:
                time.sleep(3.0)
        raise RuntimeError("serial write stalled after %d tries" % tries)

    def cli_clear_line(self):
        """Absorb any pending output so the next command's response can
        be attributed cleanly. (A bare CR is NOT sent: an empty CLI
        line prints the full help text -- verified on hardware -- which
        floods the stream and lags every subsequent parse window.)"""
        self.drain(quiet=0.6, maxwait=8.0)

    def cli(self, line, timeout=8.0, quiet=0.7):
        """Drain pending output, send a CLI line, return its output."""
        self.cli_clear_line()
        self.write_retry(line.encode() + b"\r")
        raw = self.drain(quiet=quiet, maxwait=timeout)
        return raw.decode("ascii", "replace")
