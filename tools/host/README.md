# Host-side tooling for the hardened firmware

Written and used during the v0.2.0-hardened verification pass, all
exercised against real hardware.

- `bslink.py` — robust serial driver: SRWP client (reads/writes/echo),
  XMODEM-CRC sender, VT100 screen scraping, feedback-driven menu
  navigation, busy-device tolerant writes.
- `suite.py` — the verification suite: encryption round-trip across
  reboots, wrong-password rejection, host interop (PBKDF2 +
  ChaCha20-Poly1305 decrypt of the on-chip format in Python),
  legacy algo-1 migration with auto-upgrade, ciphertext tamper
  detection, `lock` semantics.
- `t10.py` — standalone flash-journal boot-recovery test (uploads a
  crafted journal, corrupts FRAM, verifies byte-exact recovery at
  boot).
- `cleanup.py` — returns a test device to factory-clean state.

Requires python3 + the `cryptography` package for the interop tests.
If the device ever stops responding: `stty -F /dev/ttyACM0 2400`
reboots the application, `1200` reboots into the UF2 bootloader.

- `stress.py <io|heap|mixed|overlap> --rounds N [--diag]` — liveness
  stress profiles used to hunt the core1 wedge; `--diag` captures the
  4800-baud DIAG dump on a wedge, then recovers via 2400 baud.
- `t11_setup.py` — puts a device into the encrypted, locked state that
  `suite.py --t11` (PSA key slot exhaustion regression) requires.
