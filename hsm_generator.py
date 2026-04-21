#!/usr/bin/env python3
"""
hsm_generator.py — ESP32-C6 Hardware Entropy Key Generator & Daemon

Reads on-device SHA-256-conditioned hardware entropy from an ESP32-C6 at
921600 baud and uses it to generate AES-256, RSA, and ECC cryptographic
key material, or serve raw entropy bytes over a socket (daemon mode).

Firmware protocol
-----------------
The ESP32-C6 outputs exactly one SHA-256 digest per line as a 64-character
lowercase hex string (CR+LF terminated).  Each line represents 32 bytes of
hardware-conditioned true random data sourced from the on-chip SAR ADC.

Daemon protocol
---------------
Client sends  : 4-byte big-endian uint32 N  (requested bytes, 1–65536)
Server replies: exactly N bytes of hardware entropy
Connection    : stateless, one request per connection
"""
from __future__ import annotations

import argparse
import logging
import os
import platform
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import serial
from Crypto.PublicKey import ECC, RSA

# ── Constants ─────────────────────────────────────────────────────────────────

DEVICE_BAUD       = 921600
DIGEST_HEX_LEN    = 64          # SHA-256 = 32 bytes → 64 hex chars per line
MAX_DAEMON_REQUEST = 65_536      # Maximum bytes per daemon request

# PyCryptodome curve name mapping (user-friendly → library name)
CURVE_MAP: dict[str, str] = {
    "ed25519": "Ed25519",
    "p256":    "P-256",
    "p384":    "P-384",
}

# ── Logging ───────────────────────────────────────────────────────────────────

log = logging.getLogger(__name__)


def _setup_logging(logfile: str | None = None) -> None:
    fmt = "%(asctime)s - %(levelname)s - %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)


# ── Memory Hygiene ────────────────────────────────────────────────────────────

def _zero(buf: bytearray) -> None:
    """
    Overwrite every byte of *buf* with zero.

    This limits the window during which sensitive key material exists in RAM.
    Note: Python's immutable ``bytes`` objects cannot be explicitly cleared;
    only mutable ``bytearray`` accumulators are zeroed here.
    """
    for i in range(len(buf)):
        buf[i] = 0


# ── Entropy Source — Hardware Serial ─────────────────────────────────────────

class HardwareEntropyService:
    """
    Reads 64-char hex SHA-256 digests from the ESP32-C6 over USB serial.

    Each firmware line is one SHA-256 digest (32 bytes) produced by XOR-mixing
    eight hardware random samples and hashing on-device.  The output is already
    cryptographically conditioned; no further hashing is performed here.

    Thread Safety
    -------------
    A ``threading.Lock`` serialises all serial reads so that the daemon can
    serve concurrent clients without interleaving bytes from separate requests.
    """

    def __init__(self, port: str, timeout: int = 5) -> None:
        self.port    = port
        self.timeout = timeout
        self._conn: serial.Serial | None = None
        self._lock   = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        try:
            self._conn = serial.Serial(
                self.port, DEVICE_BAUD, timeout=self.timeout
            )
            self._conn.reset_input_buffer()  # Discard stale data from before connect
            log.info(
                "Connected to entropy device on %s @ %d baud",
                self.port, DEVICE_BAUD,
            )
        except serial.SerialException as exc:
            log.error("Failed to open %s: %s", self.port, exc)
            sys.exit(1)

    def is_healthy(self) -> bool:
        return self._conn is not None and self._conn.is_open

    def close(self) -> None:
        if self._conn and self._conn.is_open:
            self._conn.close()
            log.info("Serial connection closed.")

    # ── Entropy API ──────────────────────────────────────────────────────

    def rand_func(self, n_bytes: int) -> bytes:
        """
        Block until *n_bytes* of hardware entropy have been gathered.

        Reads firmware digest lines, decodes hex, and accumulates the raw
        bytes into a ``bytearray`` pool.  The pool is zeroed after the result
        slice is extracted, leaving no surplus entropy in RAM.

        Returns exactly *n_bytes* as an immutable ``bytes`` object suitable
        for direct use with PyCryptodome's ``randfunc=`` parameter.
        """
        if not self.is_healthy():
            raise RuntimeError("Serial connection is not active.")

        pool = bytearray()

        with self._lock:
            while len(pool) < n_bytes:
                try:
                    raw_line = self._conn.readline()  # type: ignore[union-attr]
                except serial.SerialException as exc:
                    log.error("Serial read error: %s", exc)
                    sys.exit(1)

                line = raw_line.strip()
                if len(line) != DIGEST_HEX_LEN:
                    continue  # Skip incomplete / stale lines from startup

                try:
                    chunk = bytearray.fromhex(line.decode("ascii"))
                    pool += chunk
                    _zero(chunk)
                except (ValueError, UnicodeDecodeError):
                    continue  # Discard malformed lines silently

        result = bytes(pool[:n_bytes])
        _zero(pool)        # Clear surplus entropy from the accumulator
        return result


# ── Entropy Source — Daemon (Client Side) ────────────────────────────────────

class DaemonEntropyService:
    """
    Fetches entropy from a running ``hsm_generator --daemon`` instance.

    *address* is either:
    - A Unix socket path, e.g. ``/tmp/entropy_hsm.sock``  (Linux)
    - A TCP ``host:port`` string, e.g. ``127.0.0.1:54321`` (all platforms)

    Each call to ``rand_func()`` opens a fresh connection, sends the request,
    reads exactly *n_bytes*, and closes the connection.
    """

    def __init__(self, address: str) -> None:
        self.address  = address
        self._is_unix = address.startswith("/")
        if not self._is_unix:
            host, _, port_str = address.rpartition(":")
            self._host = host
            self._port = int(port_str)

    def _open_socket(self) -> socket.socket:
        if self._is_unix:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.address)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self._host, self._port))
        return sock

    def rand_func(self, n_bytes: int) -> bytes:
        sock = self._open_socket()
        try:
            sock.sendall(struct.pack(">I", n_bytes))
            buf = bytearray()
            while len(buf) < n_bytes:
                chunk = sock.recv(min(4096, n_bytes - len(buf)))
                if not chunk:
                    raise RuntimeError("Daemon closed connection prematurely.")
                buf += chunk
            result = bytes(buf[:n_bytes])
            _zero(buf)
            return result
        finally:
            sock.close()

    def is_healthy(self) -> bool:
        """Send a 1-byte probe to verify the daemon is reachable."""
        try:
            return len(self.rand_func(1)) == 1
        except Exception:
            return False

    def close(self) -> None:
        pass  # Stateless connections — nothing to close.


# ── Entropy Server — Daemon Mode ─────────────────────────────────────────────

class EntropyServer:
    """
    Serves raw hardware entropy over a Unix domain socket or TCP socket.

    Each connecting client sends a 4-byte big-endian uint32 (N), and the
    server responds with exactly N bytes of hardware entropy, then closes
    the connection.  Clients are handled on individual daemon threads so
    that one slow client cannot stall others.

    Maximum request size is MAX_DAEMON_REQUEST (65 536 bytes).

    Linux extras
    ------------
    When ``feed_kernel=True``, a background thread continuously writes
    entropy to the kernel's /dev/random pool via the ``RNDADDENTROPY``
    ioctl.  This requires root privileges on the host machine.
    """

    def __init__(
        self,
        source: HardwareEntropyService,
        listen_address: str,
    ) -> None:
        self.source         = source
        self.listen_address = listen_address
        self._is_unix       = listen_address.startswith("/")
        self._running       = False

    # ── Client handler ───────────────────────────────────────────────────

    def _handle(self, conn: socket.socket, addr: object) -> None:
        try:
            header = conn.recv(4)
            if len(header) < 4:
                return

            n = struct.unpack(">I", header)[0]
            if n == 0 or n > MAX_DAEMON_REQUEST:
                log.warning("Rejected request for %d bytes from %s", n, addr)
                return

            log.debug("Serving %d entropy bytes to %s", n, addr)
            entropy = self.source.rand_func(n)
            conn.sendall(entropy)

            # Zero our local reference to the entropy output
            local_copy = bytearray(entropy)
            _zero(local_copy)
        except Exception as exc:
            log.error("Client handler error (%s): %s", addr, exc)
        finally:
            conn.close()

    # ── Linux — kernel pool feeder ───────────────────────────────────────

    def _feed_kernel_pool(self) -> None:
        """
        Continuously submit entropy to the Linux kernel's /dev/random pool
        using the RNDADDENTROPY ioctl.  Requires root.  Linux only.
        """
        try:
            import fcntl
            RNDADDENTROPY = 0x40085203          # <linux/random.h>
            log.info("Kernel entropy pool feeder started (requires root).")
            while self._running:
                chunk = self.source.rand_func(64)
                entropy_bits = len(chunk) * 8
                # struct rand_pool_info { int entropy_count; int buf_size; u32 buf[]; }
                payload = struct.pack("ii", entropy_bits, len(chunk)) + chunk
                try:
                    with open("/dev/random", "wb") as rnd:
                        fcntl.ioctl(rnd, RNDADDENTROPY, payload)
                except OSError as exc:
                    log.warning("RNDADDENTROPY failed (root required?): %s", exc)
                    return
                time.sleep(0.05)
        except Exception as exc:
            log.warning("Kernel pool feeder stopped: %s", exc)

    # ── Main server loop ─────────────────────────────────────────────────

    def run(self, feed_kernel: bool = False) -> None:
        """Start listening and serving entropy.  Blocks until interrupted."""
        if self._is_unix:
            if os.path.exists(self.listen_address):
                os.unlink(self.listen_address)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(self.listen_address)
            os.chmod(self.listen_address, 0o600)    # Owner read/write only
            log.info("Entropy daemon listening on Unix socket: %s", self.listen_address)
        else:
            host, _, port_str = self.listen_address.rpartition(":")
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, int(port_str)))
            log.info("Entropy daemon listening on TCP: %s", self.listen_address)

        srv.listen(16)
        self._running = True

        if feed_kernel and platform.system() == "Linux":
            threading.Thread(
                target=self._feed_kernel_pool, daemon=True
            ).start()

        try:
            while True:
                conn, addr = srv.accept()
                threading.Thread(
                    target=self._handle,
                    args=(conn, addr),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            log.info("Shutting down entropy daemon.")
        finally:
            self._running = False
            srv.close()
            if self._is_unix and os.path.exists(self.listen_address):
                os.unlink(self.listen_address)


# ── Key Generator ─────────────────────────────────────────────────────────────

class KeyGenerator:
    """
    Generates AES-256, RSA, and ECC key material using a supplied entropy
    source (either ``HardwareEntropyService`` or ``DaemonEntropyService``).

    All output files are written with mode 0o600 on Unix so that private key
    material is readable only by the owning user.

    Memory hygiene
    --------------
    AES key bytes are held in a ``bytearray`` and zeroed after the hex string
    is derived.  RSA and ECC private keys are held as Python strings (PEM),
    which are immutable and cannot be explicitly zeroed; they are not retained
    beyond the scope of each generate_*() call.
    """

    def __init__(
        self,
        rand_func,
        outdir: Path,
        rsa_bits: int = 4096,
        ecc_curve: str = "ed25519",
    ) -> None:
        self.rand_func = rand_func
        self.outdir    = outdir
        self.rsa_bits  = rsa_bits
        self.ecc_curve = CURVE_MAP[ecc_curve]       # Convert to PyCryptodome name
        outdir.mkdir(parents=True, exist_ok=True)

    def _secure_write(self, path: Path, content: str) -> None:
        """Write *content* to *path* and restrict permissions to 0o600 on Unix."""
        path.write_text(content)
        if platform.system() != "Windows":
            path.chmod(0o600)
        log.debug("Wrote %s", path)

    # ── AES-256 ──────────────────────────────────────────────────────────

    def generate_aes(self) -> None:
        log.info("Gathering hardware entropy for AES-256 key...")
        t0  = time.monotonic()
        raw = bytearray(self.rand_func(32))     # AES-256 = exactly 32 bytes
        aes_hex = raw.hex()
        _zero(raw)                              # Clear raw key bytes immediately

        path = self.outdir / "aes_256.key"
        self._secure_write(path, aes_hex)
        log.info("AES-256 key saved to %s (%.2fs)", path, time.monotonic() - t0)

    # ── RSA ──────────────────────────────────────────────────────────────

    def generate_rsa(self) -> None:
        log.info("Gathering entropy for RSA-%d key pair...", self.rsa_bits)
        log.info("(Prime search requires many entropy bytes — this may take several minutes.)")
        t0  = time.monotonic()
        key = RSA.generate(self.rsa_bits, randfunc=self.rand_func)

        priv_pem = key.export_key().decode()
        pub_pem  = key.publickey().export_key().decode()

        self._secure_write(self.outdir / f"rsa_{self.rsa_bits}_priv.pem", priv_pem)
        self._secure_write(self.outdir / f"rsa_{self.rsa_bits}_pub.pem",  pub_pem)
        log.info(
            "RSA-%d key pair saved to %s (%.2fs)",
            self.rsa_bits, self.outdir, time.monotonic() - t0,
        )

    # ── ECC ──────────────────────────────────────────────────────────────

    def generate_ecc(self) -> None:
        log.info("Gathering entropy for ECC %s key pair...", self.ecc_curve)
        t0  = time.monotonic()
        key = ECC.generate(curve=self.ecc_curve, randfunc=self.rand_func)

        priv_pem = key.export_key(format="PEM")
        pub_pem  = key.public_key().export_key(format="PEM")

        # Build a file-safe curve label: "Ed25519"→"ed25519", "P-256"→"p256"
        safe = self.ecc_curve.lower().replace("-", "")
        self._secure_write(self.outdir / f"ecc_{safe}_priv.pem", priv_pem)
        self._secure_write(self.outdir / f"ecc_{safe}_pub.pem",  pub_pem)
        log.info(
            "ECC %s key pair saved to %s (%.2fs)",
            self.ecc_curve, self.outdir, time.monotonic() - t0,
        )


# ── Daemonize ─────────────────────────────────────────────────────────────────

def daemonize(pid_file: str | None) -> None:
    """
    Traditional UNIX double-fork daemonization.

    After both forks the process is no longer a session leader, has no
    controlling terminal, and its stdio file descriptors are redirected to
    /dev/null.  A PID file is written if *pid_file* is provided.

    On Windows this function is a no-op.  Use NSSM (https://nssm.cc) or
    Windows Task Scheduler to run the server as a background service.
    """
    if platform.system() == "Windows":
        log.info(
            "True daemonization is not available on Windows. "
            "Running as a foreground TCP server. "
            "Use NSSM (https://nssm.cc) or Task Scheduler to install as a service."
        )
        return

    # ── First fork — detach from the invoking shell ───────────────────────
    if os.fork() > 0:
        sys.exit(0)

    os.setsid()     # Become a session leader

    # ── Second fork — relinquish session leadership ───────────────────────
    # A session leader can acquire a controlling terminal; the second fork
    # ensures the daemon can never gain one.
    if os.fork() > 0:
        sys.exit(0)

    # ── Redirect stdio to /dev/null ───────────────────────────────────────
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, "r") as dn_r, open(os.devnull, "a+") as dn_w:
        os.dup2(dn_r.fileno(), sys.stdin.fileno())
        os.dup2(dn_w.fileno(), sys.stdout.fileno())
        os.dup2(dn_w.fileno(), sys.stderr.fileno())

    if pid_file:
        Path(pid_file).write_text(str(os.getpid()))


# ── CLI ───────────────────────────────────────────────────────────────────────

_EPILOG = """\
Examples:
  # Generate all key types directly from the device
  python hsm_generator.py --type all --outdir ./keys --port COM3

  # Generate only an ECC Ed25519 key pair
  python hsm_generator.py --type ecc --outdir ./keys --port COM3

  # Generate RSA with a smaller key size
  python hsm_generator.py --type rsa --rsa-bits 2048 --outdir ./keys --port COM3

  # Run entropy daemon — Linux (Unix domain socket, default)
  python hsm_generator.py --daemon --port /dev/ttyACM0 --logfile /var/log/hsm.log

  # Run entropy daemon — Linux (TCP, with kernel pool feeding, as root)
  sudo python hsm_generator.py --daemon --listen 127.0.0.1:54321 --feed-kernel --port /dev/ttyACM0

  # Run entropy daemon — Windows (foreground TCP server)
  python hsm_generator.py --daemon --listen 127.0.0.1:54321 --port COM3

  # Generate keys from a running daemon rather than direct serial
  python hsm_generator.py --type all --outdir ./keys --source daemon --listen 127.0.0.1:54321
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ESP32-C6 Hardware Entropy Key Generator & Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    # ── Entropy Source ────────────────────────────────────────────────────
    src = p.add_argument_group("Entropy Source")
    src.add_argument(
        "--source",
        choices=["device", "daemon"],
        default="device",
        help=(
            "Where to pull entropy from. "
            "'device' reads directly from the ESP32-C6 over serial (default). "
            "'daemon' connects to a running hsm_generator --daemon instance."
        ),
    )
    src.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help=(
            "Serial port for the ESP32-C6  "
            "(e.g. /dev/ttyACM0 on Linux, COM3 on Windows). "
            "Ignored when --source=daemon. Default: /dev/ttyACM0."
        ),
    )
    src.add_argument(
        "--listen",
        default=None,
        metavar="ADDRESS",
        help=(
            "Daemon socket address. "
            "Unix socket path (e.g. /tmp/entropy_hsm.sock) "
            "or TCP host:port (e.g. 127.0.0.1:54321). "
            "Required when --daemon or --source=daemon."
        ),
    )

    # ── Key Generation ────────────────────────────────────────────────────
    kg = p.add_argument_group("Key Generation")
    kg.add_argument(
        "--type",
        choices=["aes", "rsa", "ecc", "both", "all"],
        help=(
            "Key type(s) to generate. "
            "'both' = AES-256 + RSA (backward-compatible alias). "
            "'all'  = AES-256 + RSA + ECC. "
            "Required unless --daemon is set."
        ),
    )
    kg.add_argument(
        "--outdir",
        type=Path,
        help="Output directory for key files. Created if absent. Required unless --daemon.",
    )
    kg.add_argument(
        "--rsa-bits",
        type=int,
        choices=[2048, 3072, 4096],
        default=4096,
        metavar="{2048,3072,4096}",
        help="RSA key size in bits. Default: 4096.",
    )
    kg.add_argument(
        "--ecc-curve",
        choices=list(CURVE_MAP),
        default="ed25519",
        dest="ecc_curve",
        help=(
            "ECC curve to use. "
            "ed25519 = Edwards25519 (default, modern, fastest). "
            "p256 = NIST P-256. "
            "p384 = NIST P-384."
        ),
    )

    # ── Daemon Mode ───────────────────────────────────────────────────────
    dm = p.add_argument_group("Daemon Mode")
    dm.add_argument(
        "--daemon",
        action="store_true",
        help="Run as an entropy socket server instead of generating keys.",
    )
    dm.add_argument(
        "--pid-file",
        default=None,
        metavar="PATH",
        help="Write daemon PID to this file after forking. Linux only.",
    )
    dm.add_argument(
        "--feed-kernel",
        action="store_true",
        help=(
            "Continuously feed /dev/random's entropy pool via RNDADDENTROPY ioctl. "
            "Linux only; requires root privileges."
        ),
    )
    dm.add_argument(
        "--logfile",
        default=None,
        metavar="PATH",
        help=(
            "Append log output to this file in addition to stdout. "
            "Recommended in daemon mode (stdout is /dev/null after fork on Linux)."
        ),
    )

    return p


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Set up file logging BEFORE daemonize so the handler fd is inherited by
    # the child process after the double fork.
    _setup_logging(args.logfile)

    # ── Validate arguments ────────────────────────────────────────────────
    if args.daemon:
        if args.source == "daemon":
            parser.error("--daemon and --source=daemon are mutually exclusive.")
        if args.listen is None:
            # Apply sensible platform defaults
            args.listen = (
                "/tmp/entropy_hsm.sock"
                if platform.system() == "Linux"
                else "127.0.0.1:54321"
            )
            log.info("No --listen specified; defaulting to %s", args.listen)
    else:
        if args.type is None:
            parser.error("--type is required when not in daemon mode.")
        if args.outdir is None:
            parser.error("--outdir is required when not in daemon mode.")
        if args.source == "daemon" and args.listen is None:
            parser.error("--listen is required when --source=daemon.")

    # ── Build entropy source ──────────────────────────────────────────────
    if args.source == "daemon" and not args.daemon:
        svc: HardwareEntropyService | DaemonEntropyService = DaemonEntropyService(args.listen)
        if not svc.is_healthy():
            log.error("Cannot reach daemon at %s — is it running?", args.listen)
            sys.exit(1)
        log.info("Connected to entropy daemon at %s", args.listen)
    else:
        svc = HardwareEntropyService(args.port)
        svc.connect()

    # ── Daemon mode ───────────────────────────────────────────────────────
    if args.daemon:
        # On Linux this double-forks; on Windows it returns immediately.
        daemonize(args.pid_file)

        server = EntropyServer(svc, args.listen)  # type: ignore[arg-type]
        try:
            server.run(feed_kernel=args.feed_kernel)
        finally:
            svc.close()
        return

    # ── Key generation mode ───────────────────────────────────────────────
    gen = KeyGenerator(
        rand_func  = svc.rand_func,
        outdir     = args.outdir,
        rsa_bits   = args.rsa_bits,
        ecc_curve  = args.ecc_curve,
    )

    try:
        if args.type in ("aes", "both", "all"):
            gen.generate_aes()
        if args.type in ("rsa", "both", "all"):
            gen.generate_rsa()
        if args.type in ("ecc", "all"):
            gen.generate_ecc()
    finally:
        svc.close()


if __name__ == "__main__":
    main()