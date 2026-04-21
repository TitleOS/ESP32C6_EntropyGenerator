#!/usr/bin/env python3
"""
hsm_client.py — CLI client for the hsm_generator entropy daemon.

Connects to a running ``hsm_generator --daemon`` instance and requests a
block of raw hardware entropy bytes.  Output can be written as a hex string
to stdout (--hex) or as raw bytes to stdout for piping into other tools.

Usage
-----
    # Print 32 bytes as hex
    python hsm_client.py --listen /tmp/entropy_hsm.sock --bytes 32 --hex

    # Print 64 bytes as hex via TCP
    python hsm_client.py --listen 127.0.0.1:54321 --bytes 64 --hex

    # Write raw entropy bytes and pipe to xxd
    python hsm_client.py --listen 127.0.0.1:54321 --bytes 32 | xxd

    # Save entropy to a file
    python hsm_client.py --listen 127.0.0.1:54321 --bytes 256 > entropy.bin
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys


def fetch_entropy(address: str, n_bytes: int) -> bytes:
    """Open a connection to the daemon, request *n_bytes*, and return them."""
    is_unix = address.startswith("/")

    if is_unix:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(address)
    else:
        host, _, port_str = address.rpartition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, int(port_str)))

    try:
        # Send the 4-byte big-endian request header
        sock.sendall(struct.pack(">I", n_bytes))

        # Read until we have the full response
        buf = bytearray()
        while len(buf) < n_bytes:
            chunk = sock.recv(min(4096, n_bytes - len(buf)))
            if not chunk:
                raise RuntimeError(
                    f"Daemon disconnected after {len(buf)}/{n_bytes} bytes."
                )
            buf += chunk

        return bytes(buf[:n_bytes])
    finally:
        sock.close()


def main() -> None:
    p = argparse.ArgumentParser(
        description="Fetch entropy bytes from a running hsm_generator daemon.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python hsm_client.py --listen /tmp/entropy_hsm.sock --bytes 32 --hex\n"
            "  python hsm_client.py --listen 127.0.0.1:54321 --bytes 32 | xxd\n"
            "  python hsm_client.py --listen 127.0.0.1:54321 --bytes 256 > entropy.bin\n"
        ),
    )
    p.add_argument(
        "--listen",
        required=True,
        metavar="ADDRESS",
        help="Daemon address — Unix socket path or host:port TCP.",
    )
    p.add_argument(
        "--bytes",
        type=int,
        default=32,
        dest="n_bytes",
        metavar="N",
        help="Number of entropy bytes to request (default: 32, max: 65536).",
    )
    p.add_argument(
        "--hex",
        action="store_true",
        help="Print output as a lowercase hex string + newline (default: raw binary).",
    )

    args = p.parse_args()

    if not (1 <= args.n_bytes <= 65_536):
        p.error("--bytes must be between 1 and 65536.")

    entropy = fetch_entropy(args.listen, args.n_bytes)

    if args.hex:
        print(entropy.hex())
    else:
        sys.stdout.buffer.write(entropy)


if __name__ == "__main__":
    main()
