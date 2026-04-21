# ESP32-C6 Airgapped Hardware Entropy Generator

An air-gapped USB hardware entropy generator using a XIAO ESP32-C6 board.
The firmware XOR-mixes eight SAR ADC hardware random samples, hashes them
on-device with SHA-256, and streams the 32-byte digests over USB at 921600 baud.
The host-side Python toolchain uses this entropy to generate **AES-256**,
**RSA** (2048–4096-bit), and **ECC** (Ed25519, P-256, P-384) key material —
or serves raw entropy bytes over a socket in **daemon mode**.

All RF radios (Wi-Fi, Bluetooth, and Zigbee) are disabled at boot and never re-enabled,
ensuring no RF-influenced randomness and a true hardware air-gap from all wireless networks.

---

## Requirements

### Hardware
- [Seeed XIAO ESP32-C6](https://wiki.seeedstudio.com/xiao_esp32c6_getting_started/) (or any ESP32-C6 board)

### Arduino IDE
- **Board package**: `esp32` by Espressif, **version 3.x or later**
  (Boards Manager → esp32 → install ≥ 3.0.0).
  The mbedtls SHA-256 API used in the firmware requires the ESP-IDF 5.x
  core that ships with board package v3.x+.

### Python
- Python 3.10+
- `pyserial` and `pycryptodome`:

```bash
pip install pyserial pycryptodome
```

---

## Firmware — `esp32C6_32bitEntropyGen.ino`

### What it does

| Step | Detail |
|---|---|
| **Air-gap** | Explicit disable commands for Wi-Fi, BT, and Zigbee before RNG is enabled |
| **Entropy source** | `bootloader_random_enable()` activates the internal SAR ADC TRNG |
| **XOR mixing** | Eight independent `esp_random()` calls are packed into a 32-byte buffer |
| **On-device SHA-256** | The buffer is hashed with mbedtls to produce a 32-byte digest |
| **Output** | 64-char lowercase hex string + CRLF per line at **921600 baud** |
| **Buffer zeroing** | `memset()` clears all sensitive arrays after each digest is sent |
| **Heartbeat LED** | Built-in LED blinks slowly (~1 Hz) when idle, and rapidly (~10 Hz) when being sampled |

### Protocol

```
fd3a9e1b...c04f7d82\r\n   ← 64 hex chars = 32 bytes SHA-256 output
a82c4f0e...217b9ca1\r\n
...
```

### Flashing

1. Open `esp32C6_32bitEntropyGen.ino` in the Arduino IDE.
2. Under **Tools → Board**, select **XIAO ESP32C6** (requires board package v3.x+).
3. Select the correct port under **Tools → Port**.
4. Click **Upload**.
5. After flashing, the blue LED will blink steadily — entropy is streaming.

> **Verification**: Open Serial Monitor at **921600 baud**. You should see
> a continuous stream of 64-character hex lines.

---

## Host Script — `hsm_generator.py`

### Architecture

| Class | Role |
|---|---|
| `HardwareEntropyService` | Thread-safe serial reader; parses 64-char hex digest lines |
| `DaemonEntropyService` | Client that fetches entropy from a running daemon |
| `EntropyServer` | Socket server (Unix or TCP) that serves raw entropy bytes |
| `KeyGenerator` | Generates AES / RSA / ECC key files from any entropy source |

### Arguments

#### Entropy Source

| Argument | Default | Description |
|---|---|---|
| `--source` | `device` | `device` = direct serial, `daemon` = running daemon |
| `--port` | `/dev/ttyACM0` | Serial port (e.g. `COM3`, `/dev/ttyACM0`). Ignored when `--source=daemon` |
| `--listen` | *(see below)* | Socket address for daemon server or client |

#### Key Generation

| Argument | Default | Description |
|---|---|---|
| `--type` | *(required)* | `aes`, `rsa`, `ecc`, `both` (AES+RSA), or `all` (AES+RSA+ECC) |
| `--outdir` | *(required)* | Output directory for key files |
| `--rsa-bits` | `4096` | RSA key size: `2048`, `3072`, or `4096` |
| `--ecc-curve` | `ed25519` | ECC curve: `ed25519`, `p256` (NIST P-256), `p384` (NIST P-384) |

#### Daemon Mode

| Argument | Default | Description |
|---|---|---|
| `--daemon` | off | Run as an entropy socket server instead of generating keys |
| `--listen` | `/tmp/entropy_hsm.sock` (Linux) or `127.0.0.1:54321` (Windows) | Bind address |
| `--pid-file` | none | Write daemon PID to this path (Linux only) |
| `--feed-kernel` | off | Feed `/dev/random` pool via `RNDADDENTROPY` ioctl (Linux, root required) |
| `--logfile` | none | Append logs to this file (recommended in daemon mode) |

### Output files

| Key type | Files |
|---|---|
| AES-256 | `aes_256.key` (raw hex string) |
| RSA | `rsa_<bits>_priv.pem`, `rsa_<bits>_pub.pem` |
| ECC Ed25519 | `ecc_ed25519_priv.pem`, `ecc_ed25519_pub.pem` |
| ECC P-256 | `ecc_p256_priv.pem`, `ecc_p256_pub.pem` |
| ECC P-384 | `ecc_p384_priv.pem`, `ecc_p384_pub.pem` |

All private key files are written with mode **0o600** (owner read/write only) on Linux and macOS.

---

### Usage examples

#### Direct key generation from device

```bash
# All three key types — AES-256, RSA-4096, and ECC Ed25519
python hsm_generator.py --type all --outdir ./keys --port COM3

# ECC only (default curve: Ed25519)
python hsm_generator.py --type ecc --outdir ./keys --port /dev/ttyACM0

# RSA-2048 only (faster than the default 4096)
python hsm_generator.py --type rsa --rsa-bits 2048 --outdir ./keys --port COM3

# ECC NIST P-256
python hsm_generator.py --type ecc --ecc-curve p256 --outdir ./keys --port COM3

# AES + RSA only (backward-compatible alias for --type both)
python hsm_generator.py --type both --outdir ./keys --port COM3
```

#### Daemon mode — Linux (Unix socket)

```bash
# Start daemon in the background with a logfile
python hsm_generator.py --daemon --port /dev/ttyACM0 --logfile /var/log/hsm.log &

# Also feed the Linux kernel entropy pool (requires root)
sudo python hsm_generator.py --daemon --port /dev/ttyACM0 --feed-kernel --logfile /var/log/hsm.log &

# Generate keys from the running daemon
python hsm_generator.py --type all --outdir ./keys --source daemon
```

The Unix socket defaults to `/tmp/entropy_hsm.sock`; override with `--listen /run/hsm.sock`.

#### Daemon mode — Windows (TCP, foreground)

```powershell
# Start daemon in one terminal
python hsm_generator.py --daemon --listen 127.0.0.1:54321 --port COM3

# Generate keys from the daemon in another terminal
python hsm_generator.py --type all --outdir ./keys --source daemon --listen 127.0.0.1:54321
```

> **Windows service**: To run as a persistent Windows service, wrap the daemon
> command with [NSSM](https://nssm.cc) or configure a Task Scheduler entry set
> to run at startup.

---

## Client Utility — `hsm_client.py`

`hsm_client.py` is a minimal standalone tool for fetching raw entropy bytes
from a running daemon.  Useful for testing, auditing, or piping entropy into
other programs.

```bash
# Print 32 entropy bytes as hex (Unix socket)
python hsm_client.py --listen /tmp/entropy_hsm.sock --bytes 32 --hex

# Print 64 bytes as hex (TCP)
python hsm_client.py --listen 127.0.0.1:54321 --bytes 64 --hex

# Write raw entropy bytes for piping
python hsm_client.py --listen 127.0.0.1:54321 --bytes 32 | xxd

# Save to file
python hsm_client.py --listen 127.0.0.1:54321 --bytes 256 > entropy.bin
```

### Daemon protocol

The wire protocol is intentionally minimal:

| Direction | Payload |
|---|---|
| Client → Server | 4-byte big-endian `uint32` — number of bytes requested (1–65536) |
| Server → Client | Exactly N bytes of hardware entropy |

---

## Security Notes

- **Private key permissions**: On Linux/macOS all `.pem` and `.key` files are set to `0o600` immediately after writing. On Windows, ensure the output directory ACLs are appropriately restricted.
- **Air-gap**: The firmware disables all RF radios (Wi-Fi, Bluetooth, Zigbee) before enabling the hardware RNG. Do not upload firmware that re-enables any wireless radios while using this device for key generation.
- **Log file**: File logging is disabled by default. Avoid enabling `--logfile` with verbose settings if the log path is on a shared or networked filesystem.
- **Daemon socket**: The Unix socket is created with mode `0o600` (root/owner only). The TCP daemon binds to `127.0.0.1` (loopback only) and should not be exposed to a network interface.
- **Memory hygiene**: All internal `bytearray` entropy accumulators are explicitly zeroed after use. Python immutable `bytes` / `str` objects holding PEM output cannot be cleared; for the highest-assurance use cases, generate keys on a dedicated air-gapped machine and immediately write to encrypted storage.

---

## Expected performance

| Operation | Approximate time |
|---|---|
| AES-256 key | < 1 second |
| ECC Ed25519 key pair | < 1 second |
| ECC P-256 / P-384 key pair | 1–5 seconds |
| RSA-2048 key pair | ~20–60 seconds |
| RSA-4096 key pair | ~2–5 minutes |

Performance scales with entropy throughput (~5600 bytes/sec at 921600 baud with 5 ms firmware delay) and host CPU speed for RSA prime search.

## 3D Printed Case
I personally 3d printed this [case](https://www.printables.com/model/1137008-esp32-c3c6h2s3-super-mini-case) and puttied the small case with vented lid to the side of my Proxmox node, making the RNG easily and constantly accessible. 