# ESP32-C6 Airgapped Hardware Entropy Generator

This project provides an air-gapped USB hardware entropy generator using an ESP32-C6 board (specifically optimized for the XIAO ESP32C6 model). It leverages the ESP32-C6's internal hardware True Random Number Generator (TRNG / SAR ADC) to securely generate AES and RSA keys without relying on inherently predictable software pseudorandom number generators or an active internet connection.

## `esp32C6_32bitEntropyGen.ino`

This is the Arduino sketch intended to be flashed onto the XIAO ESP32-C6 board. 

**Features:**
- Sets the Wi-Fi module strictly to `WIFI_OFF` to ensure a true air-gap from wireless networks.
- Enables the internal SAR ADC hardware entropy source via `bootloader_random_enable()`.
- Continuously polls the hardware random number generator by calling `esp_random()` and outputs the 32-bit integer values as ASCII strings over the USB serial connection.

**Usage:**
1. Connect your XIAO ESP32C6 to your computer via USB.
2. Compile and upload `esp32C6_32bitEntropyGen.ino` using the Arduino IDE (ensure the appropriate board manager for ESP32/XIAO is installed).
3. Once flashed, the device immediately begins streaming entropy over the serial interface.

## `hsm_generator.py`

This Python script runs on the host computer. It connects to the ESP32-C6 over serial, reads the raw entropy stream, hashes it to ensure uniform distribution and secure byte mapping, and uses those bytes to generate highly secure cryptographic keys.

**Features:**
- Provides a custom hardware random function (`randfunc`) that blocks and pulls real-time entropy from the ESP32-C6 over the serial connection.
- Uses SHA-256 to compress the raw text output from the serial port into secure binary streams before returning them.
- Interfaces with the `PyCryptodome` library to generate AES-256 (256-bit symmetric) and RSA-4096 (asymmetric) keypairs.

### Arguments:

- `--type` (Required): The type of key to generate. Valid choices are `aes`, `rsa`, or `both`.
- `--outdir` (Required): Directory path where the generated keys will be saved. The script will create this directory if it doesn't already exist.
- `--port` (Optional): The serial port the ESP32-C6 is connected to. Defaults to `/dev/ttyACM0` (typical for Linux), but you may need to specify this exactly (e.g., `COM3` on Windows or `/dev/cu.usbmodem...` on macOS).

**Example Usage:**

Generate both AES and RSA keys, saving them to the `keys` directory, using a specific COM port:
```bash
python hsm_generator.py --type both --outdir ./keys --port COM3
```

This will produce `aes_256.key`, `rsa_4096_priv.pem`, and `rsa_4096_pub.pem` inside the specified directory using pure hardware entropy streamed directly from the XIAO ESP32C6.

AES-256 keys can be generated in under a second on modern systems, while an RSA-4096 pair takes roughly 330 seconds on my system.

## 3D Printed Case
I personally 3d printed this [case](https://www.printables.com/model/1137008-esp32-c3c6h2s3-super-mini-case) and puttied the small case with vented lid to the side of my Proxmox node, making the RNG easily and constantly accessible. 
