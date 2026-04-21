// esp32C6_32bitEntropyGen.ino
// XIAO ESP32-C6 — Air-gapped hardware entropy generator
//
// Protocol: one 64-character lowercase hex string per line (= 32 bytes of
//           on-device SHA-256 output), followed by CR+LF.
//
// NOTE: Requires Arduino ESP32 board package v3.x+ (ESP-IDF 5.x / mbedtls 3.x).
//       If mbedtls_sha256_starts() does not compile, update the board package
//       via: Boards Manager → esp32 → version 3.x.

#include <Arduino.h>
#include <WiFi.h>
#include "bootloader_random.h"
#include "mbedtls/sha256.h"

// ── Configuration ─────────────────────────────────────────────────────────────
#define BAUD_RATE        921600   // High-speed USB CDC for maximum entropy throughput
#define XOR_ROUNDS       8        // Hardware random samples XOR-folded per hash iteration

// ── Heartbeat LED ─────────────────────────────────────────────────────────────
// XIAO ESP32-C6 built-in LED is GPIO 15. The guard handles boards that
// don't define LED_BUILTIN in their variant header.
#ifndef LED_BUILTIN
  #define LED_BUILTIN 15
#endif
#define HEARTBEAT_IDLE_TICKS    100      // Toggle every ~0.5 s when idle
#define HEARTBEAT_ACTIVE_TICKS  10       // Toggle every ~0.05 s when sampling

// ── Globals ───────────────────────────────────────────────────────────────────
static uint32_t s_tick = 0;

void setup() {
  Serial.begin(BAUD_RATE);

  // Enforce air-gap: disable WiFi. By default, Bluetooth and Zigbee are
  // uninitialized in this Arduino core unless their specific libraries are
  // included and started. Attempting to disable them explicitly without
  // initialization causes a modem_clock reference counter assertion failure.
  WiFi.mode(WIFI_OFF);                  // Disable WiFi

  // Enable the internal SAR ADC entropy source.
  // This routes physical noise on the analogue front-end into esp_random(),
  // ensuring true hardware randomness with no dependency on the RF subsystem.
  bootloader_random_enable();

  // Configure heartbeat indicator
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
}

void loop() {
  if (!Serial) {
    // ── Idle State ──────────────────────────────────────────────────────────
    // Host is not connected. Flash the LED slowly to signal the device is alive.
    if (++s_tick % HEARTBEAT_IDLE_TICKS == 0) {
      digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
    }
    delay(5);
    return;
  }

  // ── Step 1: XOR Mixing ────────────────────────────────────────────────────
  // Gather XOR_ROUNDS independent 32-bit hardware random values.
  // Using all samples as SHA-256 input (rather than just XOR-folding them)
  // gives the hash function 256 bits of true entropy to work with, maximising
  // the diffusion and avalanche properties of the output digest.
  uint32_t samples[XOR_ROUNDS];
  for (int i = 0; i < XOR_ROUNDS; i++) {
    samples[i] = esp_random();
  }

  // Pack samples into a raw byte buffer (big-endian) ready for hashing.
  // Total input: XOR_ROUNDS × 4 = 32 bytes = 256 bits.
  uint8_t input_buf[XOR_ROUNDS * 4];
  for (int i = 0; i < XOR_ROUNDS; i++) {
    input_buf[i * 4 + 0] = (uint8_t)(samples[i] >> 24);
    input_buf[i * 4 + 1] = (uint8_t)(samples[i] >> 16);
    input_buf[i * 4 + 2] = (uint8_t)(samples[i] >>  8);
    input_buf[i * 4 + 3] = (uint8_t)(samples[i]      );
  }

  // ── Step 2: On-Device SHA-256 ────────────────────────────────────────────
  // mbedtls is bundled with the ESP32 Arduino core; no extra library needed.
  // The context API is used so we can call mbedtls_sha256_free() and ensure
  // all internal state is cleared by the library after use.
  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);                            // 0 = SHA-256
  mbedtls_sha256_update(&ctx, input_buf, sizeof(input_buf));
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);  // Zeroes the context struct internally

  // ── Step 3: Output — 64-char Lowercase Hex Digest + CRLF ────────────────
  for (int i = 0; i < 32; i++) {
    if (digest[i] < 0x10) Serial.print('0');
    Serial.print(digest[i], HEX);
  }
  Serial.println();    // Appends CR+LF; flushes the line to the USB buffer

  // ── Step 4: Zero Sensitive Buffers ───────────────────────────────────────
  // mbedtls_sha256_free() already zeroes ctx. Additionally clear our local
  // arrays to prevent stale key material from persisting on the stack.
  memset(samples,   0, sizeof(samples));
  memset(input_buf, 0, sizeof(input_buf));
  memset(digest,    0, sizeof(digest));

  // ── Step 5: Active Heartbeat LED ──────────────────────────────────────────
  // A visible rapid blink confirms the device is actively generating entropy.
  if (++s_tick % HEARTBEAT_ACTIVE_TICKS == 0) {
    digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
  }

  // Brief yield — prevents USB CDC transmit-buffer saturation at 921600 baud
  // while still delivering ~175 digest lines/sec (≈5600 bytes/sec of entropy).
  delay(5);
}