#include <Arduino.h>
#include <WiFi.h>
#include "bootloader_random.h"

void setup() {
  // Use a fast baud rate for the USB serial connection
  Serial.begin(115200);
  
  // Wait for the host to open the serial connection
  while (!Serial) {
    delay(10);
  }

  // Disable Wi-Fi completely to enforce the hardware air-gap
  WiFi.mode(WIFI_OFF);

  // Enable the internal SAR ADC entropy source. 
  // This guarantees true hardware randomness without relying on the RF subsystem.
  bootloader_random_enable();
}

void loop() {
  // Fetch a 32-bit true random integer
  uint32_t raw_entropy = esp_random();
  
  // Print the raw integer as an ASCII string over USB serial
  Serial.println(raw_entropy);
  
  // A tiny delay prevents flooding the USB buffer, 
  // but keeps the entropy pool filling rapidly at 100Hz.
  delay(10); 
}