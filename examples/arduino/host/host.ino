// Copyright (c) Johan Böhlin
// SPDX-License-Identifier: GPL-3.0-or-later

#include <Arduino.h>
#include <Ieee802154NetworkHost.h>
#include <cinttypes>

// Encryption key used for our own packet encryption (GCM).
// The key should be the same for both the host and the node.
const char gcm_encryption_key[] = "0123456789ABCDEF"; // Must be exact 16 bytes long. \0 does not count.

// Used to validate the integrity of the messages.
// The secret should be the same for both the host and the node.
const char gcm_encryption_secret[] = "01234567"; // Must be exact 8 bytes long. \0 does not count.

// Shared between node and host. Keep this in you own shared .h file.
struct __attribute__((packed)) ApplicationMessage {
  double temperature;
};

Ieee802154NetworkHost _ieee802154_host(
    {
        .gcm_encryption_key = gcm_encryption_key,
        .gcm_encryption_secret = gcm_encryption_secret,
        .channel = 26,
        .pan_id = 0x1234,
    },
    [](Ieee802154NetworkHost::NodeMessage node_message) {
      if (node_message.payload.size() < sizeof(ApplicationMessage)) {
        Serial.println("Received message payload too small");
        return;
      }
      const ApplicationMessage *app = reinterpret_cast<const ApplicationMessage *>(node_message.payload.data());
      char print_buffer[128];
      snprintf(print_buffer, sizeof(print_buffer),
               "Got ApplicationMessage from [0x%llx] with firmware version %" PRIu32 ", temperature: %f",
               node_message.source_address, node_message.firmware_version, app->temperature);
      Serial.println(print_buffer);
    });

void setup() {
  Serial.begin(115200);
  _ieee802154_host.start();
  char print_buffer[64];
  snprintf(print_buffer, sizeof(print_buffer), "This device IEEE802.15.4 MAC: 0x%llx",
           _ieee802154_host.deviceMacAddress());
  Serial.println(print_buffer);
}

void loop() {}
