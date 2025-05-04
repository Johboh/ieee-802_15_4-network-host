#include <Arduino.h>
#include <Ieee802154NetworkHost.h>

// Encyption key used for our own packet encryption (GCM).
// The key should be the same for both the host and the node.
const char gcm_encryption_key[] = "0123456789ABCDEF"; // Must be exact 16 bytes long. \0 does not count.

// Used to validate the integrity of the messages.
// The secret should be the same for both the host and the node.
const char gcm_encryption_secret[] = "01234567"; // Must be exact 8 bytes long. \0 does not count.

char buffer[64];

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
      ApplicationMessage *app = reinterpret_cast<ApplicationMessage *>(node_message.payload.data());
      sprintf(buffer, "Got ApplicationMessage from [0x%llx] with firmware version %ld, temperature: %f",
              node_message.source_address, node_message.firmware_version, app->temperature);
      Serial.println(buffer);
    });

void setup() {
  _ieee802154_host.start();
  sprintf(buffer, "This device IEEE802.15.4 MAC: 0x%llx", _ieee802154_host.deviceMacAddress());
  Serial.println(buffer);
}

void loop() {}
