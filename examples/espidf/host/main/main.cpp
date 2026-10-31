#include <Ieee802154NetworkHost.h>
#include <cinttypes>
#include <cstring>
#include <esp_err.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define LOG_TAG "c6-host"

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
        ESP_LOGW(LOG_TAG, "Received message payload too small: %d bytes", node_message.payload.size());
        return;
      }
      const ApplicationMessage *app = reinterpret_cast<const ApplicationMessage *>(node_message.payload.data());
      ESP_LOGI(LOG_TAG, "Got ApplicationMessage from [0x%llx] with firmware version %" PRIu32 ", temperature: %f",
               node_message.source_address, node_message.firmware_version, app->temperature);
    });

extern "C" {
void app_main();
}

void app_main(void) {
  _ieee802154_host.start();
  ESP_LOGI(LOG_TAG, "This device IEEE802.15.4 MAC: 0x%llx", _ieee802154_host.deviceMacAddress());

  while (1) {
    vTaskDelay(500 / portTICK_PERIOD_MS);
    fflush(stdout);
  }
}
