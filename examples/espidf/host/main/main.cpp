#include <Ieee802154NetworkHost.h>
#include <cstring>
#include <driver/gpio.h>
#include <esp_err.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define LOG_TAG "c6-host"

// Encyption key used for our own packet encryption (GCM).
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
      ApplicationMessage *app = reinterpret_cast<ApplicationMessage *>(node_message.payload.data());
      ESP_LOGI(LOG_TAG, "[0x%llx] Application.temperature: %f", node_message.source_address, app->temperature);
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
