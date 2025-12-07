#include "Ota.h"
#include <Ieee802154NetworkShared.h>
#include <algorithm>
#include <esp_err.h>
#include <esp_log.h>
#include <stdint.h>

namespace Ieee802154NetworkHostUtils {

// Too small, i.e. size of 802.15.4 packages, will be very slow.
#define HTTP_BUFFER_SIZE 8192
#define HTTP_REMOTE_TIMEOUT_MS 15000

Ota::Ota(const char *log_tag, size_t data_payload_size, CrtBundleAttach crt_bundle_attach)
    : _log_tag(log_tag), _data_payload_size(data_payload_size), _crt_bundle_attach(crt_bundle_attach) {}

esp_err_t Ota::httpEventHandler(esp_http_client_event_t *evt) {
  // Not Used
  return ESP_OK;
}

int Ota::fillBuffer(esp_http_client_handle_t client, char *buffer, size_t buffer_size) {
  int total_read = 0;
  while (total_read < buffer_size) {
    int read = esp_http_client_read(client, buffer + total_read, buffer_size - total_read);
    if (read <= 0) {
      if (esp_http_client_is_complete_data_received(client)) {
        return total_read;
      } else {
        ESP_LOGE(_log_tag, "OTA: Failed to fill buffer, read zero and not complete.");
        return -1;
      }
    }
    total_read += read;
  }
  return total_read;
}

bool Ota::perform(char *url, char *md5hash, BeginCallback begin_callback, DataCallback data_callback) {

  // We want to keep this large for HTTP performance.

  esp_http_client_config_t config = {};
  config.url = url;
  config.user_data = this;
  config.event_handler = httpEventHandler;
  config.buffer_size = HTTP_BUFFER_SIZE;
  if (_crt_bundle_attach) {
    config.crt_bundle_attach = _crt_bundle_attach;
    ESP_LOGI(_log_tag, "OTA: With TLS/HTTPS support");
  } else {
    ESP_LOGI(_log_tag, "OTA: Without TLS/HTTPS support");
  }
  esp_http_client_handle_t client = esp_http_client_init(&config);

  ESP_LOGI(_log_tag, "OTA: Using URL %s", url);

  esp_http_client_set_method(client, HTTP_METHOD_GET);
  esp_http_client_set_header(client, "Accept", "*/*");
  esp_http_client_set_timeout_ms(client, HTTP_REMOTE_TIMEOUT_MS);

  bool success = false;
  esp_err_t r = esp_http_client_open(client, 0);
  if (r == ESP_OK) {
    esp_http_client_fetch_headers(client);
    auto status_code = esp_http_client_get_status_code(client);
    auto content_length = esp_http_client_get_content_length(client);
    ESP_LOGI(_log_tag, "OTA: HTTP status code: %d, content length: %lld", status_code, content_length);

    if (status_code == 200) {
      // Begin first now when we know content length.
      begin_callback(content_length);

      // Then write chunks.
      success = writeStreamAsDataMessages(data_callback, content_length,
                                          [&](char *buffer, size_t buffer_size, size_t total_bytes_left) {
                                            return fillBuffer(client, buffer, buffer_size);
                                          });
    } else {
      ESP_LOGE(_log_tag, "OTA: Got non 200 status code: %d", status_code);
    }

  } else {
    ESP_LOGE(_log_tag, "OTA: Failed to open HTTP connection:: %s", esp_err_to_name(r));
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  return success;
}

bool Ota::writeStreamAsDataMessages(
    DataCallback data_callback, size_t content_length,
    std::function<int(char *buffer, size_t buffer_size, size_t total_bytes_left)> fill_buffer) {

  char *buffer = (char *)malloc(HTTP_BUFFER_SIZE);
  if (buffer == nullptr) {
    ESP_LOGE(_log_tag, "Ota: Failed to allocate buffer of size: %d", HTTP_BUFFER_SIZE);
    return false;
  }

  int bytes_read = 0;
  while (bytes_read < content_length) {
    int bytes_filled = fill_buffer(buffer, HTTP_BUFFER_SIZE, content_length - bytes_read);
    if (bytes_filled < 0) {
      ESP_LOGE(_log_tag, "Ota: Unable to fill buffer");
      free(buffer);
      return false;
    }

    ESP_LOGV(_log_tag, "Ota: Filled buffer with %d", bytes_filled);

    // write buffer
    if (!sendBufferAsDataMessages(data_callback, buffer, bytes_filled)) {
      ESP_LOGE(_log_tag, "Ota: Failed to write buffer to partition");
      free(buffer);
      return false;
    }

    bytes_read += bytes_filled;

    // If this is the end, finish up.
    if (bytes_read == content_length) {
      ESP_LOGI(_log_tag, "Ota: End of stream");
    }

    vTaskDelay(0); // Yield/reschedule
  }

  free(buffer);
  return true;
}

bool Ota::sendBufferAsDataMessages(DataCallback data_callback, char *buffer, size_t buffer_size) {
  size_t bytes_sent = 0;
  while (bytes_sent < buffer_size) {
    auto bytes_to_send = std::min(buffer_size - bytes_sent, _data_payload_size);
    if (!data_callback(buffer + bytes_sent, bytes_to_send)) {
      return false;
    }
    bytes_sent += bytes_to_send;

    vTaskDelay(0); // Yield/reschedule
  }
  return true;
}

} // namespace Ieee802154NetworkHostUtils