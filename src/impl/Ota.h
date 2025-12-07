#pragma once

#include <esp_err.h>
#include <esp_http_client.h>
#include <functional>
#include <string>
#include <vector>

namespace Ieee802154NetworkHostUtils {

class Ota {
public:
  /**
   * @brief CRT Bundle Attach for Ardunio or ESP-IDF from MDTLS, to support TLS/HTTPS.
   *
   * Include esp_crt_bundle.h and pass the following when using respective framework:
   * for Arduino: arduino_esp_crt_bundle_attach
   * for ESP-IDF: esp_crt_bundle_attach
   *
   * C style function.
   */
  typedef esp_err_t (*CrtBundleAttach)(void *conf);

  /**
   * @param crt_bundle_attach CRT Bundle Attach for Ardunio or ESP-IDF from MDTLS, to support TLS/HTTPS. See definition
   * of CrtBundleAttach.
   */
  Ota(const char *log_tag, size_t data_payload_size, CrtBundleAttach crt_bundle_attach = nullptr);

public:
  using BeginCallback = std::function<bool(const size_t size)>;
  using DataCallback = std::function<bool(const char *data, const size_t length)>;

  bool perform(char *url, char *md5hash, BeginCallback begin_callback, DataCallback data_callback);

private:
  static esp_err_t httpEventHandler(esp_http_client_event_t *evt);
  int fillBuffer(esp_http_client_handle_t client, char *buffer, size_t buffer_size);
  bool
  writeStreamAsDataMessages(DataCallback data_callback, size_t content_length,
                            std::function<int(char *buffer, size_t buffer_size, size_t total_bytes_left)> fill_buffer);
  bool sendBufferAsDataMessages(DataCallback data_callback, char *buffer, size_t buffer_size);

private:
  const char *_log_tag;
  size_t _data_payload_size;
  CrtBundleAttach _crt_bundle_attach;
};

}; // namespace Ieee802154NetworkHostUtils