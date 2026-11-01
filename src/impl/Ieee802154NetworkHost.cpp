#include "Ieee802154NetworkHost.h"
#include <Ieee802154NetworkShared.h>
#include <cinttypes>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

Ieee802154NetworkHost::Ieee802154NetworkHost(Configuration configuration, OnNodeMessage on_node_message,
                                             OnNodeDataRequest on_node_data_request)
    : _ieee802154({.channel = configuration.channel,
                   .pan_id = configuration.pan_id,
                   .data_frame_retries = 50,
                   .tx_power = configuration.tx_power},
                  std::bind(&Ieee802154NetworkHost::onMessage, this, std::placeholders::_1),
                  std::bind(&Ieee802154NetworkHost::onDataRequest, this, std::placeholders::_1)),
      _configuration(configuration),
      _gcm_encryption(configuration.gcm_encryption_key, configuration.gcm_encryption_secret, false),
      _on_node_message(on_node_message), _on_node_data_request(on_node_data_request) {}

Ieee802154NetworkHost::~Ieee802154NetworkHost() { teardown(); }

bool Ieee802154NetworkHost::start() {
  if (_initialized) {
    ESP_LOGW(Ieee802154NetworkHostLog::TAG, "Already started");
    return true;
  }

  if (!_ieee802154.initialize()) {
    ESP_LOGE(Ieee802154NetworkHostLog::TAG, "Failed to initialize 802.15.4 radio");
    return false;
  }

  _initialized = true;
  return true;
}

void Ieee802154NetworkHost::teardown() {
  if (!_initialized) {
    return;
  }

  _ieee802154.teardown();

  {
    std::scoped_lock lock(_pending_mutex);
    _have_pending_data.clear();
    _pending_firmware.clear();
    _pending_payload.clear();
    _pending_timestamp.clear();
    _pending_forget_host.clear();
  }

  _initialized = false;
}

void Ieee802154NetworkHost::onMessage(Ieee802154::Message message) {
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got Message");
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- source MAC: 0x%llx", message.source_address);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- destination MAC: 0x%llx", message.destination_address);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- wire payload size: %d", message.payload_size);
  auto decrypted = _gcm_encryption.decrypt(message.payload);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- decrypted size: %d", decrypted.size());

  if (decrypted.empty()) {
    return;
  }

  uint8_t message_id = decrypted.data()[0];

  switch (message_id) {

  case Ieee802154NetworkShared::MESSAGE_ID_MESSAGE: {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- Got MessageV1");
    if (decrypted.size() < sizeof(Ieee802154NetworkShared::MessageV1)) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- Message packet too small: %d bytes", decrypted.size());
      break;
    }
    Ieee802154NetworkShared::MessageV1 *messagev1 =
        reinterpret_cast<Ieee802154NetworkShared::MessageV1 *>(decrypted.data());
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, "   -- Firmware version: %" PRIu32, messagev1->firmware_version);

    if (_on_node_message) {
      Ieee802154NetworkHost::NodeMessage node_message = {
          .host = *this,
          .source_address = message.source_address,
          .firmware_version = messagev1->firmware_version,
          .rssi = message.rssi,
          .payload =
              std::vector<uint8_t>(decrypted.begin() + sizeof(Ieee802154NetworkShared::MessageV1), decrypted.end()),
      };

      _on_node_message(node_message);
    }
    break;
  }

  case Ieee802154NetworkShared::MESSAGE_ID_DISCOVERY_REQUEST_V1: {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- Got DiscoveryRequestV1");
    if (decrypted.size() < sizeof(Ieee802154NetworkShared::DiscoveryRequestV1)) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- Discovery request packet too small: %d bytes", decrypted.size());
      break;
    }
    Ieee802154NetworkShared::DiscoveryResponseV1 response = {
        .channel = _configuration.channel,
    };
    auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- Failed to encrypt discovery response");
      break;
    }
    _ieee802154.setNumberOfDataFramesRetries(1);
    _ieee802154.transmit(message.source_address, encrypted.data(), encrypted.size());
    _ieee802154.setNumberOfDataFramesRetries(50);
    break;
  }

  default:
    ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- Got unhandled message %d", message_id);
    break;
  }
}

void Ieee802154NetworkHost::onDataRequest(Ieee802154::DataRequest request) {
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got Data Request");
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- source MAC: 0x%llx", request.source_address);

  std::optional<std::optional<uint64_t>> timestamp_to_send;
  std::optional<std::vector<uint8_t>> payload_to_send;
  bool forget_host_to_send = false;
  std::optional<FirmwareUpdate> firmware_to_send;

  bool has_pending = false;
  bool has_firmware = false;
  bool has_forget_host = false;
  bool has_payload = false;
  bool has_timestamp = false;

  {
    std::scoped_lock lock(_pending_mutex);
    has_pending = (_have_pending_data.find(request.source_address) != _have_pending_data.end());
    if (has_pending) {
      auto timestamp_opt = _pending_timestamp.find(request.source_address);
      if (timestamp_opt != _pending_timestamp.end()) {
        has_timestamp = true;
        timestamp_to_send = timestamp_opt->second;
        _pending_timestamp.erase(timestamp_opt);
      }

      auto payload = _pending_payload.find(request.source_address);
      if (payload != _pending_payload.end()) {
        has_payload = true;
        payload_to_send = std::move(payload->second);
        _pending_payload.erase(payload);
      }

      auto forget_it = _pending_forget_host.find(request.source_address);
      if (forget_it != _pending_forget_host.end()) {
        has_forget_host = true;
        forget_host_to_send = true;
        _pending_forget_host.erase(forget_it);
      }

      auto firmware = _pending_firmware.find(request.source_address);
      if (firmware != _pending_firmware.end()) {
        has_firmware = true;
        firmware_to_send = firmware->second;
        _pending_firmware.erase(firmware);
      }

      _have_pending_data.erase(request.source_address);
    }
  }

  if (_on_node_data_request) {
    _on_node_data_request({
        .host = *this,
        .source_address = request.source_address,
        .has_pending_data = has_pending,
        .has_firmware_update = has_firmware,
        .has_forget_host = has_forget_host,
        .has_payload = has_payload,
        .has_timestamp = has_timestamp,
    });
  }

  if (!has_pending) {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- No pending bit set.");
    return;
  }

  // Upon receiving data request, and we did indicate that we had data, we should wait a bit then start sending our
  // data.
  vTaskDelay(20 / portTICK_PERIOD_MS);

  // Timestamp
  if (timestamp_to_send.has_value()) {
    uint64_t timestamp = 0;
    if (timestamp_to_send.value()) {
      timestamp = timestamp_to_send.value().value();
    } else {
      // Timestamp in UTC.
      time_t now = time(nullptr);
      struct tm *utc_time = gmtime(&now);
      timestamp = static_cast<uint64_t>(mktime(utc_time));
    }

    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- got timestamp %lld to send to node", timestamp);
    Ieee802154NetworkShared::PendingTimestampResponseV1 response = {
        .timestamp = timestamp,
    };
    auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt timestamp");
    } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
               Ieee802154::TransmitResult::Failure) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send timestamp to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent timestamp to node");
    }
  }

  // Payload
  if (payload_to_send.has_value()) {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- got payload with size %d to send to node", payload_to_send->size());

    auto wire_message_size = sizeof(Ieee802154NetworkShared::PendingPayloadResponseV1) + payload_to_send->size();
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[wire_message_size]);
    if (!buffer) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to allocate memory for payload response");
    } else {
      Ieee802154NetworkShared::PendingPayloadResponseV1 *wire_message =
          reinterpret_cast<Ieee802154NetworkShared::PendingPayloadResponseV1 *>(buffer.get());
      wire_message->id = Ieee802154NetworkShared::MESSAGE_ID_PENDING_PAYLOAD_RESPONSE_V1;
      if (!payload_to_send->empty()) {
        memcpy(wire_message->payload, payload_to_send->data(), payload_to_send->size());
      }

      auto encrypted = _gcm_encryption.encrypt(wire_message, wire_message_size);
      if (encrypted.empty()) {
        ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt payload");
      } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
                 Ieee802154::TransmitResult::Failure) {
        ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send payload to node");
      } else {
        ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent payload to node");
      }
    }
  }

  // Forget host
  if (forget_host_to_send) {
    Ieee802154NetworkShared::ForgetHostResponseV1 response;
    auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt forget host response");
    } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
               Ieee802154::TransmitResult::Failure) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send forget host to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent forget host to node");
    }

    // Node will restart and reset its sequence number
    _ieee802154.clearLastKnownSequenceNumberFor(request.source_address);
  }

  // Firmware
  if (firmware_to_send.has_value()) {
    // Set same unique identifier for all firmware packages.
    uint32_t identifier = esp_random();

    // Update via WIFI
    // Need to send three packages here.

    Ieee802154NetworkShared::PendingFirmwareWifiCredentialsResponseV1 wifi_response = {};
    strncpy(wifi_response.wifi_ssid, firmware_to_send->wifi_ssid, sizeof(wifi_response.wifi_ssid));
    strncpy(wifi_response.wifi_password, firmware_to_send->wifi_password, sizeof(wifi_response.wifi_password));
    wifi_response.identifier = identifier;

    auto encrypted = _gcm_encryption.encrypt(&wifi_response, sizeof(wifi_response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt firmware wifi credentials");
    } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
               Ieee802154::TransmitResult::Failure) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send firmware wifi credentials to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware wifi credentials to node");
    }

    Ieee802154NetworkShared::PendingFirmwareChecksumResponseV1 checksum_response = {};
    strncpy(checksum_response.md5, firmware_to_send->md5, sizeof(checksum_response.md5));
    checksum_response.identifier = identifier;

    encrypted = _gcm_encryption.encrypt(&checksum_response, sizeof(checksum_response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt firmware checksum");
    } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
               Ieee802154::TransmitResult::Failure) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send firmware checksum to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware checksum to node");
    }

    Ieee802154NetworkShared::PendingFirmwareUrlResponseV1 url_response = {};
    strncpy(url_response.url, firmware_to_send->url, sizeof(url_response.url));
    url_response.identifier = identifier;

    encrypted = _gcm_encryption.encrypt(&url_response, sizeof(url_response));
    if (encrypted.empty()) {
      ESP_LOGE(Ieee802154NetworkHostLog::TAG, " -- failed to encrypt firmware URL");
    } else if (_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size()) ==
               Ieee802154::TransmitResult::Failure) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send firmware URL to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware URL to node");
    }

    // After sending firmware metadata, assume node will restart and forget its sequence number.
    // Don't block next message if the sequence number is the same.
    _ieee802154.clearLastKnownSequenceNumberFor(request.source_address);
  }

  // We are done processing this node.
  _ieee802154.clearPending(request.source_address);
}

void Ieee802154NetworkHost::setPendingFirmware(uint64_t target_address, const FirmwareUpdate &firmware_update) {
  {
    std::scoped_lock lock(_pending_mutex);
    _pending_firmware[target_address] = firmware_update;
    _have_pending_data.emplace(target_address);
  }
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingTimestamp(uint64_t target_address, std::optional<uint64_t> timestamp) {
  {
    std::scoped_lock lock(_pending_mutex);
    _pending_timestamp[target_address] = timestamp;
    _have_pending_data.emplace(target_address);
  }
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingPayload(uint64_t target_address, const std::vector<uint8_t> &payload) {
  if (payload.size() > 78) {
    ESP_LOGE(Ieee802154NetworkHostLog::TAG, "Payload size %d exceeds maximum allowed size of 78 bytes", payload.size());
    return;
  }
  {
    std::scoped_lock lock(_pending_mutex);
    _pending_payload[target_address] = payload;
    _have_pending_data.emplace(target_address);
  }
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingPayload(uint64_t target_address, const uint8_t *payload, uint8_t payload_size) {
  if (payload_size > 0 && payload == nullptr) {
    ESP_LOGE(Ieee802154NetworkHostLog::TAG, "Payload buffer is null with non-zero size");
    return;
  }
  if (payload_size > 78) {
    ESP_LOGE(Ieee802154NetworkHostLog::TAG, "Payload size %d exceeds maximum allowed size of 78 bytes", payload_size);
    return;
  }
  {
    std::scoped_lock lock(_pending_mutex);
    _pending_payload[target_address] = std::vector<uint8_t>(payload, payload + payload_size);
    _have_pending_data.emplace(target_address);
  }
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setForgetHost(uint64_t target_address) {
  {
    std::scoped_lock lock(_pending_mutex);
    _pending_forget_host.emplace(target_address);
    _have_pending_data.emplace(target_address);
  }
  _ieee802154.setPending(target_address);
}

uint64_t Ieee802154NetworkHost::deviceMacAddress() const { return _ieee802154.deviceMacAddress(); }
