#include "Ieee802154NetworkHost.h"
#include <Ieee802154NetworkShared.h>
#include <cstring>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

Ieee802154NetworkHost::Ieee802154NetworkHost(Configuration configuration, OnNodeMessage on_node_message)
    : _ieee802154({.channel = configuration.channel, .pan_id = configuration.pan_id, .data_frame_retries = 50},
                  std::bind(&Ieee802154NetworkHost::onMessage, this, std::placeholders::_1),
                  std::bind(&Ieee802154NetworkHost::onDataRequest, this, std::placeholders::_1)),
      _configuration(configuration),
      _gcm_encryption(configuration.gcm_encryption_key, configuration.gcm_encryption_secret, false),
      _on_node_message(on_node_message) {}

void Ieee802154NetworkHost::start() {
  if (_initialized) {
    ESP_LOGW(Ieee802154NetworkHostLog::TAG, "Already started");
    return;
  }

  _ieee802154.initialize();

  _initialized = true;
}

void Ieee802154NetworkHost::onMessage(Ieee802154::Message message) {
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got Message");
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- source MAC: 0x%llx", message.source_address);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- destination MAC: 0x%llx", message.destination_address);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- wire payload size: %d", message.payload_size);
  auto decrypted = _gcm_encryption.decrypt(message.payload);
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- decrypted size: %d", decrypted.size());

  if (decrypted.size() > 0) {
    uint8_t message_id = decrypted.data()[0];

    switch (message_id) {

    case Ieee802154NetworkShared::MESSAGE_ID_MESSAGE: {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- Got MessageV1");
      Ieee802154NetworkShared::MessageV1 *messagev1 =
          reinterpret_cast<Ieee802154NetworkShared::MessageV1 *>(decrypted.data());
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, "   -- Firmare version: %ld", messagev1->firmware_version);

      if (_on_node_message) {
        Ieee802154NetworkHost::NodeMessage node_message = {
            .host = *this,
            .source_address = message.source_address,
            .firmware_version = messagev1->firmware_version,
            .payload =
                std::vector<uint8_t>(decrypted.begin() + sizeof(Ieee802154NetworkShared::MessageV1), decrypted.end()),
        };

        _on_node_message(node_message);
      }
      break;
    }

    case Ieee802154NetworkShared::MESSAGE_ID_DISCOVERY_REQUEST_V1: {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- Got DiscoveryRequestV1");
      Ieee802154NetworkShared::DiscoveryResponseV1 response = {
          .channel = _configuration.channel,
      };
      auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
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
}

void Ieee802154NetworkHost::onDataRequest(Ieee802154::DataRequest request) {
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got Data Request");
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- source MAC: 0x%llx", request.source_address);
  if (_have_pending_data.find(request.source_address) == _have_pending_data.end()) {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- No pending bit set.");
    return;
  }
  // Upon receiving data request, and we did indicate that we had data, we should wait a bit then start sending our
  // data.

  vTaskDelay(20 / portTICK_PERIOD_MS);

  // Timestamp
  auto timestamp = _pending_timestamp.find(request.source_address);
  if (timestamp != _pending_timestamp.end()) {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- got timestamp %lld to send to node", timestamp->second);
    Ieee802154NetworkShared::PendingTimestampResponseV1 response = {
        .timestamp = timestamp->second,
    };
    auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
    if (!_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size())) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send timestamp to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent timestamp to node");
    }
  }
  _pending_timestamp.erase(request.source_address);

  // Payload
  auto payload = _pending_payload.find(request.source_address);
  if (payload != _pending_payload.end()) {
    ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- got payload with size %d to send to node", payload->second.size());

    auto wire_message_size = sizeof(Ieee802154NetworkShared::PendingPayloadResponseV1) + payload->second.size();
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[wire_message_size]);
    Ieee802154NetworkShared::PendingPayloadResponseV1 *wire_message =
        reinterpret_cast<Ieee802154NetworkShared::PendingPayloadResponseV1 *>(buffer.get());
    wire_message->id = Ieee802154NetworkShared::MESSAGE_ID_PENDING_PAYLOAD_RESPONSE_V1;
    memcpy(wire_message->payload, payload->second.data(), payload->second.size());

    auto encrypted = _gcm_encryption.encrypt(wire_message, wire_message_size);
    if (!_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size())) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to send timestamp to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent payload to node");
    }
  }
  _pending_payload.erase(request.source_address);

  // Firmware
  auto firmware = _pending_firmware.find(request.source_address);
  if (firmware != _pending_firmware.end()) {
    // Need to send three packages here.

    Ieee802154NetworkShared::PendingFirmwareWifiCredentialsResponseV1 wifi_response;
    strncpy(wifi_response.wifi_ssid, firmware->second.wifi_ssid, sizeof(wifi_response.wifi_ssid));
    strncpy(wifi_response.wifi_password, firmware->second.wifi_password, sizeof(wifi_response.wifi_password));

    auto encrypted = _gcm_encryption.encrypt(&wifi_response, sizeof(wifi_response));
    if (!_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size())) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to firmware wifi credentials to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware wifi credentials to node");
    }

    Ieee802154NetworkShared::PendingFirmwareChecksumResponseV1 checksum_response;
    strncpy(checksum_response.md5, firmware->second.md5, sizeof(checksum_response.md5));

    encrypted = _gcm_encryption.encrypt(&checksum_response, sizeof(checksum_response));
    if (!_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size())) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to firmware checksum to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware checksum to node");
    }

    Ieee802154NetworkShared::PendingFirmwareUrlResponseV1 url_response;
    strncpy(url_response.url, firmware->second.url, sizeof(url_response.url));

    encrypted = _gcm_encryption.encrypt(&url_response, sizeof(url_response));
    if (!_ieee802154.transmit(request.source_address, encrypted.data(), encrypted.size())) {
      ESP_LOGW(Ieee802154NetworkHostLog::TAG, " -- failed to firmware URL to node");
    } else {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- sent firmware URL to node");
    }
  }
  _pending_firmware.erase(request.source_address);

  // We are done processing this node.
  _have_pending_data.erase(request.source_address);
  _ieee802154.clearPending(request.source_address);
}

void Ieee802154NetworkHost::setPendingFirmware(uint64_t target_address, FirmwareUpdate &firmware_update) {
  _pending_firmware[target_address] = firmware_update;
  _have_pending_data.emplace(target_address);
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingTimestamp(uint64_t target_address, uint64_t timestamp) {
  _pending_timestamp[target_address] = timestamp;
  _have_pending_data.emplace(target_address);
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingPayload(uint64_t target_address, std::vector<uint8_t> payload) {
  _pending_payload[target_address] = payload;
  _have_pending_data.emplace(target_address);
  _ieee802154.setPending(target_address);
}

void Ieee802154NetworkHost::setPendingPayload(uint64_t target_address, uint8_t *payload, uint8_t payload_size) {
  _pending_payload[target_address] = std::vector<uint8_t>(payload, payload + payload_size);
  _ieee802154.setPending(target_address);
}

uint64_t Ieee802154NetworkHost::deviceMacAddress() { return _ieee802154.deviceMacAddress(); }