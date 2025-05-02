#include "Ieee802154NetworkHost.h"
#include <Ieee802154NetworkShared.h>
#include <cstring>
#include <esp_log.h>

Ieee802154NetworkHost::Ieee802154NetworkHost(Configuration configuration, OnApplicationMessage on_application_message)
    : _ieee802154(
          {
              .channel = configuration.channel,
              .pan_id = configuration.pan_id,
              .handle_broadcasts = false,
          },
          std::bind(&Ieee802154NetworkHost::onMessage, this, std::placeholders::_1),
          std::bind(&Ieee802154NetworkHost::onDataRequest, this, std::placeholders::_1)),
      _configuration(configuration),
      _gcm_encryption(configuration.gcm_encryption_key, configuration.gcm_encryption_secret, false),
      _on_application_message(on_application_message) {}

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
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got MESSAGE_ID_MESSAGE");
      if (_on_application_message) {
        Ieee802154NetworkHost::ApplicationMessage application_message = {
            .host = *this,
            .source_address = message.source_address,
            .payload =
                std::vector<uint8_t>(decrypted.begin() + sizeof(Ieee802154NetworkShared::MessageV1), decrypted.end()),
        };

        _on_application_message(application_message);
      }
      break;
    }

    case Ieee802154NetworkShared::MESSAGE_ID_DISCOVERY_REQUEST_V1: {
      ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got MESSAGE_ID_DISCOVERY_REQUEST_V1");
      Ieee802154NetworkShared::DiscoveryResponseV1 response = {
          .channel = _configuration.channel,
      };
      auto encrypted = _gcm_encryption.encrypt(&response, sizeof(response));
      _ieee802154.transmit(message.source_address, encrypted.data(), encrypted.size());
      break;
    }
    }
  }
}

void Ieee802154NetworkHost::onDataRequest(Ieee802154::DataRequest request) {
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, "Got Data Request");
  ESP_LOGI(Ieee802154NetworkHostLog::TAG, " -- source MAC: 0x%llx", request.source_address);
}

uint64_t Ieee802154NetworkHost::deviceMacAddress() { return _ieee802154.deviceMacAddress(); }