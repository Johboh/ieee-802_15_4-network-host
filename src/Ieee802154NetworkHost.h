#pragma once

#include <GCMEncryption.h>
#include <Ieee802154.h>
#include <cstdint>
#include <functional>
#include <vector>

namespace Ieee802154NetworkHostLog {
const char TAG[] = "802.15.4 host";
} // namespace Ieee802154NetworkHostLog

/**
 */
class Ieee802154NetworkHost {
public:
  static constexpr uint8_t DEFAULT_CHANNEL = 15;
  static constexpr uint16_t DEFAULT_PAN_ID = 0x9191;

  struct ApplicationMessage {
    Ieee802154NetworkHost &host;
    uint64_t source_address = 0;
    std::vector<uint8_t> payload;
  };

  typedef std::function<void(Ieee802154NetworkHost::ApplicationMessage application_message)> OnApplicationMessage;

  struct Configuration {
    /**
     * Encyption key used for the GCM packet encryption. Must be exact 16 bytes long. \0 does not count.
     *
     */
    const char *gcm_encryption_key;
    /**
     * Secret used for the GCM packet encryption to validate the integrity of the messages. We expect the decrypted
     * payload to contain this string. Must be exact 8 bytes long. \0 does not count.
     */
    const char *gcm_encryption_secret;
    /**
     * 802.15.4 channel to use. Value between 11 and 16, and its recommended to pick a channel that is in between the
     * common WiFi channels. 15 is a good number. The node will disover what channel to use.
     */
    uint8_t channel = DEFAULT_CHANNEL;
    /**
     * Private Area Network Identifier. Should be same between host and node.
     */
    uint16_t pan_id = DEFAULT_PAN_ID;
    /**
     * @brief Transmit power in dB.
     * Unknown allowed range.
     */
    int8_t tx_power = 20;
  };

  /**
   * @brief Construct a new Ieee 8 0 2 1 5 4 Network Host object
   *
   * @param configuration see Configuration class.
   * @param on_application_message callback on new application message.
   */
  Ieee802154NetworkHost(Configuration configuration, OnApplicationMessage on_application_message);

public:
  void start();

  /**
   * @brief Get the device mac address for this device. This would be the source address in the 802.15.4 frame (or the
   * destination address for a sender).
   */
  uint64_t deviceMacAddress();

private:
  void onMessage(Ieee802154::Message message);
  void onDataRequest(Ieee802154::DataRequest request);

private:
  Ieee802154 _ieee802154;
  bool _initialized = false;
  Configuration _configuration;
  GCMEncryption _gcm_encryption;
  OnApplicationMessage _on_application_message;
};
