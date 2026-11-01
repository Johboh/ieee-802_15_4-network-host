#pragma once

#include <GCMEncryption.h>
#include <Ieee802154.h>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
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

  struct NodeMessage {
    Ieee802154NetworkHost &host;
    uint64_t source_address = 0;
    uint32_t firmware_version = 0;
    int8_t rssi = 0;
    std::vector<uint8_t> payload;
  };

  typedef std::function<void(Ieee802154NetworkHost::NodeMessage application_message)> OnNodeMessage;

  struct NodeDataRequest {
    Ieee802154NetworkHost &host;
    uint64_t source_address = 0;
    bool has_pending_data = false;
    bool has_firmware_update = false;
    bool has_forget_host = false;
    bool has_payload = false;
    bool has_timestamp = false;
  };

  typedef std::function<void(Ieee802154NetworkHost::NodeDataRequest data_request)> OnNodeDataRequest;

  struct Configuration {
    /**
     * Encryption key used for the GCM packet encryption. Must be exact 16 bytes long. \0 does not count.
     *
     */
    const char *gcm_encryption_key;
    /**
     * Secret used for the GCM packet encryption to validate the integrity of the messages. We expect the decrypted
     * payload to contain this string. Must be exact 8 bytes long. \0 does not count.
     */
    const char *gcm_encryption_secret;
    /**
     * 802.15.4 channel to use. Value between 11 and 26, and its recommended to pick a channel that is in between the
     * common WiFi channels. 15 is the most safe best. Other good options are 20. 25-26 are good too, but risky
     * compatibility wise.
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
   * @param on_node_message callback on new message from a node.
   * @param on_node_data_request optional callback when a data request is received from a node.
   *
   */
  Ieee802154NetworkHost(Configuration configuration, OnNodeMessage on_node_message,
                        OnNodeDataRequest on_node_data_request = {});
  ~Ieee802154NetworkHost();

  Ieee802154NetworkHost(const Ieee802154NetworkHost &) = delete;
  Ieee802154NetworkHost &operator=(const Ieee802154NetworkHost &) = delete;

public:
  /**
   * Start to setup receiving callbacks.
   */
  bool start();

  void teardown();

  /**
   * @brief Get the device mac address for this device. This would be the source address in the 802.15.4 frame (or the
   * destination address for a sender).
   */
  uint64_t deviceMacAddress() const;

  /**
   * Set timestamp for a specific node.
   * Once a timestamp is set, it will be delivered when the node asks for data, and will be delivered once until
   * next call of setTimestamp(timestamp).
   *
   * @param target_address the MAC address of the node to deliver the timestamp to.
   * @param timestamp unix timestamp in seconds, UTC. If absent, will get the current timestamp, UTC, as time of sending
   * the timestamp to the node. For this, the host needs to have a synchronized clock.
   */
  void setPendingTimestamp(uint64_t target_address, std::optional<uint64_t> timestamp = std::nullopt);

  struct FirmwareUpdate {
    char wifi_ssid[32];     // WiFi SSID that node should connect to.
    char wifi_password[32]; // WiFi password that the node should connect to.
    char url[74];           // url where to find firmware binary. Note the max URL length.
    char md5[32];           // MD5 hash of firmware. Does not include trailing \0
  };

  /**
   * Notify a node, when asking for data, that there is a new firmware available.
   * When the node asks for it, it will be delivered to the node.
   *
   * @param target_address the MAC address of the node to send firmware update information to.
   * @param firmware_update firmware update metadata.
   */
  void setPendingFirmware(uint64_t target_address, const FirmwareUpdate &firmware_update);

  /**
   * Notify a node, when asking for data, that there is payload available.
   * When the node asks for it, it will be delivered to the node.
   *
   * @param target_address the MAC address of the node to send payload to.
   * @param payload the payload itself. Maximum payload size is 78 bytes.
   */
  void setPendingPayload(uint64_t target_address, const std::vector<uint8_t> &payload);

  /**
   * Notify a node, when asking for data, that there is payload available.
   * When the node asks for it, it will be delivered to the node.
   *
   * @param target_address the MAC address of the node to send payload to.
   * @param payload the payload itself.
   * @param payload_size the size of the payload. Maximum payload size is 78 bytes.
   */
  void setPendingPayload(uint64_t target_address, const uint8_t *payload, uint8_t payload_size);

  /**
   * Notify a node, when asking for data, that it should forget its host. After this, the node will restart and re-do
   * host discovery.
   *
   * @param target_address the MAC address of the node that should forget its host.
   */
  void setForgetHost(uint64_t target_address);

private:
  void onMessage(Ieee802154::Message message);
  void onDataRequest(Ieee802154::DataRequest request);

private:
  Ieee802154 _ieee802154;
  bool _initialized = false;
  Configuration _configuration;
  GCMEncryption _gcm_encryption;
  OnNodeMessage _on_node_message;
  OnNodeDataRequest _on_node_data_request;

  // Pending states
private:
  std::mutex _pending_mutex;

  // Keep track of pending nodes, as the OnDataRequest callback is received even if pending is not set.
  std::set<uint64_t> _have_pending_data;

  // Map from MAC of node to firmware to send for that specific node.
  std::map<uint64_t, FirmwareUpdate> _pending_firmware;
  // Map from MAC of node to payload to send for that specific node.
  std::map<uint64_t, std::vector<uint8_t>> _pending_payload;
  // Map from MAC of node to timestamp to send for that specific node.
  std::map<uint64_t, std::optional<uint64_t>> _pending_timestamp;
  // Set of MAC of nodes that should forget the host.
  std::set<uint64_t> _pending_forget_host;
};
