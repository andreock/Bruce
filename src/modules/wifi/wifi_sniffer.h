#pragma once
#include "esp_wifi.h"
#include "net_sniffer.h"
#include <set>

struct BeaconList {
    char MAC[6];
    uint8_t channel;
    bool operator<(const BeaconList &other) const {
        int cmp = memcmp(MAC, other.MAC, sizeof(MAC));
        if (cmp != 0) { return cmp < 0; }
        return channel < other.channel;
    }
};

class WiFiSniffer : public NetSniffer {
public:
    WiFiSniffer();
    virtual ~WiFiSniffer();

    // Main setup function (entry point)
    void sniffer_setup();

    // Override from NetSniffer
    void handleRawPacket(void *buf, wifi_promiscuous_pkt_type_t type);

    // WiFi Control
    bool initialize();
    void cleanup();
    bool startSniffer();
    void stopSniffer();
    bool isSniffing() const { return snifferActive; }

    // Channel management
    void setChannel(uint8_t channel);
    void nextChannel();
    void prevChannel();
    uint8_t getCurrentChannel() const { return currentChannel; }

    // Deauth functionality
    void enableDeauth(bool enable) { deauthEnabled = enable; }
    bool isDeauthEnabled() const { return deauthEnabled; }
    void performDeauthAttack();

    // Statistics
    int getEAPOLCount() const { return num_EAPOL; }
    int getHandshakeCount() const { return num_HS; }
    void resetEAPOLCounter() { num_EAPOL = 0; }
    void resetHandshakeCounter() { num_HS = 0; }
    void resetAllCounters();

    // Beacon management
    void registerBeacon(const char *mac, uint8_t channel);
    void clearBeacons() { registeredBeacons.clear(); }
    const std::set<BeaconList> &getRegisteredBeacons() const { return registeredBeacons; }

    // Handshake tracking
    void clearSavedHS() { SavedHS.clear(); }
    const std::set<String> &getSavedHS() const { return SavedHS; }

    // Compatibility methods
    void setHandshakeSniffer();

private:
    // WiFi Control variables
    bool snifferActive;
    uint8_t currentChannel;
    bool deauthEnabled;
    unsigned long lastDeauthTime;
    unsigned long lastTime;

    // Statistics
    int num_EAPOL;
    int num_HS;

    // Beacon and handshake tracking
    std::set<BeaconList> registeredBeacons;
    std::set<String> SavedHS;

    // WiFi setup and control
    void setupWiFiConfig();
    void handleUserInterface();
    void updateDisplay();

    // Packet processing
    bool isItEAPOL(const wifi_promiscuous_pkt_t *packet);
    void saveHandshake(const wifi_promiscuous_pkt_t *packet, bool beacon, FS &fs);
    void processEAPOLPacket(const wifi_promiscuous_pkt_t *pkt);
    void processBeaconFrame(const wifi_promiscuous_pkt_t *pkt);
    void savePacketToFile(const wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type);

    // Static callback
    static void snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type);
    static WiFiSniffer *instance;

    // PCAP header structure
    typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } pcaprec_hdr_t;
};

// Global variables for compatibility
extern uint8_t ch;
extern bool _only_HS;
extern int num_HS;
extern bool isLittleFS;
extern std::set<BeaconList> registeredBeacons;
extern std::set<String> SavedHS;
