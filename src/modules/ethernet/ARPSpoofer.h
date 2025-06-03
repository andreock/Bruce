#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include "Arduino.h"
#include "core/net_utils.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "modules/wifi/net_sniffer.h"
#include "modules/wifi/scan_hosts.h"
#include <FS.h>

class ARPSpoofer {
public:
    ARPSpoofer(
        const Host &host, IPAddress gateway, uint8_t _gatewayMAC[6], uint8_t mac[6], bool _mitm = false
    );
    ~ARPSpoofer();

    void setup(const Host &host, IPAddress gateway);
    void loop();

private:
    // ARP Spoofing specific variables
    uint8_t victimIP[4];
    uint8_t victimMAC[6];
    uint8_t gatewayIP[4];
    uint8_t gatewayMAC[6];
    uint8_t myMAC[6];
    bool mitm;

    // PCAP handling through composition
    NetSniffer *pcapHandler;

    // ARP packet creation and sending
    void sendARPPacket(uint8_t *targetIP, uint8_t *targetMAC, uint8_t *spoofedIP, uint8_t *spoofedMAC);
    bool initializePCAPCapture();
    void finalizePCAPCapture();
    void writePacketToPCAP(uint8_t *packet, uint32_t length);
};

#endif
