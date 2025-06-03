#include "net_sniffer.h"
#include "core/display.h"
#include "core/sd_functions.h"
#include <LittleFS.h>

#define FILENAME "raw_"

NetSniffer::NetSniffer()
    : fileSystem(nullptr), fileOpen(false), fileCounter(0), isLittleFS(true), _only_HS(false),
      packet_counter(0) {
    filename = "/BrucePCAP/" + (String)FILENAME + ".pcap";
    setupFileSystem();
}

NetSniffer::~NetSniffer() { closeFile(); }

bool NetSniffer::setupFileSystem() {
    _only_HS = true; // default mode

    if (setupSdCard()) {
        fileSystem = &SD;
        fileSysName = "SD";
        isLittleFS = false;
        _only_HS = false; // When using SD Card, saves everything
    } else {
        fileSystem = &LittleFS;
        fileSysName = "LittleFS";
    }

    return fileSystem != nullptr;
}

void NetSniffer::setupDirectory(const String &dirName) {
    if (!fileSystem->exists(dirName)) { fileSystem->mkdir(dirName); }
}

void NetSniffer::openFile(FS &fs) {
    setupDirectory("/BrucePCAP");

    // Find next available filename
    filename = "/BrucePCAP/" + (String)FILENAME + (String)fileCounter + ".pcap";
    while (fs.exists(filename)) {
        fileCounter++;
        filename = "/BrucePCAP/" + (String)FILENAME + (String)fileCounter + ".pcap";
    }

    pcapFile = fs.open(filename, FILE_WRITE);
    if (pcapFile) {
        fileOpen = writeHeader(pcapFile);
        Serial.println("Opened: " + filename);
    } else {
        fileOpen = false;
        Serial.println("Failed to open file: " + filename);
    }
}

void NetSniffer::closeFile() {
    if (fileOpen && pcapFile) {
        pcapFile.flush();
        pcapFile.close();
        fileOpen = false;
        Serial.println("File closed: " + filename);
    }
}

bool NetSniffer::writeHeader(File file) {
    uint32_t magic_number = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    uint32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 2500;
    uint32_t network = 105;

    if (file) {
        file.write((uint8_t *)&magic_number, sizeof(magic_number));
        file.write((uint8_t *)&version_major, sizeof(version_major));
        file.write((uint8_t *)&version_minor, sizeof(version_minor));
        file.write((uint8_t *)&thiszone, sizeof(thiszone));
        file.write((uint8_t *)&sigfigs, sizeof(sigfigs));
        file.write((uint8_t *)&snaplen, sizeof(snaplen));
        file.write((uint8_t *)&network, sizeof(network));
        return true;
    }
    return false;
}

void NetSniffer::newPacketSD(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t *buf) {
    if (pcapFile) {
        uint32_t orig_len = len;
        uint32_t incl_len = len;

        pcapFile.write((uint8_t *)&ts_sec, sizeof(ts_sec));
        pcapFile.write((uint8_t *)&ts_usec, sizeof(ts_usec));
        pcapFile.write((uint8_t *)&incl_len, sizeof(incl_len));
        pcapFile.write((uint8_t *)&orig_len, sizeof(orig_len));
        pcapFile.write(buf, incl_len);
    }
}
