#pragma once
#include <Arduino.h>
#include <FS.h>
#include <SD.h>
#include <TimeLib.h>

class NetSniffer {
public:
    NetSniffer();
    virtual ~NetSniffer();

    // File operations
    virtual void openFile(FS &fs);
    virtual void closeFile();
    virtual bool writeHeader(File file);
    virtual void newPacketSD(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t *buf);

    // File system management
    bool setupFileSystem();
    FS *getFileSystem() { return fileSystem; }
    String getFileSysName() const { return fileSysName; }
    bool isFileOpen() const { return fileOpen; }

    // Configuration
    void setOnlyHandshakes(bool onlyHS) { _only_HS = onlyHS; }
    bool getOnlyHandshakes() const { return _only_HS; }

    // Statistics
    uint32_t getPacketCount() const { return packet_counter; }
    void resetPacketCounter() { packet_counter = 0; }
    void setupDirectory(const String &dirName);

protected:
    FS *fileSystem;
    String fileSysName;
    File pcapFile;
    bool fileOpen;
    int fileCounter;
    bool isLittleFS;
    bool _only_HS;
    uint32_t packet_counter;
    String filename;

    // Helper methods
    void incrementPacketCounter() { packet_counter++; }
};
