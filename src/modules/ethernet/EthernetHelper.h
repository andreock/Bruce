#ifndef ETHERNET_HELPER_H
#define ETHERNET_HELPER_H
#include <Arduino.h>
#include <stdint.h>

class EthernetHelper {
private:
    void setup();
    uint8_t mac[6];
    void generate_mac();

public:
    EthernetHelper(/* args */);
    ~EthernetHelper();
    bool is_connected();
};

#endif // ETHERNET_H
