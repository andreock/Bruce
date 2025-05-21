#include "EthernetMenu.h"
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "modules/ethernet/ARPScanner.h"
#include "modules/ethernet/EthernetHelper.h"

void EthernetMenu::optionsMenu() {
    options = {
        {"Scan Hosts",
         [=]() {
             auto eth = EthernetHelper();

             while (!eth.is_connected()) { delay(100); }

             esp_netif_t *esp_netinterface = esp_netif_get_handle_from_ifkey("ETH_SPI_0");
             if (esp_netinterface == nullptr) {
                 Serial.println("Failed to get netif handle");
                 return;
             }
             ARPScanner{esp_netinterface};
         }},
    };
    addOptionToMainMenu();

    delay(200);

    loopOptions(options, MENU_TYPE_SUBMENU, "Ethernet");
}

void EthernetMenu::drawIconImg() {
    drawImg(
        *bruceConfig.themeFS(), bruceConfig.getThemeItemImg(bruceConfig.theme.paths.rfid), 0, imgCenterY, true
    );
}
void EthernetMenu::drawIcon(float scale) {
    clearIconArea();
    int icon_size = 50; // Size of the icon

    int iconW = scale * 65;
    int iconH = scale * 55;

    int X = iconCenterX - iconW / 2;
    int Y = iconCenterY - iconH / 2;
    int little_segment = icon_size / 3; // Divide X into 3 equal parts for the three ending segments

    int width = 5;

    // Draw the lateral lines
    tft.fillRect(X, Y, width, icon_size, bruceConfig.priColor);
    tft.fillRect(X + icon_size, Y, width, icon_size, bruceConfig.priColor);

    tft.fillRect(X, Y, icon_size, width, bruceConfig.priColor); // Draw the top lines
    /* Icon at the end:
    |------|
    |      |
    |      |
    */

    tft.fillRect(X, Y + icon_size, little_segment, width, bruceConfig.priColor);
    tft.fillRect(
        X + icon_size - little_segment + width, Y + icon_size, little_segment, width, bruceConfig.priColor
    ); // Draw a line from the left to the right

    /* Icon at the end:
    |------|
    |      |
    |--  --|
    */

    // // Make the rectangle at the end of the icon. width*2 compesate the other line thikness
    tft.fillRect(X + little_segment, Y + icon_size, width, width * 2, bruceConfig.priColor);
    tft.fillRect(X + icon_size - little_segment, Y + icon_size, width, width * 2, bruceConfig.priColor);

    // tft.fillRect(
    //     X + little_segment, Y + icon_size + 5, little_segment, width, bruceConfig.priColor
    // ); // Close the socket
}
