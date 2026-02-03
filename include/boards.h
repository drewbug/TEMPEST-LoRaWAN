#ifndef _BOARDS_H_
#define _BOARDS_H_

#include <Arduino.h>

// SX1262 LoRa radio pin definitions for Seeed Wio Tracker L1
#define RADIO_CS_PIN    D4   // P1.14
#define RADIO_DIO1_PIN  D1   // P0.07
#define RADIO_RST_PIN   D2   // P1.07
#define RADIO_BUSY_PIN  D3   // P1.10
#define RADIO_RXEN_PIN  D5   // P1.08

// TCXO reference voltage on DIO3
#define RADIO_TCXO_VOLTAGE 1.8

// LoRa frequency (MHz)
#define LoRa_frequency 915.0

// Node ID used in outgoing Meshtastic headers
#define DEVICE_NODE_ID 0x27c82356

// LoRaWAN ABP credentials (replace with your network values)
#define LORAWAN_DEV_ADDR   0x00000000
#define LORAWAN_NWK_SKEY   { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
#define LORAWAN_APP_SKEY   { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }

// LED pin
#define BOARD_LED LED_GREEN

static inline void initBoard()
{
    Serial.begin(115200);
    while (!Serial && millis() < 1000)
        ; // wait up to 1s for USB serial (skip quickly on battery)

    pinMode(BOARD_LED, OUTPUT);
    digitalWrite(BOARD_LED, LOW);
}

#endif // _BOARDS_H_
