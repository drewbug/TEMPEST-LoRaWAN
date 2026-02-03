/*
 * variant.cpp - Digital pin mapping for Seeed Wio Tracker L1
 *
 * Pin mapping array: logical digital pins (D0-D30)
 * to physical GPIO ports/pins on nRF52840.
 *
 * From meshtastic/firmware variants/nrf52840/seeed_wio_tracker_L1
 */

#include "variant.h"
#include "nrf.h"
#include "wiring_constants.h"
#include "wiring_digital.h"

extern "C" {
const uint32_t g_ADigitalPinMap[] = {
    // D0 .. D10 - Peripheral control pins
    41, // D0  P1.09    GNSS_WAKEUP
    7,  // D1  P0.07    LORA_DIO1
    39, // D2  P1.07    LORA_RESET
    42, // D3  P1.10    LORA_BUSY
    46, // D4  P1.14    LORA_CS
    40, // D5  P1.08    LORA_SW (RXEN)
    27, // D6  P0.27    GNSS_TX
    26, // D7  P0.26    GNSS_RX
    30, // D8  P0.30    SPI_SCK
    3,  // D9  P0.03    SPI_MISO
    28, // D10 P0.28    SPI_MOSI

    // D11-D12 - LED / Buzzer
    33, // D11 P1.01    User LED (green)
    32, // D12 P1.00    Buzzer

    // D13 - User input
    8,  // D13 P0.08    User Button

    // D14-D15 - OLED I2C
    6,  // D14 P0.06    OLED SDA
    5,  // D15 P0.05    OLED SCL

    // D16 - Battery ADC
    31, // D16 P0.31    VBAT_ADC

    // D17-D18 - Grove I2C
    43, // D17 P1.11    GROVE SDA
    44, // D18 P1.12    GROVE SCL

    // D19-D24 - QSPI Flash
    21, // D19 P0.21    QSPI_SCK
    25, // D20 P0.25    QSPI_CSN
    20, // D21 P0.20    QSPI_SIO_0
    24, // D22 P0.24    QSPI_SIO_1
    22, // D23 P0.22    QSPI_SIO_2
    23, // D24 P0.23    QSPI_SIO_3

    // D25-D29 - Trackball
    36, // D25 TB_UP
    12, // D26 TB_DOWN
    11, // D27 TB_LEFT
    35, // D28 TB_RIGHT
    37, // D29 TB_PRESS

    // D30 - Battery control
    4,  // D30 BAT_CTL
};
}

void initVariant()
{
    // QSPI flash CS high (deselect)
    pinMode(PIN_QSPI_CS, OUTPUT);
    digitalWrite(PIN_QSPI_CS, HIGH);

    // Battery monitoring enable
    pinMode(BAT_READ, OUTPUT);
    digitalWrite(BAT_READ, HIGH);

    // LEDs off
    pinMode(PIN_LED1, OUTPUT);
    digitalWrite(PIN_LED1, LOW);
    pinMode(PIN_LED2, OUTPUT);
    digitalWrite(PIN_LED2, LOW);
}
