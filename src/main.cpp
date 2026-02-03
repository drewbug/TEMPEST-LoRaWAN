/*
   TEMPEST-LoRaWAN → Meshtastic Relay
   Seeed Wio Tracker L1 Pro (nRF52840 + SX1262)

   Listens on TEMPEST-LoRaWAN settings (915 MHz, BW 500, SF 7).
   When a packet arrives, relays it as a Meshtastic text message
   (906.875 MHz, BW 250, SF 11, encrypted with the default key).
   Then switches back to listening.
*/

#include <RadioLib.h>
#include <U8g2lib.h>
#include <Wire.h>
#include "boards.h"

// ── Software AES-128-ECB (tiny-AES, public domain) ──────────────
// Only the encrypt direction is needed for CTR mode.

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void keyExpansion(const uint8_t key[16], uint8_t roundKeys[176])
{
    memcpy(roundKeys, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t tmp[4];
        memcpy(tmp, &roundKeys[(i - 1) * 4], 4);
        if (i % 4 == 0) {
            uint8_t t = tmp[0];
            tmp[0] = sbox[tmp[1]] ^ Rcon[i / 4];
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[3]];
            tmp[3] = sbox[t];
        }
        for (int j = 0; j < 4; j++)
            roundKeys[i * 4 + j] = roundKeys[(i - 4) * 4 + j] ^ tmp[j];
    }
}

static uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x >> 7) * 0x1b); }

static void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16], rk[176];
    keyExpansion(key, rk);
    memcpy(state, in, 16);

    // AddRoundKey 0
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];

    for (int round = 1; round <= 10; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
        // ShiftRows
        uint8_t t;
        t = state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
        t = state[2]; state[2]=state[10]; state[10]=t; t=state[6]; state[6]=state[14]; state[14]=t;
        t = state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=t;
        // MixColumns (skip on last round)
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                int i = c * 4;
                uint8_t a0=state[i], a1=state[i+1], a2=state[i+2], a3=state[i+3];
                uint8_t x0=xtime(a0), x1=xtime(a1), x2=xtime(a2), x3=xtime(a3);
                state[i]   = x0 ^ x1 ^ a1 ^ a2 ^ a3;
                state[i+1] = a0 ^ x1 ^ x2 ^ a2 ^ a3;
                state[i+2] = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                state[i+3] = x0 ^ a0 ^ a1 ^ a2 ^ x3;
            }
        }
        // AddRoundKey
        for (int i = 0; i < 16; i++) state[i] ^= rk[round * 16 + i];
    }
    memcpy(out, state, 16);
}

// ── Meshtastic default encryption key ───────────────────────────
static const uint8_t meshKey[16] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

// ── Meshtastic header constants ─────────────────────────────────
static const uint32_t MESH_BROADCAST = 0xFFFFFFFF;
static const uint8_t  MESH_FLAGS     = 0x63;       // hop_start=3, hop_limit=3
static const uint8_t  MESH_CHANNEL   = 0x08;       // XOR("LongFast") ^ XOR(defaultPSK)

// ── LoRaWAN ABP credentials & channel plan ──────────────────────
static const uint8_t nwkSKey[16] = LORAWAN_NWK_SKEY;
static const uint8_t appSKey[16] = LORAWAN_APP_SKEY;
static uint16_t lorawanFCnt = 0;

// US915 sub-band 2 (channels 8-15)
static const float lorawanFreqs[8] = {
    903.9, 904.1, 904.3, 904.5, 904.7, 904.9, 905.1, 905.3
};
static uint8_t lorawanChIdx = 0;

// ── Radio object ────────────────────────────────────────────────
SX1262 radio = new Module(RADIO_CS_PIN, RADIO_DIO1_PIN, RADIO_RST_PIN, RADIO_BUSY_PIN);

// ── OLED display (SSD1306 128x64, I2C addr 0x3d) ───────────────
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);
static uint32_t relayCount = 0;

static void displayStatus(const char *line1, const char *line2,
                           const char *line3, const char *line4)
{
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    if (line1) u8g2.drawStr(8,  14, line1);
    if (line2) u8g2.drawStr(8,  28, line2);
    if (line3) u8g2.drawStr(8,  42, line3);
    if (line4) u8g2.drawStr(8,  56, line4);
    u8g2.sendBuffer();
}

// ── Interrupt flag ──────────────────────────────────────────────
volatile bool receivedFlag = false;
volatile bool enableInterrupt = true;

void setFlag(void)
{
    if (!enableInterrupt) return;
    receivedFlag = true;
}

// ── Packet ID counter (incrementing) ────────────────────────────
static uint32_t packetIdCounter = 1;

// ─────────────────────────────────────────────────────────────────
// AES-128-CTR encrypt in-place
//   nonce: [packetId:8LE][fromNode:4LE][0x00:4]
//   Uses software AES-128-ECB (SoftDevice ECB unreliable)
// ─────────────────────────────────────────────────────────────────
static void aes128ctr_encrypt(const uint8_t key[16], uint32_t packetId,
                              uint32_t fromNode, uint8_t *data, size_t len)
{
    // Build initial nonce (16 bytes)
    uint8_t nonce[16];
    memset(nonce, 0, sizeof(nonce));
    // packetId as 8-byte LE (upper 4 bytes stay zero)
    nonce[0] = (uint8_t)(packetId);
    nonce[1] = (uint8_t)(packetId >> 8);
    nonce[2] = (uint8_t)(packetId >> 16);
    nonce[3] = (uint8_t)(packetId >> 24);
    // fromNode as 4-byte LE at offset 8
    nonce[8]  = (uint8_t)(fromNode);
    nonce[9]  = (uint8_t)(fromNode >> 8);
    nonce[10] = (uint8_t)(fromNode >> 16);
    nonce[11] = (uint8_t)(fromNode >> 24);
    // bytes 4-7 and 12-15 are zero

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < len) {
        // Encrypt nonce → keystream block
        aes128_ecb_encrypt(key, nonce, keystream);

        // XOR keystream with data
        size_t blockLen = (len - offset < 16) ? (len - offset) : 16;
        for (size_t i = 0; i < blockLen; i++) {
            data[offset + i] ^= keystream[i];
        }
        offset += blockLen;

        // Increment nonce (big-endian over full 128 bits)
        for (int i = 15; i >= 0; i--) {
            if (++nonce[i] != 0) break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Encode a Meshtastic Data protobuf
//   field 1 = portnum (varint)
//   field 2 = payload (length-delimited)
//   Returns total encoded length
// ─────────────────────────────────────────────────────────────────
static size_t encodeDataProtobuf(uint8_t *out, uint32_t portnum,
                                 const uint8_t *payload, size_t payloadLen)
{
    size_t pos = 0;

    // field 1, wire type 0 (varint): tag = 0x08
    out[pos++] = 0x08;
    // encode portnum as varint
    uint32_t v = portnum;
    while (v >= 0x80) {
        out[pos++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[pos++] = (uint8_t)v;

    // field 2, wire type 2 (length-delimited): tag = 0x12
    out[pos++] = 0x12;
    // encode length as varint
    v = (uint32_t)payloadLen;
    while (v >= 0x80) {
        out[pos++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[pos++] = (uint8_t)v;

    // copy payload
    memcpy(&out[pos], payload, payloadLen);
    pos += payloadLen;

    return pos;
}

// ─────────────────────────────────────────────────────────────────
// Configure radio for Meshtastic TX (906.875 MHz, BW 250, SF 11)
// ─────────────────────────────────────────────────────────────────
static void configMeshtastic()
{
    radio.setFrequency(906.875);
    radio.setBandwidth(250);
    radio.setSpreadingFactor(11);
    radio.setCodingRate(5);
    radio.setPreambleLength(16);
    radio.setSyncWord(0x2B);
    radio.setCRC(0);            // Meshtastic disables LoRa-level CRC
    radio.setOutputPower(22);   // max power for relay
}

// ─────────────────────────────────────────────────────────────────
// Configure radio for TEMPEST-LoRaWAN RX (915 MHz, BW 500, SF 7)
// ─────────────────────────────────────────────────────────────────
static void configTempest()
{
    radio.setFrequency(LoRa_frequency);  // 915.0
    radio.setBandwidth(500);
    radio.setSpreadingFactor(7);
    radio.setCodingRate(5);
    radio.setPreambleLength(8);
    radio.setSyncWord(RADIOLIB_SX126X_SYNC_WORD_PRIVATE);
    radio.setCRC(2);
}

// ─────────────────────────────────────────────────────────────────
// AES-128-CTR for LoRaWAN payload encryption
//   Ai = 0x01 | 0x00 0x00 0x00 0x00 | Dir | DevAddr(4 LE) | FCnt(4 LE) | 0x00 | i
// ─────────────────────────────────────────────────────────────────
static void aes128ctr_lorawan(const uint8_t key[16], uint8_t dir,
                               uint32_t devAddr, uint32_t fCnt,
                               uint8_t *data, size_t len)
{
    uint8_t numBlocks = (len + 15) / 16;
    for (uint8_t i = 1; i <= numBlocks; i++) {
        uint8_t Ai[16];
        Ai[0]  = 0x01;
        Ai[1]  = 0x00;
        Ai[2]  = 0x00;
        Ai[3]  = 0x00;
        Ai[4]  = 0x00;
        Ai[5]  = dir;
        Ai[6]  = (uint8_t)(devAddr);
        Ai[7]  = (uint8_t)(devAddr >> 8);
        Ai[8]  = (uint8_t)(devAddr >> 16);
        Ai[9]  = (uint8_t)(devAddr >> 24);
        Ai[10] = (uint8_t)(fCnt);
        Ai[11] = (uint8_t)(fCnt >> 8);
        Ai[12] = (uint8_t)(fCnt >> 16);
        Ai[13] = (uint8_t)(fCnt >> 24);
        Ai[14] = 0x00;
        Ai[15] = i;

        uint8_t Si[16];
        aes128_ecb_encrypt(key, Ai, Si);

        size_t offset = (size_t)(i - 1) * 16;
        size_t blockLen = (len - offset < 16) ? (len - offset) : 16;
        for (size_t j = 0; j < blockLen; j++) {
            data[offset + j] ^= Si[j];
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// AES-CMAC (RFC 4493) — used for LoRaWAN MIC
// ─────────────────────────────────────────────────────────────────
static void aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
                     uint8_t mac[16])
{
    // Step 1: Generate subkeys K1, K2
    uint8_t L[16], K1[16], K2[16];
    uint8_t zeros[16];
    memset(zeros, 0, 16);
    aes128_ecb_encrypt(key, zeros, L);

    // Left-shift L to get K1
    uint8_t overflow = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next_overflow = (L[i] & 0x80) ? 1 : 0;
        K1[i] = (L[i] << 1) | overflow;
        overflow = next_overflow;
    }
    if (L[0] & 0x80) K1[15] ^= 0x87;

    // Left-shift K1 to get K2
    overflow = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next_overflow = (K1[i] & 0x80) ? 1 : 0;
        K2[i] = (K1[i] << 1) | overflow;
        overflow = next_overflow;
    }
    if (K1[0] & 0x80) K2[15] ^= 0x87;

    // Step 2: Determine number of blocks and completeness
    size_t n = (len + 15) / 16;
    bool lastComplete;
    if (n == 0) {
        n = 1;
        lastComplete = false;
    } else {
        lastComplete = (len % 16 == 0);
    }

    // Step 3: CBC-MAC
    uint8_t X[16];
    memset(X, 0, 16);

    for (size_t i = 0; i < n; i++) {
        uint8_t M[16];
        if (i < n - 1) {
            // Not the last block — straight copy
            memcpy(M, msg + i * 16, 16);
        } else {
            // Last block
            size_t remaining = len - i * 16;
            memset(M, 0, 16);
            memcpy(M, msg + i * 16, remaining);
            if (lastComplete) {
                for (int j = 0; j < 16; j++) M[j] ^= K1[j];
            } else {
                M[remaining] = 0x80;  // padding
                for (int j = 0; j < 16; j++) M[j] ^= K2[j];
            }
        }
        // XOR then encrypt
        for (int j = 0; j < 16; j++) X[j] ^= M[j];
        aes128_ecb_encrypt(key, X, X);
    }

    memcpy(mac, X, 16);
}

// ─────────────────────────────────────────────────────────────────
// Build LoRaWAN Unconfirmed Data Up frame
//   Returns total frame length written into `out`
// ─────────────────────────────────────────────────────────────────
static size_t buildLoRaWANUplink(uint8_t *out, const uint8_t *payload,
                                  size_t payloadLen, uint32_t devAddr,
                                  uint16_t fCnt)
{
    size_t pos = 0;

    // MHDR: Unconfirmed Data Up, LoRaWAN R1
    out[pos++] = 0x40;

    // DevAddr (4 bytes LE)
    out[pos++] = (uint8_t)(devAddr);
    out[pos++] = (uint8_t)(devAddr >> 8);
    out[pos++] = (uint8_t)(devAddr >> 16);
    out[pos++] = (uint8_t)(devAddr >> 24);

    // FCtrl: no ADR, no ACK, no FOptsLen
    out[pos++] = 0x00;

    // FCnt (lower 16 bits, LE)
    out[pos++] = (uint8_t)(fCnt);
    out[pos++] = (uint8_t)(fCnt >> 8);

    // FPort = 1 (application data)
    out[pos++] = 0x01;

    // FRMPayload: encrypt in-place copy
    memcpy(&out[pos], payload, payloadLen);
    aes128ctr_lorawan(appSKey, 0, devAddr, (uint32_t)fCnt,
                      &out[pos], payloadLen);
    pos += payloadLen;

    // Compute MIC over B0 || MHDR..FRMPayload
    size_t msgLen = pos;  // everything so far
    uint8_t micInput[16 + 256];
    // B0 block
    micInput[0]  = 0x49;
    micInput[1]  = 0x00;
    micInput[2]  = 0x00;
    micInput[3]  = 0x00;
    micInput[4]  = 0x00;
    micInput[5]  = 0x00;  // Dir = 0 (uplink)
    micInput[6]  = (uint8_t)(devAddr);
    micInput[7]  = (uint8_t)(devAddr >> 8);
    micInput[8]  = (uint8_t)(devAddr >> 16);
    micInput[9]  = (uint8_t)(devAddr >> 24);
    micInput[10] = (uint8_t)(fCnt);
    micInput[11] = (uint8_t)(fCnt >> 8);
    micInput[12] = 0x00;
    micInput[13] = 0x00;
    micInput[14] = 0x00;
    micInput[15] = (uint8_t)(msgLen);
    memcpy(&micInput[16], out, msgLen);

    uint8_t fullMac[16];
    aes_cmac(nwkSKey, micInput, 16 + msgLen, fullMac);

    // Append first 4 bytes of CMAC as MIC
    out[pos++] = fullMac[0];
    out[pos++] = fullMac[1];
    out[pos++] = fullMac[2];
    out[pos++] = fullMac[3];

    return pos;
}

// ─────────────────────────────────────────────────────────────────
// Configure radio for LoRaWAN TX (US915 sub-band 2, BW 125, SF 7)
// ─────────────────────────────────────────────────────────────────
static void configLoRaWAN(float freq)
{
    radio.setFrequency(freq);
    radio.setBandwidth(125);
    radio.setSpreadingFactor(7);
    radio.setCodingRate(5);
    radio.setPreambleLength(8);
    radio.setSyncWord(0x34);        // public LoRaWAN sync word
    radio.setCRC(2);                // LoRa HW CRC enabled
    radio.setOutputPower(22);
}

// ─────────────────────────────────────────────────────────────────
void setup()
{
    initBoard();
    delay(10);

    // Init OLED (address 0x3d)
    u8g2.setI2CAddress(0x3d << 1);
    u8g2.begin();
    displayStatus("TEMPEST-LoRaWAN", "", "Booting...", "");

    if (Serial) Serial.print(F("[TEMPEST-LoRa] Initializing radio ... "));

    // Begin with TCXO voltage; initial params don't matter much
    // since we immediately call configTempest()
    int state = radio.begin(
        LoRa_frequency,
        500.0,
        7,
        5,
        RADIOLIB_SX126X_SYNC_WORD_PRIVATE,
        10,
        8,
        RADIO_TCXO_VOLTAGE
    );

    // RF switch setup
    radio.setDio2AsRfSwitch(true);
    radio.setRfSwitchPins(RADIO_RXEN_PIN, RADIOLIB_NC);

    // Apply TEMPEST-LoRaWAN settings
    configTempest();

    if (state == RADIOLIB_ERR_NONE) {
        if (Serial) Serial.println(F("success!"));
    } else {
        if (Serial) { Serial.print(F("failed, code ")); Serial.println(state); }
        displayStatus("TEMPEST-LoRaWAN", "", "RADIO INIT FAIL", "");
        while (true);
    }

    // Set up receive interrupt
    radio.setDio1Action(setFlag);

    state = radio.startReceive();
    if (state == RADIOLIB_ERR_NONE) {
        if (Serial) Serial.println(F("[TEMPEST-LoRa] Listening on 915 MHz (BW500/SF7) ... success!"));
    } else {
        if (Serial) { Serial.print(F("startReceive failed, code ")); Serial.println(state); }
        displayStatus("TEMPEST-LoRaWAN", "", "RX START FAIL", "");
        while (true);
    }

    displayStatus("TEMPEST-LoRaWAN", "", "Listening 915MHz", "BW500 / SF7");
}

// ─────────────────────────────────────────────────────────────────
void loop()
{
    if (!receivedFlag) return;

    // Disable interrupt while processing
    enableInterrupt = false;
    receivedFlag = false;

    // ── 1. Read TEMPEST-LoRaWAN packet ─────────────────────────────
    uint8_t buf[256];
    int len = radio.getPacketLength();
    int state = radio.readData(buf, len);

    if (state != RADIOLIB_ERR_NONE) {
        if (Serial) { Serial.print(F("[TEMPEST-LoRa] Read error, code ")); Serial.println(state); }
        goto resume_rx;
    }

    {
        // ── 2. Print to Serial (only when USB connected) ────────
        float rssi = radio.getRSSI();
        float snr  = radio.getSNR();
        if (Serial) {
            Serial.print(F("[TEMPEST-LoRa] Received "));
            Serial.print(len);
            Serial.print(F(" bytes: "));
            for (int i = 0; i < len; i++) {
                if (buf[i] < 0x10) Serial.print('0');
                Serial.print(buf[i], HEX);
                Serial.print(' ');
            }
            Serial.println();
            Serial.print(F("[TEMPEST-LoRa] Text: "));
            Serial.write(buf, len);
            Serial.println();
            Serial.print(F("[TEMPEST-LoRa] RSSI: "));
            Serial.print(rssi);
            Serial.print(F(" dBm, SNR: "));
            Serial.print(snr);
            Serial.println(F(" dB"));
        }

        // Show received text on display
        {
            char rxLine[22];
            char rssiLine[22];
            snprintf(rxLine, sizeof(rxLine), "RX: %.*s", (len > 16 ? 16 : len), buf);
            snprintf(rssiLine, sizeof(rssiLine), "RSSI:%d SNR:%.1f",
                     (int)rssi, (double)snr);
            displayStatus("TEMPEST-LoRaWAN", rxLine, "Relaying...", rssiLine);
        }

        // ── 3. LoRaWAN TX ──────────────────────────────────────────
        uint8_t lwPkt[256];
        size_t lwLen = buildLoRaWANUplink(lwPkt, buf, (size_t)len,
                                          LORAWAN_DEV_ADDR, lorawanFCnt);

        float lwFreq = lorawanFreqs[lorawanChIdx];
        lorawanChIdx = (lorawanChIdx + 1) % 8;

        if (Serial) {
            Serial.print(F("[LoRaWAN] Sending "));
            Serial.print(lwLen);
            Serial.print(F(" bytes on "));
            Serial.print(lwFreq, 1);
            Serial.print(F(" MHz (FCnt="));
            Serial.print(lorawanFCnt);
            Serial.print(F(") ... "));
        }

        configLoRaWAN(lwFreq);
        state = radio.transmit(lwPkt, lwLen);

        if (state == RADIOLIB_ERR_NONE) {
            if (Serial) Serial.println(F("OK"));
        } else {
            if (Serial) { Serial.print(F("failed, code ")); Serial.println(state); }
        }
        lorawanFCnt++;

        // ── 4. Encode as Meshtastic protobuf ────────────────────
        uint8_t pbBuf[256];
        size_t pbLen = encodeDataProtobuf(pbBuf, 1, buf, (size_t)len);
        // portnum=1 is TEXT_MESSAGE_APP

        // ── 5. Encrypt with AES-128-CTR ─────────────────────────
        uint32_t pktId = packetIdCounter++;
        aes128ctr_encrypt(meshKey, pktId, DEVICE_NODE_ID, pbBuf, pbLen);

        // ── 6. Build 16-byte Meshtastic header ──────────────────
        uint8_t meshPkt[256 + 16];
        size_t pos = 0;

        // to (4 bytes LE) — broadcast
        meshPkt[pos++] = (uint8_t)(MESH_BROADCAST);
        meshPkt[pos++] = (uint8_t)(MESH_BROADCAST >> 8);
        meshPkt[pos++] = (uint8_t)(MESH_BROADCAST >> 16);
        meshPkt[pos++] = (uint8_t)(MESH_BROADCAST >> 24);

        // from (4 bytes LE)
        meshPkt[pos++] = (uint8_t)(DEVICE_NODE_ID);
        meshPkt[pos++] = (uint8_t)(DEVICE_NODE_ID >> 8);
        meshPkt[pos++] = (uint8_t)(DEVICE_NODE_ID >> 16);
        meshPkt[pos++] = (uint8_t)(DEVICE_NODE_ID >> 24);

        // packet id (4 bytes LE)
        meshPkt[pos++] = (uint8_t)(pktId);
        meshPkt[pos++] = (uint8_t)(pktId >> 8);
        meshPkt[pos++] = (uint8_t)(pktId >> 16);
        meshPkt[pos++] = (uint8_t)(pktId >> 24);

        // flags (1 byte)
        meshPkt[pos++] = MESH_FLAGS;

        // channel hash (1 byte)
        meshPkt[pos++] = MESH_CHANNEL;

        // padding (2 bytes, reserved)
        meshPkt[pos++] = 0x00;
        meshPkt[pos++] = 0x00;

        // ── 7. Append encrypted protobuf ────────────────────────
        memcpy(&meshPkt[pos], pbBuf, pbLen);
        pos += pbLen;

        // ── 8. Switch to Meshtastic, transmit ───────────────────
        if (Serial) {
            Serial.print(F("[Meshtastic] Sending "));
            Serial.print(pos);
            Serial.print(F(" bytes (id=0x"));
            Serial.print(pktId, HEX);
            Serial.println(F(")"));
            Serial.print(F("[Meshtastic] Packet: "));
            for (size_t i = 0; i < pos; i++) {
                if (meshPkt[i] < 0x10) Serial.print('0');
                Serial.print(meshPkt[i], HEX);
                Serial.print(' ');
            }
            Serial.println();
            Serial.print(F("[Meshtastic] TX ... "));
        }

        configMeshtastic();
        state = radio.transmit(meshPkt, pos);

        if (state == RADIOLIB_ERR_NONE) {
            if (Serial) Serial.println(F("OK"));
            relayCount++;
        } else {
            if (Serial) { Serial.print(F("failed, code ")); Serial.println(state); }
        }

        // Show result on display
        {
            char rxLine[22];
            char txLine[22];
            char cntLine[22];
            snprintf(rxLine, sizeof(rxLine), "RX: %.*s", (len > 16 ? 16 : len), buf);
            snprintf(txLine, sizeof(txLine), "TX: OK");
            snprintf(cntLine, sizeof(cntLine), "Relayed: %lu", (unsigned long)relayCount);
            displayStatus("TEMPEST-LoRaWAN", rxLine, txLine, cntLine);
        }
    }

resume_rx:
    // ── 8. Switch back to TEMPEST-LoRaWAN and resume listening ─────
    configTempest();
    radio.setDio1Action(setFlag);
    radio.startReceive();
    enableInterrupt = true;
}
