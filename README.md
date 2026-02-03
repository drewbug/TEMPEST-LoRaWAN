# TEMPEST-LoRaWAN

Triple-mode relay for the Seeed Wio Tracker L1 Pro (nRF52840 + SX1262).

1. **RX** TEMPEST-LoRa (915 MHz, BW 500, SF 7)
2. **TX** LoRaWAN ABP uplink (US915 sub-band 2, BW 125, SF 7)
3. **TX** Meshtastic text message (906.875 MHz, BW 250, SF 11)

```
pio run

python3 uf2conv.py -c -f 0xADA52840 \
  -o .pio/build/seeed_wio_tracker_L1/firmware.uf2 \
  .pio/build/seeed_wio_tracker_L1/firmware.hex

cp .pio/build/seeed_wio_tracker_L1/firmware.uf2 /media/$USER/TRACKER\ L1/
```

