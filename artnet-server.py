#!/usr/bin/env python3

"""
Art-Net protocol for Pimoroni Unicorn Hat
Open Pixel Control protocol for Pimoroni Unicorn Hat
License: MIT

2025-06-22  — v2.0  (Python 3, hardened, lint-clean)

* Listens UDP 6454 (Art-Net, OpCode 0x5000) and TCP 7890 (OPC)
* Only accepts frames sized for exactly 64 RGB LEDs
* Rejects malformed packets with explicit log messages
* Designed for systemd / DietPi service: runs unprivileged, exits non-zero on
  unrecoverable errors so systemd can restart it.

"""
from __future__ import annotations

import logging
import os
import struct
from typing import Tuple

import unicornhat as unicorn
from twisted.internet import endpoints, protocol, reactor
from twisted.internet.protocol import DatagramProtocol

# ─────────────────────────────── Config ──────────────────────────────────────
LED_WIDTH, LED_HEIGHT = 8, 8
LED_COUNT = LED_WIDTH * LED_HEIGHT
ARTNET_PORT = 6454
OPC_PORT = 7890
BRIGHTNESS = float(os.getenv("UHC_BRIGHTNESS", "0.5"))
LOG_LEVEL = os.getenv("UHC_LOGLEVEL", "INFO").upper()

# ─────────────────────────────── Setup ───────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

unicorn.brightness(max(0.0, min(1.0, BRIGHTNESS)))
unicorn.off()  # clear display at startup


# ──────────────────────────── Art-Net handler ────────────────────────────────
class ArtNet(DatagramProtocol):
    """Minimal Art-Net 4 ‘ArtDMX’ receiver (OpCode 0x5000)."""

    def datagramReceived(self, data: bytes, addr: Tuple[str, int]) -> None:  # noqa: N802
        host, port = addr
        if len(data) < 18 or not data.startswith(b"Art-Net\x00"):
            logging.warning("Rejected non-Art-Net packet from %s:%d", host, port)
            return

        (
            op_code,
            proto_ver,
            _seq,
            _phy,
            sub_universe,
            net,
            rgb_len,
        ) = struct.unpack(">HHBBBxBHB", data[8:18])

        if op_code != 0x5000:
            logging.debug("Ignored non-ArtDMX OpCode 0x%04X from %s", op_code, host)
            return
        if proto_ver < 14:
            logging.warning("Down-rev Art-Net %d from %s – ignored", proto_ver, host)
            return
        if rgb_len != LED_COUNT * 3:
            logging.warning(
                "Payload length %d != %d – ignored", rgb_len, LED_COUNT * 3
            )
            return

        payload = data[18 : 18 + rgb_len]  # exactly 192 bytes expected
        for i in range(LED_COUNT):
            r, g, b = payload[i * 3 : i * 3 + 3]
            unicorn.set_pixel(i % LED_WIDTH, i // LED_WIDTH, r, g, b)
        unicorn.show()


# ───────────────────────────── OPC handler ───────────────────────────────────
class OPC(protocol.Protocol):
    """Streaming Open Pixel Control receiver (channel 0 only)."""

    _buffer: bytearray = bytearray()

    def dataReceived(self, data: bytes) -> None:  # noqa: N802
        self._buffer.extend(data)
        while True:
            if len(self._buffer) < 4:
                return  # not enough header yet
            channel, cmd, length = struct.unpack(">BBH", self._buffer[:4])

            if cmd != 0 or channel > 1:
                logging.warning("Unsupported OPC cmd=%d channel=%d – dropped", cmd, channel)
                self._buffer.clear()
                return

            if length != LED_COUNT * 3:
                logging.warning("OPC length %d != %d – dropped", length, LED_COUNT * 3)
                self._buffer.clear()
                return

            if len(self._buffer) < 4 + length:
                return  # wait for more

            payload = self._buffer[4 : 4 + length]
            del self._buffer[: 4 + length]  # consume packet

            for i in range(LED_COUNT):
                r, g, b = payload[i * 3 : i * 3 + 3]
                unicorn.set_pixel(i % LED_WIDTH, i // LED_WIDTH, r, g, b)
            unicorn.show()


class OPCFactory(protocol.Factory):
    protocol = OPC


# ────────────────────────────── Main ─────────────────────────────────────────
def main() -> None:
    try:
        reactor.listenUDP(ARTNET_PORT, ArtNet())
        endpoints.serverFromString(reactor, f"tcp:{OPC_PORT}").listen(OPCFactory())
        logging.info("Art-Net on UDP %d, OPC on TCP %d – ready", ARTNET_PORT, OPC_PORT)
        reactor.run()
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
