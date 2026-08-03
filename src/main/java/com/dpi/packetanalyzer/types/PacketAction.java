package com.dpi.packetanalyzer.types;

/** What to do with a packet. Mirrors DPI::PacketAction. */
public enum PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
}
