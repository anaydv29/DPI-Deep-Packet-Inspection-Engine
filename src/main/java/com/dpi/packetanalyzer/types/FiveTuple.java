package com.dpi.packetanalyzer.types;

import java.util.Objects;

/**
 * Uniquely identifies a connection/flow. Mirrors DPI::FiveTuple.
 *
 * IP addresses are stored as raw 32-bit ints in the same byte layout the
 * packet parser produced them in (see PacketParser); ports/protocol are
 * widened into ints since Java has no unsigned short/byte.
 */
public final class FiveTuple {
    public final int srcIp;
    public final int dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol; // TCP=6, UDP=17

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /** Creates the reverse tuple (for matching bidirectional flows). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    private static String formatIp(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return formatIp(srcIp) + ":" + srcPort + " -> " + formatIp(dstIp) + ":" + dstPort + " (" + proto + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple other)) return false;
        return srcIp == other.srcIp && dstIp == other.dstIp &&
               srcPort == other.srcPort && dstPort == other.dstPort &&
               protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        // Mirrors the mixing pattern of DPI::FiveTupleHash for parity, though
        // any well-distributed hash works equally well for load balancing.
        long h = 0;
        h ^= Objects.hashCode(srcIp) + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= Objects.hashCode(dstIp) + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= Objects.hashCode(srcPort) + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= Objects.hashCode(dstPort) + 0x9e3779b9L + (h << 6) + (h >>> 2);
        h ^= Objects.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >>> 2);
        return (int) h;
    }
}
