package com.dpi.packetanalyzer.types;

/**
 * Packet wrapper passed between pipeline threads (reader -> LB -> FP -> output).
 * Mirrors DPI::PacketJob.
 */
public class PacketJob {
    public long packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = -1;
    public int payloadLength = 0;
    public int tcpFlags = 0;

    // Timestamps (from the PCAP packet header)
    public int tsSec;
    public int tsUsec;

    /** Returns true if this job carries a non-empty payload. */
    public boolean hasPayload() {
        return payloadOffset >= 0 && payloadLength > 0 && payloadOffset < data.length;
    }
}
