package com.dpi.packetanalyzer.parser;

/**
 * Parsed packet information in human-readable form.
 * Mirrors PacketAnalyzer::ParsedPacket.
 */
public class ParsedPacket {
    // Timestamps
    public int timestampSec;
    public int timestampUsec;

    // Ethernet layer
    public String srcMac;
    public String destMac;
    public int etherType; // unsigned 16-bit, stored widened in an int

    // IP layer (if present)
    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol; // TCP=6, UDP=17, ICMP=1
    public int ttl;

    // Transport layer (if present)
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;

    // TCP-specific
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload: offset + length into the original raw packet bytes
    public int payloadOffset = -1;
    public int payloadLength = 0;
}
