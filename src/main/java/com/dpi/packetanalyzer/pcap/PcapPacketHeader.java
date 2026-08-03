package com.dpi.packetanalyzer.pcap;

/**
 * PCAP Packet Header (16 bytes) - precedes every packet's raw bytes in the file.
 * Mirrors PacketAnalyzer::PcapPacketHeader from pcap_reader.h.
 */
public class PcapPacketHeader {
    public int tsSec;    // timestamp seconds
    public int tsUsec;   // timestamp microseconds
    public int inclLen;  // number of bytes saved in file
    public int origLen;  // actual length of packet on the wire

    public static final int SIZE_BYTES = 16;
}
