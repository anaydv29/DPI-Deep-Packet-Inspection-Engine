package com.dpi.packetanalyzer.pcap;

/**
 * PCAP Global Header (24 bytes) - sits at the very beginning of every .pcap file.
 * Mirrors PacketAnalyzer::PcapGlobalHeader from pcap_reader.h.
 */
public class PcapGlobalHeader {
    public int magicNumber;    // 0xa1b2c3d4 (or swapped for big-endian)
    public short versionMajor; // usually 2
    public short versionMinor; // usually 4
    public int thiszone;       // GMT offset (usually 0)
    public int sigfigs;        // accuracy of timestamps (usually 0)
    public int snaplen;        // max length of captured packets
    public int network;        // data link type (1 = Ethernet)

    public static final int SIZE_BYTES = 24;
}
