package com.dpi.packetanalyzer.pcap;

/**
 * Represents a single captured packet: header + raw bytes.
 * Mirrors PacketAnalyzer::RawPacket.
 */
public class RawPacket {
    public PcapPacketHeader header = new PcapPacketHeader();
    public byte[] data = new byte[0];
}
