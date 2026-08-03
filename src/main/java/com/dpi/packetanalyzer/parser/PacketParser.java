package com.dpi.packetanalyzer.parser;

import com.dpi.packetanalyzer.pcap.RawPacket;

/**
 * Extracts protocol fields (Ethernet, IPv4, TCP, UDP) from raw packet bytes.
 * Mirrors PacketAnalyzer::PacketParser from packet_parser.cpp/.h.
 *
 * All multi-byte header fields on the wire are big-endian ("network byte
 * order"); we read them explicitly as big-endian regardless of host
 * endianness, which is the Java equivalent of the C++ code's ntohs/ntohl calls.
 */
public final class PacketParser {

    private PacketParser() {}

    // ---- TCP flag bits ----
    public static final class TcpFlags {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;
        private TcpFlags() {}
    }

    // ---- IP protocol numbers ----
    public static final class Protocol {
        public static final int ICMP = 1;
        public static final int TCP = 6;
        public static final int UDP = 17;
        private Protocol() {}
    }

    // ---- EtherType values ----
    public static final class EtherType {
        public static final int IPV4 = 0x0800;
        public static final int IPV6 = 0x86DD;
        public static final int ARP = 0x0806;
        private EtherType() {}
    }

    private static final int ETH_HEADER_LEN = 14;
    private static final int MIN_IP_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    /** Parses a raw packet, filling in {@code parsed}. Returns false if unparseable. */
    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int len = data.length;

        int[] offsetHolder = {0};
        if (!parseEthernet(data, len, parsed, offsetHolder)) {
            return false;
        }

        if (parsed.etherType == EtherType.IPV4) {
            if (!parseIPv4(data, len, parsed, offsetHolder)) {
                return false;
            }

            if (parsed.protocol == Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offsetHolder)) {
                    return false;
                }
            } else if (parsed.protocol == Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offsetHolder)) {
                    return false;
                }
            }
        }

        int offset = offsetHolder[0];
        if (offset < len) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = len - offset;
        } else {
            parsed.payloadOffset = -1;
            parsed.payloadLength = 0;
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < ETH_HEADER_LEN) {
            return false;
        }
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = readUint16BE(data, 12);
        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int off = offset[0];
        if (len < off + MIN_IP_HEADER_LEN) {
            return false;
        }

        int versionIhl = data[off] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (parsed.ipVersion != 4) {
            return false;
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < off + ipHeaderLen) {
            return false;
        }

        parsed.ttl = data[off + 8] & 0xFF;
        parsed.protocol = data[off + 9] & 0xFF;

        int srcIp = readInt32(data, off + 12);
        int destIp = readInt32(data, off + 16);
        parsed.srcIp = ipToString(srcIp);
        parsed.destIp = ipToString(destIp);

        parsed.hasIp = true;
        offset[0] = off + ipHeaderLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int off = offset[0];
        if (len < off + MIN_TCP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = readUint16BE(data, off);
        parsed.destPort = readUint16BE(data, off + 2);
        parsed.seqNumber = readUint32BE(data, off + 4);
        parsed.ackNumber = readUint32BE(data, off + 8);

        int dataOffset = (data[off + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        parsed.tcpFlags = data[off + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < off + tcpHeaderLen) {
            return false;
        }

        parsed.hasTcp = true;
        offset[0] = off + tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int off = offset[0];
        if (len < off + UDP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = readUint16BE(data, off);
        parsed.destPort = readUint16BE(data, off + 2);

        parsed.hasUdp = true;
        offset[0] = off + UDP_HEADER_LEN;
        return true;
    }

    // ---- helpers ----

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /** Formats a 4-byte IP address (stored in network byte order) as dotted-quad. */
    public static String ipToString(int ip) {
        return ((ip) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case Protocol.ICMP -> "ICMP";
            case Protocol.TCP -> "TCP";
            case Protocol.UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TcpFlags.SYN) != 0) sb.append("SYN ");
        if ((flags & TcpFlags.ACK) != 0) sb.append("ACK ");
        if ((flags & TcpFlags.FIN) != 0) sb.append("FIN ");
        if ((flags & TcpFlags.RST) != 0) sb.append("RST ");
        if ((flags & TcpFlags.PSH) != 0) sb.append("PSH ");
        if ((flags & TcpFlags.URG) != 0) sb.append("URG ");
        if (sb.length() > 0) sb.setLength(sb.length() - 1);
        return sb.length() == 0 ? "none" : sb.toString();
    }

    /** Reads a big-endian 16-bit unsigned value, widened into an int. */
    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Reads a big-endian 32-bit unsigned value, widened into a long. */
    private static long readUint32BE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) << 8) |
               (data[offset + 3] & 0xFF);
    }

    /**
     * Reads 4 raw bytes as they appear on the wire (network/big-endian order)
     * into an int whose bit pattern matches the C++ uint32_t src_ip/dest_ip
     * fields (which are memcpy'd straight from the packet, i.e. still in
     * network byte order). ipToString() then extracts bytes the same way
     * the original code does.
     */
    private static int readInt32(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
               ((data[offset + 1] & 0xFF) << 8) |
               ((data[offset + 2] & 0xFF) << 16) |
               ((data[offset + 3] & 0xFF) << 24);
    }
}
