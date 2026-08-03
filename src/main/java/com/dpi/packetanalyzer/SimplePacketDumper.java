package com.dpi.packetanalyzer;

import com.dpi.packetanalyzer.parser.PacketParser;
import com.dpi.packetanalyzer.parser.ParsedPacket;
import com.dpi.packetanalyzer.pcap.PcapReader;
import com.dpi.packetanalyzer.pcap.RawPacket;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Simple human-readable packet dumper. Mirrors main.cpp (the CMake-built
 * "packet_analyzer" executable): reads a PCAP file and prints each parsed
 * packet's Ethernet/IP/TCP/UDP fields plus a short payload preview.
 */
public final class SimplePacketDumper {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private SimplePacketDumper() {}

    private static void printPacketSummary(ParsedPacket pkt, RawPacket raw, int packetNum) {
        String time = TIME_FORMAT.format(Instant.ofEpochSecond(pkt.timestampSec));

        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.printf("Time: %s.%06d%n", time, pkt.timestampUsec);

        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf("  EtherType:       0x%04x", pkt.etherType);

        if (pkt.etherType == PacketParser.EtherType.IPV4) {
            System.out.print(" (IPv4)");
        } else if (pkt.etherType == PacketParser.EtherType.IPV6) {
            System.out.print(" (IPv6)");
        } else if (pkt.etherType == PacketParser.EtherType.ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();

        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");

            StringBuilder preview = new StringBuilder("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                preview.append(String.format("%02x ", raw.data[pkt.payloadOffset + i] & 0xFF));
            }
            if (pkt.payloadLength > 32) {
                preview.append("...");
            }
            System.out.println(preview);
        }
    }

    private static void printUsage(String programName) {
        System.out.println("Usage: " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  " + programName + " capture.pcap");
        System.out.println("  " + programName + " capture.pcap 10");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================\n");

        if (args.length < 1) {
            printUsage("packet-analyzer");
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = -1; // -1 means no limit

        if (args.length >= 2) {
            maxPackets = Integer.parseInt(args[1]);
        }

        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(filename)) {
                System.exit(1);
            }

            System.out.println("\n--- Reading packets ---");

            RawPacket rawPacket = new RawPacket();
            ParsedPacket parsedPacket = new ParsedPacket();
            int packetCount = 0;
            int parseErrors = 0;

            while (reader.readNextPacket(rawPacket)) {
                packetCount++;

                if (PacketParser.parse(rawPacket, parsedPacket)) {
                    printPacketSummary(parsedPacket, rawPacket, packetCount);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + packetCount);
                    parseErrors++;
                }

                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + packetCount);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");
        }
    }
}
