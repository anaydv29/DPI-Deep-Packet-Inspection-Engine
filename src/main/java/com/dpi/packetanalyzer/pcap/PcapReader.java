package com.dpi.packetanalyzer.pcap;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads PCAP files (the format Wireshark saves captures in).
 * Mirrors PacketAnalyzer::PcapReader from pcap_reader.cpp/.h.
 */
public class PcapReader implements AutoCloseable {

    private static final int PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    private InputStream in;
    private PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean isOpen() {
        return in != null;
    }

    /** Open a pcap file for reading. Returns false (and prints an error) on failure. */
    public boolean open(String filename) {
        close();
        try {
            in = new FileInputStream(filename);

            byte[] headerBytes = readFully(PcapGlobalHeader.SIZE_BYTES);
            if (headerBytes == null) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            // Peek the first 4 bytes (magic number) in big-endian to compare against
            // both possible magic constants, regardless of file's actual byte order.
            int magicBE = ByteBuffer.wrap(headerBytes, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();

            if (magicBE == PCAP_MAGIC_NATIVE) {
                byteOrder = ByteOrder.BIG_ENDIAN;
            } else if (magicBE == PCAP_MAGIC_SWAPPED) {
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else {
                // Try the reverse framing too (covers little/big endian source files)
                int magicLE = ByteBuffer.wrap(headerBytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                if (magicLE == PCAP_MAGIC_NATIVE) {
                    byteOrder = ByteOrder.LITTLE_ENDIAN;
                } else if (magicLE == PCAP_MAGIC_SWAPPED) {
                    byteOrder = ByteOrder.BIG_ENDIAN;
                } else {
                    System.err.printf("Error: Invalid PCAP magic number: 0x%08x%n", magicBE);
                    close();
                    return false;
                }
            }

            ByteBuffer bb = ByteBuffer.wrap(headerBytes).order(byteOrder);
            globalHeader = new PcapGlobalHeader();
            globalHeader.magicNumber = bb.getInt();
            globalHeader.versionMajor = bb.getShort();
            globalHeader.versionMinor = bb.getShort();
            globalHeader.thiszone = bb.getInt();
            globalHeader.sigfigs = bb.getInt();
            globalHeader.snaplen = bb.getInt();
            globalHeader.network = bb.getInt();

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network
                    + (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            close();
            return false;
        }
    }

    /** Read the next packet. Returns false when there are no more packets. */
    public boolean readNextPacket(RawPacket packet) {
        if (in == null) {
            return false;
        }
        try {
            byte[] headerBytes = readFully(PcapPacketHeader.SIZE_BYTES);
            if (headerBytes == null) {
                return false; // clean EOF
            }

            ByteBuffer bb = ByteBuffer.wrap(headerBytes).order(byteOrder);
            packet.header.tsSec = bb.getInt();
            packet.header.tsUsec = bb.getInt();
            packet.header.inclLen = bb.getInt();
            packet.header.origLen = bb.getInt();

            long inclLenUnsigned = Integer.toUnsignedLong(packet.header.inclLen);
            long snaplenUnsigned = Integer.toUnsignedLong(globalHeader.snaplen);
            if (inclLenUnsigned > snaplenUnsigned || inclLenUnsigned > 65535) {
                System.err.println("Error: Invalid packet length: " + inclLenUnsigned);
                return false;
            }

            byte[] data = readFully((int) inclLenUnsigned);
            if (data == null) {
                System.err.println("Error: Could not read packet data");
                return false;
            }
            packet.data = data;
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void close() {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // best-effort close
            }
            in = null;
        }
    }

    /** Reads exactly {@code len} bytes, or returns null on clean EOF before any bytes read. */
    private byte[] readFully(int len) throws IOException {
        if (len == 0) {
            return new byte[0];
        }
        byte[] buf = new byte[len];
        int total = 0;
        while (total < len) {
            int read = in.read(buf, total, len - total);
            if (read < 0) {
                if (total == 0) {
                    return null; // clean EOF
                }
                throw new EOFException("Unexpected end of file while reading " + len + " bytes");
            }
            total += read;
        }
        return buf;
    }
}
