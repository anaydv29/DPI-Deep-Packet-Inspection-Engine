package com.dpi.packetanalyzer.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Parses a TLS Client Hello to extract the Server Name Indication (SNI).
 * Mirrors DPI::SNIExtractor from sni_extractor.cpp/.h.
 *
 * <pre>
 * TLS Client Hello structure (simplified):
 *   Record Layer:      ContentType(1) Version(2) Length(2)
 *   Handshake Layer:   HandshakeType(1) Length(3) ClientVersion(2) Random(32)
 *                       SessionIdLen(1) SessionId(var) CipherSuitesLen(2) CipherSuites(var)
 *                       CompressionMethodsLen(1) CompressionMethods(var) ExtensionsLen(2) Extensions(var)
 *   SNI Extension (type 0x0000): ExtLen(2) SniListLen(2) SniType(1) SniLen(2) SniValue(var)
 * </pre>
 */
public final class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SNIExtractor() {}

    private static int u8(byte[] p, int i) {
        return p[i] & 0xFF;
    }

    private static int readUint16BE(byte[] p, int offset) {
        return (u8(p, offset) << 8) | u8(p, offset + 1);
    }

    private static int readUint24BE(byte[] p, int offset) {
        return (u8(p, offset) << 16) | (u8(p, offset + 1) << 8) | u8(p, offset + 2);
    }

    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        if (u8(payload, offset) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;

        return u8(payload, offset + 5) == HANDSHAKE_CLIENT_HELLO;
    }

    /**
     * Extracts the SNI hostname from a TLS Client Hello.
     *
     * @param payload the buffer containing the TCP payload
     * @param offset  index into {@code payload} where the payload begins
     * @param length  number of valid bytes starting at {@code offset}
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = offset + 5; // skip TLS record header

        // Skip handshake header: type(1, already checked) + length(3)
        pos += 4;

        // Client version (2) + Random (32)
        pos += 2 + 32;

        int end = offset + length;

        if (pos >= end) return Optional.empty();
        int sessionIdLength = u8(payload, pos);
        pos += 1 + sessionIdLength;

        if (pos + 2 > end) return Optional.empty();
        int cipherSuitesLength = readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLength;

        if (pos >= end) return Optional.empty();
        int compressionMethodsLength = u8(payload, pos);
        pos += 1 + compressionMethodsLength;

        if (pos + 2 > end) return Optional.empty();
        int extensionsLength = readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLength;
        if (extensionsEnd > end) {
            extensionsEnd = end; // truncated, but try to parse anyway
        }

        while (pos + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, pos);
            int extensionLength = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;

                int sniListLength = readUint16BE(payload, pos);
                if (sniListLength < 3) break;

                int sniType = u8(payload, pos + 2);
                int sniLength = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                String sni = new String(payload, pos + 5, sniLength, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }

            pos += extensionLength;
        }

        return Optional.empty();
    }
}
