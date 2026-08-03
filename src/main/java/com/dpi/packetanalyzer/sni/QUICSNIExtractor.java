package com.dpi.packetanalyzer.sni;

import java.util.Optional;

/**
 * Very simplified QUIC Initial-packet SNI extraction. QUIC's own framing
 * around the embedded TLS Client Hello is not fully parsed here, matching
 * the original C++ implementation's scope. Mirrors DPI::QUICSNIExtractor.
 */
public final class QUICSNIExtractor {

    private QUICSNIExtractor() {}

    public static boolean isQUICInitial(byte[] payload, int offset, int length) {
        if (length < 5) return false;
        int firstByte = payload[offset] & 0xFF;
        // Long header form (top bit set)
        return (firstByte & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQUICInitial(payload, offset, length)) {
            return Optional.empty();
        }

        for (int i = offset; i + 50 < offset + length; i++) {
            if (payload[i] == 0x01) { // Client Hello handshake type
                int searchOffset = i - 5;
                int searchLength = length - (i - offset) + 5;
                if (searchOffset >= 0 && searchLength > 0) {
                    Optional<String> result = SNIExtractor.extract(payload, searchOffset, searchLength);
                    if (result.isPresent()) {
                        return result;
                    }
                }
            }
        }

        return Optional.empty();
    }
}
