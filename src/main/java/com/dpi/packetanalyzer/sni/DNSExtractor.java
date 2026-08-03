package com.dpi.packetanalyzer.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS query packet.
 * Mirrors DPI::DNSExtractor.
 */
public final class DNSExtractor {

    private DNSExtractor() {}

    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;

        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // this is a response, not a query

        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount != 0;
    }

    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int pos = offset + 12;
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLength = payload[pos] & 0xFF;

            if (labelLength == 0) {
                break; // end of domain name
            }
            if (labelLength > 63) {
                break; // compression pointer or invalid
            }

            pos++;
            if (pos + labelLength > end) break;

            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, pos, labelLength, StandardCharsets.US_ASCII));
            pos += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
