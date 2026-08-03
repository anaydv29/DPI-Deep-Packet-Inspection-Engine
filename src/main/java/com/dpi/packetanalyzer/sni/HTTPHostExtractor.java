package com.dpi.packetanalyzer.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the "Host:" header from a plaintext HTTP request.
 * Mirrors DPI::HTTPHostExtractor.
 */
public final class HTTPHostExtractor {

    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    private HTTPHostExtractor() {}

    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        outer:
        for (String method : METHODS) {
            for (int i = 0; i < 4; i++) {
                if (payload[offset + i] != (byte) method.charAt(i)) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            char c0 = (char) (payload[i] & 0xFF);
            char c1 = (char) (payload[i + 1] & 0xFF);
            char c2 = (char) (payload[i + 2] & 0xFF);
            char c3 = (char) (payload[i + 3] & 0xFF);
            char c4 = (char) (payload[i + 4] & 0xFF);

            if ((c0 == 'H' || c0 == 'h') && (c1 == 'o' || c1 == 'O') &&
                (c2 == 's' || c2 == 'S') && (c3 == 't' || c3 == 'T') && c4 == ':') {

                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start, StandardCharsets.US_ASCII);
                    int colon = host.indexOf(':');
                    if (colon != -1) {
                        host = host.substring(0, colon);
                    }
                    return Optional.of(host);
                }
            }
        }

        return Optional.empty();
    }
}
