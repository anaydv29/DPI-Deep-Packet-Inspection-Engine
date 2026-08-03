package com.dpi.packetanalyzer.types;

import java.util.Locale;

/**
 * Application classification. Mirrors DPI::AppType plus the free functions
 * appTypeToString() and sniToAppType() from types.cpp.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String display;

    AppType(String display) {
        this.display = display;
    }

    public String displayName() {
        return display;
    }

    /** Looks up an AppType by its display name (used for CLI args / rule files). */
    public static AppType fromDisplayName(String name) {
        for (AppType type : values()) {
            if (type.display.equals(name)) {
                return type;
            }
        }
        return null;
    }

    /** Maps an SNI/Host domain string to a known application. */
    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        String s = sni.toLowerCase(Locale.ROOT);

        if (containsAny(s, "google", "gstatic", "googleapis", "ggpht", "gvt1")) {
            return GOOGLE;
        }
        if (containsAny(s, "youtube", "ytimg", "youtu.be", "yt3.ggpht")) {
            return YOUTUBE;
        }
        if (containsAny(s, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) {
            return FACEBOOK;
        }
        if (containsAny(s, "instagram", "cdninstagram")) {
            return INSTAGRAM;
        }
        if (containsAny(s, "whatsapp", "wa.me")) {
            return WHATSAPP;
        }
        if (containsAny(s, "twitter", "twimg", "x.com", "t.co")) {
            return TWITTER;
        }
        if (containsAny(s, "netflix", "nflxvideo", "nflximg")) {
            return NETFLIX;
        }
        if (containsAny(s, "amazon", "amazonaws", "cloudfront", "aws")) {
            return AMAZON;
        }
        if (containsAny(s, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) {
            return MICROSOFT;
        }
        if (containsAny(s, "apple", "icloud", "mzstatic", "itunes")) {
            return APPLE;
        }
        if (containsAny(s, "telegram", "t.me")) {
            return TELEGRAM;
        }
        if (containsAny(s, "tiktok", "tiktokcdn", "musical.ly", "bytedance")) {
            return TIKTOK;
        }
        if (containsAny(s, "spotify", "scdn.co")) {
            return SPOTIFY;
        }
        if (containsAny(s, "zoom")) {
            return ZOOM;
        }
        if (containsAny(s, "discord", "discordapp")) {
            return DISCORD;
        }
        if (containsAny(s, "github", "githubusercontent")) {
            return GITHUB;
        }
        if (containsAny(s, "cloudflare", "cf-")) {
            return CLOUDFLARE;
        }

        // SNI present but not recognized: still mark as encrypted HTTPS traffic
        return HTTPS;
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
