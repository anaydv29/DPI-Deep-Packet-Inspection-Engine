package com.dpi.packetanalyzer.rules;

import com.dpi.packetanalyzer.types.AppType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages blocking/filtering rules: IP, application, domain (with wildcard
 * support), and port. Thread-safe for concurrent access from Fast Path
 * threads. Mirrors DPI::RuleManager from rule_manager.cpp/.h.
 */
public class RuleManager {

    public enum BlockType { IP, APP, DOMAIN, PORT }

    public record BlockReason(BlockType type, String detail) {}

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    private final ReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedIps = new HashSet<>();

    private final ReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = EnumSet.noneOf(AppType.class);

    private final ReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new CopyOnWriteArrayList<>(); // wildcard patterns

    private final ReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    // ========== IP Blocking ==========

    public static int parseIp(String ip) {
        int result = 0;
        int octet = 0;
        int shift = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }

    public static String ipToString(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
    }

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
    }

    public void blockIP(String ip) {
        blockIP(parseIp(ip));
    }

    public void unblockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked IP: " + ipToString(ip));
    }

    public void unblockIP(String ip) {
        unblockIP(parseIp(ip));
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (int ip : blockedIps) result.add(ipToString(ip));
            return result;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ========== Application Blocking ==========

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked app: " + app.displayName());
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
        } finally {
            appLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked app: " + app.displayName());
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ========== Domain Blocking ==========

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
        } finally {
            domainLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        // Handle *.example.com pattern
        if (pattern.length() >= 2 && pattern.charAt(0) == '*' && pattern.charAt(1) == '.') {
            String suffix = pattern.substring(1); // .example.com
            if (domain.length() >= suffix.length() && domain.endsWith(suffix)) {
                return true;
            }
            // Also match the bare domain (example.com matches *.example.com)
            return domain.equals(pattern.substring(2));
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) {
                return true;
            }
            String lowerDomain = domain.toLowerCase(Locale.ROOT);
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lowerDomain, pattern.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    // ========== Port Blocking ==========

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            portLock.writeLock().unlock();
        }
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ========== Combined Check ==========

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockType.IP, ipToString(srcIp)));
        }
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockType.PORT, String.valueOf(dstPort)));
        }
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockType.APP, app.displayName()));
        }
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockType.DOMAIN, domain));
        }
        return Optional.empty();
    }

    // ========== Persistence ==========

    public boolean saveRules(String filename) {
        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(filename), StandardCharsets.UTF_8))) {

            w.write("[BLOCKED_IPS]\n");
            for (String ip : getBlockedIPs()) w.write(ip + "\n");

            w.write("\n[BLOCKED_APPS]\n");
            for (AppType app : getBlockedApps()) w.write(app.displayName() + "\n");

            w.write("\n[BLOCKED_DOMAINS]\n");
            for (String domain : getBlockedDomains()) w.write(domain + "\n");

            w.write("\n[BLOCKED_PORTS]\n");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) w.write(port + "\n");
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(filename), StandardCharsets.UTF_8))) {

            String line;
            String currentSection = "";

            while ((line = r.readLine()) != null) {
                if (line.isEmpty()) continue;

                if (line.charAt(0) == '[') {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]" -> blockIP(line);
                    case "[BLOCKED_APPS]" -> {
                        AppType app = AppType.fromDisplayName(line);
                        if (app != null) blockApp(app);
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line.trim()));
                    default -> { /* ignore unrecognized sections */ }
                }
            }

            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        try { blockedIps.clear(); } finally { ipLock.writeLock().unlock(); }

        appLock.writeLock().lock();
        try { blockedApps.clear(); } finally { appLock.writeLock().unlock(); }

        domainLock.writeLock().lock();
        try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }

        portLock.writeLock().lock();
        try { blockedPorts.clear(); } finally { portLock.writeLock().unlock(); }

        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        int ips, apps, domains, ports;

        ipLock.readLock().lock();
        try { ips = blockedIps.size(); } finally { ipLock.readLock().unlock(); }

        appLock.readLock().lock();
        try { apps = blockedApps.size(); } finally { appLock.readLock().unlock(); }

        domainLock.readLock().lock();
        try { domains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }

        portLock.readLock().lock();
        try { ports = blockedPorts.size(); } finally { portLock.readLock().unlock(); }

        return new RuleStats(ips, apps, domains, ports);
    }
}
