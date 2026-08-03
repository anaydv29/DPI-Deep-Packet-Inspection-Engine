package com.dpi.packetanalyzer.tracker;

import com.dpi.packetanalyzer.types.AppType;
import com.dpi.packetanalyzer.types.Connection;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Aggregates statistics across all per-FP ConnectionTracker instances.
 * Mirrors DPI::GlobalConnectionTable.
 */
public class GlobalConnectionTable {

    public record GlobalStats(long totalActiveConnections, long totalConnectionsSeen,
                               Map<AppType, Long> appDistribution,
                               List<Map.Entry<String, Long>> topDomains) {}

    private final ConnectionTracker[] trackers;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        trackers = new ConnectionTracker[numFps];
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId < trackers.length) {
                trackers[fpId] = tracker;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        lock.readLock().lock();
        try {
            long totalActive = 0;
            long totalSeen = 0;
            Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats stats = tracker.getStats();
                totalActive += stats.activeConnections();
                totalSeen += stats.totalConnectionsSeen();

                tracker.forEach(conn -> {
                    appDistribution.merge(conn.appType, 1L, Long::sum);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                });
            }

            List<Map.Entry<String, Long>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            List<Map.Entry<String, Long>> topDomains = domainList.subList(0, Math.min(20, domainList.size()));

            return new GlobalStats(totalActive, totalSeen, appDistribution, new ArrayList<>(topDomains));
        } finally {
            lock.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n").append("=".repeat(66)).append("\n");
        sb.append("               CONNECTION STATISTICS REPORT\n");
        sb.append("=".repeat(66)).append("\n");
        sb.append(String.format("Active Connections:     %10d%n", stats.totalActiveConnections()));
        sb.append(String.format("Total Connections Seen: %10d%n", stats.totalConnectionsSeen()));

        sb.append("-".repeat(66)).append("\n");
        sb.append("                    APPLICATION BREAKDOWN\n");
        sb.append("-".repeat(66)).append("\n");

        long total = 0;
        for (long v : stats.appDistribution().values()) total += v;

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution().entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sortedApps) {
            double pct = total > 0 ? (100.0 * e.getValue() / total) : 0;
            sb.append(String.format("%-20s%10d (%5.1f%%)%n", e.getKey().displayName(), e.getValue(), pct));
        }

        if (!stats.topDomains().isEmpty()) {
            sb.append("-".repeat(66)).append("\n");
            sb.append("                      TOP DOMAINS\n");
            sb.append("-".repeat(66)).append("\n");
            for (Map.Entry<String, Long> e : stats.topDomains()) {
                String domain = e.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                sb.append(String.format("%-40s%10d%n", domain, e.getValue()));
            }
        }

        sb.append("=".repeat(66)).append("\n");
        return sb.toString();
    }
}
