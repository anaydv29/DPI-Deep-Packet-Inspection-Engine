package com.dpi.packetanalyzer.pipeline;

import com.dpi.packetanalyzer.rules.RuleManager;
import com.dpi.packetanalyzer.types.AppType;
import com.dpi.packetanalyzer.types.Connection;
import com.dpi.packetanalyzer.types.PacketAction;
import com.dpi.packetanalyzer.types.PacketJob;

import java.util.*;
import java.util.function.BiConsumer;

/** Creates and manages multiple FastPathProcessor threads. Mirrors DPI::FPManager. */
public class FPManager {

    public record AggregatedStats(long totalProcessed, long totalForwarded, long totalDropped, long totalConnections) {}

    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) fp.start();
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) fp.stop();
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> ptrs = new ArrayList<>();
        for (FastPathProcessor fp : fps) ptrs.add(fp.getInputQueue());
        return ptrs;
    }

    public int getNumFPs() {
        return fps.size();
    }

    public AggregatedStats getAggregatedStats() {
        long processed = 0, forwarded = 0, dropped = 0, connections = 0;
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats s = fp.getStats();
            processed += s.packetsProcessed();
            forwarded += s.packetsForwarded();
            dropped += s.packetsDropped();
            connections += s.connectionsTracked();
        }
        return new AggregatedStats(processed, forwarded, dropped, connections);
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        Map<String, Long> domainCounts = new HashMap<>();
        long[] totals = new long[2]; // [0] = classified, [1] = unknown

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(conn -> {
                appCounts.merge(conn.appType, 1L, Long::sum);
                if (conn.appType == AppType.UNKNOWN) {
                    totals[1]++;
                } else {
                    totals[0]++;
                }
                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.merge(conn.sni, 1L, Long::sum);
                }
            });
        }

        long totalClassified = totals[0];
        long totalUnknown = totals[1];
        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n").append("=".repeat(66)).append("\n");
        sb.append("                 APPLICATION CLASSIFICATION REPORT\n");
        sb.append("=".repeat(66)).append("\n");
        sb.append(String.format("Total Connections:    %10d%n", total));
        sb.append(String.format("Classified:            %10d (%.1f%%)%n", totalClassified, classifiedPct));
        sb.append(String.format("Unidentified:          %10d (%.1f%%)%n", totalUnknown, unknownPct));
        sb.append("-".repeat(66)).append("\n");
        sb.append("                    APPLICATION DISTRIBUTION\n");
        sb.append("-".repeat(66)).append("\n");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> e : sortedApps) {
            double pct = total > 0 ? (100.0 * e.getValue() / total) : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(Math.max(0, barLen));
            sb.append(String.format("%-15s%8d %5.1f%% %-20s%n", e.getKey().displayName(), e.getValue(), pct, bar));
        }

        sb.append("=".repeat(66)).append("\n");
        return sb.toString();
    }
}
