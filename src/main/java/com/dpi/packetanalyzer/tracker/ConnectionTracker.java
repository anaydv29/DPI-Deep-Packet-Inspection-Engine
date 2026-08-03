package com.dpi.packetanalyzer.tracker;

import com.dpi.packetanalyzer.types.*;

import java.util.*;
import java.util.function.Consumer;

/**
 * Maintains the flow table for all active connections handled by a single
 * Fast Path thread. Each FP owns exactly one tracker (no sharing needed,
 * since flows are consistently hashed to the same FP), so plain
 * (non-thread-safe) collections are fine here.
 * Mirrors DPI::ConnectionTracker from connection_tracker.cpp/.h.
 */
public class ConnectionTracker {

    public record TrackerStats(long activeConnections, long totalConnectionsSeen,
                                long classifiedConnections, long blockedConnections) {}

    private final int fpId;
    private final int maxConnections;

    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = connections.get(tuple);
        if (existing != null) {
            return existing;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        Connection conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        long now = System.nanoTime();
        conn.firstSeenNanos = now;
        conn.lastSeenNanos = now;

        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeenNanos = System.nanoTime();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni == null ? "" : sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    /** Removes connections idle longer than {@code timeoutSeconds}. Returns the number removed. */
    public long cleanupStale(long timeoutSeconds) {
        long now = System.nanoTime();
        long timeoutNanos = timeoutSeconds * 1_000_000_000L;
        long removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection conn = it.next().getValue();
            long age = now - conn.lastSeenNanos;
            if (age > timeoutNanos || conn.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() {
        connections.clear();
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;

        Map.Entry<FiveTuple, Connection> oldest = null;
        for (Map.Entry<FiveTuple, Connection> e : connections.entrySet()) {
            if (oldest == null || e.getValue().lastSeenNanos < oldest.getValue().lastSeenNanos) {
                oldest = e;
            }
        }
        if (oldest != null) {
            connections.remove(oldest.getKey());
        }
    }
}
