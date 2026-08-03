package com.dpi.packetanalyzer.pipeline;

import com.dpi.packetanalyzer.rules.RuleManager;
import com.dpi.packetanalyzer.sni.DNSExtractor;
import com.dpi.packetanalyzer.sni.HTTPHostExtractor;
import com.dpi.packetanalyzer.sni.SNIExtractor;
import com.dpi.packetanalyzer.tracker.ConnectionTracker;
import com.dpi.packetanalyzer.types.*;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

/**
 * Fast Path Processor thread: connection tracking, deep packet inspection
 * (SNI/Host/DNS extraction), rule matching, and forward/drop decisions.
 * This is the workhorse of the DPI engine.
 * Mirrors DPI::FastPathProcessor from fast_path.cpp/.h.
 */
public class FastPathProcessor {

    public record FPStats(long packetsProcessed, long packetsForwarded, long packetsDropped,
                           long connectionsTracked, long sniExtractions, long classificationHits) {}

    private static final int TCP_SYN = 0x02;
    private static final int TCP_ACK = 0x10;
    private static final int TCP_FIN = 0x01;
    private static final int TCP_RST = 0x04;

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final BiConsumer<PacketJob, PacketAction> outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, BiConsumer<PacketJob, PacketAction> outputCallback) {
        this.fpId = fpId;
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "FP-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    private void run() {
        while (running) {
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

            if (jobOpt.isEmpty()) {
                connTracker.cleanupStale(300);
                continue;
            }

            packetsProcessed.incrementAndGet();

            PacketJob job = jobOpt.get();
            PacketAction action = processPacket(job);

            if (outputCallback != null) {
                outputCallback.accept(job, action);
            }

            if (action == PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            return PacketAction.FORWARD;
        }

        boolean isOutbound = true; // all packets from user traffic are outbound in this model
        connTracker.updateConnection(conn, job.data.length, isOutbound);

        if (job.tuple.protocol == 6) { // TCP
            updateTCPState(conn, job.tcpFlags);
        }

        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        if (conn.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (!job.hasPayload()) {
            return;
        }

        if (tryExtractSNI(job, conn)) {
            return;
        }
        if (tryExtractHTTPHost(job, conn)) {
            return;
        }

        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = DNSExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, domain.get());
                return;
            }
        }

        if (job.tuple.dstPort == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 443 && job.payloadLength < 50) {
            return false;
        }
        if (!job.hasPayload()) {
            return false;
        }

        Optional<String> sni = SNIExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();

            AppType app = AppType.sniToAppType(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        if (job.tuple.dstPort != 80) {
            return false;
        }
        if (!job.hasPayload()) {
            return false;
        }

        Optional<String> host = HTTPHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host.isPresent()) {
            AppType app = AppType.sniToAppType(host.get());
            connTracker.classifyConnection(conn, app, host.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
                job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni);

        if (reason.isPresent()) {
            RuleManager.BlockReason r = reason.get();
            String label = switch (r.type()) {
                case IP -> "IP " + r.detail();
                case APP -> "App " + r.detail();
                case DOMAIN -> "Domain " + r.detail();
                case PORT -> "Port " + r.detail();
            };
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + label);

            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        if ((tcpFlags & TCP_SYN) != 0) {
            if ((tcpFlags & TCP_ACK) != 0) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }

        if (conn.synSeen && conn.synAckSeen && (tcpFlags & TCP_ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((tcpFlags & TCP_FIN) != 0) {
            conn.finSeen = true;
        }

        if ((tcpFlags & TCP_RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.finSeen && (tcpFlags & TCP_ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public FPStats getStats() {
        return new FPStats(
                packetsProcessed.get(), packetsForwarded.get(), packetsDropped.get(),
                connTracker.getActiveCount(), sniExtractions.get(), classificationHits.get());
    }
}
