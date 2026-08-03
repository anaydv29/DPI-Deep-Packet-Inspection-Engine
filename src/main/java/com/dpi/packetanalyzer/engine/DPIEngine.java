package com.dpi.packetanalyzer.engine;

import com.dpi.packetanalyzer.parser.PacketParser;
import com.dpi.packetanalyzer.parser.ParsedPacket;
import com.dpi.packetanalyzer.pcap.PcapGlobalHeader;
import com.dpi.packetanalyzer.pcap.PcapReader;
import com.dpi.packetanalyzer.pcap.RawPacket;
import com.dpi.packetanalyzer.pipeline.*;
import com.dpi.packetanalyzer.rules.RuleManager;
import com.dpi.packetanalyzer.tracker.GlobalConnectionTable;
import com.dpi.packetanalyzer.types.*;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

/**
 * Main orchestrator for the DPI engine pipeline:
 *
 * <pre>
 *   PCAP Reader -&gt; [hash % numLBs] -&gt; Load Balancers -&gt; [hash % fpsPerLb] -&gt;
 *   Fast Path Processors (DPI + classification + blocking) -&gt; Output Queue -&gt; Output Writer
 * </pre>
 *
 * Mirrors DPI::DPIEngine from dpi_engine.cpp/.h.
 */
public class DPIEngine {

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10_000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;

    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;
    private FPManager fpManager;
    private LBManager lbManager;

    private final ThreadSafeQueue<PacketJob> outputQueue;
    private Thread outputThread;
    private OutputStream outputStream;
    private final Object outputLock = new Object();

    private final DPIStats stats = new DPIStats();

    private volatile boolean running = false;
    private volatile boolean processingComplete = false;

    private Thread readerThread;

    public DPIEngine(Config config) {
        this.config = config;
        this.outputQueue = new ThreadSafeQueue<>(10_000);

        System.out.println();
        System.out.println("=".repeat(66));
        System.out.println("                    DPI ENGINE v1.0 (Java)");
        System.out.println("               Deep Packet Inspection System");
        System.out.println("=".repeat(66));
        System.out.println("Configuration:");
        System.out.println("  Load Balancers:    " + config.numLoadBalancers);
        System.out.println("  FPs per LB:        " + config.fpsPerLb);
        System.out.println("  Total FP threads:  " + (config.numLoadBalancers * config.fpsPerLb));
        System.out.println("=".repeat(66));
    }

    public boolean initialize() {
        ruleManager = new RuleManager();

        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        fpManager = new FPManager(totalFps, ruleManager, this::handleOutput);

        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueuePtrs());

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running) return;
        running = true;
        processingComplete = false;

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.start();

        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running) return;
        running = false;

        if (lbManager != null) {
            lbManager.stopAll();
        }
        if (fpManager != null) {
            fpManager.stopAll();
        }

        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        processingComplete = true;
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println();
        System.out.println("[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile);
        System.out.println();

        if (ruleManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        try {
            openOutputFile(outputFile);
        } catch (IOException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();

        readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
        readerThread.start();

        waitForCompletion();

        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        stop();

        synchronized (outputLock) {
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException ignored) {
                    // best-effort close
                }
            }
        }

        System.out.println(generateReport());
        System.out.println(fpManager.generateClassificationReport());

        return true;
    }

    private void openOutputFile(String outputFile) throws IOException {
        synchronized (outputLock) {
            this.outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        }
    }

    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file");
                return;
            }

            writeOutputHeader(reader.getGlobalHeader());

            RawPacket raw = new RawPacket();
            ParsedPacket parsed = new ParsedPacket();
            long packetId = 0;

            System.out.println("[Reader] Starting packet processing...");

            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }

                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }

                PacketJob job = createPacketJob(raw, parsed, packetId++);

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);

                if (parsed.hasTcp) {
                    stats.tcpPackets.incrementAndGet();
                } else if (parsed.hasUdp) {
                    stats.udpPackets.incrementAndGet();
                }

                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                lb.getInputQueue().push(job);
            }

            System.out.println("[Reader] Finished reading " + packetId + " packets");
        }
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, long packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;

        int srcIp = parseIpFromDottedQuad(parsed.srcIp);
        int dstIp = parseIpFromDottedQuad(parsed.destIp);

        job.tuple = new FiveTuple(srcIp, dstIp, parsed.srcPort, parsed.destPort, parsed.protocol);
        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data;

        job.ethOffset = 0;
        job.ipOffset = 14;

        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;

            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpDataOffset = (job.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }

            if (job.payloadOffset >= 0 && job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }

        return job;
    }

    /** Parses "a.b.c.d" back into the same little-endian-packed int PacketParser produces. */
    private static int parseIpFromDottedQuad(String ip) {
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

    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            Optional<PacketJob> jobOpt = outputQueue.popWithTimeout(100);
            jobOpt.ifPresent(this::writeOutputPacket);
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    private void writeOutputHeader(PcapGlobalHeader header) {
        synchronized (outputLock) {
            if (outputStream == null) return;
            try {
                ByteBuffer bb = ByteBuffer.allocate(PcapGlobalHeader.SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt(header.magicNumber);
                bb.putShort(header.versionMajor);
                bb.putShort(header.versionMinor);
                bb.putInt(header.thiszone);
                bb.putInt(header.sigfigs);
                bb.putInt(header.snaplen);
                bb.putInt(header.network);
                outputStream.write(bb.array());
            } catch (IOException e) {
                System.err.println("[DPIEngine] Error writing PCAP header: " + e.getMessage());
            }
        }
    }

    private void writeOutputPacket(PacketJob job) {
        synchronized (outputLock) {
            if (outputStream == null) return;
            try {
                ByteBuffer bb = ByteBuffer.allocate(PcapPacketHeaderSize()).order(ByteOrder.LITTLE_ENDIAN);
                bb.putInt(job.tsSec);
                bb.putInt(job.tsUsec);
                bb.putInt(job.data.length);
                bb.putInt(job.data.length);
                outputStream.write(bb.array());
                outputStream.write(job.data);
            } catch (IOException e) {
                System.err.println("[DPIEngine] Error writing packet: " + e.getMessage());
            }
        }
    }

    private static int PcapPacketHeaderSize() {
        return com.dpi.packetanalyzer.pcap.PcapPacketHeader.SIZE_BYTES;
    }

    // ========== Rule Management API ==========

    public void blockIP(String ip) {
        if (ruleManager != null) ruleManager.blockIP(ip);
    }

    public void unblockIP(String ip) {
        if (ruleManager != null) ruleManager.unblockIP(ip);
    }

    public void blockApp(AppType app) {
        if (ruleManager != null) ruleManager.blockApp(app);
    }

    public void blockApp(String appName) {
        AppType app = AppType.fromDisplayName(appName);
        if (app != null) {
            blockApp(app);
        } else {
            System.err.println("[DPIEngine] Unknown app: " + appName);
        }
    }

    public void unblockApp(AppType app) {
        if (ruleManager != null) ruleManager.unblockApp(app);
    }

    public void unblockApp(String appName) {
        AppType app = AppType.fromDisplayName(appName);
        if (app != null) unblockApp(app);
    }

    public void blockDomain(String domain) {
        if (ruleManager != null) ruleManager.blockDomain(domain);
    }

    public void unblockDomain(String domain) {
        if (ruleManager != null) ruleManager.unblockDomain(domain);
    }

    public boolean loadRules(String filename) {
        return ruleManager != null && ruleManager.loadRules(filename);
    }

    public boolean saveRules(String filename) {
        return ruleManager != null && ruleManager.saveRules(filename);
    }

    // ========== Reporting ==========

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n").append("=".repeat(66)).append("\n");
        sb.append("                    DPI ENGINE STATISTICS\n");
        sb.append("=".repeat(66)).append("\n");

        sb.append("PACKET STATISTICS\n");
        sb.append(String.format("  Total Packets:      %12d%n", stats.totalPackets.get()));
        sb.append(String.format("  Total Bytes:        %12d%n", stats.totalBytes.get()));
        sb.append(String.format("  TCP Packets:        %12d%n", stats.tcpPackets.get()));
        sb.append(String.format("  UDP Packets:        %12d%n", stats.udpPackets.get()));

        sb.append("-".repeat(66)).append("\n");
        sb.append("FILTERING STATISTICS\n");
        sb.append(String.format("  Forwarded:          %12d%n", stats.forwardedPackets.get()));
        sb.append(String.format("  Dropped/Blocked:    %12d%n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            sb.append(String.format("  Drop Rate:          %11.2f%%%n", dropRate));
        }

        if (lbManager != null) {
            LBManager.AggregatedStats lbStats = lbManager.getAggregatedStats();
            sb.append("-".repeat(66)).append("\n");
            sb.append("LOAD BALANCER STATISTICS\n");
            sb.append(String.format("  LB Received:        %12d%n", lbStats.totalReceived()));
            sb.append(String.format("  LB Dispatched:      %12d%n", lbStats.totalDispatched()));
        }

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            sb.append("-".repeat(66)).append("\n");
            sb.append("FAST PATH STATISTICS\n");
            sb.append(String.format("  FP Processed:       %12d%n", fpStats.totalProcessed()));
            sb.append(String.format("  FP Forwarded:       %12d%n", fpStats.totalForwarded()));
            sb.append(String.format("  FP Dropped:         %12d%n", fpStats.totalDropped()));
            sb.append(String.format("  Active Connections: %12d%n", fpStats.totalConnections()));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            sb.append("-".repeat(66)).append("\n");
            sb.append("BLOCKING RULES\n");
            sb.append(String.format("  Blocked IPs:        %12d%n", ruleStats.blockedIps()));
            sb.append(String.format("  Blocked Apps:       %12d%n", ruleStats.blockedApps()));
            sb.append(String.format("  Blocked Domains:    %12d%n", ruleStats.blockedDomains()));
            sb.append(String.format("  Blocked Ports:      %12d%n", ruleStats.blockedPorts()));
        }

        sb.append("=".repeat(66)).append("\n");
        return sb.toString();
    }

    public String generateClassificationReport() {
        return fpManager != null ? fpManager.generateClassificationReport() : "";
    }

    public DPIStats getStats() {
        return stats;
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public Config getConfig() {
        return config;
    }

    public boolean isRunning() {
        return running;
    }

    public void printStatus() {
        System.out.println();
        System.out.println("--- Live Status ---");
        System.out.println("Packets: " + stats.totalPackets.get()
                + " | Forwarded: " + stats.forwardedPackets.get()
                + " | Dropped: " + stats.droppedPackets.get());

        if (fpManager != null) {
            FPManager.AggregatedStats fpStats = fpManager.getAggregatedStats();
            System.out.println("Connections: " + fpStats.totalConnections());
        }
    }
}
