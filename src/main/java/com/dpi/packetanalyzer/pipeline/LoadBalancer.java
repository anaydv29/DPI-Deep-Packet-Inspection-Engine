package com.dpi.packetanalyzer.pipeline;

import com.dpi.packetanalyzer.types.FiveTuple;
import com.dpi.packetanalyzer.types.PacketJob;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * Load Balancer thread: pulls packets from its input queue, hashes the
 * five-tuple, and forwards each packet to the appropriate Fast Path queue.
 * Consistent hashing ensures a given flow always lands on the same FP,
 * which is required for correct connection tracking.
 * Mirrors DPI::LoadBalancer from load_balancer.cpp/.h.
 */
public class LoadBalancer {

    public record LBStats(long packetsReceived, long packetsDispatched, long[] perFpPackets) {}

    private final int lbId;
    private final int fpStartId;
    private final int numFps;

    private final ThreadSafeQueue<PacketJob> inputQueue = new ThreadSafeQueue<>(10_000);
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;

    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final AtomicLongArray perFpCounts;

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.fpQueues = fpQueues;
        this.perFpCounts = new AtomicLongArray(fpQueues.size());
    }

    public int getId() {
        return lbId;
    }

    public boolean isRunning() {
        return running;
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this::run, "LB-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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
        System.out.println("[LB" + lbId + "] Stopped");
    }

    private void run() {
        while (running) {
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);
            if (jobOpt.isEmpty()) {
                continue; // timeout or shutdown
            }

            packetsReceived.incrementAndGet();

            PacketJob job = jobOpt.get();
            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);

            packetsDispatched.incrementAndGet();
            perFpCounts.incrementAndGet(fpIndex);
        }
    }

    private int selectFP(FiveTuple tuple) {
        int h = tuple.hashCode();
        return Math.floorMod(h, numFps);
    }

    public LBStats getStats() {
        long[] perFp = new long[perFpCounts.length()];
        for (int i = 0; i < perFp.length; i++) {
            perFp[i] = perFpCounts.get(i);
        }
        return new LBStats(packetsReceived.get(), packetsDispatched.get(), perFp);
    }
}
