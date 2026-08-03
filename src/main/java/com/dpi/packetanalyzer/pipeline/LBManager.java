package com.dpi.packetanalyzer.pipeline;

import com.dpi.packetanalyzer.types.FiveTuple;
import com.dpi.packetanalyzer.types.PacketJob;

import java.util.ArrayList;
import java.util.List;

/** Creates and manages multiple LoadBalancer threads. Mirrors DPI::LBManager. */
public class LBManager {

    public record AggregatedStats(long totalReceived, long totalDispatched) {}

    private final List<LoadBalancer> lbs = new ArrayList<>();

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues) {
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int fpStart = lbId * fpsPerLb;
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }
            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }
        System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) lb.start();
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) lb.stop();
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int index = Math.floorMod(tuple.hashCode(), lbs.size());
        return lbs.get(index);
    }

    public LoadBalancer getLB(int id) {
        return lbs.get(id);
    }

    public int getNumLBs() {
        return lbs.size();
    }

    public AggregatedStats getAggregatedStats() {
        long totalReceived = 0;
        long totalDispatched = 0;
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats stats = lb.getStats();
            totalReceived += stats.packetsReceived();
            totalDispatched += stats.packetsDispatched();
        }
        return new AggregatedStats(totalReceived, totalDispatched);
    }
}
