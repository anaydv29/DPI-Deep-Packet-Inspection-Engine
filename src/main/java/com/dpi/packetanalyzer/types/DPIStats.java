package com.dpi.packetanalyzer.types;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Engine-wide, thread-safe statistics counters. Mirrors DPI::DPIStats.
 * Non-copyable in the original (atomics); we simply never copy it either.
 */
public class DPIStats {
    public final AtomicLong totalPackets = new AtomicLong();
    public final AtomicLong totalBytes = new AtomicLong();
    public final AtomicLong forwardedPackets = new AtomicLong();
    public final AtomicLong droppedPackets = new AtomicLong();
    public final AtomicLong tcpPackets = new AtomicLong();
    public final AtomicLong udpPackets = new AtomicLong();
    public final AtomicLong otherPackets = new AtomicLong();
    public final AtomicLong activeConnections = new AtomicLong();
}
