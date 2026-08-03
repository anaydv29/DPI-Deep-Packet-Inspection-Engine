package com.dpi.packetanalyzer.types;

/**
 * Tracked state for a single flow. Mirrors DPI::Connection.
 * Instances live inside a single ConnectionTracker, which is owned by one
 * Fast Path thread, so no internal synchronization is required here.
 */
public class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";

    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;

    public long firstSeenNanos;
    public long lastSeenNanos;

    public PacketAction action = PacketAction.FORWARD;

    // TCP state tracking
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

    /** Shallow copy, used when snapshotting connections for reporting. */
    public Connection copy() {
        Connection c = new Connection();
        c.tuple = this.tuple;
        c.state = this.state;
        c.appType = this.appType;
        c.sni = this.sni;
        c.packetsIn = this.packetsIn;
        c.packetsOut = this.packetsOut;
        c.bytesIn = this.bytesIn;
        c.bytesOut = this.bytesOut;
        c.firstSeenNanos = this.firstSeenNanos;
        c.lastSeenNanos = this.lastSeenNanos;
        c.action = this.action;
        c.synSeen = this.synSeen;
        c.synAckSeen = this.synAckSeen;
        c.finSeen = this.finSeen;
        return c;
    }
}
