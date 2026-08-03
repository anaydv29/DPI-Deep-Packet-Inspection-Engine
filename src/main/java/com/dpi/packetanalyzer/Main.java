package com.dpi.packetanalyzer;

import com.dpi.packetanalyzer.engine.DPIEngine;

import java.util.ArrayList;
import java.util.List;

/**
 * CLI entry point for the DPI Engine. Mirrors main_dpi.cpp exactly:
 * same arguments, same usage text, same processing order (rules file,
 * then CLI block rules, then process the file).
 */
public final class Main {

    private Main() {}

    private static void printUsage(String program) {
        System.out.println("""

                \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
                \u2551                    DPI ENGINE v1.0                            \u2551
                \u2551               Deep Packet Inspection System                   \u2551
                \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
                """);
        System.out.println("Usage: " + program + " <input.pcap> <output.pcap> [options]\n");
        System.out.println("""
                Arguments:
                  input.pcap     Input PCAP file (captured user traffic)
                  output.pcap    Output PCAP file (filtered traffic to internet)

                Options:
                  --block-ip <ip>        Block packets from source IP
                  --block-app <app>      Block application (e.g., YouTube, Facebook)
                  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
                  --rules <file>         Load blocking rules from file
                  --lbs <n>              Number of load balancer threads (default: 2)
                  --fps <n>              FP threads per LB (default: 2)
                  --verbose              Enable verbose output
                """);
        System.out.println("Examples:");
        System.out.println("  " + program + " capture.pcap filtered.pcap");
        System.out.println("  " + program + " capture.pcap filtered.pcap --block-app YouTube");
        System.out.println("  " + program + " capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com");
        System.out.println("  " + program + " capture.pcap filtered.pcap --rules blocking_rules.txt\n");
        System.out.println("""
                Supported Apps for Blocking:
                  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
                  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

                Architecture:
                  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
                  \u2502 PCAP Reader \u2502  Reads packets from input file
                  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2500\u2518
                         \u2502 hash(5-tuple) % num_lbs
                         \u25bc
                  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2500\u2510
                  \u2502 Load Balancer \u2502  2 LB threads distribute to FPs
                  \u2502   LB0 \u2502 LB1   \u2502
                  \u2514\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2518
                     \u2502         \u2502  hash(5-tuple) % fps_per_lb
                     \u25bc         \u25bc
                  \u250c\u2500\u2500\u252c\u2500\u2500\u2510   \u250c\u2500\u2500\u252c\u2500\u2500\u2510
                  \u2502FP0-1\u2502   \u2502FP2-3\u2502  4 FP threads: DPI, classification, blocking
                  \u2514\u2500\u2500\u252c\u2500\u2500\u2518   \u2514\u2500\u2500\u252c\u2500\u2500\u2518
                     \u2502         \u2502
                     \u25bc         \u25bc
                  \u250c\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2518
                  \u2502 Output Writer \u2502  Writes forwarded packets to output
                  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518
                """);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("packet-analyzer");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        String rulesFile = "";

        int i = 2;
        while (i < args.length) {
            String arg = args[i];

            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--rules") && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.numLoadBalancers = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            } else if (arg.equals("--verbose")) {
                config.verbose = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                printUsage("packet-analyzer");
                System.exit(0);
            }
            i++;
        }

        DPIEngine engine = new DPIEngine(config);

        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }

        if (!rulesFile.isEmpty()) {
            engine.loadRules(rulesFile);
        }

        for (String ip : blockIps) {
            engine.blockIP(ip);
        }
        for (String app : blockApps) {
            engine.blockApp(app);
        }
        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }

        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            System.exit(1);
        }

        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }
}
