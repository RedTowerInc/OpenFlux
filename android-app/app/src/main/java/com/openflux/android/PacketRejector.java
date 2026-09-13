package com.openflux.android;

import java.util.Arrays;

/**
 * Builds immediate ICMP rejection packets for traffic the current TCP-only
 * OpenFlux transport cannot carry. Silent drops make browsers/apps wait for
 * QUIC/IPv6 timeouts; explicit rejection makes them fall back to IPv4/TCP.
 */
final class PacketRejector {
    private PacketRejector() {}

    /**
     * Returns ICMPv4 destination/port-unreachable for outbound IPv4 UDP that is
     * not DNS (UDP/53). Returns null for TCP, DNS, fragments or invalid packets.
     */
    static byte[] rejectUnsupportedIpv4Udp(byte[] packet) {
        if (packet == null || packet.length < 28) return null;
        if (((packet[0] >>> 4) & 0x0f) != 4) return null;

        int ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || packet.length < ihl + 8) return null;
        if ((packet[9] & 0xff) != 17) return null; // UDP

        // Do not try to parse non-initial IPv4 fragments as UDP headers.
        int fragmentOffset = ((packet[6] & 0x1f) << 8) | (packet[7] & 0xff);
        if (fragmentOffset != 0) return null;

        int dstPort = ((packet[ihl + 2] & 0xff) << 8) | (packet[ihl + 3] & 0xff);
        if (dstPort == 53) return null; // DNS is handled by PacketTunnel.

        int declaredLength = ((packet[2] & 0xff) << 8) | (packet[3] & 0xff);
        int originalLength = packet.length;
        if (declaredLength >= ihl && declaredLength <= packet.length) {
            originalLength = declaredLength;
        }

        int quoteLength = Math.min(originalLength, ihl + 8);
        int icmpLength = 8 + quoteLength;
        int totalLength = 20 + icmpLength;
        byte[] out = new byte[totalLength];

        // IPv4 header.
        out[0] = 0x45;
        out[1] = 0;
        out[2] = (byte) (totalLength >>> 8);
        out[3] = (byte) totalLength;
        out[4] = 0;
        out[5] = 0;
        out[6] = 0;
        out[7] = 0;
        out[8] = 64;
        out[9] = 1; // ICMP
        // Swap original destination/source addresses.
        System.arraycopy(packet, 16, out, 12, 4);
        System.arraycopy(packet, 12, out, 16, 4);
        writeChecksum(out, 10, checksum(out, 0, 20));

        int icmp = 20;
        out[icmp] = 3;      // Destination Unreachable
        out[icmp + 1] = 3;  // Port Unreachable
        // bytes +4..+7 remain zero (unused)
        System.arraycopy(packet, 0, out, icmp + 8, quoteLength);
        writeChecksum(out, icmp + 2, checksum(out, icmp, icmpLength));
        return out;
    }

    /**
     * Returns ICMPv6 destination-unreachable for any IPv6 packet. The MVP does
     * not carry IPv6, so explicit rejection is preferable to a silent blackhole.
     */
    static byte[] rejectIpv6(byte[] packet) {
        if (packet == null || packet.length < 40) return null;
        if (((packet[0] >>> 4) & 0x0f) != 6) return null;

        // Keep the generated ICMPv6 packet within IPv6 minimum MTU (1280).
        int quoteLength = Math.min(packet.length, 1232); // 40 + 8 + 1232 = 1280
        int icmpLength = 8 + quoteLength;
        int totalLength = 40 + icmpLength;
        byte[] out = new byte[totalLength];

        out[0] = 0x60;
        out[4] = (byte) (icmpLength >>> 8);
        out[5] = (byte) icmpLength;
        out[6] = 58; // ICMPv6
        out[7] = 64;
        // Swap original IPv6 destination/source addresses.
        System.arraycopy(packet, 24, out, 8, 16);
        System.arraycopy(packet, 8, out, 24, 16);

        int icmp = 40;
        out[icmp] = 1;      // Destination Unreachable
        out[icmp + 1] = 0;  // No route to destination
        System.arraycopy(packet, 0, out, icmp + 8, quoteLength);

        int csum = icmpv6Checksum(out, icmp, icmpLength);
        writeChecksum(out, icmp + 2, csum);
        return out;
    }

    private static int icmpv6Checksum(byte[] ipv6Packet, int icmpOffset, int icmpLength) {
        byte[] pseudo = new byte[40 + icmpLength];
        System.arraycopy(ipv6Packet, 8, pseudo, 0, 16);   // source
        System.arraycopy(ipv6Packet, 24, pseudo, 16, 16); // destination
        pseudo[32] = (byte) (icmpLength >>> 24);
        pseudo[33] = (byte) (icmpLength >>> 16);
        pseudo[34] = (byte) (icmpLength >>> 8);
        pseudo[35] = (byte) icmpLength;
        // pseudo[36..38] are zero
        pseudo[39] = 58;
        System.arraycopy(ipv6Packet, icmpOffset, pseudo, 40, icmpLength);
        return checksum(pseudo, 0, pseudo.length);
    }

    private static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int end = offset + length;
        int i = offset;
        while (i + 1 < end) {
            sum += ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
            while ((sum >>> 16) != 0) {
                sum = (sum & 0xffff) + (sum >>> 16);
            }
            i += 2;
        }
        if (i < end) {
            sum += (data[i] & 0xff) << 8;
            while ((sum >>> 16) != 0) {
                sum = (sum & 0xffff) + (sum >>> 16);
            }
        }
        return (int) (~sum) & 0xffff;
    }

    private static void writeChecksum(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 8);
        data[offset + 1] = (byte) value;
    }
}
