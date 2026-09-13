package com.openflux.android;

/**
 * Builds immediate ICMP rejection packets for a narrow compatibility case.
 *
 * OpenFlux is currently TCP-only. We only reject IPv4 UDP/443 (QUIC/HTTP3),
 * because rejecting every UDP flow caused too much local TUN churn and could
 * starve normal TCP traffic. DNS/53 and all other UDP remain untouched here.
 */
final class PacketRejector {
    private PacketRejector() {}

    /**
     * Returns ICMPv4 destination/port-unreachable only for outbound IPv4
     * UDP/443 (QUIC). Returns null for TCP, DNS, non-443 UDP, fragments or
     * invalid packets.
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
        if (dstPort != 443) return null;

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
        System.arraycopy(packet, 0, out, icmp + 8, quoteLength);
        writeChecksum(out, icmp + 2, checksum(out, icmp, icmpLength));
        return out;
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
