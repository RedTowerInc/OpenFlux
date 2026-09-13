package com.openflux.android;

import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Local DNS gateway for badvpn-tun2socks. Android DNS arrives as UDP, while
 * OpenFlux itself is TCP-only. Queries are therefore converted to DNS-over-TCP
 * and sent through the local OpenFlux SOCKS5 listener to a public resolver.
 */
public final class SocksDnsProxy {
    private static final String TAG = "OpenFluxDns";
    public static final int LISTEN_PORT = 5353;
    private static final String SOCKS_HOST = "127.0.0.1";
    private static final int SOCKS_PORT = 1080;
    private static final byte[][] UPSTREAMS = new byte[][]{
            {(byte) 1, (byte) 1, (byte) 1, (byte) 1},
            {(byte) 8, (byte) 8, (byte) 8, (byte) 8}
    };

    private final AtomicLong queries = new AtomicLong();
    private final AtomicLong answers = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();

    private volatile boolean running;
    private DatagramSocket socket;
    private Thread receiveThread;
    private ExecutorService workers;

    public synchronized void start() throws Exception {
        if (running) return;
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), LISTEN_PORT));
        socket.setSoTimeout(1000);
        ThreadFactory tf = runnable -> {
            Thread t = new Thread(runnable, "openflux-dns-worker");
            t.setDaemon(true);
            return t;
        };
        workers = Executors.newFixedThreadPool(4, tf);
        running = true;
        receiveThread = new Thread(this::receiveLoop, "openflux-dns-recv");
        receiveThread.setDaemon(true);
        receiveThread.start();
    }

    private void receiveLoop() {
        byte[] buf = new byte[65507];
        while (running) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                byte[] query = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                InetAddress clientAddress = packet.getAddress();
                int clientPort = packet.getPort();
                queries.incrementAndGet();
                workers.execute(() -> resolveAndReply(query, clientAddress, clientPort));
            } catch (SocketTimeoutException ignored) {
            } catch (Throwable t) {
                if (running) Log.w(TAG, "DNS receive failed", t);
            }
        }
    }

    private void resolveAndReply(byte[] query, InetAddress clientAddress, int clientPort) {
        for (byte[] upstream : UPSTREAMS) {
            try {
                byte[] response = resolveViaSocks(query, upstream);
                DatagramPacket reply = new DatagramPacket(response, response.length, clientAddress, clientPort);
                synchronized (this) {
                    if (!running || socket == null) return;
                    socket.send(reply);
                }
                answers.incrementAndGet();
                return;
            } catch (Throwable t) {
                Log.d(TAG, "DNS upstream failed: " + t.getMessage());
            }
        }
        failures.incrementAndGet();
    }

    private static byte[] resolveViaSocks(byte[] query, byte[] upstream) throws Exception {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(SOCKS_HOST, SOCKS_PORT), 3500);
            s.setSoTimeout(6000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            out.write(new byte[]{0x05, 0x01, 0x00});
            out.flush();
            int v = in.readUnsignedByte();
            int method = in.readUnsignedByte();
            if (v != 0x05 || method != 0x00) throw new Exception("SOCKS auth rejected");

            byte[] request = new byte[]{
                    0x05, 0x01, 0x00, 0x01,
                    upstream[0], upstream[1], upstream[2], upstream[3],
                    0x00, 0x35
            };
            out.write(request);
            out.flush();

            int ver = in.readUnsignedByte();
            int rep = in.readUnsignedByte();
            in.readUnsignedByte(); // RSV
            int atyp = in.readUnsignedByte();
            if (ver != 0x05 || rep != 0x00) throw new Exception("SOCKS connect failed rep=" + rep);
            consumeAddress(in, atyp);

            if (query.length > 65535) throw new Exception("DNS query too large");
            out.writeShort(query.length);
            out.write(query);
            out.flush();

            int length;
            try {
                length = in.readUnsignedShort();
            } catch (EOFException e) {
                throw new Exception("DNS TCP closed", e);
            }
            if (length <= 0 || length > 65535) throw new Exception("Bad DNS response length " + length);
            byte[] response = new byte[length];
            in.readFully(response);
            return response;
        }
    }

    private static void consumeAddress(DataInputStream in, int atyp) throws Exception {
        switch (atyp) {
            case 0x01:
                in.skipBytes(4);
                break;
            case 0x03:
                int n = in.readUnsignedByte();
                in.skipBytes(n);
                break;
            case 0x04:
                in.skipBytes(16);
                break;
            default:
                throw new Exception("Unknown SOCKS ATYP " + atyp);
        }
        in.skipBytes(2); // BND.PORT
    }

    public synchronized void stop() {
        running = false;
        if (socket != null) socket.close();
        socket = null;
        if (receiveThread != null) receiveThread.interrupt();
        receiveThread = null;
        if (workers != null) workers.shutdownNow();
        workers = null;
    }

    public long getQueries() { return queries.get(); }
    public long getAnswers() { return answers.get(); }
    public long getFailures() { return failures.get(); }
}
