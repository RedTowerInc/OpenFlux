package com.openflux.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import mobile.Mobile;

public class OpenFluxVpnService extends VpnService {
    public static final String ACTION_START = "com.openflux.android.action.START";
    public static final String ACTION_STOP = "com.openflux.android.action.STOP";
    public static final String EXTRA_CONFIG = "config_json";
    public static final String RUNTIME_PREFS = "openflux_runtime";

    private static final String CHANNEL_ID = "openflux_vpn";
    private static final int NOTIFICATION_ID = 2001;
    private static final int MTU = 1500;
    // One ICMP reject is enough to tell a QUIC socket that UDP/443 is not
    // available. Rate-limit globally so reject traffic can never starve TCP.
    private static final long QUIC_REJECT_INTERVAL_NS = 100_000_000L; // 100 ms

    private final Object lifecycleLock = new Object();
    private final Object tunWriteLock = new Object();
    private final AtomicLong tunInPackets = new AtomicLong();
    private final AtomicLong tunInBytes = new AtomicLong();
    private final AtomicLong tunOutPackets = new AtomicLong();
    private final AtomicLong tunOutBytes = new AtomicLong();
    private final AtomicLong quicRejected = new AtomicLong();
    private final AtomicLong ipv6Dropped = new AtomicLong();
    private final AtomicLong lastQuicRejectNanos = new AtomicLong();

    private volatile boolean running;
    private volatile boolean starting;
    private ParcelFileDescriptor tun;
    private FileInputStream tunIn;
    private FileOutputStream tunOut;
    private Thread readThread;
    private Thread writeThread;
    private Thread statusThread;

    @Override
    public void onCreate() {
        super.onCreate();
        Mobile.touch();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            new Thread(() -> stopTunnel("STOPPED", ""), "openflux-stop").start();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(action)) {
            String config = intent.getStringExtra(EXTRA_CONFIG);
            if (config == null || config.trim().isEmpty()) {
                setRuntime("FAILED", "Missing configuration");
                stopSelf();
                return START_NOT_STICKY;
            }
            if (!running && !starting) {
                starting = true;
                setRuntime("STARTING", "");
                startForegroundCompat(buildNotification("Starting OpenFlux..."));
                new Thread(() -> startTunnel(config), "openflux-start").start();
            }
        }
        return START_NOT_STICKY;
    }

    private void startTunnel(String config) {
        synchronized (lifecycleLock) {
            try {
                if (running) return;

                tunInPackets.set(0);
                tunInBytes.set(0);
                tunOutPackets.set(0);
                tunOutBytes.set(0);
                quicRejected.set(0);
                ipv6Dropped.set(0);
                lastQuicRejectNanos.set(0);

                Builder builder = new Builder()
                        .setSession("OpenFlux")
                        .setMtu(MTU)
                        .setBlocking(true)
                        .addAddress("10.10.10.2", 24)
                        .addRoute("0.0.0.0", 0)
                        // PacketTunnel resolves DNS through the OpenFlux TCP path.
                        .addDnsServer("1.1.1.1")
                        .addDnsServer("8.8.8.8")
                        // Keep IPv6 inside the VPN to avoid leaks. The current
                        // transport is IPv4/TCP-only, so IPv6 is dropped here.
                        .addAddress("fd00::2", 128)
                        .addRoute("::", 0);

                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (PackageManager.NameNotFoundException e) {
                    throw new IllegalStateException("Could not exclude OpenFlux from its VPN", e);
                }

                tun = builder.establish();
                if (tun == null) {
                    throw new IllegalStateException("Android returned no VPN interface");
                }

                Mobile.startVPN(config, MTU);

                tunIn = new FileInputStream(tun.getFileDescriptor());
                tunOut = new FileOutputStream(tun.getFileDescriptor());
                running = true;
                starting = false;
                setRuntime("RUNNING", "");
                updateNotification("OpenFlux VPN active");
                startPumps();
            } catch (Throwable t) {
                starting = false;
                stopTunnel("FAILED", safeMessage(t));
            }
        }
    }

    private void startPumps() {
        readThread = new Thread(this::pumpTunToGo, "openflux-tun-read");
        writeThread = new Thread(this::pumpGoToTun, "openflux-tun-write");
        statusThread = new Thread(this::statusLoop, "openflux-status");
        readThread.start();
        writeThread.start();
        statusThread.start();
    }

    private void pumpTunToGo() {
        byte[] buffer = new byte[32768];
        try {
            while (running) {
                int n = tunIn.read(buffer);
                if (n < 0) break;
                if (n == 0) continue;

                tunInPackets.incrementAndGet();
                tunInBytes.addAndGet(n);

                int version = (buffer[0] >> 4) & 0x0f;
                byte[] packet = Arrays.copyOf(buffer, n);

                if (version == 6) {
                    // Do not synthesize an ICMPv6 packet for every attempt. The
                    // previous build did that and the resulting TUN churn could
                    // starve normal TCP. DNS compatibility filtering already
                    // suppresses the common AAAA/HTTPS records.
                    ipv6Dropped.incrementAndGet();
                    continue;
                }

                if (version != 4) {
                    continue;
                }

                // Only fail QUIC/HTTP3 (UDP/443), and at a low rate. All other
                // UDP remains silently unsupported as in the last fast build.
                byte[] quicReject = PacketRejector.rejectUnsupportedIpv4Udp(packet);
                if (quicReject != null) {
                    if (allowQuicReject()) {
                        quicRejected.incrementAndGet();
                        writeTunPacket(quicReject);
                    }
                    continue;
                }

                Mobile.writeVPNPacket(packet);
            }
            if (running) {
                stopTunnel("FAILED", "TUN read pump stopped unexpectedly");
            }
        } catch (Throwable t) {
            if (running) stopTunnel("FAILED", "TUN read: " + safeMessage(t));
        }
    }

    private boolean allowQuicReject() {
        long now = System.nanoTime();
        long prev = lastQuicRejectNanos.get();
        if (prev != 0 && now - prev < QUIC_REJECT_INTERVAL_NS) {
            return false;
        }
        return lastQuicRejectNanos.compareAndSet(prev, now);
    }

    private void pumpGoToTun() {
        try {
            while (running) {
                byte[] packet = Mobile.readVPNPacket();
                if (packet == null || packet.length == 0) {
                    if (!running) break;
                    continue;
                }
                writeTunPacket(packet);
            }
        } catch (Throwable t) {
            if (running) stopTunnel("FAILED", "TUN write: " + safeMessage(t));
        }
    }

    private void writeTunPacket(byte[] packet) throws Exception {
        synchronized (tunWriteLock) {
            if (!running || tunOut == null) return;
            tunOut.write(packet);
            tunOut.flush();
            tunOutPackets.incrementAndGet();
            tunOutBytes.addAndGet(packet.length);
        }
    }

    private void statusLoop() {
        while (running) {
            try {
                String raw = Mobile.statusVPNJSON();
                getSharedPreferences(RUNTIME_PREFS, MODE_PRIVATE).edit()
                        .putString("core", raw)
                        .putLong("tunInPackets", tunInPackets.get())
                        .putLong("tunInBytes", tunInBytes.get())
                        .putLong("tunOutPackets", tunOutPackets.get())
                        .putLong("tunOutBytes", tunOutBytes.get())
                        .putLong("quicRejected", quicRejected.get())
                        .putLong("ipv6Dropped", ipv6Dropped.get())
                        .apply();
                JSONObject status = new JSONObject(raw);
                boolean connected = status.optBoolean("connected", false);
                updateNotification(connected ? "OpenFlux transport connected" : "OpenFlux transport connecting...");
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return;
            } catch (Throwable ignored) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
            }
        }
    }

    private void stopTunnel(String finalState, String error) {
        synchronized (lifecycleLock) {
            boolean wasActive = running || starting || tun != null;
            running = false;
            starting = false;

            try { Mobile.stopVPN(); } catch (Throwable ignored) {}
            try { if (tun != null) tun.close(); } catch (Throwable ignored) {}
            tun = null;
            tunIn = null;
            tunOut = null;

            if (readThread != null) readThread.interrupt();
            if (writeThread != null) writeThread.interrupt();
            if (statusThread != null) statusThread.interrupt();
            readThread = null;
            writeThread = null;
            statusThread = null;

            setRuntime(finalState, error == null ? "" : error);
            if (wasActive) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            }
            stopSelf();
        }
    }

    private void setRuntime(String state, String error) {
        SharedPreferences.Editor e = getSharedPreferences(RUNTIME_PREFS, MODE_PRIVATE).edit()
                .putString("state", state)
                .putString("error", error == null ? "" : error)
                .putLong("tunInPackets", tunInPackets.get())
                .putLong("tunInBytes", tunInBytes.get())
                .putLong("tunOutPackets", tunOutPackets.get())
                .putLong("tunOutBytes", tunOutBytes.get())
                .putLong("quicRejected", quicRejected.get())
                .putLong("ipv6Dropped", ipv6Dropped.get());
        if (!"RUNNING".equals(state)) e.remove("core");
        e.apply();
    }

    private void createNotificationChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "OpenFlux VPN", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("OpenFlux VPN connection status");
        nm.createNotificationChannel(channel);
    }

    private Notification buildNotification(String text) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent contentIntent = PendingIntent.getActivity(
                this, 1, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent stop = new Intent(this, OpenFluxVpnService.class).setAction(ACTION_STOP);
        PendingIntent stopIntent = PendingIntent.getService(
                this, 2, stop, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("OpenFlux")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentIntent(contentIntent)
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(
                        null, "Disconnect", stopIntent).build())
                .build();
    }

    private void startForegroundCompat(Notification notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void updateNotification(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(NOTIFICATION_ID, buildNotification(text));
    }

    private static String safeMessage(Throwable t) {
        String message = t.getMessage();
        return message == null || message.isEmpty() ? t.getClass().getSimpleName() : message;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }
}
