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

import mobile.Mobile;

/**
 * Android VPN front-end for OpenFlux.
 *
 * Dataplane:
 * Android apps -> TUN -> badvpn-tun2socks -> 127.0.0.1:1080 SOCKS5 -> OpenFlux -> exit-node.
 * DNS is converted from UDP to DNS-over-TCP and sent through the same SOCKS5/OpenFlux path.
 */
public class OpenFluxVpnService extends VpnService {
    public static final String ACTION_START = "com.openflux.android.action.START";
    public static final String ACTION_STOP = "com.openflux.android.action.STOP";
    public static final String EXTRA_CONFIG = "config_json";
    public static final String RUNTIME_PREFS = "openflux_runtime";

    private static final String CHANNEL_ID = "openflux_vpn";
    private static final int NOTIFICATION_ID = 2001;
    private static final int MTU = 1500;

    private final Object lifecycleLock = new Object();

    private volatile boolean running;
    private volatile boolean starting;
    private volatile boolean coreStarted;
    private ParcelFileDescriptor tun;
    private Tun2SocksLauncher tun2socks;
    private SocksDnsProxy dnsProxy;
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
            new Thread(() -> stopTunnel("STOPPED", "", true), "openflux-stop").start();
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

                clearOldRuntimeCounters();

                // Start the embedded OpenFlux SOCKS5 core first. Bind() is
                // synchronous, so 127.0.0.1:1080 is ready before tun2socks.
                Mobile.start(config);
                coreStarted = true;

                Builder builder = new Builder()
                        .setSession("OpenFlux")
                        .setMtu(MTU)
                        .setBlocking(true)
                        .addAddress("26.26.26.1", 24)
                        .addRoute("0.0.0.0", 0)
                        // Android sends DNS into the TUN. tun2socks forwards
                        // UDP/53 to our local DNS gateway, which converts it to
                        // DNS-over-TCP through the OpenFlux SOCKS5 path.
                        .addDnsServer("1.1.1.1");

                // Critical loop prevention: OpenFlux, tun2socks and the DNS
                // gateway all run under this app UID. Their own sockets must
                // stay outside the VPN while traffic from other apps enters it.
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (PackageManager.NameNotFoundException e) {
                    throw new IllegalStateException("Could not exclude OpenFlux from its VPN", e);
                }

                tun = builder.establish();
                if (tun == null) {
                    throw new IllegalStateException("Android returned no VPN interface");
                }

                dnsProxy = new SocksDnsProxy();
                dnsProxy.start();

                tun2socks = new Tun2SocksLauncher(this);
                if (!tun2socks.start(tun.getFd())) {
                    throw new IllegalStateException("tun2socks failed to start or accept TUN fd");
                }

                running = true;
                starting = false;
                setRuntime("RUNNING", "");
                updateNotification("OpenFlux VPN active (tun2socks)");
                startStatusLoop();
            } catch (Throwable t) {
                starting = false;
                stopTunnel("FAILED", safeMessage(t), true);
            }
        }
    }

    private void startStatusLoop() {
        statusThread = new Thread(this::statusLoop, "openflux-status");
        statusThread.setDaemon(true);
        statusThread.start();
    }

    private void statusLoop() {
        while (running) {
            try {
                String raw = Mobile.statusJSON();
                boolean t2sAlive = tun2socks != null && tun2socks.isAlive();
                long dnsQueries = dnsProxy == null ? 0 : dnsProxy.getQueries();
                long dnsAnswers = dnsProxy == null ? 0 : dnsProxy.getAnswers();
                long dnsFailures = dnsProxy == null ? 0 : dnsProxy.getFailures();

                getSharedPreferences(RUNTIME_PREFS, MODE_PRIVATE).edit()
                        .putString("core", raw)
                        .putString("mode", "SOCKS5 + tun2socks")
                        .putBoolean("tun2socksAlive", t2sAlive)
                        .putLong("dnsQueries", dnsQueries)
                        .putLong("dnsAnswers", dnsAnswers)
                        .putLong("dnsFailures", dnsFailures)
                        .apply();

                if (!t2sAlive) {
                    stopTunnel("FAILED", "tun2socks process exited", true);
                    return;
                }

                JSONObject status = new JSONObject(raw);
                boolean connected = status.optBoolean("connected", false);
                updateNotification(connected
                        ? "OpenFlux transport connected (tun2socks)"
                        : "OpenFlux transport connecting...");
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return;
            } catch (Throwable ignored) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }
    }

    private void stopTunnel(String finalState, String error, boolean stopService) {
        synchronized (lifecycleLock) {
            running = false;
            starting = false;

            if (statusThread != null) statusThread.interrupt();
            statusThread = null;

            try {
                if (tun2socks != null) tun2socks.stop();
            } catch (Throwable ignored) {
            }
            tun2socks = null;

            try {
                if (dnsProxy != null) dnsProxy.stop();
            } catch (Throwable ignored) {
            }
            dnsProxy = null;

            try {
                if (tun != null) tun.close();
            } catch (Throwable ignored) {
            }
            tun = null;

            if (coreStarted) {
                try {
                    Mobile.stop();
                } catch (Throwable ignored) {
                }
                coreStarted = false;
            }

            setRuntime(finalState, error == null ? "" : error);
            try {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } catch (Throwable ignored) {
            }
            if (stopService) stopSelf();
        }
    }

    private void clearOldRuntimeCounters() {
        getSharedPreferences(RUNTIME_PREFS, MODE_PRIVATE).edit()
                .remove("core")
                .remove("tunInPackets")
                .remove("tunInBytes")
                .remove("tunOutPackets")
                .remove("tunOutBytes")
                .remove("quicRejected")
                .remove("ipv6Dropped")
                .remove("udpSeen")
                .putString("mode", "SOCKS5 + tun2socks")
                .putBoolean("tun2socksAlive", false)
                .putLong("dnsQueries", 0)
                .putLong("dnsAnswers", 0)
                .putLong("dnsFailures", 0)
                .apply();
    }

    private void setRuntime(String state, String error) {
        SharedPreferences.Editor e = getSharedPreferences(RUNTIME_PREFS, MODE_PRIVATE).edit()
                .putString("state", state)
                .putString("error", error == null ? "" : error)
                .putString("mode", "SOCKS5 + tun2socks")
                .putBoolean("tun2socksAlive", tun2socks != null && tun2socks.isAlive())
                .putLong("dnsQueries", dnsProxy == null ? 0 : dnsProxy.getQueries())
                .putLong("dnsAnswers", dnsProxy == null ? 0 : dnsProxy.getAnswers())
                .putLong("dnsFailures", dnsProxy == null ? 0 : dnsProxy.getFailures());
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
    public void onRevoke() {
        stopTunnel("STOPPED", "VPN permission revoked", true);
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        if (running || starting || coreStarted || tun != null) {
            stopTunnel("STOPPED", "", false);
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }
}
