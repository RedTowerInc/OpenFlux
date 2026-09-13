package com.openflux.android;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Starts the same badvpn-tun2socks runtime used by the upstream Android client,
 * but points it at the SOCKS5 listener exposed by the embedded OpenFlux core.
 */
public final class Tun2SocksLauncher {
    private static final String TAG = "OpenFluxTun2Socks";
    private static final int SEND_FD_ATTEMPTS = 20;
    private static final long SEND_FD_DELAY_MS = 150L;

    private final Context context;
    private Process process;
    private File socketFile;
    private File pidFile;
    private Thread logThread;

    public Tun2SocksLauncher(Context context) {
        this.context = context.getApplicationContext();
    }

    public synchronized boolean start(int tunFd) {
        if (tunFd <= 0) {
            Log.e(TAG, "Invalid TUN fd: " + tunFd);
            return false;
        }
        if (process != null && process.isAlive()) return true;

        try {
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File binary = new File(nativeDir, "libtun2socks.so");
            if (!binary.exists()) {
                Log.e(TAG, "Missing tun2socks runtime: " + binary);
                return false;
            }

            socketFile = new File(context.getApplicationInfo().dataDir, "openflux_tun2socks.sock");
            pidFile = new File(context.getFilesDir(), "openflux_tun2socks.pid");
            // The upstream launcher creates the path before starting badvpn;
            // badvpn replaces/uses it as its fd-passing UNIX socket.
            if (socketFile.exists()) socketFile.delete();
            socketFile.createNewFile();
            if (pidFile.exists()) pidFile.delete();

            List<String> command = new ArrayList<>();
            command.add(binary.getAbsolutePath());
            command.add("--netif-ipaddr"); command.add("26.26.26.2");
            command.add("--netif-netmask"); command.add("255.255.255.0");
            command.add("--socks-server-addr"); command.add("127.0.0.1:1080");
            command.add("--tunfd"); command.add(Integer.toString(tunFd));
            command.add("--tunmtu"); command.add("1500");
            command.add("--loglevel"); command.add("3");
            command.add("--pid"); command.add(pidFile.getAbsolutePath());
            command.add("--sock"); command.add(socketFile.getAbsolutePath());
            command.add("--dnsgw"); command.add("127.0.0.1:5353");

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(context.getFilesDir());
            pb.redirectErrorStream(true);
            pb.environment().put("LD_LIBRARY_PATH", nativeDir.getAbsolutePath());
            process = pb.start();
            startLogDrain(process);

            for (int attempt = 1; attempt <= SEND_FD_ATTEMPTS; attempt++) {
                if (!process.isAlive()) {
                    Log.e(TAG, "tun2socks exited before fd handoff");
                    stop();
                    return false;
                }
                int result = NativeBridge.sendFd(tunFd, socketFile.getAbsolutePath());
                if (result == 0) {
                    Log.i(TAG, "TUN fd handed to tun2socks on attempt " + attempt);
                    return true;
                }
                Thread.sleep(SEND_FD_DELAY_MS * Math.min(attempt, 5));
            }

            Log.e(TAG, "Failed to hand TUN fd to tun2socks");
            stop();
            return false;
        } catch (Throwable t) {
            Log.e(TAG, "Failed to start tun2socks", t);
            stop();
            return false;
        }
    }

    private void startLogDrain(Process p) {
        logThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) Log.d(TAG, line);
                }
            } catch (Throwable ignored) {
            }
        }, "openflux-tun2socks-log");
        logThread.setDaemon(true);
        logThread.start();
    }

    public synchronized boolean isAlive() {
        return process != null && process.isAlive();
    }

    public synchronized void stop() {
        Process p = process;
        process = null;
        if (p != null) {
            p.destroy();
            try {
                if (!p.waitFor(700, TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                    p.waitFor(700, TimeUnit.MILLISECONDS);
                }
            } catch (Throwable ignored) {
                p.destroyForcibly();
            }
        }
        if (logThread != null) logThread.interrupt();
        logThread = null;
        if (socketFile != null) socketFile.delete();
        if (pidFile != null) pidFile.delete();
        socketFile = null;
        pidFile = null;
    }
}
