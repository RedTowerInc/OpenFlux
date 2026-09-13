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
 * Starts badvpn-tun2socks and points it at the SOCKS5 listener exposed by the
 * embedded OpenFlux core.
 *
 * Important: do NOT pass --pid here. The Android badvpn build daemonizes when
 * --pid is supplied. In that mode ProcessBuilder observes the short-lived
 * parent process and incorrectly concludes that tun2socks died before the TUN
 * fd handoff. Keeping tun2socks in the foreground gives us a real Process
 * handle and deterministic lifecycle management.
 */
public final class Tun2SocksLauncher {
    private static final String TAG = "OpenFluxTun2Socks";
    private static final int SEND_FD_ATTEMPTS = 30;
    private static final long SEND_FD_DELAY_MS = 100L;

    private final Context context;
    private Process process;
    private File socketFile;
    private Thread logThread;
    private volatile String lastLogLine = "";
    private volatile String lastError = "";

    public Tun2SocksLauncher(Context context) {
        this.context = context.getApplicationContext();
    }

    public synchronized boolean start(int tunFd) {
        lastError = "";
        lastLogLine = "";

        if (tunFd <= 0) {
            lastError = "invalid TUN fd: " + tunFd;
            Log.e(TAG, lastError);
            return false;
        }
        if (process != null && process.isAlive()) return true;

        try {
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File binary = new File(nativeDir, "libtun2socks.so");
            if (!binary.exists()) {
                lastError = "missing tun2socks runtime: " + binary;
                Log.e(TAG, lastError);
                return false;
            }
            if (!binary.canExecute()) {
                lastError = "tun2socks runtime is not executable: " + binary;
                Log.e(TAG, lastError);
                return false;
            }

            socketFile = new File(context.getApplicationInfo().dataDir, "openflux_tun2socks.sock");
            if (socketFile.exists() && !socketFile.delete()) {
                lastError = "could not remove stale tun2socks socket: " + socketFile;
                Log.e(TAG, lastError);
                return false;
            }

            List<String> command = new ArrayList<>();
            command.add(binary.getAbsolutePath());
            command.add("--netif-ipaddr"); command.add("26.26.26.2");
            command.add("--netif-netmask"); command.add("255.255.255.0");
            command.add("--socks-server-addr"); command.add("127.0.0.1:1080");
            command.add("--tunfd"); command.add(Integer.toString(tunFd));
            command.add("--tunmtu"); command.add("1500");
            command.add("--loglevel"); command.add("3");
            command.add("--sock"); command.add(socketFile.getAbsolutePath());
            // This address is not an ordinary host-side UDP destination.
            // badvpn rewrites DNS packets and writes them back through the TUN.
            // Match upstream OpenFluxAndroid exactly: the Android side owns
            // 26.26.26.1 and the DNS gateway listens on UDP/8091 there.
            command.add("--dnsgw"); command.add("26.26.26.1:8091");

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(context.getFilesDir());
            pb.redirectErrorStream(true);
            pb.environment().put("LD_LIBRARY_PATH", nativeDir.getAbsolutePath());
            process = pb.start();
            startLogDrain(process);

            // The native process creates and listens on the UNIX socket before
            // waiting for SCM_RIGHTS. Retry until that socket is ready.
            for (int attempt = 1; attempt <= SEND_FD_ATTEMPTS; attempt++) {
                Process p = process;
                if (p == null || !p.isAlive()) {
                    int exitCode = safeExitCode(p);
                    lastError = "tun2socks exited before TUN fd handoff"
                            + (exitCode == Integer.MIN_VALUE ? "" : " (exit=" + exitCode + ")")
                            + logSuffix();
                    Log.e(TAG, lastError);
                    stop();
                    return false;
                }

                if (socketFile.exists()) {
                    int result = NativeBridge.sendFd(tunFd, socketFile.getAbsolutePath());
                    if (result == 0) {
                        Thread.sleep(80L);
                        if (!p.isAlive()) {
                            int exitCode = safeExitCode(p);
                            lastError = "tun2socks exited after TUN fd handoff"
                                    + (exitCode == Integer.MIN_VALUE ? "" : " (exit=" + exitCode + ")")
                                    + logSuffix();
                            Log.e(TAG, lastError);
                            stop();
                            return false;
                        }
                        Log.i(TAG, "TUN fd handed to tun2socks on attempt " + attempt);
                        return true;
                    }
                }

                Thread.sleep(SEND_FD_DELAY_MS * Math.min(attempt, 6));
            }

            lastError = "timed out waiting for tun2socks TUN fd socket" + logSuffix();
            Log.e(TAG, lastError);
            stop();
            return false;
        } catch (Throwable t) {
            lastError = "failed to start tun2socks: " + safeMessage(t) + logSuffix();
            Log.e(TAG, lastError, t);
            stop();
            return false;
        }
    }

    private void startLogDrain(Process p) {
        logThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        lastLogLine = trimmed;
                        Log.d(TAG, trimmed);
                    }
                }
            } catch (Throwable ignored) {
            }
        }, "openflux-tun2socks-log");
        logThread.setDaemon(true);
        logThread.start();
    }

    private String logSuffix() {
        String line = lastLogLine;
        return line == null || line.isEmpty() ? "" : "; native: " + line;
    }

    private static int safeExitCode(Process p) {
        if (p == null) return Integer.MIN_VALUE;
        try {
            return p.exitValue();
        } catch (IllegalThreadStateException e) {
            return Integer.MIN_VALUE;
        }
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return m == null || m.isEmpty() ? t.getClass().getSimpleName() : m;
    }

    public synchronized boolean isAlive() {
        return process != null && process.isAlive();
    }

    public String getLastError() {
        return lastError == null ? "" : lastError;
    }

    public String getLastLogLine() {
        return lastLogLine == null ? "" : lastLogLine;
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
        socketFile = null;
    }
}
