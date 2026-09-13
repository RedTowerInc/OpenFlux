package com.openflux.android;

/** Minimal JNI helper used to pass the Android TUN file descriptor to badvpn-tun2socks. */
public final class NativeBridge {
    static {
        System.loadLibrary("openfluxbridge");
    }

    private NativeBridge() {}

    public static native int sendFd(int fd, String socketPath);
}
