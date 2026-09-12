# OpenFlux Android MVP

The Android app uses `VpnService` and the Go gVisor packet stack already present
in OpenFlux. CI builds `openflux.aar`, copies it into `app/libs/`, then builds a
debug APK.

Networking path:

`Android apps -> VpnService TUN -> gomobile -> gVisor PacketTunnel -> OpenFlux TCPTunnel -> Yandex/MAX -> exit node`

Current limitation: IPv4/TCP only. DNS UDP/53 is translated to DNS-over-TCP.
Other UDP/QUIC is not forwarded. IPv6 is captured and dropped to avoid leaks.
