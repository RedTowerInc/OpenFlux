OpenFlux Windows Exit Node
==========================

This folder is the Windows counterpart for the OpenFlux Android app.
The PC becomes the Internet exit-node; the phone and PC communicate through
the same Yandex Docs transport URL.

Current configured URL:
https://disk.yandex.ru/i/z9UdacNeXv5Iiw

QUICK START
-----------
1. Make sure this PC has unrestricted working Internet access.
2. Extract the whole ZIP to one folder. Do NOT run files from inside the ZIP.
3. Double-click START_EXIT_NODE.cmd.
4. Accept the Windows UAC / Administrator prompt.
5. Keep the black console window open.
6. On Android, use Yandex Docs and the exact same URL shown above.
7. Press Connect on Android.
8. Open a normal HTTPS website on the phone and watch RX/TX counters.

EXPECTED WINDOWS LOGS
---------------------
Healthy startup normally contains lines similar to:
  Mode: EXIT NODE
  Transport: yandex
  [YDOCS] WebSocket connected ...
  [WD] Interface: IP=...
  Running as EXIT NODE on Windows

The exact order can vary because the Yandex connection is asynchronous.

IMPORTANT
---------
- START_EXIT_NODE.cmd must run as Administrator because WinDivert needs it.
- Keep OpenFluxExitNode.exe, WinDivert.dll and WinDivert64.sys together.
- Windows Firewall may ask for permission. Allow it for your normal/private
  network if prompted.
- No router port forwarding and no public IP are needed.
- This MVP is IPv4/TCP-only. UDP/QUIC is not supported yet.
- If your Yandex public link changes, edit config.cmd and put the new URL there.
- The PC must remain powered on and connected to the Internet while the phone
  uses this exit-node.

STOP
----
Press Ctrl+C in the exit-node console, or run STOP_EXIT_NODE.cmd.

TROUBLESHOOTING
---------------
If the phone says Connected=true but RX/TX stays at 0 B after opening websites,
send screenshots of BOTH:
  1. the Windows exit-node console;
  2. the Android OpenFlux status screen.

WinDivert 2.2.2 binaries are taken from the official basil00/WinDivert release.
OpenFlux remains under its upstream GPL-3.0-or-later terms.
