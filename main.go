package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	godebug "runtime/debug"
	"strconv"

	_ "github.com/wlynxg/anet"

	"universal-bypass-tool/socks5"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"
)

var (
	globalDocUrl string
	maxToken     string
	maxUid       string
	localIP      string
)

func main() {
	fmt.Print("written by p1neappleXpress\n")

	exitNode := flag.Bool("exit-node", false, "Run as exit node (administrator/root privileges required)")
	client := flag.Bool("client", false, "Run as client")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	socksAddr := flag.String("socks5", ":1080", "SOCKS5 address")
	transportType := flag.String("transport", "yandex", "Transport type (yandex, vyandex, oneme)")
	flag.StringVar(&globalDocUrl, "url", "http://#", "Document URL for Yandex Docs transport")
	flag.StringVar(&maxToken, "maxToken", "", "MAX Web token")
	flag.StringVar(&maxUid, "maxUid", "", "MAX call user id")
	flag.StringVar(&localIP, "local-ip", "", "Egress IP for exit node (Linux scoped RST drop)")
	flag.Parse()

	if localIP != "" {
		tunnel.SetLocalIP(localIP)
	}

	if *exitNode {
		godebug.SetGCPercent(20)
	}

	if !*exitNode && !*client {
		flag.Usage()
		os.Exit(1)
	}

	if *debug {
		utils.EnableDebug()
	}

	log.Printf("=== Universal Bypass Tool ===")
	log.Printf("Mode: %s", map[bool]string{true: "EXIT NODE", false: "CLIENT"}[*exitNode])
	log.Printf("Transport: %s", *transportType)

	config := transport.DefaultConfig()
	var trans transport.Transport

	switch *transportType {
	case "vyandex":
		trans = transport.NewCompressedTransport(yandex.NewYandexVolgaTransport(globalDocUrl, config))
	case "yandex":
		trans = transport.NewCompressedTransport(yandex.NewYandexDocsTransport(globalDocUrl, config))
	case "oneme":
		uidint, _ := strconv.ParseInt(maxUid, 10, 64)
		trans = transport.NewCompressedTransport(oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config))
	default:
		log.Fatalf("Unknown transport type: %s", *transportType)
	}

	if err := trans.Start(); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}

	tun := tunnel.NewTCPTunnel(trans, *exitNode)

	if *exitNode {
		if runtime.GOOS == "windows" {
			log.Printf("Running as EXIT NODE on Windows")
			log.Printf("Administrator privileges are required for WinDivert")
			log.Printf("WinDivert handles the TCP packet interception/RST suppression; no iptables rule is needed")
		} else {
			log.Printf("Running as EXIT NODE (root/raw socket privileges required)")
			if localIP != "" {
				log.Printf("! Run: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP", localIP)
			} else {
				log.Printf("! Kernel RSTs would tear down tunnel connections. Prefer a scoped rule:")
				log.Printf("!   assign a dedicated alias IP, run with --local-ip <ip>, then:")
				log.Printf("!   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <ip> -j DROP")
				log.Printf("! Host-wide fallback (drops ALL outbound RST; makes closed ports look filtered):")
				log.Printf("!   sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
			}
		}
		select {}
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", *socksAddr)
		socks5Server := socks5.NewSOCKS5Server(*socksAddr, tun)
		log.Fatal(socks5Server.Start())
	}
}
