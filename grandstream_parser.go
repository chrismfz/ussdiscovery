package main

import (
    "fmt"
    "net"
    "strings"
)

// GrandstreamDevice holds info parsed from a discovery response
type GrandstreamDevice struct {
    IP       string
    MAC      string
    Model    string
    Version  string
    RawReply string
}

// parseGrandstreamPacket is a placeholder until we see actual packet formats
func parseGrandstreamPacket(data []byte, addr net.Addr) *GrandstreamDevice {
    ip, _, _ := net.SplitHostPort(addr.String())

    // Try to decode as UTF-8 text
    text := string(data)
    textClean := strings.TrimSpace(text)

    // If it's readable, print it for analysis
    if len(textClean) > 0 && strings.IndexFunc(textClean, func(r rune) bool {
        return r >= 32 && r <= 126 // printable ASCII
    }) > -1 {
        fmt.Printf("[GRANDSTREAM] Raw Reply from %s: %q\n", addr.String(), textClean)
    } else {
        fmt.Printf("[GRANDSTREAM] Raw HEX from %s: %x\n", addr.String(), data)
    }

    // Later, pattern-match model/MAC/IP/firmware if possible
    return &GrandstreamDevice{
        IP:       ip,
        RawReply: textClean,
    }
}
