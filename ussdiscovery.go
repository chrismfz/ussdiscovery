package main

import (
    "crypto/rand"
    "fmt"
    "html"
    "net"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
    "ussdiscovery/discovery"
)
func normUSN(s string) string {
    s = strings.TrimSpace(s)
    if i := strings.Index(s, "::"); i >= 0 { // keep the left part (UUID)
        s = s[:i]
    }
    s = strings.TrimPrefix(strings.ToLower(s), "uuid:")
    return s
}


// ports we listen on for discovery replies
var ports = []int{10000, 10001, 10002, 5678, 2048}

// Discovery keeps track of “seen” devices so we only print
// when something is new or actually changes.
type Discovery struct {
    mu               sync.Mutex
    mikrotikSeen     map[string]*MikroTikDevice
    ubntSeen         map[string]*UBNTDevice
    grandstreamSeen  map[string]*GrandstreamDevice
    ssdpSeen         map[string]*SSDPDevice
    wsdSeen          map[string]*WSDevice
}

type SSDPDevice struct {
    USN       string   // normalized uuid (lowercase, no 'uuid:')
    ST        string   // single search target (αυτό χρησιμοποιείς στον κώδικα)
    Server    string
    Location  string
    CacheCtrl string
    LastAddr  string
    Friendly  string // optional (from device.xml)
    Model     string // optional (from device.xml)
    Maker     string // optional (from device.xml)
}

type WSDevice struct {
    XAddrs string // space-separated URLs
    Types  string // qname list
    Addr   string // responder IP:port
}


func NewDiscovery() *Discovery {
    return &Discovery{
        mikrotikSeen:    make(map[string]*MikroTikDevice),
        ubntSeen:        make(map[string]*UBNTDevice),
        grandstreamSeen: make(map[string]*GrandstreamDevice),
        ssdpSeen:        make(map[string]*SSDPDevice),
        wsdSeen:         make(map[string]*WSDevice),
    }
}

func (d *Discovery) ProcessGrandstream(dev *GrandstreamDevice) bool {
    d.mu.Lock()
    defer d.mu.Unlock()
    key := dev.IP // fallback to IP if MAC is not present yet
    prev, ok := d.grandstreamSeen[key]
    if !ok || prev.RawReply != dev.RawReply {
        d.grandstreamSeen[key] = dev
        return true
    }
    return false
}


// ProcessMikroTik returns true if this MikroTikDevice is new or has changed.
func (d *Discovery) ProcessMikroTik(dev *MikroTikDevice) bool {
    d.mu.Lock()
    defer d.mu.Unlock()
    prev, ok := d.mikrotikSeen[dev.MAC]
    if !ok || !mikrotikEqual(prev, dev) {
        d.mikrotikSeen[dev.MAC] = dev
        return true
    }
    return false
}

// ProcessUBNT returns true if this UBNTDevice is new or has changed.
func (d *Discovery) ProcessUBNT(dev *UBNTDevice) bool {
    d.mu.Lock()
    defer d.mu.Unlock()
    prev, ok := d.ubntSeen[dev.MAC]
    if !ok || !ubntEqual(prev, dev) {
        d.ubntSeen[dev.MAC] = dev
        return true
    }
    return false
}


func (d *Discovery) ProcessSSDP(dev *SSDPDevice) bool {
    d.mu.Lock(); defer d.mu.Unlock()
    key := dev.USN
    prev, ok := d.ssdpSeen[key]
    if !ok || !ssdpEqual(prev, dev) {
        d.ssdpSeen[key] = dev
        return true
    }
    return false
}

func ssdpEqual(a, b *SSDPDevice) bool {
    if a == nil || b == nil { return a == b }
    return a.USN == b.USN &&
        a.ST == b.ST &&
        a.Server == b.Server &&
        a.Location == b.Location &&
        a.CacheCtrl == b.CacheCtrl &&
        a.LastAddr == b.LastAddr &&
        a.Friendly == b.Friendly &&
        a.Model == b.Model &&
        a.Maker == b.Maker
}
func (d *Discovery) ProcessWSD(dev *WSDevice) bool {
    d.mu.Lock(); defer d.mu.Unlock()
    key := dev.XAddrs + "|" + dev.Types
    prev, ok := d.wsdSeen[key]
    if !ok || *prev != *dev {
        d.wsdSeen[key] = dev
        return true
    }
    return false
}

//=============================================================================
// Helper equality functions:

func mikrotikEqual(a, b *MikroTikDevice) bool {
    return a.IP == b.IP &&
        a.Identity == b.Identity &&
        a.Version == b.Version &&
        a.Platform == b.Platform &&
        a.Board == b.Board &&
        a.Bridge == b.Bridge
}

func ubntEqual(a, b *UBNTDevice) bool {
    return a.IP == b.IP &&
        a.Hostname == b.Hostname &&
        a.Model == b.Model &&
        a.Platform == b.Platform &&
        a.Version == b.Version
}

// replace listenMulticast with this:
func listenAllMulticast(group string, port int) ([]*net.UDPConn, error) {
    var conns []*net.UDPConn
    gaddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", group, port))
    if err != nil {
        return nil, err
    }
    ifaces, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    for _, ifi := range ifaces {
        // skip down/loopback or interfaces without multicast/v4
        if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
            continue
        }
        // must have an IPv4 addr
        hasV4 := false
        ifAddrs, _ := ifi.Addrs()
        for _, a := range ifAddrs {
            if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
                hasV4 = true
                break
            }
        }
        if !hasV4 {
            continue
        }

        c, err := net.ListenMulticastUDP("udp4", &ifi, gaddr)
        if err != nil {
            // not fatal; just try next interface
            continue
        }
        c.SetReadBuffer(1 << 20)
        conns = append(conns, c)
    }
    if len(conns) == 0 {
        return nil, fmt.Errorf("no multicast-capable IPv4 interfaces found")
    }
    return conns, nil
}



func listenSSDP(c *net.UDPConn, disc *Discovery) {
    defer c.Close()
    buf := make([]byte, 8192)
    for {
        n, _, err := c.ReadFromUDP(buf); if err != nil { return }
        lines := strings.Split(string(buf[:n]), "\r\n")
        hdr := map[string]string{}
        // πρώτη γραμμή μπορεί να είναι "NOTIFY * HTTP/1.1" ή "HTTP/1.1 200 OK"
        for _, ln := range lines[1:] {
            if i := strings.Index(ln, ":"); i > 0 {
                k := strings.ToUpper(strings.TrimSpace(ln[:i]))
                v := strings.TrimSpace(ln[i+1:])
                hdr[k] = v
            }
        }
        dev := &SSDPDevice{
            USN:       hdr["USN"],
            ST:        hdr["ST"],
            Server:    hdr["SERVER"],
            Location:  hdr["LOCATION"],
            CacheCtrl: hdr["CACHE-CONTROL"],
        }
        if dev.USN == "" && dev.Location == "" { continue }
        if disc.ProcessSSDP(dev) {
            fmt.Printf("[SSDP] %s | ST=%s | Server=%s | Location=%s\n",
                dev.USN, dev.ST, dev.Server, dev.Location)
        }
    }
}


var (
    reTypes  = regexp.MustCompile(`(?s)<d:Types[^>]*>(.*?)</d:Types>`)
    reXAddrs = regexp.MustCompile(`(?s)<d:XAddrs[^>]*>(.*?)</d:XAddrs>`)
)

func listenWSD(c *net.UDPConn, disc *Discovery) {
    defer c.Close()
    buf := make([]byte, 16384)
    for {
        n, addr, err := c.ReadFromUDP(buf); if err != nil { return }
        s := string(buf[:n])
        types := ""
        xaddrs := ""
        if m := reTypes.FindStringSubmatch(s); len(m) == 2 { types = strings.TrimSpace(html.UnescapeString(m[1])) }
        if m := reXAddrs.FindStringSubmatch(s); len(m) == 2 { xaddrs = strings.TrimSpace(html.UnescapeString(m[1])) }
        if xaddrs == "" && types == "" { continue }
        dev := &WSDevice{ XAddrs: xaddrs, Types: types, Addr: addr.String() }
        if disc.ProcessWSD(dev) {
            fmt.Printf("[WSD] %s | Types=%s | From=%s\n", xaddrs, types, addr.String())
        }
    }
}

var KnownPrivateCIDRs = []string{
    "10.23.140.0/24",
    "172.16.0.0/12",
    "192.168.0.0/16",

}

var scannedSubnets sync.Map // subnet CIDR -> struct{}
var seenHosts sync.Map      // ip -> struct{}

func markNewHost(ip string) bool {
    _, loaded := seenHosts.LoadOrStore(ip, struct{}{})
    return !loaded // true μόνο την 1η φορά
}


func sendDiscovery(disc *Discovery) {
    // ---- UBNT & Grandstream probes ----
    msg := []byte{1, 0, 0, 0}
    broadcasts := []string{
        "255.255.255.255:10001", // UBNT
        "255.255.255.255:10000", // Grandstream
    }
    for _, addr := range broadcasts {
        conn, err := net.DialUDP("udp", nil, resolveUDP(addr))
        if err != nil {
            fmt.Println("Failed to dial UDP:", err)
            continue
        }
        conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
        conn.Write(msg)
        conn.Close()
    }

    // ---- SSDP M-SEARCH (define BEFORE using) ----
    ssdpStr := "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 1\r\n" +
        "ST: ssdp:all\r\n\r\n"

    // send & read SSDP replies on one ephemeral socket (to catch unicast 200 OK)
    if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}); err == nil {
        c.SetWriteDeadline(time.Now().Add(2 * time.Second))
        c.WriteToUDP([]byte(ssdpStr), resolveUDP("239.255.255.250:1900"))

        // read unicast replies for ~1.5s
        _ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
        buf := make([]byte, 8192)
        for {
            n, addr, err := c.ReadFromUDP(buf)
            if err != nil {
                break
            }
            // reuse SSDP header parse
            lines := strings.Split(string(buf[:n]), "\r\n")
            hdr := map[string]string{}
            for _, ln := range lines[1:] {
                if i := strings.Index(ln, ":"); i > 0 {
                    k := strings.ToUpper(strings.TrimSpace(ln[:i]))
                    v := strings.TrimSpace(ln[i+1:])
                    hdr[k] = v
                }
            }
            dev := &SSDPDevice{
                USN: hdr["USN"], ST: hdr["ST"], Server: hdr["SERVER"],
                Location: hdr["LOCATION"], CacheCtrl: hdr["CACHE-CONTROL"],
            }
            if dev.USN != "" || dev.Location != "" {
                if disc.ProcessSSDP(dev) {
                    fmt.Printf("[SSDP] From=%s | %s | ST=%s | Server=%s | Location=%s\n",
                        addr.String(), dev.USN, dev.ST, dev.Server, dev.Location)
                }
            }
        }
        c.Close()
    }

    // (optional extra broadcast — can keep or remove)
    if c, err := net.DialUDP("udp", nil, resolveUDP("239.255.255.250:1900")); err == nil {
        c.Write([]byte(ssdpStr))
        c.Close()
    }

    // ---- WS-Discovery Probe (unchanged) ----
    probe := `<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <e:Header>
  <w:MessageID>uuid:` + uuid4() + `</w:MessageID>
  <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body>
  <d:Probe><d:Types/></d:Probe>
 </e:Body>
</e:Envelope>`
    if c, err := net.DialUDP("udp", nil, resolveUDP("239.255.255.250:3702")); err == nil {
        c.Write([]byte(probe))
        c.Close()
    }
}





// tiny uuid (good-enough for message id)
func uuid4() string {
    b := make([]byte, 16)
    rand.Read(b)
    b[6] = (b[6] & 0x0f) | 0x40
    b[8] = (b[8] & 0x3f) | 0x80
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}


func listenAndParse(pc net.PacketConn, localIPs []string, disc *Discovery) {
    defer pc.Close()
    buf := make([]byte, 2048)

    for {
        n, addr, err := pc.ReadFrom(buf)
        if err != nil {
            return
        }

        host, _, _ := net.SplitHostPort(addr.String())
        if contains(localIPs, host) {
            continue
        }

        localPort := pc.LocalAddr().(*net.UDPAddr).Port
        //fmt.Printf("[Port %d] Reply from %s:\n", localPort, addr.String())
        data := buf[:n]

        switch localPort {
        case 5678:
            dev := parseMikroTikPacket(data)
            if dev != nil && disc.ProcessMikroTik(dev) {
                fmt.Printf("[MIKROTIK] Identity: %s | MAC: %s | IP: %s | Version: %s | Board: %s | Bridge: %s\n",
                    dev.Identity, dev.MAC, dev.IP, dev.Version, dev.Board, dev.Bridge)
            }
        case 10000:
			dev := parseGrandstreamPacket(data, addr)
			if dev != nil && disc.ProcessGrandstream(dev) {
				fmt.Printf("[GRANDSTREAM] IP: %s | Model: %s | MAC: %s | Version: %s | Raw: %s\n",
					dev.IP, dev.Model, dev.MAC, dev.Version, dev.RawReply)
    }

		default:
            dev := parseUBNTPacket(data)
            if dev != nil && disc.ProcessUBNT(dev) {
                fmt.Printf("[UBNT] IP: %s | MAC: %s | Hostname: %s | Model: %s | Platform: %s | Version: %s\n",
                    dev.IP, dev.MAC, dev.Hostname, dev.Model, dev.Platform, dev.Version)
            }
        }
    }
}

func resolveUDP(addr string) *net.UDPAddr {
    udpAddr, err := net.ResolveUDPAddr("udp", addr)
    if err != nil {
        fmt.Println("Invalid address:", addr)
        os.Exit(1)
    }
    return udpAddr
}

func getLocalIPs() []string {
    var ips []string
    ifaces, err := net.Interfaces()
    if err != nil {
        fmt.Println("Error fetching interfaces:", err)
        return ips
    }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
            continue
        }
        addrs, _ := iface.Addrs()
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            if ip == nil || ip.IsLoopback() || ip.To4() == nil {
                continue
            }
            ips = append(ips, ip.String())
        }
    }
    return ips
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}










func main() {
    fmt.Println("Starting UBNT & Mikrotik Discovery...")

    localIPs := getLocalIPs()
    fmt.Println("Local IPs detected:", localIPs)

    // --- UDP listeners for discovery replies ---
    var listeners []net.PacketConn
    for _, port := range ports {
        pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
        if err != nil {
            fmt.Printf("Failed to bind port %d: %v\n", port, err)
            continue
        }
        listeners = append(listeners, pc)
    }

    disc := NewDiscovery()

    // spawn a goroutine per UDP listener
    var wg sync.WaitGroup
    for _, pc := range listeners {
        wg.Add(1)
        go func(p net.PacketConn) {
            defer wg.Done()
            listenAndParse(p, localIPs, disc)
        }(pc)
    }

    // ---- SSDP (239.255.255.250:1900) listeners on all multicast-capable ifaces ----
    if ssdpConns, err := listenAllMulticast("239.255.255.250", 1900); err == nil {
        for _, c := range ssdpConns {
            wg.Add(1)
            go func(conn *net.UDPConn) {
                defer wg.Done()
                listenSSDP(conn, disc)
            }(c)
        }
    } else {
        fmt.Println("SSDP multicast failed:", err)
    }

    // ---- WS-Discovery (239.255.255.250:3702) ----
    if wsdConns, err := listenAllMulticast("239.255.255.250", 3702); err == nil {
        for _, c := range wsdConns {
            wg.Add(1)
            go func(conn *net.UDPConn) {
                defer wg.Done()
                listenWSD(conn, disc)
            }(c)
        }
    } else {
        fmt.Println("WSD multicast failed:", err)
    }

    // -------------------------------------------------------
    // Subnet Hunter (separate logs, dedup per-subnet & per-host)
    // -------------------------------------------------------
    fmt.Println("Starting Subnet Hunter on private ranges...")
    results := make(chan discovery.HunterResult, 1024)

    // producer: run hunter for each known private CIDR
    go func() {
        for _, cidr := range KnownPrivateCIDRs {
            discovery.SubnetHunter(cidr, results)
        }
        close(results)
    }()

    // consumer: scan each candidate subnet once; print each host once
    go func() {
        for r := range results {
            if _, loaded := scannedSubnets.LoadOrStore(r.Subnet, struct{}{}); loaded {
                // subnet already scanned or in-progress
                continue
            }

            fmt.Printf("\n=== HUNTER Results for %s ===\n", r.Subnet)

            discovery.ScanSubnet(r.Subnet, func(ip string) {
                if markNewHost(ip) {
                    fmt.Printf("[HOST] %s\n", ip)
                }
            })

            fmt.Println("=== End HUNTER ===\n")
        }
    }()
    // -------------------------------------------------------

    // periodic discovery broadcasts
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        sendDiscovery(disc)
        <-ticker.C
    }
}
