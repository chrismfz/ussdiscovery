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
	"bytes"
	"sort"
	"net/url"

	"ussdiscovery/discovery"
)

// --- Pretty printing & sorting helpers ---

type displayItem struct {
    ip    string
    kind  string   // MikroTik, UBNT, Unknown
    hints []string // tcp/10001 open; ssh:...; http:server=...
}

func ipLess(a, b string) bool {
    ipa := net.ParseIP(a)
    ipb := net.ParseIP(b)
    if ipa == nil || ipb == nil {
        return a < b
    }
    // Προτιμάμε v4 πριν από v6, και μετά byte-compare
    a4 := ipa.To4()
    b4 := ipb.To4()
    if (a4 != nil) != (b4 != nil) {
        return a4 != nil // v4 πριν το v6
    }
    if a4 != nil && b4 != nil {
        return bytes.Compare(a4, b4) < 0
    }
    return bytes.Compare(ipa, ipb) < 0
}

func kindOrder(kind string) int {
    switch kind {
    case "MikroTik":
        return 0
    case "UBNT":
        return 1
    default:
        return 2
    }
}

// Θεωρούμε “ουσιαστικό” fingerprint αν:
// - αναγνωρίστηκε kind (UBNT/MikroTik) ή
// - υπάρχουν hints με χρησιμότητα (ssh banner, http server, open ports)
func isInteresting(kind string, hints []string) bool {
    if kind != "Unknown" {
        return true
    }
    return len(hints) > 0
}

func ssdpShouldPrint(key string) bool {
    if key == "" {
        return false
    }
    now := time.Now()
    if v, ok := seenSSDP.Load(key); ok {
        if t, ok2 := v.(time.Time); ok2 {
            if now.Sub(t) < ssdpSuppress { // εντός παραθύρου καταστολής
                return false
            }
        }
    }
    seenSSDP.Store(key, now)
    return true
}

func normUSN(s string) string {
    s = strings.TrimSpace(strings.ToLower(s))
    if i := strings.Index(s, "::"); i >= 0 {
        s = s[:i] // κόψε ό,τι υπάρχει μετά το πρώτο '::'
    }
    s = strings.TrimPrefix(s, "uuid:")
    return s
}

func ssdpKey(usn, location, lastIP string) string {
    // 1) Προτίμησε normalized USN (σταθερό ανά device)
    if k := normUSN(usn); k != "" {
        return "usn:" + k
    }
    // 2) Αλλιώς πάρε host από Location (συνήθως IP)
    if u, err := url.Parse(location); err == nil && u != nil && u.Hostname() != "" {
        return "loc:" + u.Hostname()
    }
    // 3) Τελευταίο fallback: η IP που απάντησε
    if lastIP != "" {
        return "ip:" + lastIP
    }
    return ""
}

// ports we listen on for discovery replies
var ports = []int{10000, 10001, 10002, 5678, 2048}

// κρατάμε references στους listening UDP sockets για να στέλνουμε από αυτούς
var portUDPConns = map[int]*net.UDPConn{} // port -> *net.UDPConn

// Discovery keeps track of “seen” devices so we only print
// when something is new or actually changes.
type Discovery struct {
	mu              sync.Mutex
	mikrotikSeen    map[string]*MikroTikDevice
	ubntSeen        map[string]*UBNTDevice
	grandstreamSeen map[string]*GrandstreamDevice
	ssdpSeen        map[string]*SSDPDevice
	wsdSeen         map[string]*WSDevice
}

type SSDPDevice struct {
	USN       string // normalized uuid (lowercase, no 'uuid:')
	ST        string // single search target
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
	d.mu.Lock()
	defer d.mu.Unlock()
	key := dev.USN
	prev, ok := d.ssdpSeen[key]
	if !ok || !ssdpEqual(prev, dev) {
		d.ssdpSeen[key] = dev
		return true
	}
	return false
}

func ssdpEqual(a, b *SSDPDevice) bool {
	if a == nil || b == nil {
		return a == b
	}
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
	d.mu.Lock()
	defer d.mu.Unlock()
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
		_ = c.SetReadBuffer(1 << 20)
		conns = append(conns, c)
	}
	if len(conns) == 0 {
		return nil, fmt.Errorf("no multicast-capable IPv4 interfaces found")
	}
	return conns, nil
}

var seenSSDP sync.Map // key=USN ή IP
const ssdpSuppress = 10 * time.Minute // προαιρετικό: μην ξαναεκτυπώσεις πριν περάσει αυτό

func listenSSDP(c *net.UDPConn, disc *Discovery) {
    defer c.Close()
    buf := make([]byte, 8192)
    for {
        n, addr, err := c.ReadFromUDP(buf)
        if err != nil {
            return
        }
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
            USN:       hdr["USN"],
            ST:        hdr["ST"],
            Server:    hdr["SERVER"],
            Location:  hdr["LOCATION"],
            CacheCtrl: hdr["CACHE-CONTROL"],
            LastAddr:  addr.IP.String(),
        }

        // φτιάξε stable key & έλεγξε rate-limited dedup
        key := ssdpKey(dev.USN, dev.Location, dev.LastAddr)
        if !ssdpShouldPrint(key) {
            continue
        }

        // μόνο IP — όσο πιο “στεγνό”, τόσο λιγότερο noise
        fmt.Printf("[SSDP] %s\n", addr.IP.String())
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
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s := string(buf[:n])
		types := ""
		xaddrs := ""
		if m := reTypes.FindStringSubmatch(s); len(m) == 2 {
			types = strings.TrimSpace(html.UnescapeString(m[1]))
		}
		if m := reXAddrs.FindStringSubmatch(s); len(m) == 2 {
			xaddrs = strings.TrimSpace(html.UnescapeString(m[1]))
		}
		if xaddrs == "" && types == "" {
			continue
		}
		dev := &WSDevice{XAddrs: xaddrs, Types: types, Addr: addr.String()}
		if disc.ProcessWSD(dev) {
			fmt.Printf("[WSD] %s | Types=%s | From=%s\n", xaddrs, types, addr.String())
		}
	}
}

var KnownPrivateCIDRs = []string{
	"10.23.140.0/24",
	"192.168.0.0/24",
	"192.168.1.0/24",
	"192.168.2.0/24",
	"192.168.88.0/24",
		
	
}

var scannedSubnets sync.Map // subnet CIDR -> struct{}
var seenHosts sync.Map      // ip -> struct{}
var printedFP sync.Map      // ip -> last printed fingerprint line

func markNewHost(ip string) bool {
	_, loaded := seenHosts.LoadOrStore(ip, struct{}{})
	return !loaded // true μόνο την 1η φορά
}

// ---- helper: send using the already-open listening socket (fixed source port)
func sendFromListeningPort(port int, payload []byte, addr string) {
	uc := portUDPConns[port]
	if uc == nil {
		return
	}
	raddr := resolveUDP(addr)
	_ = uc.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	_, _ = uc.WriteToUDP(payload, raddr)
}

// ---------------------------
// NEW: subnet “poke” helpers
// ---------------------------

// compute directed broadcast for a CIDR (support /24 primary use)
func cidrBroadcast(cidr string) (string, bool) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", false
	}
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	if ip == nil || len(mask) != net.IPv4len {
		return "", false
	}
	bcast := net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast.String(), true
}

func pokeUBNTSubnet(subnet string) {
	if b, ok := cidrBroadcast(subnet); ok {
		msg := []byte{1, 0, 0, 0}
		// directed broadcast
		sendFromListeningPort(10001, msg, net.JoinHostPort(b, "10001"))
		// και global broadcast (μερικά stacks απαντούν μόνο έτσι)
		sendFromListeningPort(10001, msg, "255.255.255.255:10001")
	}
}

func pokeMNDPSubnet(subnet string) {
	// MikroTik MNDP (UDP/5678) — απλά στείλε κάτι σε broadcast
	if b, ok := cidrBroadcast(subnet); ok {
		sendFromListeningPort(5678, []byte{0}, net.JoinHostPort(b, "5678"))
		sendFromListeningPort(5678, []byte{0}, "255.255.255.255:5678")
	}
}

// optional: TCP hint for UBNT
func isOpenTCP(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = c.Close()
		return true
	}
	return false
}

func nudgeUBNTviaTCP(ip string) {
	// Αν 10001/tcp είναι ανοιχτό, στείλε ξανά UDP probe από το listening port
	if isOpenTCP(net.JoinHostPort(ip, "10001"), 300*time.Millisecond) {
		probeUBNT(ip)
	}
}

// ---------------------------
// NEW: TCP fingerprint helpers
// ---------------------------

// κρατά μόνο printable ASCII και κόβει στην πρώτη γραμμή
func sanitizeBanner(s string) string {
	// κόψε στην πρώτη γραμμή
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	// φιλτράρισε printable (32..126) + tabs
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || (r >= 32 && r <= 126) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// Γρήγορος TCP "is open?"
func tcpOpen(ip string, port int, d time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), d)
	if err == nil {
		_ = c.Close()
		return true
	}
	return false
}

// Διάβασε SSH banner (μέχρι ~256 bytes) και καθάρισέ το
func sshBanner(ip string, d time.Duration) (string, error) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), d)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(d))
	var buf [256]byte
	n, err := c.Read(buf[:])
	if n <= 0 {
		return "", err
	}
	return sanitizeBanner(string(buf[:n])), nil
}

// Πάρε HTTP Server header (HEAD /) σε 80
func httpServerHeader(ip string, port int, d time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), d)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	req := "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: ussdiscovery/1.0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	s := strings.ToLower(string(buf[:n]))
	for _, line := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(line, "server:") {
			return strings.TrimSpace(line[len("server:"):]), nil
		}
	}
	return "", nil
}

func shortenServerHeader(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func classifyByTCP(ip string) (kind string, hints []string) {
	// 10001/tcp => ισχυρό hint για UBNT
	if tcpOpen(ip, 10001, 250*time.Millisecond) {
		hints = append(hints, "tcp/10001 open")
		kind = "UBNT"
	}

	// SSH banner
	if b, err := sshBanner(ip, 300*time.Millisecond); err == nil && b != "" {
		lb := strings.ToLower(b)
		if strings.Contains(lb, "rosssh") || strings.Contains(lb, "mikrotik") {
			hints = append(hints, "ssh:"+b)
			if kind == "" {
				kind = "MikroTik"
			}
		} else {
			hints = append(hints, "ssh:"+b)
		}
	}

	// HTTP server header (80)
	if srv, err := httpServerHeader(ip, 80, 400*time.Millisecond); err == nil && srv != "" {
		ls := strings.ToLower(srv)
		srv = shortenServerHeader(srv)
		if strings.Contains(ls, "mikrotik") || strings.Contains(ls, "routeros") {
			hints = append(hints, "http:server="+srv)
			if kind == "" {
				kind = "MikroTik"
			}
		} else if strings.Contains(ls, "ubnt") || strings.Contains(ls, "air") || strings.Contains(ls, "unifi") || strings.Contains(ls, "lighttpd") {
			hints = append(hints, "http:server="+srv)
			if kind == "" {
				kind = "UBNT"
			}
		} else {
			hints = append(hints, "http:server="+srv)
		}
	}

	if kind == "" {
		kind = "Unknown"
	}
	return
}

// ---------------------------
// NEW: TCP-based UBNT probe
// ---------------------------

func tcpProbeUBNT(ip string, disc *Discovery) {
	// Αν η πόρτα δεν είναι ανοιχτή, μην ενοχλείς
	if !tcpOpen(ip, 10001, 200*time.Millisecond) {
		return
	}
	addr := net.JoinHostPort(ip, "10001")
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(600 * time.Millisecond))

	// στείλε το κλασικό discovery payload (ίδιο με UDP)
	_, _ = c.Write([]byte{1, 0, 0, 0})

	// διάβασε απάντηση (UBNT συνήθως στέλνει μικρό packet)
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if n <= 0 || err != nil {
		return
	}
	// προσπάθησε να το περάσεις από τον ίδιο parser
	if dev := parseUBNTPacket(buf[:n]); dev != nil {
		if disc.ProcessUBNT(dev) {
			fmt.Printf("[UBNT/TCP] IP: %s | MAC: %s | Hostname: %s | Model: %s | Platform: %s | Version: %s\n",
				dev.IP, dev.MAC, dev.Hostname, dev.Model, dev.Platform, dev.Version)
		}
	}
}

func sendDiscovery(disc *Discovery) {
	// ---- UBNT & Grandstream probes (broadcast) FROM listening ports ----
	msg := []byte{1, 0, 0, 0}
	// Ubiquiti
	sendFromListeningPort(10001, msg, "255.255.255.255:10001")
	// Grandstream
	sendFromListeningPort(10000, msg, "255.255.255.255:10000")

	// ---- SSDP M-SEARCH ----
	ssdpStr := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"

	// send & read SSDP replies on one ephemeral socket (to catch unicast 200 OK)
	if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}); err == nil {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.WriteToUDP([]byte(ssdpStr), resolveUDP("239.255.255.250:1900"))

		// read unicast replies for ~1.5s
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 8192)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
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
				USN:       hdr["USN"],
				ST:        hdr["ST"],
				Server:    hdr["SERVER"],
				Location:  hdr["LOCATION"],
				CacheCtrl: hdr["CACHE-CONTROL"],
				LastAddr:  addr.IP.String(),
			}
			
			key := ssdpKey(dev.USN, dev.Location, dev.LastAddr)
if ssdpShouldPrint(key) {
    fmt.Printf("[SSDP] %s\n", addr.IP.String())
}

			if dev.USN != "" || dev.Location != "" {
				if disc.ProcessSSDP(dev) {
					fmt.Printf("[SSDP] From=%s | %s | ST=%s | Server=%s | Location=%s\n",
						addr.String(), dev.USN, dev.ST, dev.Server, dev.Location)
				}
			}
		}
		_ = c.Close()
	}

	// (optional extra broadcast — can keep or remove)
	if c, err := net.DialUDP("udp", nil, resolveUDP("239.255.255.250:1900")); err == nil {
		_, _ = c.Write([]byte(ssdpStr))
		_ = c.Close()
	}

	// ---- WS-Discovery Probe ----
	probe := `<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <e:Header>
  <w:MessageID>uuid:` + uuid4() + `</w:MessageID>
  <w:To>urn:schemas-xmlsoap-org:ws:2005:04/discovery</w:To>
  <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body>
  <d:Probe><d:Types/></d:Probe>
 </e:Body>
</e:Envelope>`
	if c, err := net.DialUDP("udp", nil, resolveUDP("239.255.255.250:3702")); err == nil {
		_, _ = c.Write([]byte(probe))
		_ = c.Close()
	}
}

// tiny uuid (good-enough for message id)
func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
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

// ----- Targeted probes για “τάισμα” IPs από Hunter (FROM listening ports) -----
func probeUBNT(ip string) {
	msg := []byte{1, 0, 0, 0}
	sendFromListeningPort(10001, msg, net.JoinHostPort(ip, "10001"))
}

func probeGrandstream(ip string) {
	msg := []byte{1, 0, 0, 0}
	sendFromListeningPort(10000, msg, net.JoinHostPort(ip, "10000"))
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

		// κρατάμε *net.UDPConn* για sendFromListeningPort
		if uc, ok := pc.(*net.UDPConn); ok {
			portUDPConns[port] = uc
			_ = uc.SetReadBuffer(1 << 20)
		}
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

	// consumer: σταθερό worker-pool για ScanSubnet (bounded goroutines)
	const scanWorkers = 12
	subnetQueue := make(chan string, scanWorkers*4)

	// workers
	var scanWG sync.WaitGroup


worker := func() {
    defer scanWG.Done()
    for subnet := range subnetQueue {
        // Μαζεύουμε ευρήματα σε slice και τυπώνουμε ΜΟΝΟ στο τέλος (αν βρέθηκε κάτι)
        items := make([]displayItem, 0, 64)

        // “Pokes” πριν το scan ώστε να έρθουν γρήγορα replies στα listeners
        pokeUBNTSubnet(subnet)
        pokeMNDPSubnet(subnet)

        // Scan subnet
        discovery.ScanSubnet(subnet, func(ip string) {
            if !markNewHost(ip) {
                return
            }

            // Στέλνουμε στοχευμένα probes (δεν τυπώνουμε ακόμα τίποτα)
            probeUBNT(ip)
            probeGrandstream(ip)
            nudgeUBNTviaTCP(ip)
            tcpProbeUBNT(ip, disc)

            // TCP-based ταξινόμηση/ενδείξεις
            kind, hints := classifyByTCP(ip)

            // Αν δεν υπάρχει τίποτα ενδιαφέρον, μην ρυπαίνεις output
            if !isInteresting(kind, hints) {
                return
            }

            items = append(items, displayItem{
                ip:    ip,
                kind:  kind,
                hints: hints,
            })
        })

        // Αν δεν βρέθηκε τίποτα, μην εκτυπώσεις block για το subnet
        if len(items) == 0 {
            continue
        }

        // Ταξινόμηση: πρώτα ανά είδος (MikroTik, UBNT, Unknown) κι έπειτα ανά IP
        sort.Slice(items, func(i, j int) bool {
            ki, kj := kindOrder(items[i].kind), kindOrder(items[j].kind)
            if ki != kj {
                return ki < kj
            }
            return ipLess(items[i].ip, items[j].ip)
        })

        // Εκτυπώσεις ΜΟΝΟ στο τέλος, καθαρά & ομαλά
        fmt.Printf("\n=== HUNTER Results for %s ===\n", subnet)
        for _, it := range items {
            // Ενιαία, περιεκτική γραμμή· αποφεύγουμε σκέτα [HOST]
            line := fmt.Sprintf("[FINGERPRINT] %s -> %s", it.ip, it.kind)
            if len(it.hints) > 0 {
                line += " | " + strings.Join(it.hints, "; ")
            }
            // Dedup ίδιου fingerprint για την IP (αν το έχεις ήδη)
            if prev, _ := printedFP.Load(it.ip); prev != line {
                fmt.Println(line)
                printedFP.Store(it.ip, line)
            }
        }
        fmt.Println("=== End HUNTER ===\n")
    }
}



	scanWG.Add(scanWorkers)
	for i := 0; i < scanWorkers; i++ {
		go worker()
	}

	// feeder: διαβάζει από results και γεμίζει την ουρά χωρίς να φτιάχνει goroutines ανά result
	go func() {
		for r := range results {
			if _, loaded := scannedSubnets.LoadOrStore(r.Subnet, struct{}{}); loaded {
				continue
			}
			subnetQueue <- r.Subnet
		}
		close(subnetQueue)
	}()

	// periodic discovery broadcasts
	ticker := time.NewTicker(30 * time.Second) // λίγο πιο χαλαρά για να μην φορτώνει το δίκτυο
	defer ticker.Stop()
	for {
		sendDiscovery(disc)
		<-ticker.C
	}
}
