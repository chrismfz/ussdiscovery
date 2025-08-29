package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanSubnet σαρώνει ένα CIDR και καλεί το onAlive(ip) για κάθε host που φαίνεται ζωντανός.
// Δεν τυπώνει τίποτα μόνο του.
func ScanSubnet(cidr string, onAlive func(ip string)) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("bad subnet:", err)
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 200) // limit concurrency

	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip, 1) {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		addr := ip4.String() // copy value for goroutine

		// (προαιρετικό) skip πιθανό network/broadcast για /24
		// αν δεν το θες, βγάλ' το αυτό το if
		if ones, bits := ipnet.Mask.Size(); bits == 32 && ones <= 30 {
			last := ip4[3]
			if last == 0 || last == 255 {
				continue
			}
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(a string) {
			defer wg.Done()
			defer func() { <-sem }()
			if pingProbe(a, 200*time.Millisecond) {
				if onAlive != nil {
					onAlive(a)
				}
			}
		}(addr)
	}
	wg.Wait()
}

func pingProbe(ip string, timeout time.Duration) bool {
	// Ελαφρύ TCP connect ως “ping” (χωρίς raw ICMP privileges).
	conn, err := net.DialTimeout("tcp", ip+":80", timeout)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}
