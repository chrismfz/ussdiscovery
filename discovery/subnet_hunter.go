package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// HunterResult κρατάει το CIDR που βρέθηκε "ζωντανό"
type HunterResult struct {
	Subnet string
	Alive  bool
}

// SubnetHunter σκανάρει gateways (x.y.z.1 και x.y.z.254) για να βρει candidate subnets
func SubnetHunter(prefix string, out chan<- HunterResult) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 200) // concurrency limit

	// π.χ. /16 = ~256 subnets → κάνει iterate ανά /24
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		fmt.Println("bad prefix:", err)
		return
	}

	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip, 256) {
		subnet := fmt.Sprintf("%s/24", ip.String())
		wg.Add(1)
		go func(cidr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if probeGateway(cidr) {
				out <- HunterResult{Subnet: cidr, Alive: true}
			}
		}(subnet)
	}
	wg.Wait()
	close(out)
}

// probeGateway δοκιμάζει .1 και .254
func probeGateway(cidr string) bool {
	_, ipnet, _ := net.ParseCIDR(cidr)
	base := ipnet.IP.To4()
	if base == nil {
		return false
	}
	ips := []net.IP{
		net.IPv4(base[0], base[1], base[2], 1),
		net.IPv4(base[0], base[1], base[2], 254),
	}
	for _, target := range ips {
		if tcpProbe(target.String(), 80, 200*time.Millisecond) {
			return true
		}
	}
	return false
}

// tcpProbe ανοίγει TCP connection με timeout
func tcpProbe(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

// helper: increment IP by step (256 για να πας στο επόμενο /24)
func inc(ip net.IP, step int) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j] += byte(step)
		if ip[j] != 0 {
			break
		}
	}
}
