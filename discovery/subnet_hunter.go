package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ------------------------------------------------------------
// Debug toggle
// ------------------------------------------------------------
const debugHunter = true

// HunterResult κρατάει το CIDR που βρέθηκε "ζωντανό"
type HunterResult struct {
	Subnet string
	Alive  bool
}

// SubnetHunter σκανάρει gateways (x.y.z.1 και x.y.z.254) για να βρει candidate subnets.
// Βελτίωση:
// - Αν το prefix είναι /24 (ή στενότερο, ones >= 24), ΔΕΝ φιλτράρουμε — στέλνουμε όλα τα /24 κατευθείαν.
// - Για μεγαλύτερα prefixes (π.χ. /16, /12), χρησιμοποιούμε bounded worker-pool και probeGateway φίλτρο.
func SubnetHunter(prefix string, out chan<- HunterResult) {
	_, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		fmt.Println("bad prefix:", err)
		return
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		// μόνο IPv4 εδώ
		return
	}

	// --- φτιάχνουμε λίστα στόχων /24 (μία φορά)
	var targets []string
	// προσοχή: δουλεύουμε πάνω σε αντίγραφο ώστε να μην αλλοιώσουμε ipnet.IP
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP.Mask(ipnet.Mask))

	for ipnet.Contains(ip) {
		targets = append(targets, fmt.Sprintf("%s/24", ip.String()))
		inc(ip, 256) // πήγαινε στο επόμενο /24
	}

	if debugHunter {
		fmt.Printf("[Hunter] %s -> %d /24 targets\n", prefix, len(targets))
	}

	// Αν το prefix είναι ήδη /24 (ή στενότερο), στείλ’ τα όλα χωρίς probe φίλτρο.
	if ones >= 24 {
		for _, cidr := range targets {
			if debugHunter {
				fmt.Printf("[Hunter] emit %s (no filter)\n", cidr)
			}
			out <- HunterResult{Subnet: cidr, Alive: true}
		}
		return
	}

	// --- αλλιώς, bounded worker pool με probeGateway φίλτρο
	const workers = 64 // ρύθμισε το ανάλογα με το σύστημά σου
	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for cidr := range jobs {
			if probeGateway(cidr) {
				if debugHunter {
					fmt.Printf("[Hunter] emit %s (probe ok)\n", cidr)
				}
				out <- HunterResult{Subnet: cidr, Alive: true}
			} else if debugHunter {
				fmt.Printf("[Hunter] skip %s (probe failed)\n", cidr)
			}
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

	for _, cidr := range targets {
		jobs <- cidr
	}
	close(jobs)
	wg.Wait()
}

// probeGateway δοκιμάζει .1 και .254 σε μερικές “συνηθισμένες” πόρτες
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

	ports := []int{80, 443, 22}
	for _, target := range ips {
		ts := target.String()
		for _, p := range ports {
			if tcpProbe(ts, p, 200*time.Millisecond) {
				return true
			}
		}
	}
	return false
}

// tcpProbe ανοίγει TCP connection με timeout
func tcpProbe(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

// helper: increment IPv4 by 'step' (π.χ. 256 για επόμενο /24)
func inc(ip net.IP, step int) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	v := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	v += uint32(step)
	ip4[0] = byte(v >> 24)
	ip4[1] = byte(v >> 16)
	ip4[2] = byte(v >> 8)
	ip4[3] = byte(v)
	copy(ip, ip4) // ενημέρωσε το αρχικό slice
}
