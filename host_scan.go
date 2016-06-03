package portscanner

import (
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
)

// PortRange - Used for specifying a port range
type PortRange struct {
	Start, End int
}

var (
	// AllPorts - Convinience var for full port range
	AllPorts = PortRange{1, 65535}
)

// ScanType - Type of scan
type ScanType int

const (
	// ConnectScan - TCP Connect Scan
	ConnectScan ScanType = iota
	// SynScan - TCP SYN Scan
	SynScan
)

// Protocol - returns the protocol name in string format for a ScanType
func (st ScanType) Protocol() string {
	switch st {
	case ConnectScan, SynScan:
		return "TCP"
	default:
		return "UDP"
	}
}

func (st ScanType) String() string {
	switch st {
	case SynScan:
		return "SYN Scan(TCP)"
	default:
		return "Connect Scan(TCP)"
	}
}

// HostPortStatus - Decriptor for the status of port on a particular host
type HostPortStatus struct {
	Host   string
	Port   int
	Scan   ScanType
	Status PortStatus
}

// ScanResultHandler - function type for callback used to handle results
type ScanResultHandler func(*HostPortStatus)

// HostScanner - struct used to store information needed to scan a particular
//  host
type HostScanner struct {
	// Host Address
	Host string
	// Host IP
	IP net.IP
	// Port range to scan
	Range PortRange
	// Throttle for overall concurrency
	Gate chan int
	// RTT Timout
	Timeout time.Duration
	// Use SYNScan instead of Connect Scan for TCP scan
	SYNScan bool
}

// NewHostScanner -  Create a new scanner for a host
// host - hostname/ip address
// portRange - range of ports to scan
func NewHostScanner(host string, portRange PortRange) (*HostScanner, error) {
	ip, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// default to entire port range
	if portRange.Start == 0 {
		portRange.Start = 1
	}
	if portRange.End == 0 {
		portRange.End = 65535
	}

	return &HostScanner{host, ip[0], portRange, make(chan int, 1), 5 * time.Second, false}, nil
}

/*
Override the default channel used for limiting the number of simultaneous
requests. One buffered channel can be shared between multiple HostScanner
to limit the overall simultaneous requests.

g - new gating channel to be used
*/
func (hs *HostScanner) setGate(g chan int) {
	close(hs.Gate)
	hs.Gate = g
}

/*
Scan the ports for the current HostScanner
handler - callback for each port scanned
*/
func (hs *HostScanner) Scan(handler ScanResultHandler) error {
	var wg sync.WaitGroup
	var scn scanner
	var err error

	if hs.SYNScan {
		if scn, err = newSYNScanner(hs.IP); err != nil {
			return err
		}
	} else {
		scn = newConnectScanner(hs.IP)
	}

	wg.Add(hs.Range.End - hs.Range.Start + 1)
	for p := hs.Range.Start; p <= hs.Range.End; p++ {
		hs.Gate <- 1
		go func(p int) {
			defer func() {
				<-hs.Gate
				wg.Done()
			}()
			if status, err := scn.Scan(p, hs.Timeout); err != nil {
				glog.Errorf("Error encountered while scanning %v:%v - %v, ignoring", hs.Host, p, err)
			} else {
				handler(&HostPortStatus{hs.Host, p, ConnectScan, status})
			}
		}(p)
	}
	wg.Wait()
	scn.Close()
	return nil
}

// ScanOpts - struct for aggregating differen scan options
type ScanOpts struct {
	// Max number of concurrent requests
	Concurrency int
	// Amount of time to wait for a response
	Timeout time.Duration
	// Port Range to scan
	Range PortRange
	// use SYN Scan instead of ConnectScan
	SYNScan bool
}

// ScanHosts - Perform scan on a list of hosts.
// hosts - list of host to scan
// concurrency - number of simultaneous requests
// timeout - request timeout for Connect Scan
// hanlder - port scan result callback, result for each port scanned is
// passed back in the handler, note that handler can be called concurrently
func ScanHosts(hosts []string, opts ScanOpts, handler ScanResultHandler) error {
	gate := make(chan int, opts.Concurrency)
	var scanners []*HostScanner

	defer close(gate)

	// create all hosts first so any errors will stop the execution before scans start
	for _, h := range hosts {
		if hs, err := NewHostScanner(h, opts.Range); err == nil {
			hs.Timeout = opts.Timeout
			hs.SYNScan = opts.SYNScan
			scanners = append(scanners, hs)
		} else {
			return err
		}
	}

	// start the scanning
	for _, s := range scanners {
		s.setGate(gate) // share the same throttle
		s.Scan(handler)
	}
	return nil
}
