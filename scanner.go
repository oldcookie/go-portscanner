package portscanner

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
)

type PortRange struct {
	Start, End int
}

var (
	AllPorts = PortRange{1, 65535}
)

type ScanType int

const (
	TCPConnectScan ScanType = iota
	TCPSynScan
)

type HostScanner struct {
	host    string
	IP      net.IP
	Range   PortRange
	Gate    chan int
	Timeout time.Duration
}

type ScanResultHandler func(host string, port int, scanType ScanType, status PortStatus)

func NewHostScanner(host string, portRange PortRange) (*HostScanner, error) {
	ip, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// defaults
	if portRange.Start == 0 {
		portRange.Start = 1
	}
	if portRange.End == 0 {
		portRange.End = 65535
	}
	return &HostScanner{host, ip[0], portRange, make(chan int, 1), 5 * time.Second}, nil
}

func (hs *HostScanner) setGate(g chan int) {
	close(hs.Gate)
	hs.Gate = g
}

func (hs *HostScanner) Scan(handler ScanResultHandler) {
	var wg sync.WaitGroup
	wg.Add(hs.Range.End - hs.Range.Start + 1)
	for p := hs.Range.Start; p <= hs.Range.End; p++ {
		hs.Gate <- 1
		go func(p int) {
			defer func() {
				<-hs.Gate
				wg.Done()
			}()
			pc := newPortChecker(hs.IP, strconv.Itoa(p))
			if status, err := pc.TcpConnectScan(hs.Timeout); err != nil {
				glog.Errorf("Error encountered while scanning %v:%v - %v, ignoring", hs.host, p, err)
			} else {
				handler(hs.host, p, TCPConnectScan, status)
			}
		}(p)
	}
	wg.Wait()
}

func ScanHosts(hosts []string, concurrency int, timeout time.Duration, handler ScanResultHandler) error {
	gate := make(chan int, concurrency)
	scanners := []*HostScanner{}

	defer close(gate)

	// create all hosts first so any errors will stop the execution before scans start
	for _, h := range hosts {
		if hs, err := NewHostScanner(h, AllPorts); err == nil {
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
