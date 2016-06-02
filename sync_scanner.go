package portscanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
)

// tplMatchFn - Function used to identify if a packet is a match.
// Should return true on matches
type tplMatchFn func(*layers.TCP) bool

type pendingEntry struct {
	timer *time.Timer
	res   chan<- *layers.TCP
	match tplMatchFn
}

type tcpPacketsListener struct {
	ipVer string
	laddr *net.IPAddr
	conn  *net.IPConn
	done  chan bool

	pending struct {
		sync.RWMutex
		m map[string]map[uint32]*pendingEntry
	}
}

func newTCPPacketsListener(laddr *net.IPAddr, ipVer string) (*tcpPacketsListener, error) {
	tpl := &tcpPacketsListener{done: make(chan bool), ipVer: ipVer}
	tpl.laddr = laddr
	tpl.pending.m = make(map[string]map[uint32]*pendingEntry)
	switch ipVer {
	case "ip4", "ip6":
		var err error
		tpl.conn, err = net.ListenIP(ipVer+":tcp", laddr)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Invalid network type, expecting ip4 or ip6, got %v", ipVer)
	}
	return tpl, nil
}

// Check if there are pending requests for a host
func (tpl *tcpPacketsListener) isHostPending(host string) bool {
	p := tpl.pending
	p.RLock()
	defer p.RUnlock()
	return p.m[host] != nil
}

// quick way to generate a combined key from 2 port numbers
func portKey(lport, rport layers.TCPPort) uint32 {
	return uint32(lport)<<16 | uint32(rport)
}

func (tpl *tcpPacketsListener) lookupPending(lport layers.TCPPort, rhost string, rport layers.TCPPort) *pendingEntry {
	pk := portKey(lport, rport)
	p := tpl.pending
	p.RLock()
	defer p.RUnlock()

	glog.Infof("Looking up %v, %v, %v, %v\n", rhost, lport, rport, pk)
	return p.m[rhost][pk]
}

// Remove a pending request
func (tpl *tcpPacketsListener) removePending(lport layers.TCPPort, rhost string, rport layers.TCPPort) *pendingEntry {
	pk := portKey(lport, rport)
	p := tpl.pending

	p.Lock()
	defer p.Unlock()

	glog.Infof("removing %v, %d, %d, %v\n", rhost, lport, rport, pk)
	res := p.m[rhost][pk]
	if delete(p.m[rhost], pk); len(p.m[rhost]) == 0 {
		// remove the entry if no more requests for host
		glog.Infof("No more entries for %v, removing submap from table\n", rhost)
		delete(p.m, rhost)
	}
	return res
}

// Add a pending request
func (tpl *tcpPacketsListener) addPending(lport layers.TCPPort, rhost string, rport layers.TCPPort, entry *pendingEntry) {
	p := tpl.pending
	pk := portKey(lport, rport)

	p.Lock()
	defer p.Unlock()

	glog.Infof("adding %v, %v, %v, %v\n", rhost, lport, rport, pk)
	if p.m[rhost] == nil {
		p.m[rhost] = make(map[uint32]*pendingEntry)
	}
	p.m[rhost][pk] = entry
}

// Start processing packets
func (tpl *tcpPacketsListener) Start() error {
	var tcp layers.TCP
	glog.Info("Start reading TCP packets...")
	data := make([]byte, 4096)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
	for {
		// check for stop signal
		select {
		case <-tpl.done:
			glog.Info("Stop signal received, stopping...")
			return nil
		default:
			// keep processing
		}

		if err := tpl.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			glog.Error("Error setting read deadline", err)
			return err
		}

		n, addr, err := tpl.conn.ReadFromIP(data)
		if err != nil {
			nwErr, ok := err.(net.Error)
			switch {
			case !ok:
				glog.Error("Unexpected(non-network) error occured", err)
				return err
			case (nwErr.Timeout() || nwErr.Temporary()):
				// keep going
				continue
			default:
				glog.Error("error reading packet: ", err)
				return err
			}
		}

		if tpl.isHostPending(addr.IP.String()) {
			glog.Infof("Incoming packet from pending host: %v\n", addr.IP)
			// Decode the packet
			decoded := make([]gopacket.LayerType, 0, 2)
			if err := parser.DecodeLayers(data[:n], &decoded); err != nil || len(decoded) == 0 {
				glog.Error("Failed to code packet", data[:n])
				// not a TCP packet
				continue
			}

			// since we only passed in one decoder, no need to check layers
			// note: dst port is local port in this case
			if e := tpl.lookupPending(tcp.DstPort, addr.IP.String(), tcp.SrcPort); e != nil {
				switch {
				case e.match(&tcp):
					var clone layers.TCP
					glog.Info("Match found!", tcp.SrcPort, addr.IP.String(), tcp.DstPort)
					tpl.removePending(tcp.SrcPort, addr.IP.String(), tcp.DstPort)
					clone = tcp // copy the packet first
					e.res <- &clone
				default:
					glog.Info("Call to Match Function failed", tcp)
				}
			}
		}
	}
}

func (tpl *tcpPacketsListener) Stop() {
	tpl.done <- true
}

func (tpl *tcpPacketsListener) Write(dstIP net.IP, dstPort layers.TCPPort, tcp *layers.TCP) error {
	var ip gopacket.NetworkLayer
	switch tpl.ipVer {
	case "ip4":
		ip = &layers.IPv4{
			SrcIP:    tpl.laddr.IP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
	default:
		ip = &layers.IPv6{
			SrcIP:      tpl.laddr.IP,
			DstIP:      dstIP,
			NextHeader: layers.IPProtocolTCP,
		}
	}

	// Add checksum and serialize
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return err
	}

	_, err := tpl.conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP})
	return err
}

// WaitFor: wait for a particular TCP packet.  Returns the packet if a match was
// found, else returns nil
// lport - local port
// rIP - remote IP
// rport - remote port
// fn - matching function
func (tpl *tcpPacketsListener) WaitFor(lport layers.TCPPort, rIP net.IP, rport layers.TCPPort,
	timeout time.Duration, fn tplMatchFn) *layers.TCP {
	res := make(chan *layers.TCP)
	expired := make(chan bool)

	// take care of timeout
	t := time.AfterFunc(timeout, func() {
		tpl.removePending(lport, rIP.String(), rport)
		expired <- true
	})
	tpl.addPending(lport, rIP.String(), rport, &pendingEntry{
		timer: t,
		match: fn,
		res:   res,
	})
	select {
	case r := <-res:
		return r
	case <-expired:
		glog.Infof("Timeout waiting for packet from %v:%v", rIP.String(), rport)
		return nil
	}
}

// private type for SYN Scan
type synScanner struct {
	isIPv4   bool
	src, dst net.IP
	laddr    net.IPAddr
	srcPort  layers.TCPPort
	conn     *net.UDPConn

	Retries int
	Timeout time.Duration
}

type listenReq struct {
	scanner *synScanner
}

func newSYNScanner(ip net.IP, router routing.Router) (*synScanner, error) {
	s := &synScanner{
		dst:     ip,
		Retries: 3,
		Timeout: 5 * time.Second,
		isIPv4:  ip.To4() != nil,
	}

	lIP, lPort, conn, err := getLocalIPPort(s.dst)
	if err != nil {
		return nil, err
	}

	s.src, s.srcPort, s.conn = lIP, layers.TCPPort(lPort), conn
	return s, nil
}

func (s *synScanner) Scan(port int, timeout time.Duration) (PortStatus, error) {
	return 0, nil
}

// hack to get the local ip and port based on our destination ip
// also returns the UDP connection so that the local IP an port is
// allocated
func getLocalIPPort(dst net.IP) (net.IP, int, *net.UDPConn, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dst.String(), "12345"))
	if err != nil {
		return nil, -1, nil, err
	}

	var conn *net.UDPConn
	if conn, err = net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port, conn, nil
		}
	}
	glog.Error("could not get local ip: " + err.Error())
	return nil, -1, nil, err
}

func matchSYNTestResps(tcp *layers.TCP) bool {
	// simple matching crit
	return tcp.SYN && tcp.ACK || tcp.RST
}
