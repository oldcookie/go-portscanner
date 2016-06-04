package portscanner

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

type tplMap struct {
	sync.RWMutex
	m map[string]*tcpPacketsListener
}

var tplFactory struct {
	once      sync.Once
	listeners *tplMap
}

type tcpWritableListener interface {
	Write(dstIP net.IP, dstPort layers.TCPPort, tcp *layers.TCP) error
	NotifyOn(lport layers.TCPPort, rIP net.IP, rport layers.TCPPort, timeout time.Duration, fn tplMatchFn) <-chan *layers.TCP
}

// Get an instance of TCP Listener for a particular IP version and Address
//
// TODO add tracking of the number of instances requested for TCP listener
// and stop them if there are no more outstanding
func getTCPListener(ipVer string, laddr *net.IPAddr) (tcpWritableListener, error) {
	tplFactory.once.Do(func() {
		// initialize the singleton
		tplFactory.listeners = &tplMap{m: make(map[string]*tcpPacketsListener)}
	})

	key := ipVer + ":" + laddr.IP.String()
	l := tplFactory.listeners

	l.Lock()
	defer l.Unlock()

	if l.m[key] != nil {
		return l.m[key], nil
	}

	var err error
	if l.m[key], err = newTCPPacketsListener(laddr, ipVer); err == nil {
		go func(tpl *tcpPacketsListener, key string) {
			if err := tpl.Listen(); err != nil {
				glog.Error("Unxpected error ready packet, listner quit.")
				glog.Error(err.Error())
				return
			}
			tplFactory.listeners.Lock()
			defer tplFactory.listeners.Unlock()
			delete(tplFactory.listeners.m, key)
		}(l.m[key], key)
		return l.m[key], nil
	}
	return nil, err
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
	e := p.m[rhost][pk]
	if delete(p.m[rhost], pk); len(p.m[rhost]) == 0 {
		// remove the entry if no more requests for host
		glog.Infof("No more entries for %v, removing submap from table\n", rhost)
		delete(p.m, rhost)
	}
	e.timer.Stop()
	return e
}

// Add a pending request
func (tpl *tcpPacketsListener) addPending(lport layers.TCPPort, rhost string,
	rport layers.TCPPort, match tplMatchFn, timeout time.Duration) <-chan *layers.TCP {

	p := tpl.pending
	pk := portKey(lport, rport)

	p.Lock()
	defer p.Unlock()

	glog.Infof("adding %v, %v, %v, %v\n", rhost, lport, rport, pk)
	if p.m[rhost] == nil {
		p.m[rhost] = make(map[uint32]*pendingEntry)
	}

	res := make(chan *layers.TCP)

	// take care of timeout
	t := time.AfterFunc(timeout, func() {
		tpl.removePending(lport, rhost, rport)
		res <- nil
	})

	p.m[rhost][pk] = &pendingEntry{
		timer: t,
		match: match,
		res:   res,
	}
	return res
}

// Start processing packets
func (tpl *tcpPacketsListener) Listen() error {
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

		if err := tpl.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
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
					tpl.removePending(tcp.DstPort, addr.IP.String(), tcp.SrcPort)
					var clone layers.TCP
					glog.Info("Match found!", tcp.SrcPort, addr.IP.String(), tcp.DstPort)
					clone = tcp // copy the packet first
					e.res <- &clone
				default:
					glog.Info("Call to Match Function failed", tcp)
				}
			} else {
				glog.Error("Incoming packet matches host, but no pending\n", tcp)
			}
		}
	}
}

func (tpl *tcpPacketsListener) Close() {
	tpl.done <- true
}

// Write - Write a TCP packet
func (tpl *tcpPacketsListener) Write(dstIP net.IP, dstPort layers.TCPPort, tcp *layers.TCP) error {
	var ip gopacket.NetworkLayer
	switch tpl.ipVer {
	case "ip4":
		glog.Infof("IPv4 Packet, local IP: %v, remove IP: %v\n", tpl.laddr.IP, dstIP)
		ip = &layers.IPv4{
			SrcIP:    tpl.laddr.IP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
	default:
		glog.Infof("IPv6 Packet, local IP: %v, remove IP: %v\n", tpl.laddr.IP, dstIP)
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
func (tpl *tcpPacketsListener) NotifyOn(lport layers.TCPPort, rIP net.IP, rport layers.TCPPort,
	timeout time.Duration, fn tplMatchFn) <-chan *layers.TCP {

	return tpl.addPending(lport, rIP.String(), rport, fn, timeout)
}

// private type for SYN Scan
type synScanner struct {
	ipVer    string
	src, dst net.IP
	laddr    *net.IPAddr
	lport    layers.TCPPort
	conn     *net.UDPConn

	Retries int
	Timeout time.Duration
}

type listenReq struct {
	scanner *synScanner
}

func newSYNScanner(ip net.IP) (scanner, error) {
	s := &synScanner{
		dst:     ip,
		Retries: 3,
		Timeout: 3 * time.Second,
		ipVer:   "ip4",
	}
	if ip.To4() == nil {
		s.ipVer = "ip6"
	}

	lIP, lport, conn, err := getLocalIPPort(s.dst)
	if err != nil {
		return nil, err
	}

	s.src, s.lport, s.conn = lIP, layers.TCPPort(lport), conn
	if s.laddr, err = net.ResolveIPAddr(s.ipVer, s.src.String()); err == nil {
		return s, nil
	}
	return nil, err
}

func (s *synScanner) Scan(port int, timeout time.Duration) (PortStatus, error) {
	l, err := getTCPListener(s.ipVer, s.laddr)
	if err != nil {
		return -1, err
	}

	seq := rand.Uint32()
	rport := layers.TCPPort(port)
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: s.lport,
		DstPort: rport,
		Seq:     seq,
		SYN:     true,
		Window:  14600,
	}

	res := l.NotifyOn(s.lport, s.dst, rport, timeout, matchSYNTestResps)
	if err := l.Write(s.dst, rport, tcp); err != nil {
		return PSError, err
	}

	r := <-res
	return mapTCPAckToPortStatus(r), nil
}

func mapTCPAckToPortStatus(t *layers.TCP) PortStatus {
	switch {
	case t == nil:
		return PSTimeout
	case t.SYN && t.ACK:
		return PSOpen
	case t.RST:
		return PSClose
	}
	return PSError
}

func (s *synScanner) Close() {
	s.conn.Close()
}

// hack to get the local ip and port based on our destination ip
// also returns the UDP connection so that the local IP an port is
// allocated
func getLocalIPPort(dst net.IP) (net.IP, int, *net.UDPConn, error) {
	//local port doesn't really matter, just getting a routable address
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dst.String(), "12345"))
	if err != nil {
		glog.Error("Error resolving address: " + err.Error())
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
