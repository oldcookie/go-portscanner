package portscanner

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ip4 = "ip4"
	ip6 = "ip6"
)

// tplMatchFn - Function used to identify if a packet is a match.
// Should return true on matches
type tplMatchFn func(*layers.TCP) bool

type pendingEntry struct {
	timer *time.Timer
	res   chan<- PortStatus
	match tplMatchFn
}

type tcpPacketsListener struct {
	ipVer    string
	laddr    *net.IPAddr
	conn     *net.IPConn
	icmpConn *net.IPConn
	done     chan bool

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
	NotifyOn(lport layers.TCPPort, rIP net.IP, rport layers.TCPPort, timeout time.Duration, fn tplMatchFn) <-chan PortStatus
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
	case ip4, ip6:
		var err error
		tpl.conn, err = net.ListenIP(ipVer+":tcp", laddr)
		if err != nil {
			return nil, err
		}
		if ipVer == ip6 {
			tpl.icmpConn, err = net.ListenIP("ip6:ipv6-icmp", laddr)
		} else {
			tpl.icmpConn, err = net.ListenIP("ip4:icmp", laddr)
		}
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
	p := &tpl.pending
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
	p := &tpl.pending
	p.RLock()
	defer p.RUnlock()

	glog.Infof("Looking up %v, %v, %v, %v\n", rhost, lport, rport, pk)
	return p.m[rhost][pk]
}

// Remove a pending request
func (tpl *tcpPacketsListener) removePending(lport layers.TCPPort, rhost string, rport layers.TCPPort) *pendingEntry {
	pk := portKey(lport, rport)
	p := &tpl.pending

	p.Lock()
	defer p.Unlock()

	glog.Infof("removing %v, %d, %d, %v\n", rhost, lport, rport, pk)
	e := p.m[rhost][pk]
	if delete(p.m[rhost], pk); len(p.m[rhost]) == 0 {
		// remove the entry if no more requests for host
		glog.Infof("No more entries for %v, removing submap from table\n", rhost)
		delete(p.m, rhost)
	}
	if e != nil {
		e.timer.Stop()
	}
	return e
}

// Add a pending request
func (tpl *tcpPacketsListener) addPending(lport layers.TCPPort, rhost string,
	rport layers.TCPPort, match tplMatchFn, timeout time.Duration) <-chan PortStatus {

	p := &tpl.pending
	pk := portKey(lport, rport)

	p.Lock()
	defer p.Unlock()

	glog.Infof("adding %v, %v, %v, %v\n", rhost, lport, rport, pk)
	if p.m[rhost] == nil {
		p.m[rhost] = make(map[uint32]*pendingEntry)
	}

	res := make(chan PortStatus)
	// take care of timeout
	t := time.AfterFunc(timeout, func() {
		tpl.removePending(lport, rhost, rport)
		res <- PSTimeout
	})

	p.m[rhost][pk] = &pendingEntry{
		timer: t,
		match: match,
		res:   res,
	}
	return res
}

func (tpl *tcpPacketsListener) ListenForUnreachable() chan<- bool {
	var icmp layers.ICMPv4
	var icmp6 layers.ICMPv6
	var payload gopacket.Payload
	var parser *gopacket.DecodingLayerParser

	done := make(chan bool)
	data := make([]byte, 4096)
	if tpl.ipVer == ip6 {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv6, &icmp6, &payload)
	} else {
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, &icmp, &payload)
	}

	decoded := make([]gopacket.LayerType, 0, 2)
	go func() {
		for {
			select {
			case <-done:
				glog.Info("Stop signal received, stopping...")
				return
			default:
				// keep processing
			}

			n, _, err := tpl.icmpConn.ReadFromIP(data)
			if err != nil {
				nwErr, ok := err.(net.Error)
				switch {
				case !ok:
					glog.Error("Unexpected(non-network) error occured", err)
					return
				case (nwErr.Timeout() || nwErr.Temporary()):
					// keep going
					continue
				default:
					glog.Error("error reading packet: ", err)
					return
				}
			}

			// Decode the packet
			if err := parser.DecodeLayers(data[:n], &decoded); err != nil || len(decoded) == 0 {
				glog.Error("Failed to code packet", data[:n])
				// not a TCP packet
				continue
			}

			glog.Infof("Decoded len %v\n", len(decoded))
			for _, d := range decoded {
				switch d {
				case layers.LayerTypeICMPv4:
					glog.Infof("ICMPv4 layer %v\n", icmp)
					glog.Infof("ICMPv4 TypeCode %v\n", icmp.TypeCode.Type())
					if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
						rhost := net.IP(payload.Payload()[16:20])
						lport := layers.TCPPort(binary.BigEndian.Uint16(payload.Payload()[20:22]))
						rport := layers.TCPPort(binary.BigEndian.Uint16(payload.Payload()[22:24]))
						glog.Infof("Unroutable packet received IPV4 %v:%v, lport %v\n", rhost, rport, lport)
						if e := tpl.removePending(lport, rhost.String(), rport); e != nil {
							e.res <- PSUnreachable
						}
					}
				case layers.LayerTypeICMPv6:
					glog.Infof("ICMPv6 layer %v\n", icmp6)
					glog.Infof("ICMPv6 TypeCode %v\n", icmp6.TypeCode.Type())
					if icmp6.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable {
						glog.Infof("Unroutable ICMPV6 payload %v\n", payload.Payload())
						rhost := net.IP(payload.Payload()[24:40])
						lport := layers.TCPPort(binary.BigEndian.Uint16(payload.Payload()[40:42]))
						rport := layers.TCPPort(binary.BigEndian.Uint16(payload.Payload()[42:44]))
						glog.Infof("Unroutable packet received IPV6 %v:%v, lport %v\n", rhost, rport, lport)
						if e := tpl.removePending(lport, rhost.String(), rport); e != nil {
							e.res <- PSUnreachable
						}
					}
				}
			}
		}
	}()
	return done
}

// Start processing packets
func (tpl *tcpPacketsListener) Listen() error {
	stopUnreachable := tpl.ListenForUnreachable()

	var tcp layers.TCP
	glog.Info("Start reading TCP packets...")
	data := make([]byte, 4096)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)

	decoded := make([]gopacket.LayerType, 0, 2)
	for {
		// check for stop signal
		select {
		case <-tpl.done:
			stopUnreachable <- true
			glog.Info("Stop signal received, stopping...")
			return nil
		default:
			// keep processing
		}

		if err := tpl.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
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
					glog.Info("Match found!", tcp.SrcPort, addr.IP.String(), tcp.DstPort)
					e.res <- mapTCPAckToPortStatus(&tcp)
				default:
					glog.Info("Call to Match Function failed", tcp)
				}
			} else {
				glog.Info("Incoming packet matches host, but no pending\n", tcp)
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
	timeout time.Duration, fn tplMatchFn) <-chan PortStatus {

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
	return r, nil
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
