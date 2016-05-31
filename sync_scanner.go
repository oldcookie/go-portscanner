package portscanner

import (
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
)

// private type for SYN Scan
// SYN Scan Adapted from kdar/gorawtcpsyn
type synScanner struct {
	isIPv4   bool
	src, dst net.IP
	laddr    net.IPAddr
	srcPort  layers.TCPPort
	nwlayer  gopacket.NetworkLayer

	Retries int
	Timeout time.Duration
}

var listenerCmd = make(chan bool)
func init() {
  go func() {
    var c int
    var conn
    for cmd := range listenerCmd {
      switch {
      case cmd && c == 0:
        conn, err := net
        c++
      default:
        c--
      }
    }
  }()
}

func newSYNScanner(ip net.IP, router routing.Router) (*synScanner, error) {
	s := &synScanner{
		dst:     ip,
		Retries: 3,
		Timeout: 5 * time.Second,
		isIPv4:  ip.To4() != nil,
	}

	lIP, lPort, err := s.getLocalIPPort()
	if err != nil {
		return nil, err
	}
	s.src, s.srcPort = lIP, layers.TCPPort(lPort)

	if s.isIPv4 {
		s.nwlayer = &layers.IPv4{
			SrcIP:    s.src,
			DstIP:    s.dst,
			Protocol: layers.IPProtocolTCP,
		}
	} else {
		s.nwlayer = &layers.IPv6{
			SrcIP:      s.src,
			DstIP:      s.dst,
			NextHeader: layers.IPProtocolTCP,
		}
	}
	return s, nil
}

func (s *synScanner) Scan(port int, timeout time.Duration) (PortStatus, error) {

}

// get the local ip and port based on our destination ip
func (s *synScanner) getLocalIPPort() (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", s.dst.String()+":12345")
	if err != nil {
		return nil, -1, err
	}

	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	glog.Error("could not get local ip: " + err.Error())
	return nil, -1, err
}

func (s *synScanner) listen() {

}
