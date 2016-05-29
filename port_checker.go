package portscanner

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

type PortStatus int

const (
	PSOpen PortStatus = iota
	PSClose
	PSTimeout
	PSError
)

type portChecker struct {
	hostIp  net.IP
	port    string
	address string
}

type NoNetworkError struct {
	What string
}

func (e NoNetworkError) Error() string {
	return fmt.Sprintf("%v", e.What)
}

func newPortChecker(ip net.IP, port string) *portChecker {
	var address = net.JoinHostPort(ip.String(), port)
	return &portChecker{ip, port, address}
}

func (pc *portChecker) TcpConnectScan(timeout time.Duration) (PortStatus, error) {
	conn, err := net.DialTimeout("tcp", pc.address, timeout)
	if err != nil {
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			return PSTimeout, nil
		}

		switch t := err.(type) {
		default:
			fmt.Printf("unexpected type %T\n", t) // %T prints whatever type t has
		case *net.OpError:
			switch t.Op {
			case "read", "dial":
				return PSClose, nil
			}

		case syscall.Errno:
			if t == syscall.ECONNREFUSED {
				return PSClose, nil
			}
		}
		return PSError, err
	}
	conn.Close()
	return PSOpen, nil
}

func myIPNet() (*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet, nil
			}
		}
	}
	return nil, &NoNetworkError{"Cannot find a non-loopback interface"}
}

func (*portChecker) TcpSynScan() {
	// TODO
}
