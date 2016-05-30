package portscanner

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// PortStatus - Type for describing Status for a port
type PortStatus int

const (
	// PSOpen - Port is open
	PSOpen PortStatus = iota
	// PSClose - Port is closed
	PSClose
	// PSTimeout - Port timed out
	PSTimeout
	// PSError - Other errors when trying connect
	PSError
)

func (ps PortStatus) String() string {
	switch ps {
	case PSOpen:
		return "Open"
	case PSClose:
		return "Closed"
	case PSTimeout:
		return "Timed Out"
	default:
		return "Error"
	}
}

// private type for aggregating port checking functinalities
type portChecker struct {
	hostIP  net.IP
	port    string
	address string
}

// NoNetworkError - thrown when a non-loopback interface cannot be found
type NoNetworkError struct {
	What string
}

func (e NoNetworkError) Error() string {
	return fmt.Sprintf("%v", e.What)
}

// Create a new PortChecker
func newPortChecker(ip net.IP, port string) *portChecker {
	var address = net.JoinHostPort(ip.String(), port)
	return &portChecker{ip, port, address}
}

// Start a TCP connect scan for the current port, consider it failed if timeout
// is exceeded
func (pc *portChecker) ConnectScan(timeout time.Duration) (PortStatus, error) {
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

func (*portChecker) SynScan() {
	// TODO
}
