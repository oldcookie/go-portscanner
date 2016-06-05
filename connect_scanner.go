package portscanner

import (
	"fmt"
	"net"
	"strconv"
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
	// PSUnreachable - Host/address unreachable
	PSUnreachable
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
	case PSUnreachable:
		return "Unreachable"
	default:
		return "Error"
	}
}

// private interface for a scan job
type scanner interface {
	// Scan - Tell the scanner to scan a particular port
	//
	// Note: duration is specified in the Scan method so that we can potentially vary timeouts
	// algorithmically for retries later on
	Scan(port int, timeout time.Duration) (PortStatus, error)

	// Close the scanner
	Close()
}

// private type for connect scan
type connectScanner struct {
	hostIP net.IP
}

// Create a new PortChecker
func newConnectScanner(ip net.IP) scanner {
	return &connectScanner{ip}
}

// Start a TCP connect scan for the current port, consider it failed if timeout
// is exceeded
func (cs *connectScanner) Scan(port int, timeout time.Duration) (PortStatus, error) {
	var addr = net.JoinHostPort(cs.hostIP.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
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

func (cs *connectScanner) Close() {
	//nothing to do
}
