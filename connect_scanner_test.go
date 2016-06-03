package portscanner

import (
	"net"
	"strconv"
	"testing"
	"time"
)

const (
	unroutableIP = "198.51.100.1" // TEST-NET-2 IP
)

type tcpTestServer struct {
	l          *net.TCPListener
	host, port string
	quit       bool
}

// create a new test server
func createTCPTestServer(ip string) *tcpTestServer {
	addr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip, "0"))
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	host, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		panic(err)
	}

	ts := &tcpTestServer{l, host, port, false}
	go func() {
		for {
			_, err := l.AcceptTCP()
			if err != nil {
				if ts.quit == true {
					return
				}
				panic(err)
			}
		}
	}()
	return ts
}

func (ts *tcpTestServer) Stop() {
	ts.quit = true
	ts.l.Close()
}

func TestConnectScan(t *testing.T) {
	ipnet, err := myIPNet()
	if err != nil {
		t.Error(err)
		return
	}

	ip := ipnet.IP.String()
	t.Logf("Test ip address: %v", ip)

	ts := createTCPTestServer(ip)
	defer ts.Stop()

	tsClosed := createTCPTestServer(ip)
	tsClosed.Stop()

	googleAddr, _ := net.ResolveIPAddr("ip", "google.com")

	var portTests = []struct {
		ip   string
		port string
		out  PortStatus
	}{
		{ts.host, ts.port, PSOpen},
		{tsClosed.host, tsClosed.port, PSClose},
		{unroutableIP, "80", PSTimeout},
		{googleAddr.IP.String(), "80", PSOpen},
		{googleAddr.IP.String(), "443", PSOpen},
	}

	for i, tc := range portTests {
		t.Logf("Test case %v: %v", i, tc)
		cs := newConnectScanner(net.ParseIP(tc.ip))
		p, _ := strconv.Atoi(tc.port)
		if ps, err := cs.Scan(p, 2*time.Second); err != nil {
			t.Errorf("TestCase %v failed, error: ", err)
		} else if tc.out != ps {
			t.Errorf("Result for %v doesn't match, expected %v, got %v", i, tc.out, ps)
		}
	}
}
