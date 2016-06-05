package portscanner

import (
	"math/rand"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestIPPacketListener(t *testing.T) {
	ipnet, err := myIPNet()
	if err != nil {
		t.Error(err)
		return
	}
	tsClosed := createTCPTestServer(ipnet.IP.String())
	tsClosed.Stop()
	closedPort, _ := strconv.Atoi(tsClosed.port)

	var tests = []struct {
		ipv      string
		addr     string
		port     layers.TCPPort
		expected PortStatus
	}{
		{"ip4", tsClosed.host, layers.TCPPort(closedPort), PSTimeout},
		{"ip4", "google.com", 80, PSOpen}, // Sorry google...
		//		{"ip6", "google.com", 80, expectSYNACK},
		{"ip4", unroutableIP, 80, PSTimeout},
		// TODO need to figure out more test cases that works
	}

	var wg sync.WaitGroup
	wg.Add(len(tests))
	for i, tc := range tests {
		raddr, err := net.ResolveIPAddr(tc.ipv, tc.addr)
		if err != nil {
			t.Errorf("Error encounted on testcase %v: %v", i, err)
			return
		}
		dstIP, dstport := raddr.IP, layers.TCPPort(80)
		ip, port, conn, err := getLocalIPPort(dstIP)
		if err != nil {
			t.Errorf("Error encounted on testcase %v: %v", i, err)
			continue
		}
		conn.Close()

		laddr, _ := net.ResolveIPAddr(tc.ipv, ip.String())
		tpl, err := newTCPPacketsListener(laddr, tc.ipv)
		if err != nil {
			t.Errorf("Error encounted on testcase %v: %v", i, err)
			return
		}
		lport := layers.TCPPort(port)

		seq := rand.Uint32()
		// Our TCP header
		tcp := &layers.TCP{
			SrcPort: lport,
			DstPort: dstport,
			Seq:     seq,
			SYN:     true,
			Window:  14600,
		}

		go func(tpl *tcpPacketsListener) {
			err := tpl.Listen()
			if err != nil {
				t.Error(err)
			}
		}(tpl)

		go func(i int, tpl *tcpPacketsListener, lport layers.TCPPort, dstIP net.IP, dstport layers.TCPPort, expected PortStatus) {
			defer func() {
				wg.Done()
				tpl.Close()
			}()

			res := tpl.NotifyOn(lport, dstIP, dstport, 5*time.Second, matchSYNTestResps)
			if expected != <-res {
				t.Errorf("Testcase %v: %v, Unexpected Result %v\n", i, tc, res)
				return
			}
		}(i, tpl, lport, dstIP, dstport, tc.expected)

		if err = tpl.Write(dstIP, dstport, tcp); err != nil {
			t.Error(err)
			return
		}
	}
	wg.Wait()
}

func TestSYNScanner(t *testing.T) {
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

	googleAddr, err := net.ResolveIPAddr("ip", "google.com")
	if err != nil {
		t.Error(err)
		return
	}

	var tests = []struct {
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

	for i, tc := range tests {
		t.Logf("Test case %v: %v\n", i, tc)
		var ss scanner
		var err error
		var ps PortStatus

		if ss, err = newSYNScanner(net.ParseIP(tc.ip)); err != nil {
			t.Error(err)
			continue
		}
		p, _ := strconv.Atoi(tc.port)
		if ps, err = ss.Scan(p, 2*time.Second); err != nil {
			t.Errorf("TestCase %v failed, error: ", err)
		} else if tc.out != ps {
			t.Errorf("Result for %v doesn't match, expected %v, got %v", i, tc.out, ps)
		}

	}
}
