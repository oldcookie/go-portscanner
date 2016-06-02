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

func expectNil(tcp *layers.TCP) bool {
	return tcp == nil
}

func expectSYNACK(tcp *layers.TCP) bool {
	return tcp != nil && tcp.SYN && tcp.ACK
}

func fail(*layers.TCP) bool {
	return false
}

func TestIPPacketListener(t *testing.T) {
	ipnet, err := myIPNet()
	if err != nil {
		t.Error(err)
		return
	}
	tsClosed := createTCPTestServer(ipnet.IP.String())
	tsClosed.Stop()
	closedPort, _ := strconv.Atoi(tsClosed.port)

	/*
		ts6 := createTCPTestServer("::1")
		defer ts6.Stop()
		ts6Port, _ := strconv.Atoi(ts6.port)
	*/

	var tests = []struct {
		ipv      string
		addr     string
		port     layers.TCPPort
		expected func(*layers.TCP) bool
	}{
		{"ip4", tsClosed.host, layers.TCPPort(closedPort), expectNil},
		{"ip4", "google.com", 80, expectSYNACK}, // Sorry google...
		//		{"ip6", "google.com", 80, expectSYNACK},
		{"ip4", unroutableIP, 80, expectNil},
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
			err := tpl.Start()
			if err != nil {
				t.Error(err)
			}
		}(tpl)

		go func(i int, tpl *tcpPacketsListener, lport layers.TCPPort, dstIP net.IP, dstport layers.TCPPort, expected func(*layers.TCP) bool) {
			defer func() {
				wg.Done()
				tpl.Stop()
			}()
			res := tpl.WaitFor(lport, dstIP, dstport, 5*time.Second, matchSYNTestResps)
			if !expected(res) {
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
