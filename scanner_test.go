package portscanner

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

type tcpScanTestCase struct {
	host   string
	ports  PortRange
	status []PortStatus
}

func makeTCPValidator(tc tcpScanTestCase, st ScanType, t *testing.T) ScanResultHandler {
	return func(hps *HostPortStatus) {
		i := hps.Port - tc.ports.Start
		if hps.Host != tc.host || hps.Scan != st || hps.Status != tc.status[i] {
			t.Errorf("Results doesn't match (%v, %v, %v, %v)", hps.Host, hps.Port, hps.Scan, hps.Status)
			t.Errorf("Expected (%v, %v, %v, %v)", tc.host, hps.Port, st, tc.status[i])
		}
	}
}

func TestHostTCPScan(t *testing.T) {
	ts := createTCPTestServer("::1")
	defer ts.stop()
	tsPort, err := strconv.Atoi(ts.port)
	if err != nil {
		t.Error(err)
	}

	var testCases = []tcpScanTestCase{
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:fffa",
			PortRange{80, 84},
			[]PortStatus{PSClose, PSClose, PSClose, PSClose, PSClose}},
		{unroutableIP,
			PortRange{80, 84},
			[]PortStatus{PSTimeout, PSTimeout, PSTimeout, PSTimeout, PSTimeout}},
		{"::1",
			PortRange{tsPort, tsPort},
			[]PortStatus{PSOpen}},
		{"google.com",
			PortRange{80, 81},
			[]PortStatus{PSOpen, PSTimeout}},
	}

	for _, tc := range testCases {
		t.Log("Test Case: ", tc)
		hs, err := NewHostScanner(tc.host, tc.ports)
		if err != nil {
			t.Error(err)
		}
		hs.Timeout = time.Millisecond * 200 // set timeout to lower than default
		hs.Scan(makeTCPValidator(tc, ConnectScan, t))
	}
}

func TestHostScannerConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	var concurrency = 10
	var ch = make(chan int, 100)
	var pr = PortRange{80, 120}
	var wg sync.WaitGroup
	var quit = make(chan bool)
	wg.Add(pr.End - pr.Start + 1)

	// create scanner
	hs, err := NewHostScanner(unroutableIP, pr)
	if err != nil {
		t.Error(err)
	}
	hs.Timeout = time.Millisecond * 100 // set timeout to lower than default
	gate := make(chan int, concurrency)
	hs.setGate(gate)

	// count max
	go func() {
		var max, current int
		for w := range ch {
			current += w
			if current > max {
				max = current
			}
		}
		if max > concurrency || max <= 1 {
			t.Errorf("Concurrency not working, max concurrency workers %v", max)
		}
		t.Logf("Final count- %v", current)
		t.Logf("Max concurrency - %v", max)
		quit <- true
	}()

	hs.Scan(func(*HostPortStatus) {
		defer wg.Done()
		ch <- 1
		time.Sleep(200 * time.Millisecond)
		ch <- -1
	})
	wg.Wait() // wait for all scan before closing channel
	close(ch)
	<-quit // wait for counting goroutine to finish
}
