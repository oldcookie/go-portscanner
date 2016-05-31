package portscanner

import (
	"net"
	"testing"

	"github.com/google/gopacket/routing"
)

func TestSyncScannerGetHwAddr(t *testing.T) {
	router, err := routing.New()
	handleError(err, t)

	var tests = []struct {
		ip string
	}{
		{"8.8.8.8"},
		{"2001:4860:4860::8888"},
	}
	for _, tc := range tests {
		s, err := newSYNScanner(net.ParseIP(tc.ip), router)
		handleError(err, t)
		t.Log(s)
	}
}
