package portscanner

import (
	"testing"
)

func TestExpandCIDR(t *testing.T) {
	var tests = []struct {
		cidr     string
		expected []string
		fails    bool
	}{
		{"127.0.0.1", nil, true},
		{"invalid/10", nil, true},
		{"127.0.0.1/32", []string{"127.0.0.1"}, false},
		{"127.0.0.1/30", []string{"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"}, false},
		{"2001:db8::/128", []string{"2001:db8::"}, false},
		{"2001:db8::/126", []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}, false},
	}

	for _, tc := range tests {
		ips, err := ExpandCIDR(tc.cidr)
		switch {
		case err != nil && tc.fails:
			if ips != nil {
				t.Error("Not nil list of ip returned on error")
			}
			continue
		case err != nil && !tc.fails:
			t.Error("Unexpected error", err)
		case len(ips) != len(tc.expected):
			t.Log("IPs: ", ips)
			t.Error("Result length doesn't match")
		default:
			for i, ip := range ips {
				if ip != tc.expected[i] {
					t.Errorf("Results didn't match(expected, actual): %v, %v", ip, tc.expected[i])
				}
			}
		}
	}
}
