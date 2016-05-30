package portscanner

import (
	"net"

	"github.com/ziutek/utils/netaddr"
)

// ExpandCIDR - Util function for expanding a CIDR into a list of IPs
func ExpandCIDR(cidr string) ([]string, error) {
	ipFirst, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipFirst.Mask(ipnet.Mask); ipnet.Contains(ip); ip = netaddr.IPAdd(ip, 1) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// utitlity function for getting a non-loopback IP
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
