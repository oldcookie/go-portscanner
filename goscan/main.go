package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"net/http"
	_ "net/http/pprof"

	"github.com/oldcookie/go-portscanner"
)

func init() {
	// Replace the usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s - Ports scanner for identifying open ports.\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s <options> [<host> ...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Where <host> can be a hostname, IPv4/IPv6 address, or IP range in CIDR\n"+
			"notation.  Note that the Network Address and Broadcast address are included\n"+
			"in the CIDR range by default.\n\n")
		fmt.Fprintln(os.Stderr, "Options supported:")
		flag.PrintDefaults()
	}
}

func newPortResultHandler(ch chan *portscanner.HostPortStatus) portscanner.ScanResultHandler {
	return func(hps *portscanner.HostPortStatus) {
		ch <- hps
	}
}

type resultsMap map[string]map[portscanner.ScanType]map[portscanner.PortStatus][]int

// Aggregate output to print report.
func aggregateOutput(ch chan *portscanner.HostPortStatus, done chan bool, portServiceMap map[string]string) {
	// Using channel to aggregate output makes working with maps easier
	resMap := make(resultsMap)
	var i = 0
	for hps := range ch {
		if i++; i == 50 {
			i = 0
			fmt.Print(".") // old school print dot to show progress
		}

		switch hps.Status {
		case portscanner.PSClose, portscanner.PSTimeout:
			// ignoring anything that's closed, or timedout
			continue
		default:
			if resMap[hps.Host] == nil {
				resMap[hps.Host] = make(map[portscanner.ScanType]map[portscanner.PortStatus][]int)
			}
			if resMap[hps.Host][hps.Scan] == nil {
				resMap[hps.Host][hps.Scan] = make(map[portscanner.PortStatus][]int)
			}
			if resMap[hps.Host][hps.Scan][hps.Status] == nil {
				resMap[hps.Host][hps.Scan][hps.Status] = []int{}
			}
			resMap[hps.Host][hps.Scan][hps.Status] = append(resMap[hps.Host][hps.Scan][hps.Status], hps.Port)
		}
	}
	fmt.Println()
	printReport(resMap, portServiceMap)
	done <- true
}

func printReport(m resultsMap, portServiceMap map[string]string) {
	fmt.Println("Report")
	fmt.Println("==================================================================")
	for host, scans := range m {
		fmt.Printf("Host: %v\n", host)
		fmt.Print("Protocol\tPort\t\tStatus")
		if portServiceMap != nil {
			fmt.Print("\t\tService")
		}
		fmt.Println("\n------------------------------------------------------------------")
		for stype, sm := range scans {
			for status, ports := range sm {
				sort.Ints(ports)
				for _, p := range ports {
					fmt.Printf("%v\t\t%v\t\t%v", stype.Protocol(), p, status.String())
					port := strconv.Itoa(p)
					if portServiceMap != nil && len(portServiceMap[port]) > 0 {
						fmt.Printf("\t\t%v", portServiceMap[port])
					}
					fmt.Println()
				}
			}
		}
		fmt.Print("\n\n")
	}
}

func main() {
	var opts portscanner.ScanOpts
	var cto int64
	var servMapFile string

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// flags definition
	flag.BoolVar(&opts.SYNScan, "SYN", false, "Use SYN Scan instead of Connect scan for TCP check.(Super user only)")
	flag.IntVar(&opts.Concurrency, "concurrency", 25, "Max number of concurrent requests")
	flag.Int64Var(&cto, "connect-timeout", 2000, "Number of milliseconds to wait for TCP Connect Scan before timeout")
	flag.IntVar(&opts.Range.Start, "port-range-start", 1, "Start of port range to scan")
	flag.IntVar(&opts.Range.End, "port-range-end", 65535, "End of port range to scan(inclusive")
	flag.StringVar(&servMapFile, "service-map", "", "file containing port to service mapping in JSON format")
	var memprofile = flag.String("memprofile", "", "write memory profile to this file")
	flag.Parse()
	args := flag.Args()
	opts.Timeout = time.Duration(cto) * time.Millisecond

	if len(args) <= 0 {
		fmt.Fprintln(os.Stderr, "No hosts specified. For usage, use '-h' option")
		os.Exit(1)
	}

	// Parse service map
	var portServiceMap map[string]string
	if servMapFile != "" {
		buf, err := ioutil.ReadFile(servMapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read file %v [Error: %v]\n", servMapFile, err)
			os.Exit(1)
		}

		err = json.Unmarshal(buf, &portServiceMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to JSON, [Error: %v]", err)
			os.Exit(1)
		}
	}

	// parse hosts from args
	var hosts []string
	for _, arg := range args {
		// check for IP ranges
		if strings.Contains(arg, "/") {
			ips, err := portscanner.ExpandCIDR(arg)
			if err != nil {
				fmt.Printf("Cannot parse CIDR, error: %v", err)
			}
			hosts = append(hosts, ips...)
		} else {
			hosts = append(hosts, arg)
		}
	}
	fmt.Printf("Scanning options {concurrency: %v, port range: [%v, %v], connect timeout: %v, SYN: %v}\n",
		opts.Concurrency, opts.Range.Start, opts.Range.End, opts.Timeout.String(), opts.SYNScan)

	// Start scanning
	start := time.Now()
	resultsCh := make(chan *portscanner.HostPortStatus, opts.Concurrency)
	done := make(chan bool)
	go aggregateOutput(resultsCh, done, portServiceMap)
	portscanner.ScanHosts(
		hosts,
		opts,
		newPortResultHandler(resultsCh))
	close(resultsCh)
	<-done

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
	}
	elapsed := time.Since(start)
	fmt.Printf("%s took %s\n", os.Args[0], elapsed)

}
