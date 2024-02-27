package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/richartkeil/nplan/core"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ParseNmap(path string) core.Scan {
	data, err := os.ReadFile(path)
	check(err)

	var scan Scan
	xml.Unmarshal(data, &scan)

	return convertScan(scan)
}

func ParseScan6(path string) []core.Host {
	data, err := os.ReadFile(path)
	check(err)

	output := strings.TrimSpace(string(data))
	lines := strings.Split(output, "\n")

	ipType := ""
	macHostMap := make(map[string]core.Host)
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Splits the first part of "Global addresses" or "Link-local addresses" to get the type of IP address.
		if strings.Contains(line, "addresses") {
			ipType = strings.Split(line, " ")[0]
			continue
		}

		cols := strings.Split(line, " @ ")
		ip := cols[0]
		mac := strings.ToUpper(cols[1])

		if ipType == "Link-local" {
			if host, exists := macHostMap[mac]; exists {
				host.IPv6LinkLocal = ip
				macHostMap[mac] = host
			} else {
				macHostMap[mac] = core.Host{
					IPv6LinkLocal: ip,
					MAC:           mac,
				}
			}
		} else if ipType == "Global" {
			if host, exists := macHostMap[mac]; exists {
				host.IPv6Global = ip
				macHostMap[mac] = host
			} else {
				macHostMap[mac] = core.Host{
					IPv6Global: ip,
					MAC:        mac,
				}
			}
		}
	}

	var hosts []core.Host
	for _, host := range macHostMap {
		hosts = append(hosts, host)
	}
	return hosts
}

func convertScan(scan Scan) core.Scan {
	var hosts []core.Host
	for _, host := range scan.Hosts {
		hosts = append(hosts, convertHost(host))
	}

	return core.Scan{
		Hosts: hosts,
	}
}

func convertHost(nmapHost Host) core.Host {
	var host core.Host

	for _, address := range nmapHost.Address {
		if address.Type == "ipv4" {
			host.IPv4 = address.Value
		} else if address.Type == "ipv6" {
			host.IPv6Global = address.Value
		} else if address.Type == "mac" {
			host.MAC = address.Value
		}
	}

	for _, hostname := range nmapHost.Hostnames {
		host.Hostname = hostname.Name
	}

	for _, port := range nmapHost.Ports {
		host.Ports = append(host.Ports, convertPort(port))
	}

	host.Hops = nmapHost.Distance.Value
	host.OS = getHostOS(nmapHost.OSMatches)

	return host
}

func convertPort(nmapPort Port) core.Port {
	version := ""
	if nmapPort.Service.Version != "" || nmapPort.Service.Product != "" {
		version = fmt.Sprintf("%v %v", nmapPort.Service.Product, nmapPort.Service.Version)
	}

	port := core.Port{
		Protocol:       nmapPort.Protocol,
		Number:         nmapPort.Portid,
		ServiceName:    nmapPort.Service.Name,
		ServiceVersion: version,
	}
	for _, table := range nmapPort.Tables {
		port.HostKeys = append(port.HostKeys, convertKey(table))
	}
	return port
}

func getHostOS(nmapOSMatches []OS) string {
	if len(nmapOSMatches) < 1 {
		return ""
	}
	// Nmap sorts OS matches by accuracy, so we take the first one:
	match := nmapOSMatches[0]
	return fmt.Sprintf("%v (%v%%)", match.Name, match.Accuracy)
}

func convertKey(nmapTable Table) core.HostKey {
	var key core.HostKey
	for _, element := range nmapTable.Elements {
		if element.Key == "type" {
			key.Type = element.Value
		}
		if element.Key == "key" {
			key.Key = element.Value
		}
		if element.Key == "fingerprint" {
			key.Fingerprint = element.Value
		}
	}
	return key
}
