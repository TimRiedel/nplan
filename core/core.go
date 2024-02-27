package core

import "fmt"

// Merges an existing scan with hosts obtained from a scan6 file.
func ComplementWithIPv6(scan *Scan, ipv6Hosts *[]Host) *Scan {
	for _, ipv6Host := range *ipv6Hosts {
		foundExistingHost := false
		for i, existingHost := range scan.Hosts {
			if existingHost.MAC == ipv6Host.MAC {
				scan.Hosts[i].IPv6Global = ipv6Host.IPv6Global
				scan.Hosts[i].IPv6LinkLocal = ipv6Host.IPv6LinkLocal
				foundExistingHost = true
			}
		}
		if !foundExistingHost {
			fmt.Printf("[!] Scan6 file contains a host with MAC [%v] and global IPv6 [%v] that is not present in the model.\n", ipv6Host.MAC, ipv6Host.IPv6Global)
			// Only add the unidentified host if it is not already present:
			unidentifiedHost := findUnidentifiedHostByGlobalIPv6(scan, ipv6Host.IPv6Global)
			if unidentifiedHost == nil {
				scan.UnidentifiedHosts = append(scan.UnidentifiedHosts, UnidentifiedHost{
					IPv6Global: ipv6Host.IPv6Global,
					IPv6Local:  ipv6Host.IPv6LinkLocal,
					MAC:        ipv6Host.MAC,
				})
			}
		}
	}
	return scan
}

func findUnidentifiedHostByGlobalIPv6(scan *Scan, ipv6Global string) *UnidentifiedHost {
	for i, host := range scan.UnidentifiedHosts {
		if host.IPv6Global == ipv6Global {
			return &scan.UnidentifiedHosts[i]
		}
	}
	return nil
}

// Merges an existing scan with a new scan. For that, we check for all new
// hosts if there is already a host with the same IPv4. If there is, we merge
// the two hosts, prioritizing information from the new host. If there is not,
// we just add the new host.
func ComplementWithNmap(scan *Scan, newScan *Scan) *Scan {
	for _, newHost := range newScan.Hosts {
		existingHost := findHostByIPv4(scan, newHost.IPv4)
		if existingHost != nil {
			mergeHost(existingHost, newHost)
		} else {
			scan.Hosts = append(scan.Hosts, newHost)
		}
	}
	return scan
}

func findHostByIPv4(scan *Scan, ipv4 string) *Host {
	for i, existingHost := range scan.Hosts {
		if existingHost.IPv4 == ipv4 {
			return &scan.Hosts[i]
		}
	}
	return nil
}

func mergeHost(hostPtr *Host, newHost Host) *Host {
	if newHost.IPv6Global != "" {
		hostPtr.IPv6Global = newHost.IPv6Global
	}
	if newHost.IPv6LinkLocal != "" {
		hostPtr.IPv6LinkLocal = newHost.IPv6LinkLocal
	}
	if newHost.MAC != "" {
		hostPtr.MAC = newHost.MAC
	}
	if newHost.Hostname != "" {
		hostPtr.Hostname = newHost.Hostname
	}
	if newHost.Hops != 0 {
		hostPtr.Hops = newHost.Hops
	}
	if newHost.OS != "" {
		hostPtr.OS = newHost.OS
	}

	for _, newPort := range newHost.Ports {
		existingPort := findPortByNumber(hostPtr, newPort.Number)
		if existingPort != nil {
			mergePort(existingPort, newPort)
		} else {
			hostPtr.Ports = append(hostPtr.Ports, newPort)
		}
	}
	return hostPtr
}

func findPortByNumber(host *Host, number int) *Port {
	for i, port := range host.Ports {
		if port.Number == number {
			return &host.Ports[i]
		}
	}
	return nil
}

func mergePort(port *Port, newPort Port) *Port {
	if newPort.Protocol != "" {
		port.Protocol = newPort.Protocol
	}
	if newPort.ServiceName != "" {
		port.ServiceName = newPort.ServiceName
	}
	if newPort.ServiceVersion != "" {
		port.ServiceVersion = newPort.ServiceVersion
	}
	mergeKeys(port, newPort)
	return port
}

func mergeKeys(port *Port, newPort Port) {
	if port.HostKeys == nil {
		port.HostKeys = newPort.HostKeys
		return
	}

	for _, hostKey := range newPort.HostKeys {
		existingKey := findKeyByType(port, hostKey)
		if existingKey != nil {
			*existingKey = hostKey
		} else {
			port.HostKeys = append(port.HostKeys, hostKey)
		}
	}
}

func findKeyByType(port *Port, newKey HostKey) *HostKey {
	for i, key := range port.HostKeys {
		if key.Type == newKey.Type {
			return &port.HostKeys[i]
		}
	}
	return nil
}
