package http

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Tracerouter struct {
	timeout time.Duration
}

func NewTracerouter() *Tracerouter {
	return &Tracerouter{
		timeout: 30 * time.Second,
	}
}

func (t *Tracerouter) Trace(host string) ([]HopInfo, error) {
	var hops []HopInfo

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host: %v", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host")
	}

	targetIP := ips[0]

	output, err := t.executeTraceroute(targetIP)
	if err != nil {
		return nil, err
	}

	hops = t.parseTracerouteOutput(output)

	return hops, nil
}

func (t *Tracerouter) executeTraceroute(targetIP string) (string, error) {
	commands := []string{"traceroute"}

	for _, cmd := range commands {
		if output, err := t.runCommand(cmd, targetIP); err == nil {
			return output, nil
		}
	}

	return "", fmt.Errorf("traceroute command not found")
}

func (t *Tracerouter) runCommand(command, target string) (string, error) {
	var args []string

	switch command {
	case "traceroute":
		args = []string{"-n", "-w", "1", "-q", "1", target}
	case "tracert":
		args = []string{"-d", "-h", "30", target}
	case "tracepath":
		args = []string{"-n", target}
	default:
		args = []string{target}
	}

	cmd := exec.Command(command, args...)

	output, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return string(output), nil
}

func (t *Tracerouter) parseTracerouteOutput(output string) []HopInfo {
	var hops []HopInfo

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		patterns := []*regexp.Regexp{
			// Linux traceroute: " 1  192.168.1.1  1.234 ms"
			regexp.MustCompile(`^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+([\d.]+)\s+ms`),
			// Windows tracert: "  1     1 ms     1 ms     1 ms  192.168.1.1"
			regexp.MustCompile(`^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)$`),
			// Other: "1:  192.168.1.1  1.234ms"
			regexp.MustCompile(`^\s*(\d+):\s+(\d+\.\d+\.\d+\.\d+)\s+([\d.]+)ms`),
		}

		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 3 {
				hopNum, _ := strconv.Atoi(matches[1])
				ip := matches[2]

				rtt := 0.0
				if len(matches) >= 4 {
					rtt, _ = strconv.ParseFloat(matches[3], 64)
				}

				hop := HopInfo{
					Hop:         hopNum,
					IP:          ip,
					RTT:         rtt,
					IsReachable: true,
				}

				if hostnames, err := net.LookupAddr(ip); err == nil && len(hostnames) > 0 {
					hop.Hostname = strings.TrimSuffix(hostnames[0], ".")
				}

				hops = append(hops, hop)
				break
			}
		}
	}

	return hops
}

func (t *Tracerouter) SimpleTrace(host string) ([]HopInfo, error) {
	var hops []HopInfo

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found")
	}

	targetIP := ips[0]

	for ttl := 1; ttl <= 30; ttl++ {
		hop, reached, err := t.pingWithTTL(targetIP, ttl)
		if err != nil {
			continue
		}

		hops = append(hops, hop)

		if reached {
			break
		}
	}

	return hops, nil
}

func (t *Tracerouter) pingWithTTL(targetIP string, ttl int) (HopInfo, bool, error) {
	hop := HopInfo{
		Hop:         ttl,
		IsReachable: false,
	}
	conn, err := net.Dial("ip4:icmp", targetIP)
	if err != nil {
		return hop, false, fmt.Errorf("failed to dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()

	msg := make([]byte, 64)
	msg[0] = 8 // Echo request
	msg[1] = 0 // Code 0

	check := checksum(msg)
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 0xff)

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return hop, false, fmt.Errorf("failed to write: %v", err)
	}

	reply := make([]byte, 64)
	if _, err := conn.Read(reply); err != nil {
		return hop, false, fmt.Errorf("failed to read: %v", err)
	}

	hop.RTT = time.Since(start).Seconds() * 1000 // Convert to milliseconds
	hop.IP = targetIP
	hop.IsReachable = true

	return hop, true, nil
}

func checksum(msg []byte) int {
	sum := 0
	for i := 0; i < len(msg)-1; i += 2 {
		sum += int(msg[i])<<8 | int(msg[i+1])
	}
	if len(msg)%2 == 1 {
		sum += int(msg[len(msg)-1]) << 8
	}
	return sum
}
