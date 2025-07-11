package resolve

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
)

type CloudDetector struct {
	ipRanges map[string][]string
}

func NewCloudDetector() *CloudDetector {
	detector := &CloudDetector{
		ipRanges: make(map[string][]string),
	}
	return detector
}

func (cd *CloudDetector) DetectByIP(ip string) string {
	if provider := cd.detectByIPRanges(ip); provider != "" {
		return provider
	}

	return cd.detectByWhois(ip)
}

func (cd *CloudDetector) detectByIPRanges(ip string) string {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return ""
	}

	// Verificar AWS
	if cd.isIPInAWSRanges(ipAddr) {
		return "AWS"
	}

	// Verificar Azure
	if cd.isIPInAzureRanges(ipAddr) {
		return "Azure"
	}

	// Verificar Google Cloud
	if cd.isIPInGCPRanges(ipAddr) {
		return "Google Cloud"
	}

	// Verificar Cloudflare
	if cd.isIPInCloudflareRanges(ipAddr) {
		return "Cloudflare"
	}

	return ""
}

func (cd *CloudDetector) isIPInAWSRanges(ipAddr net.IP) bool {
	data, err := os.ReadFile("assets/aws_ranges.json")
	if err != nil {
		return false
	}

	var awsRanges struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &awsRanges); err != nil {
		return false
	}

	for _, prefix := range awsRanges.Prefixes {
		if prefix.IPPrefix != "" {
			_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
			if err != nil {
				continue
			}
			if ipNet.Contains(ipAddr) {
				return true
			}
		}
	}

	return false
}

func (cd *CloudDetector) isIPInAzureRanges(ipAddr net.IP) bool {
	data, err := os.ReadFile("assets/azure_ranges.json")
	if err != nil {
		return false
	}

	var azureRanges struct {
		Values []struct {
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}

	if err := json.Unmarshal(data, &azureRanges); err != nil {
		return false
	}

	for _, value := range azureRanges.Values {
		for _, prefix := range value.Properties.AddressPrefixes {
			if prefix != "" {
				_, ipNet, err := net.ParseCIDR(prefix)
				if err != nil {
					continue
				}
				if ipNet.Contains(ipAddr) {
					return true
				}
			}
		}
	}

	return false
}

func (cd *CloudDetector) isIPInGCPRanges(ipAddr net.IP) bool {
	data, err := os.ReadFile("assets/gcp_ranges.json")
	if err != nil {
		return false
	}

	var gcpRanges struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			Service    string `json:"service"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &gcpRanges); err != nil {
		return false
	}

	for _, prefix := range gcpRanges.Prefixes {
		if prefix.IPv4Prefix != "" {
			_, ipNet, err := net.ParseCIDR(prefix.IPv4Prefix)
			if err != nil {
				continue
			}
			if ipNet.Contains(ipAddr) {
				return true
			}
		}
	}

	return false
}

func (cd *CloudDetector) isIPInCloudflareRanges(ipAddr net.IP) bool {
	data, err := os.ReadFile("assets/cf_ranges.txt")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		if ipNet.Contains(ipAddr) {
			return true
		}
	}

	return false
}

func (cd *CloudDetector) detectByWhois(ip string) string {
	cmd := exec.Command("whois", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	outputStr := strings.ToLower(string(output))

	whoisPatterns := map[string]string{
		"amazon":       "AWS",
		"aws":          "AWS",
		"google":       "Google Cloud",
		"microsoft":    "Azure",
		"azure":        "Azure",
		"cloudflare":   "Cloudflare",
		"digitalocean": "DigitalOcean",
		"heroku":       "Heroku",
		"vercel":       "Vercel",
		"netlify":      "Netlify",
		"linode":       "Linode",
		"vultr":        "Vultr",
		"ovh":          "OVH",
		"hetzner":      "Hetzner",
		"scaleway":     "Scaleway",
		"upcloud":      "UpCloud",
		"webflow":      "Webflow",
	}

	for keyword, provider := range whoisPatterns {
		if strings.Contains(outputStr, keyword) {
			return provider
		}
	}

	return ""
}
