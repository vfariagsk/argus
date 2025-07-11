package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"argus/internal/discovery"
	"argus/internal/http"
	"argus/internal/resolve"
)

type ReportData struct {
	Domain            string                         `json:"domain"`
	ScanTime          time.Time                      `json:"scan_time"`
	Duration          time.Duration                  `json:"duration"`
	Configuration     ScanConfig                     `json:"configuration"`
	DiscoveryResults  *discovery.DiscoveryResult     `json:"discovery_results"`
	ResolutionResults []*resolve.DNSResolutionResult `json:"resolution_results,omitempty"`
	HTTPResults       []*http.HTTPInfo               `json:"http_results,omitempty"`
	Summary           ScanSummary                    `json:"summary"`
	Errors            []string                       `json:"errors,omitempty"`
}

type ScanConfig struct {
	Threads       int           `json:"threads"`
	Timeout       time.Duration `json:"timeout"`
	WordlistPath  string        `json:"wordlist_path"`
	EnableCT      bool          `json:"enable_ct_logs"`
	EnableBF      bool          `json:"enable_brute_force"`
	EnableAPIs    bool          `json:"enable_apis"`
	EnablePassive bool          `json:"enable_passive"`
	EnableResolve bool          `json:"enable_resolve"`
	EnableHTTP    bool          `json:"enable_http"`
}

type ScanSummary struct {
	TotalSubdomains    int `json:"total_subdomains"`
	ResolvedSubdomains int `json:"resolved_subdomains"`
	TLSEnabled         int `json:"tls_enabled"`
	CDNUsage           int `json:"cdn_usage"`
	CloudProviders     int `json:"cloud_providers"`
	TakeoverRisks      int `json:"takeover_risks"`
	LoadBalancers      int `json:"load_balancers"`
	WildcardDNS        int `json:"wildcard_dns"`
	HTTPResponding     int `json:"http_responding"`
	HTTPSEnabled       int `json:"https_enabled"`
	Technologies       int `json:"technologies"`
	HostingProviders   int `json:"hosting_providers"`
}

type Reporter struct {
	outputDir string
}

func NewReporter(outputDir string) *Reporter {
	return &Reporter{
		outputDir: outputDir,
	}
}

func (r *Reporter) GenerateReport(data *ReportData, formats []string) error {
	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	baseFilename := fmt.Sprintf("%s_%s", data.Domain, timestamp)

	for _, format := range formats {
		switch strings.ToLower(format) {
		case "json":
			if err := r.generateJSON(data, baseFilename); err != nil {
				return fmt.Errorf("failed to generate JSON report: %v", err)
			}
		case "markdown":
			if err := r.generateMarkdown(data, baseFilename); err != nil {
				return fmt.Errorf("failed to generate Markdown report: %v", err)
			}
		case "console":
			r.generateConsole(data)
		default:
			return fmt.Errorf("unsupported format: %s", format)
		}
	}

	return nil
}

func (r *Reporter) generateJSON(data *ReportData, baseFilename string) error {
	filename := filepath.Join(r.outputDir, baseFilename+".json")

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return err
	}

	fmt.Printf("📄 JSON report saved: %s\n", filename)
	return nil
}

func (r *Reporter) generateMarkdown(data *ReportData, baseFilename string) error {
	filename := filepath.Join(r.outputDir, baseFilename+".md")

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	content := r.buildMarkdownContent(data)

	if _, err := file.WriteString(content); err != nil {
		return err
	}

	fmt.Printf("📄 Markdown report saved: %s\n", filename)
	return nil
}

func (r *Reporter) generateConsole(data *ReportData) {
	fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
	fmt.Printf("📊 ARGUS SCAN REPORT\n")
	fmt.Printf(strings.Repeat("=", 80) + "\n")

	fmt.Printf("🎯 Target Domain: %s\n", data.Domain)
	fmt.Printf("🕐 Scan Time: %s\n", data.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("⏱️  Duration: %v\n", data.Duration)

	fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
	fmt.Printf("📈 SCAN SUMMARY\n")
	fmt.Printf(strings.Repeat("-", 80) + "\n")

	fmt.Printf("📋 Total Subdomains: %d\n", data.Summary.TotalSubdomains)
	fmt.Printf("🌐 Resolved: %d (%.1f%%)\n", data.Summary.ResolvedSubdomains,
		float64(data.Summary.ResolvedSubdomains)/float64(data.Summary.TotalSubdomains)*100)
	fmt.Printf("🔐 TLS Enabled: %d (%.1f%%)\n", data.Summary.TLSEnabled,
		float64(data.Summary.TLSEnabled)/float64(data.Summary.ResolvedSubdomains)*100)
	fmt.Printf("🛡️  CDN Usage: %d (%.1f%%)\n", data.Summary.CDNUsage,
		float64(data.Summary.CDNUsage)/float64(data.Summary.ResolvedSubdomains)*100)
	fmt.Printf("☁️  Cloud Providers: %d (%.1f%%)\n", data.Summary.CloudProviders,
		float64(data.Summary.CloudProviders)/float64(data.Summary.ResolvedSubdomains)*100)
	fmt.Printf("⚠️  Takeover Risks: %d (%.1f%%)\n", data.Summary.TakeoverRisks,
		float64(data.Summary.TakeoverRisks)/float64(data.Summary.ResolvedSubdomains)*100)
	fmt.Printf("⚖️  Load Balancers: %d\n", data.Summary.LoadBalancers)
	fmt.Printf("🎯 Wildcard DNS: %d\n", data.Summary.WildcardDNS)

	if data.Configuration.EnableHTTP {
		fmt.Printf("🌐 HTTP Responding: %d (%.1f%%)\n", data.Summary.HTTPResponding,
			float64(data.Summary.HTTPResponding)/float64(data.Summary.TotalSubdomains)*100)
		fmt.Printf("🔐 HTTPS Enabled: %d (%.1f%%)\n", data.Summary.HTTPSEnabled,
			float64(data.Summary.HTTPSEnabled)/float64(data.Summary.HTTPResponding)*100)
		fmt.Printf("🧱 Technologies: %d\n", data.Summary.Technologies)
		fmt.Printf("🏠 Hosting Providers: %d\n", data.Summary.HostingProviders)
	}

	if len(data.ResolutionResults) > 0 {
		fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
		fmt.Printf("🔍 DETAILED RESULTS\n")
		fmt.Printf(strings.Repeat("-", 80) + "\n")

		for _, res := range data.ResolutionResults {
			if res.Resolved {
				fmt.Printf("\n📍 %s:\n", res.Host)
				fmt.Printf("   IPs: %d", len(res.IPs))
				if len(res.IPs) > 0 {
					fmt.Printf(" (")
					for i, ip := range res.IPs {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("%s", ip.IP)
						if ip.IsCDN {
							fmt.Printf(" [%s]", ip.CDNProvider)
						}
						if ip.IsCloud {
							fmt.Printf(" [%s]", ip.CloudProvider)
						}
						if ip.Hosting != "" {
							fmt.Printf(" [Hosting: %s]", ip.Hosting)
						}
					}
					fmt.Printf(")")
				}
				fmt.Printf("\n")

				if res.TLS.Enabled {
					fmt.Printf("   TLS: %s, %s", res.TLS.Version, res.TLS.Issuer)
					if res.TLS.Expired {
						fmt.Printf(" [EXPIRED]")
					}
					if res.TLS.SelfSigned {
						fmt.Printf(" [SELF-SIGNED]")
					}
					fmt.Printf("\n")
				}

				if res.LoadBalancer.Detected {
					fmt.Printf("   Load Balancer: %s (%s)\n", res.LoadBalancer.Type, res.LoadBalancer.Provider)
				}

				if res.TakeoverRisk {
					fmt.Printf("   ⚠️  Takeover Risk: %s\n", res.TakeoverDetails)
				}

				if res.Wildcard {
					fmt.Printf("   🎯 Wildcard DNS detected\n")
				}
			}
		}
	}

	if len(data.HTTPResults) > 0 {
		fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
		fmt.Printf("🌐 HTTP FINGERPRINTING RESULTS\n")
		fmt.Printf(strings.Repeat("-", 80) + "\n")

		for _, httpInfo := range data.HTTPResults {
			fmt.Printf("\n🔗 %s:\n", httpInfo.URL)
			fmt.Printf("   Status: %d\n", httpInfo.Status)
			fmt.Printf("   Title: %s\n", httpInfo.Title)
			fmt.Printf("   Server: %s\n", httpInfo.Server)

			if len(httpInfo.Technologies) > 0 {
				var techNames []string
				for _, tech := range httpInfo.Technologies {
					techNames = append(techNames, tech.Name)
				}
				fmt.Printf("   Technologies: %s\n", strings.Join(techNames, ", "))
			}

			if httpInfo.Hosting != nil {
				fmt.Printf("   Hosting: %s (%.0f%% confidence)\n", httpInfo.Hosting.Provider, httpInfo.Hosting.Confidence*100)
			}

			if len(httpInfo.Traceroute) > 0 {
				fmt.Printf("   Traceroute: %d hops\n", len(httpInfo.Traceroute))
			}
		}
	}

	if len(data.Errors) > 0 {
		fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
		fmt.Printf("❌ ERRORS\n")
		fmt.Printf(strings.Repeat("-", 80) + "\n")
		for _, err := range data.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
}

func (r *Reporter) buildMarkdownContent(data *ReportData) string {
	var content strings.Builder

	content.WriteString("# Argus Subdomain Intelligence Report\n\n")
	content.WriteString(fmt.Sprintf("**Target Domain:** %s\n", data.Domain))
	content.WriteString(fmt.Sprintf("**Scan Time:** %s\n", data.ScanTime.Format("2006-01-02 15:04:05 UTC")))
	content.WriteString(fmt.Sprintf("**Duration:** %v\n\n", data.Duration))

	content.WriteString("## Configuration\n\n")
	content.WriteString("| Setting | Value |\n")
	content.WriteString("|---------|-------|\n")
	content.WriteString(fmt.Sprintf("| Threads | %d |\n", data.Configuration.Threads))
	content.WriteString(fmt.Sprintf("| Timeout | %v |\n", data.Configuration.Timeout))
	content.WriteString(fmt.Sprintf("| CT Logs | %t |\n", data.Configuration.EnableCT))
	content.WriteString(fmt.Sprintf("| Brute Force | %t |\n", data.Configuration.EnableBF))
	content.WriteString(fmt.Sprintf("| APIs | %t |\n", data.Configuration.EnableAPIs))
	content.WriteString(fmt.Sprintf("| Passive | %t |\n", data.Configuration.EnablePassive))
	content.WriteString(fmt.Sprintf("| Resolve | %t |\n", data.Configuration.EnableResolve))
	content.WriteString(fmt.Sprintf("| HTTP | %t |\n\n", data.Configuration.EnableHTTP))

	content.WriteString("## Summary\n\n")
	content.WriteString("| Metric | Count | Percentage |\n")
	content.WriteString("|--------|-------|------------|\n")
	content.WriteString(fmt.Sprintf("| Total Subdomains | %d | 100%% |\n", data.Summary.TotalSubdomains))
	content.WriteString(fmt.Sprintf("| Resolved | %d | %.1f%% |\n", data.Summary.ResolvedSubdomains,
		float64(data.Summary.ResolvedSubdomains)/float64(data.Summary.TotalSubdomains)*100))
	content.WriteString(fmt.Sprintf("| TLS Enabled | %d | %.1f%% |\n", data.Summary.TLSEnabled,
		float64(data.Summary.TLSEnabled)/float64(data.Summary.ResolvedSubdomains)*100))
	content.WriteString(fmt.Sprintf("| CDN Usage | %d | %.1f%% |\n", data.Summary.CDNUsage,
		float64(data.Summary.CDNUsage)/float64(data.Summary.ResolvedSubdomains)*100))
	content.WriteString(fmt.Sprintf("| Cloud Providers | %d | %.1f%% |\n", data.Summary.CloudProviders,
		float64(data.Summary.CloudProviders)/float64(data.Summary.ResolvedSubdomains)*100))
	content.WriteString(fmt.Sprintf("| Takeover Risks | %d | %.1f%% |\n", data.Summary.TakeoverRisks,
		float64(data.Summary.TakeoverRisks)/float64(data.Summary.ResolvedSubdomains)*100))
	content.WriteString(fmt.Sprintf("| Load Balancers | %d | - |\n", data.Summary.LoadBalancers))
	content.WriteString(fmt.Sprintf("| Wildcard DNS | %d | - |\n", data.Summary.WildcardDNS))
	content.WriteString(fmt.Sprintf("| HTTP Responding | %d | - |\n", data.Summary.HTTPResponding))
	content.WriteString(fmt.Sprintf("| HTTPS Enabled | %d | - |\n", data.Summary.HTTPSEnabled))
	content.WriteString(fmt.Sprintf("| Technologies | %d | - |\n", data.Summary.Technologies))
	content.WriteString(fmt.Sprintf("| Hosting Providers | %d | - |\n", data.Summary.HostingProviders))
	content.WriteString("\n")

	if len(data.ResolutionResults) > 0 {
		content.WriteString("## Detailed Results\n\n")

		for _, res := range data.ResolutionResults {
			if res.Resolved {
				content.WriteString(fmt.Sprintf("### %s\n\n", res.Host))

				if len(res.IPs) > 0 {
					content.WriteString("**IPs:** ")
					for i, ip := range res.IPs {
						if i > 0 {
							content.WriteString(", ")
						}
						content.WriteString(ip.IP)
						if ip.IsCDN {
							content.WriteString(fmt.Sprintf(" [%s]", ip.CDNProvider))
						}
						if ip.IsCloud {
							content.WriteString(fmt.Sprintf(" [%s]", ip.CloudProvider))
						}
						if ip.Hosting != "" {
							content.WriteString(fmt.Sprintf(" [Hosting: %s]", ip.Hosting))
						}
					}
					content.WriteString("\n\n")
				}

				if res.TLS.Enabled {
					content.WriteString(fmt.Sprintf("**TLS:** %s, %s", res.TLS.Version, res.TLS.Issuer))
					if res.TLS.Expired {
						content.WriteString(" [EXPIRED]")
					}
					if res.TLS.SelfSigned {
						content.WriteString(" [SELF-SIGNED]")
					}
					content.WriteString("\n\n")
				}

				if res.LoadBalancer.Detected {
					content.WriteString(fmt.Sprintf("**Load Balancer:** %s (%s)\n\n", res.LoadBalancer.Type, res.LoadBalancer.Provider))
				}

				if res.TakeoverRisk {
					content.WriteString(fmt.Sprintf("⚠️ **Takeover Risk:** %s\n\n", res.TakeoverDetails))
				}

				if res.Wildcard {
					content.WriteString("🎯 **Wildcard DNS detected**\n\n")
				}
			}
		}
	}

	if len(data.Errors) > 0 {
		content.WriteString("## Errors\n\n")
		for _, err := range data.Errors {
			content.WriteString(fmt.Sprintf("- %s\n", err))
		}
		content.WriteString("\n")
	}

	content.WriteString("---\n")
	content.WriteString("*Generated by Argus Subdomain Intelligence Scanner*\n")

	return content.String()
}
