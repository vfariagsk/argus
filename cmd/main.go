package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"argus/internal/discovery"
	"argus/internal/http"
	"argus/internal/report"
	"argus/internal/resolve"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	threads        int
	timeout        time.Duration
	wordlistPath   string
	enableCT       bool
	enableBF       bool
	enableAPIs     bool
	enablePassive  bool
	enableResolve  bool
	enableHTTP     bool
	outputFormat   string
	outputDir      string
	resolveType    string
	enableWildcard bool
)

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Printf("ℹ️  No .env file found, using system environment variables\n")
	}

	fmt.Printf(`
       ___           ___           ___           ___           ___     
      /  /\         /  /\         /  /\         /  /\         /  /\    
     /  /::\       /  /::\       /  /::\       /  /:/        /  /::\   
    /  /:/\:\     /  /:/\:\     /  /:/\:\     /  /:/        /__/:/\:\  
   /  /::\ \:\   /  /::\ \:\   /  /:/  \:\   /  /:/        _\_ \:\ \:\ 
  /__/:/\:\_\:\ /__/:/\:\_\:\ /__/:/_\_ \:\ /__/:/     /\ /__/\ \:\ \:\
  \__\/  \:\/:/ \__\/~|::\/:/ \  \:\__/\_\/ \  \:\    /:/ \  \:\ \:\_\/
       \__\::/     |  |:|::/   \  \:\ \:\    \  \:\  /:/   \  \:\_\:\  
       /  /:/      |  |:|\/     \  \:\/:/     \  \:\/:/     \  \:\/:/  
      /__/:/       |__|:|~       \  \::/       \  \::/       \  \::/   
      \__\/         \__\|         \__\/         \__\/         \__\/  

   Subdomain Intelligence Scanner v1.0.0
   Developed by @0X6A316E676C33

`)
	var rootCmd = &cobra.Command{
		Use:   "argus",
		Short: "Argus - Subdomain Intelligence Scanner",
		Long:  `Argus is a high-fidelity subdomain scanner and analyzer built for penetration testers and security researchers.`,
	}

	var discoverCmd = &cobra.Command{
		Use:   "discover [domain]",
		Short: "Discover subdomains for a given domain",
		Long:  `Discover subdomains using multiple methods including CT logs, brute force, and passive reconnaissance.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runDiscovery(args[0])
		},
	}

	var subsCmd = &cobra.Command{
		Use:   "subs [domain]",
		Short: "Discover subdomains and export to raw text",
		Long:  `Discover subdomains using multiple methods and export results to a raw text file.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runSubsDiscovery(args[0])
		},
	}

	var resolveCmd = &cobra.Command{
		Use:   "resolve [domain] [subdomains_file]",
		Short: "Resolve subdomains to IPs and/or validate HTTP/HTTPS",
		Long:  `Resolve discovered subdomains to IPs and optionally validate HTTP/HTTPS connectivity. Use --type to specify: ip (DNS only), url (HTTP validation), or both.`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			runResolve(args[0], args[1])
		},
	}

	var httpCmd = &cobra.Command{
		Use:   "http [domain] [resolved_file]",
		Short: "Perform HTTP fingerprinting and technology detection",
		Long:  `Perform detailed HTTP fingerprinting, technology detection, and hosting analysis.`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			runHTTPScan(args[0], args[1])
		},
	}

	discoverCmd.Flags().IntVarP(&threads, "threads", "T", 50, "Number of concurrent threads")
	discoverCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Timeout per request")
	discoverCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "assets/common_subs.txt", "Path to wordlist file")
	discoverCmd.Flags().BoolVarP(&enableCT, "ct-logs", "c", true, "Enable Certificate Transparency logs")
	discoverCmd.Flags().BoolVarP(&enableBF, "brute-force", "b", true, "Enable DNS brute force")
	discoverCmd.Flags().BoolVarP(&enableAPIs, "apis", "a", true, "Enable passive APIs")
	discoverCmd.Flags().BoolVarP(&enablePassive, "passive", "p", true, "Enable passive URL parsing")
	discoverCmd.Flags().BoolVarP(&enableResolve, "resolve", "r", false, "Enable detailed DNS resolution and infrastructure analysis")
	discoverCmd.Flags().BoolVarP(&enableHTTP, "http", "H", false, "Enable HTTP fingerprinting and technology detection")
	discoverCmd.Flags().StringVarP(&outputFormat, "format", "f", "console", "Output format: console, json, markdown, both")
	discoverCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./output", "Output directory for reports")

	subsCmd.Flags().IntVarP(&threads, "threads", "T", 50, "Number of concurrent threads")
	subsCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Timeout per request")
	subsCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "assets/common_subs.txt", "Path to wordlist file")
	subsCmd.Flags().BoolVarP(&enableCT, "ct-logs", "c", true, "Enable Certificate Transparency logs")
	subsCmd.Flags().BoolVarP(&enableBF, "brute-force", "b", true, "Enable DNS brute force")
	subsCmd.Flags().BoolVarP(&enableAPIs, "apis", "a", true, "Enable passive APIs")
	subsCmd.Flags().BoolVarP(&enablePassive, "passive", "p", true, "Enable passive URL parsing")
	subsCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./output", "Output directory for results")

	resolveCmd.Flags().IntVarP(&threads, "threads", "T", 50, "Number of concurrent threads")
	resolveCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Timeout per request")
	resolveCmd.Flags().StringVarP(&resolveType, "type", "y", "both", "Resolution type: ip, url, both")
	resolveCmd.Flags().BoolVarP(&enableWildcard, "wildcard", "w", true, "Enable wildcard check during DNS resolution")
	resolveCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./output", "Output directory for results")

	httpCmd.Flags().IntVarP(&threads, "threads", "T", 50, "Number of concurrent threads")
	httpCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "Timeout per request")
	httpCmd.Flags().StringVarP(&outputFormat, "format", "f", "console", "Output format: console, json, markdown, both")
	httpCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./output", "Output directory for results")

	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(subsCmd)
	rootCmd.AddCommand(resolveCmd)
	rootCmd.AddCommand(httpCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runDiscovery(domain string) {
	startTime := time.Now()

	fmt.Printf("🎯 Target: %s\n", domain)
	fmt.Printf("⚙️  Configuration:\n")
	fmt.Printf("   Threads: %d\n", threads)
	fmt.Printf("   Timeout: %v\n", timeout)
	fmt.Printf("   Wordlist: %s\n", wordlistPath)
	fmt.Printf("   CT Logs: %t\n", enableCT)
	fmt.Printf("   Brute Force: %t\n", enableBF)
	fmt.Printf("   APIs: %t\n", enableAPIs)
	fmt.Printf("   Passive: %t\n", enablePassive)
	fmt.Printf("   Resolve: %t\n", enableResolve)
	fmt.Printf("   HTTP: %t\n", enableHTTP)
	fmt.Printf("   Format: %s\n", outputFormat)
	fmt.Printf("   Output Dir: %s\n", outputDir)
	fmt.Printf("\n")

	config := discovery.DiscoveryConfig{
		Domain:           domain,
		Threads:          threads,
		Timeout:          timeout,
		WordlistPath:     wordlistPath,
		EnableCTLogs:     enableCT,
		EnableBruteForce: enableBF,
		EnableAPIs:       enableAPIs,
		EnablePassive:    enablePassive,
		UserAgent:        "Argus/1.0 (Security Scanner)",
	}

	orchestrator := discovery.NewOrchestrator(config)
	result, err := orchestrator.Discover(domain)
	if err != nil {
		fmt.Printf("❌ Error during discovery: %v\n", err)
		os.Exit(1)
	}

	reportData := &report.ReportData{
		Domain:   domain,
		ScanTime: startTime,
		Duration: time.Since(startTime),
		Configuration: report.ScanConfig{
			Threads:       threads,
			Timeout:       timeout,
			WordlistPath:  wordlistPath,
			EnableCT:      enableCT,
			EnableBF:      enableBF,
			EnableAPIs:    enableAPIs,
			EnablePassive: enablePassive,
			EnableResolve: enableResolve,
			EnableHTTP:    enableHTTP,
		},
		DiscoveryResults: result,
		Errors:           result.Errors,
	}

	if enableResolve && len(result.Subdomains) > 0 {
		fmt.Printf("🔍 Starting DNS resolution and infrastructure analysis...\n")

		dnsConfig := resolve.DefaultDNSConfig()
		dnsConfig.Threads = threads
		dnsConfig.Timeout = timeout
		dnsConfig.EnableWildcardCheck = enableWildcard

		resolver := resolve.NewResolver(dnsConfig)

		var hosts []string
		for _, sub := range result.Subdomains {
			hosts = append(hosts, sub.Host)
		}

		resolutionResults, err := resolver.ResolveHosts(hosts)
		if err != nil {
			fmt.Printf("❌ Error during DNS resolution: %v\n", err)
			reportData.Errors = append(reportData.Errors, fmt.Sprintf("DNS resolution failed: %v", err))
		} else {
			reportData.ResolutionResults = resolutionResults

			resolvedCount := 0
			tlsEnabledCount := 0
			cdnCount := 0
			cloudCount := 0
			hostingCount := 0
			takeoverRiskCount := 0
			loadBalancerCount := 0
			wildcardCount := 0

			for _, res := range resolutionResults {
				if res.Resolved {
					resolvedCount++

					if res.TLS.Enabled {
						tlsEnabledCount++
					}

					hasHosting := false
					for _, ip := range res.IPs {
						if ip.IsCDN {
							cdnCount++
						}
						if ip.IsCloud {
							cloudCount++
						}
						if ip.Hosting != "" {
							hasHosting = true
						}
					}

					if hasHosting {
						hostingCount++
					}

					if res.TakeoverRisk {
						takeoverRiskCount++
					}

					if res.LoadBalancer.Detected {
						loadBalancerCount++
					}

					if res.Wildcard {
						wildcardCount++
					}
				}
			}

			reportData.Summary = report.ScanSummary{
				TotalSubdomains:    len(result.Subdomains),
				ResolvedSubdomains: resolvedCount,
				TLSEnabled:         tlsEnabledCount,
				CDNUsage:           cdnCount,
				CloudProviders:     cloudCount,
				HostingProviders:   hostingCount,
				TakeoverRisks:      takeoverRiskCount,
				LoadBalancers:      loadBalancerCount,
				WildcardDNS:        wildcardCount,
			}
		}
	} else {
		reportData.Summary = report.ScanSummary{
			TotalSubdomains: len(result.Subdomains),
		}
	}

	if enableHTTP && len(result.Subdomains) > 0 {
		fmt.Printf("🌐 Starting HTTP fingerprinting and technology detection...\n")

		httpConfig := http.DefaultHTTPConfig()
		httpConfig.Threads = threads
		httpConfig.Timeout = timeout

		scanner := http.NewScanner(httpConfig)

		var addresses []struct {
			IP  string
			URL string
		}

		if len(reportData.ResolutionResults) > 0 {
			for _, res := range reportData.ResolutionResults {
				if res.Resolved && len(res.IPs) > 0 {
					ip := res.IPs[0].IP
					addresses = append(addresses, struct {
						IP  string
						URL string
					}{IP: ip, URL: "http://" + res.Host})
					addresses = append(addresses, struct {
						IP  string
						URL string
					}{IP: ip, URL: "https://" + res.Host})
				}
			}
		} else {
			for _, sub := range result.Subdomains {
				addresses = append(addresses, struct {
					IP  string
					URL string
				}{IP: "", URL: "http://" + sub.Host})
				addresses = append(addresses, struct {
					IP  string
					URL string
				}{IP: "", URL: "https://" + sub.Host})
			}
		}

		httpResults, err := scanner.ScanURLs(addresses)
		if err != nil {
			fmt.Printf("❌ Error during HTTP scanning: %v\n", err)
			reportData.Errors = append(reportData.Errors, fmt.Sprintf("HTTP scanning failed: %v", err))
		} else {
			reportData.HTTPResults = httpResults

			httpRespondingCount := 0
			httpsEnabledCount := 0
			technologiesCount := 0

			for _, httpInfo := range httpResults {
				if httpInfo.IsLive {
					httpRespondingCount++

					if strings.HasPrefix(httpInfo.URL, "https://") {
						httpsEnabledCount++
					}

					technologiesCount += len(httpInfo.Technologies)
				}
			}

			reportData.Summary.HTTPResponding = httpRespondingCount
			reportData.Summary.HTTPSEnabled = httpsEnabledCount
			reportData.Summary.Technologies = technologiesCount

			fmt.Printf("✅ HTTP scanning completed. Found %d live hosts.\n", len(httpResults))
		}
	}

	var formats []string
	switch strings.ToLower(outputFormat) {
	case "both":
		formats = []string{"console", "json", "markdown"}
	case "json", "markdown", "console":
		formats = []string{strings.ToLower(outputFormat)}
	default:
		fmt.Printf("❌ Invalid format: %s. Using console.\n", outputFormat)
		formats = []string{"console"}
	}

	reporter := report.NewReporter(outputDir)
	if err := reporter.GenerateReport(reportData, formats); err != nil {
		fmt.Printf("❌ Error generating reports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ Scan completed successfully!\n")
}

func runSubsDiscovery(domain string) {
	startTime := time.Now()

	fmt.Printf("🎯 Target: %s\n", domain)
	fmt.Printf("⚙️  Configuration:\n")
	fmt.Printf("   Threads: %d\n", threads)
	fmt.Printf("   Timeout: %v\n", timeout)
	fmt.Printf("   Wordlist: %s\n", wordlistPath)
	fmt.Printf("   CT Logs: %t\n", enableCT)
	fmt.Printf("   Brute Force: %t\n", enableBF)
	fmt.Printf("   APIs: %t\n", enableAPIs)
	fmt.Printf("   Passive: %t\n", enablePassive)
	fmt.Printf("   Output Dir: %s\n", outputDir)
	fmt.Printf("\n")

	config := discovery.DiscoveryConfig{
		Domain:           domain,
		Threads:          threads,
		Timeout:          timeout,
		WordlistPath:     wordlistPath,
		EnableCTLogs:     enableCT,
		EnableBruteForce: enableBF,
		EnableAPIs:       enableAPIs,
		EnablePassive:    enablePassive,
		UserAgent:        "Argus/1.0 (Security Scanner)",
	}

	orchestrator := discovery.NewOrchestrator(config)
	result, err := orchestrator.Discover(domain)
	if err != nil {
		fmt.Printf("❌ Error during discovery: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("❌ Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s/%s_subs_%s.txt", outputDir, domain, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	for _, sub := range result.Subdomains {
		file.WriteString(sub.Host + "\n")
	}

	fmt.Printf("✅ Discovery completed!\n")
	fmt.Printf("📊 Found %d subdomains\n", len(result.Subdomains))
	fmt.Printf("📄 Raw results saved: %s\n", filename)
	fmt.Printf("⏱️  Duration: %v\n", time.Since(startTime))
}

func runResolve(domain, subsFile string) {
	startTime := time.Now()

	fmt.Printf("🎯 Target: %s\n", domain)
	fmt.Printf("📄 Subdomains file: %s\n", subsFile)
	fmt.Printf("⚙️  Configuration:\n")
	fmt.Printf("   Threads: %d\n", threads)
	fmt.Printf("   Timeout: %v\n", timeout)
	fmt.Printf("   Resolve Type: %s\n", resolveType)
	fmt.Printf("   Output Dir: %s\n", outputDir)
	fmt.Printf("\n")

	content, err := os.ReadFile(subsFile)
	if err != nil {
		fmt.Printf("❌ Error reading subdomains file: %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(string(content), "\n")
	var subdomains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	fmt.Printf("📋 Loaded %d subdomains from file\n", len(subdomains))

	dnsConfig := resolve.DefaultDNSConfig()
	dnsConfig.Threads = threads
	dnsConfig.Timeout = timeout
	dnsConfig.EnableWildcardCheck = enableWildcard

	resolver := resolve.NewResolver(dnsConfig)
	resolutionResults, err := resolver.ResolveHosts(subdomains)
	if err != nil {
		fmt.Printf("❌ Error during DNS resolution: %v\n", err)
		os.Exit(1)
	}

	var httpResults []*http.HTTPInfo
	var addresses []struct {
		IP  string
		URL string
	}

	resolvedCount := 0
	for _, res := range resolutionResults {
		if res.Resolved && len(res.IPs) > 0 {
			resolvedCount++
		}
	}

	if resolveType == "url" || resolveType == "both" {
		httpConfig := http.DefaultHTTPConfig()
		httpConfig.Threads = threads
		httpConfig.Timeout = timeout

		scanner := http.NewScanner(httpConfig)

		for _, res := range resolutionResults {
			if res.Resolved && len(res.IPs) > 0 {
				ip := res.IPs[0].IP
				addresses = append(addresses, struct {
					IP  string
					URL string
				}{IP: ip, URL: "http://" + res.Host})
				addresses = append(addresses, struct {
					IP  string
					URL string
				}{IP: ip, URL: "https://" + res.Host})
			}
		}

		httpResults, err = scanner.ScanURLs(addresses)
		if err != nil {
			fmt.Printf("❌ Error during HTTP validation: %v\n", err)
			os.Exit(1)
		}
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("❌ Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")

	if len(resolutionResults) > 0 {
		fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
		fmt.Printf("🔍 DETAILED RESULTS\n")
		fmt.Printf(strings.Repeat("-", 80) + "\n")

		for _, res := range resolutionResults {
			if res.Resolved && len(res.IPs) > 0 {
				fmt.Printf("\n📍 %s:\n", res.Host)
				for i, ip := range res.IPs {
					fmt.Printf("   IP %d: %s", i+1, ip.IP)
					if ip.IsCDN {
						fmt.Printf(" [CDN: %s]", ip.CDNProvider)
					}
					if ip.IsCloud {
						fmt.Printf(" [Cloud: %s]", ip.CloudProvider)
					}
					if ip.Hosting != "" {
						fmt.Printf(" [Hosting: %s]", ip.Hosting)
					}
					if ip.Country != "" {
						fmt.Printf(" [%s, %s]", ip.Country, ip.City)
						if ip.ISP != "" {
							fmt.Printf(" [ISP: %s]", ip.ISP)
						}
						if ip.ASN != "" {
							fmt.Printf(" [ASN: %s]", ip.ASN)
						}
						if ip.Lat != 0 && ip.Long != 0 {
							fmt.Printf(" [%.6f, %.6f]", ip.Lat, ip.Long)
						}
					}
					fmt.Printf("\n")
				}

				// Mostrar informações de TLS se disponível
				if res.TLS.Enabled {
					fmt.Printf("   🔐 TLS: %s, %s", res.TLS.Version, res.TLS.Issuer)
					if res.TLS.Expired {
						fmt.Printf(" [EXPIRED]")
					}
					if res.TLS.SelfSigned {
						fmt.Printf(" [SELF-SIGNED]")
					}
					if res.TLS.RiskScore > 0 {
						fmt.Printf(" [RISK: %d]", res.TLS.RiskScore)
					}
					fmt.Printf("\n")

					// Mostrar informações detalhadas de segurança
					if len(res.TLS.SupportedVersions) > 0 {
						fmt.Printf("     📋 Versions: %s\n", strings.Join(res.TLS.SupportedVersions, ", "))
					}
					if len(res.TLS.WeakCiphers) > 0 {
						fmt.Printf("     ⚠️  Weak Ciphers: %s\n", strings.Join(res.TLS.WeakCiphers, ", "))
					}
					if len(res.TLS.SecurityHeaders) > 0 {
						fmt.Printf("     🛡️  Security Headers: %d found\n", len(res.TLS.SecurityHeaders))
					}
				}
			}
		}
		fmt.Printf("\n" + strings.Repeat("-", 80) + "\n")
	}

	if resolveType == "ip" {
		ipFilename := fmt.Sprintf("%s/%s_ips_%s.txt", outputDir, domain, timestamp)
		file, err := os.Create(ipFilename)
		if err != nil {
			fmt.Printf("❌ Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		geoIPCount := 0
		for _, res := range resolutionResults {
			if res.Resolved && len(res.IPs) > 0 {
				for _, ip := range res.IPs {
					// Formato: host,ip,country,city,isp,asn,lat,long
					geoInfo := ""
					if ip.Country != "" {
						geoIPCount++
						geoInfo = fmt.Sprintf(",%s,%s,%s,%s",
							ip.Country,
							ip.City,
							ip.ISP,
							ip.ASN)
						if ip.Lat != 0 && ip.Long != 0 {
							geoInfo += fmt.Sprintf(",%.6f,%.6f", ip.Lat, ip.Long)
						}
					}
					file.WriteString(fmt.Sprintf("%s,%s%s\n", res.Host, ip.IP, geoInfo))
				}
			}
		}

		fmt.Printf("✅ IP resolution completed!\n")
		fmt.Printf("📊 DNS Resolved: %d/%d (%.1f%%)\n", resolvedCount, len(subdomains),
			float64(resolvedCount)/float64(len(subdomains))*100)
		if geoIPCount > 0 {
			fmt.Printf("🌍 GeoIP Info: %d IPs with location data\n", geoIPCount)
		}
		fmt.Printf("📄 IP results saved: %s\n", ipFilename)
		fmt.Printf("⏱️  Duration: %v\n", time.Since(startTime))

	} else if resolveType == "url" || resolveType == "both" {
		// Exportar URLs com validação HTTP
		urlFilename := fmt.Sprintf("%s/%s_urls_%s.txt", outputDir, domain, timestamp)
		file, err := os.Create(urlFilename)
		if err != nil {
			fmt.Printf("❌ Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		liveCount := 0
		for _, httpInfo := range httpResults {
			if httpInfo.IsLive {
				liveCount++
				file.WriteString(fmt.Sprintf("%s,%d\n",
					httpInfo.URL,
					httpInfo.Status))
			}
		}

		fmt.Printf("✅ URL resolution completed!\n")
		fmt.Printf("📊 DNS Resolved: %d/%d (%.1f%%)\n", resolvedCount, len(subdomains),
			float64(resolvedCount)/float64(len(subdomains))*100)
		fmt.Printf("🌐 HTTP Live: %d/%d (%.1f%%)\n", liveCount, len(httpResults),
			float64(liveCount)/float64(len(httpResults))*100)
		fmt.Printf("📄 URL results saved: %s\n", urlFilename)
		fmt.Printf("⏱️  Duration: %v\n", time.Since(startTime))
	}
}

func runHTTPScan(domain, resolvedFile string) {
	startTime := time.Now()

	fmt.Printf("🎯 Target: %s\n", domain)
	fmt.Printf("📄 Resolved file: %s\n", resolvedFile)
	fmt.Printf("⚙️  Configuration:\n")
	fmt.Printf("   Threads: %d\n", threads)
	fmt.Printf("   Timeout: %v\n", timeout)
	fmt.Printf("   Format: %s\n", outputFormat)
	fmt.Printf("   Output Dir: %s\n", outputDir)
	fmt.Printf("\n")

	content, err := os.ReadFile(resolvedFile)
	if err != nil {
		fmt.Printf("❌ Error reading resolved file: %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(string(content), "\n")
	var addresses []struct {
		IP  string
		URL string
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				url := parts[0]
				addresses = append(addresses, struct {
					IP  string
					URL string
				}{IP: "", URL: url})
			}
		}
	}

	fmt.Printf("📋 Loaded %d URLs from file\n", len(addresses))

	// HTTP Scanning
	httpConfig := http.DefaultHTTPConfig()
	httpConfig.Threads = threads
	httpConfig.Timeout = timeout

	scanner := http.NewScanner(httpConfig)
	httpResults, err := scanner.ScanURLs(addresses)
	if err != nil {
		fmt.Printf("❌ Error during HTTP scanning: %v\n", err)
		os.Exit(1)
	}

	reportData := &report.ReportData{
		Domain:   domain,
		ScanTime: startTime,
		Duration: time.Since(startTime),
		Configuration: report.ScanConfig{
			Threads:    threads,
			Timeout:    timeout,
			EnableHTTP: true,
		},
		HTTPResults: httpResults,
		Summary: report.ScanSummary{
			TotalSubdomains: len(addresses),
		},
	}

	httpRespondingCount := 0
	httpsEnabledCount := 0
	technologiesCount := 0
	hostingProvidersCount := 0

	for _, httpInfo := range httpResults {
		if httpInfo.IsLive {
			httpRespondingCount++

			if strings.HasPrefix(httpInfo.URL, "https://") {
				httpsEnabledCount++
			}

			technologiesCount += len(httpInfo.Technologies)

			if httpInfo.Hosting != nil {
				hostingProvidersCount++
			}
		}
	}

	reportData.Summary.HTTPResponding = httpRespondingCount
	reportData.Summary.HTTPSEnabled = httpsEnabledCount
	reportData.Summary.Technologies = technologiesCount
	reportData.Summary.HostingProviders = hostingProvidersCount

	var formats []string
	switch strings.ToLower(outputFormat) {
	case "both":
		formats = []string{"console", "json", "markdown"}
	case "json", "markdown", "console":
		formats = []string{strings.ToLower(outputFormat)}
	default:
		fmt.Printf("❌ Invalid format: %s. Using console.\n", outputFormat)
		formats = []string{"console"}
	}

	reporter := report.NewReporter(outputDir)
	if err := reporter.GenerateReport(reportData, formats); err != nil {
		fmt.Printf("❌ Error generating reports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ HTTP scanning completed successfully!\n")
}
