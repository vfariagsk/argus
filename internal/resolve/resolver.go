package resolve

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	client          *dns.Client
	config          DNSConfig
	tlsAnalyzer     *TLSAnalyzer
	geoAnalyzer     *GeoIPAnalyzer
	cdnDetector     *CDNDetector
	takeoverChecker *TakeoverChecker
	cloudDetector   *CloudDetector
	geoIPCache      map[string]*GeoIPInfo
	cacheMutex      sync.RWMutex
}

func NewResolver(config DNSConfig) *Resolver {
	return &Resolver{
		client: &dns.Client{
			Timeout: config.Timeout,
		},
		config:          config,
		tlsAnalyzer:     NewTLSAnalyzer(config),
		geoAnalyzer:     NewGeoIPAnalyzer(config),
		cdnDetector:     NewCDNDetector(),
		takeoverChecker: NewTakeoverChecker(),
		cloudDetector:   NewCloudDetector(),
		geoIPCache:      make(map[string]*GeoIPInfo),
	}
}

func (r *Resolver) ResolveHost(host string) (*DNSResolutionResult, error) {
	result := &DNSResolutionResult{
		Host:       host,
		ResolvedAt: time.Now(),
		Records:    make(map[string][]DNSRecord),
	}

	if err := r.resolveDNSRecordsParallel(host, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DNS resolution failed: %v", err))
		return result, nil
	}

	if !result.Resolved {
		return result, nil
	}

	if err := r.analyzeIPsParallel(result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("IP analysis failed: %v", err))
	}

	if r.config.EnableTLS && len(result.IPs) > 0 {
		if err := r.analyzeTLS(host, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("TLS analysis failed: %v", err))
		}
	}

	r.detectLoadBalancer(result)

	if r.config.EnableWildcardCheck {
		r.checkWildcard(host, result)
	}

	if r.config.EnableTakeoverCheck {
		r.checkTakeover(host, result)
	}

	return result, nil
}

func (r *Resolver) ResolveHosts(hosts []string) ([]*DNSResolutionResult, error) {
	results := make([]*DNSResolutionResult, len(hosts))
	errors := make([]error, len(hosts))

	workerCount := r.config.Threads
	if workerCount <= 0 {
		workerCount = 50
	}

	jobs := make(chan int, len(hosts))
	done := make(chan bool, len(hosts))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jobIndex := range jobs {
				host := hosts[jobIndex]
				result, err := r.ResolveHost(host)

				results[jobIndex] = result
				errors[jobIndex] = err
				done <- true
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range hosts {
			jobs <- i
		}
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	for i := 0; i < len(hosts); i++ {
		<-done
	}

	return results, nil
}

func (r *Resolver) resolveDNSRecordsParallel(host string, result *DNSResolutionResult) error {
	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT, dns.TypeNS, dns.TypeMX}

	type dnsResult struct {
		recordType uint16
		records    []DNSRecord
		err        error
	}

	results := make(chan dnsResult, len(recordTypes))
	var wg sync.WaitGroup

	for _, recordType := range recordTypes {
		wg.Add(1)
		go func(rt uint16) {
			defer wg.Done()
			records, err := r.queryDNS(host, rt)
			results <- dnsResult{
				recordType: rt,
				records:    records,
				err:        err,
			}
		}(recordType)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.err == nil && len(res.records) > 0 {
			result.Resolved = true
			typeName := dns.TypeToString[res.recordType]
			result.Records[typeName] = r.removeDuplicateRecords(res.records)
		}
	}

	return nil
}

func (r *Resolver) removeDuplicateRecords(records []DNSRecord) []DNSRecord {
	seen := make(map[string]bool)
	var uniqueRecords []DNSRecord

	for _, record := range records {
		key := record.Type + ":" + record.Value
		if !seen[key] {
			seen[key] = true
			uniqueRecords = append(uniqueRecords, record)
		}
	}

	return uniqueRecords
}

func (r *Resolver) queryDNS(host string, recordType uint16) ([]DNSRecord, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), recordType)

	var records []DNSRecord

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	for _, nameserver := range r.config.Nameservers {
		resp, _, err := client.Exchange(msg, nameserver)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeSuccess {
			for _, answer := range resp.Answer {
				record := DNSRecord{
					Type: dns.TypeToString[recordType],
					TTL:  answer.Header().Ttl,
				}

				switch rr := answer.(type) {
				case *dns.A:
					record.Value = rr.A.String()
				case *dns.AAAA:
					record.Value = rr.AAAA.String()
				case *dns.CNAME:
					record.Value = strings.TrimSuffix(rr.Target, ".")
				case *dns.TXT:
					if len(rr.Txt) > 0 {
						record.Value = strings.Join(rr.Txt, " ")
					}
				case *dns.NS:
					record.Value = strings.TrimSuffix(rr.Ns, ".")
				case *dns.MX:
					record.Value = strings.TrimSuffix(rr.Mx, ".")
				}

				records = append(records, record)
			}
			break
		}
	}

	return records, nil
}

func (r *Resolver) analyzeIPsParallel(result *DNSResolutionResult) error {
	var ips []string

	for _, record := range result.Records["A"] {
		if net.ParseIP(record.Value) != nil {
			ips = append(ips, record.Value)
		}
	}
	for _, record := range result.Records["AAAA"] {
		if net.ParseIP(record.Value) != nil {
			ips = append(ips, record.Value)
		}
	}

	if len(ips) == 0 {
		return nil
	}

	type ipAnalysisResult struct {
		index  int
		ipInfo IPInfo
	}

	results := make(chan ipAnalysisResult, len(ips))
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, ipAddr string) {
			defer wg.Done()
			ipInfo := r.analyzeSingleIP(ipAddr, result)
			results <- ipAnalysisResult{
				index:  index,
				ipInfo: ipInfo,
			}
		}(i, ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	ipInfos := make([]IPInfo, len(ips))
	for res := range results {
		ipInfos[res.index] = res.ipInfo
	}

	result.IPs = ipInfos
	return nil
}

func (r *Resolver) analyzeSingleIP(ip string, result *DNSResolutionResult) IPInfo {
	if net.ParseIP(ip) == nil {
		return IPInfo{
			IP:       ip,
			Type:     "INVALID",
			IsPublic: false,
		}
	}

	ipInfo := IPInfo{
		IP: ip,
		Type: func() string {
			if net.ParseIP(ip).To4() != nil {
				return "A"
			}
			return "AAAA"
		}(),
	}

	ipInfo.IsPublic = r.isPublicIP(ip)

	if r.config.EnableCDNDetection {
		if cdnProvider := r.cdnDetector.Detect(ip); cdnProvider != "" {
			ipInfo.IsCDN = true
			ipInfo.CDNProvider = cdnProvider
		}
	}

	if cloudProvider := r.cloudDetector.DetectByIP(ip); cloudProvider != "" {
		ipInfo.IsCloud = true
		ipInfo.CloudProvider = cloudProvider
	}

	hostingProvider := r.detectHostingProvider(result)
	if hostingProvider != "" {
		ipInfo.Hosting = hostingProvider
	}

	if r.config.EnableGeoIP && ipInfo.IsPublic {
		if geoInfo := r.getCachedGeoIP(ip); geoInfo != nil {
			ipInfo.Country = geoInfo.Country
			ipInfo.City = geoInfo.City
			ipInfo.ISP = geoInfo.ISP
			ipInfo.ASN = geoInfo.ASN
			ipInfo.ASName = geoInfo.ASName
			ipInfo.Lat = geoInfo.Lat
			ipInfo.Long = geoInfo.Long
		}
	}

	return ipInfo
}

func (r *Resolver) getCachedGeoIP(ip string) *GeoIPInfo {
	r.cacheMutex.RLock()
	if cached, exists := r.geoIPCache[ip]; exists {
		r.cacheMutex.RUnlock()
		return cached
	}
	r.cacheMutex.RUnlock()

	if geoInfo, err := r.geoAnalyzer.Lookup(ip); err == nil {
		r.cacheMutex.Lock()
		r.geoIPCache[ip] = geoInfo
		r.cacheMutex.Unlock()
		return geoInfo
	}

	return nil
}

func (r *Resolver) analyzeTLS(host string, result *DNSResolutionResult) error {
	tlsInfo, err := r.tlsAnalyzer.Analyze(host)
	if err != nil {
		result.TLS.Enabled = false
		result.TLS.Errors = append(result.TLS.Errors, err.Error())
		return err
	}

	result.TLS = *tlsInfo
	return nil
}

func (r *Resolver) detectLoadBalancer(result *DNSResolutionResult) {
	validIPs := 0
	for _, ipInfo := range result.IPs {
		if net.ParseIP(ipInfo.IP) != nil {
			validIPs++
		}
	}

	if validIPs > 1 {
		result.LoadBalancer.Detected = true

		var validIPList []string
		for _, ipInfo := range result.IPs {
			if net.ParseIP(ipInfo.IP) != nil {
				validIPList = append(validIPList, ipInfo.IP)
			}
		}
		result.LoadBalancer.IPs = validIPList

		lbType := r.determineLoadBalancerType(result.IPs)
		result.LoadBalancer.Type = lbType

		if len(result.IPs) > 0 {
			firstIP := result.IPs[0]
			if firstIP.IsCloud {
				result.LoadBalancer.Provider = firstIP.CloudProvider
			} else if firstIP.IsCDN {
				result.LoadBalancer.Provider = firstIP.CDNProvider
			}
		}
	}
}

func (r *Resolver) determineLoadBalancerType(ips []IPInfo) string {
	allCDN := true
	cdnProviders := make(map[string]bool)
	for _, ip := range ips {
		if !ip.IsCDN {
			allCDN = false
		} else {
			cdnProviders[ip.CDNProvider] = true
		}
	}

	if allCDN && len(cdnProviders) == 1 {
		return "cdn-distribution"
	}

	countries := make(map[string]bool)
	for _, ip := range ips {
		if ip.Country != "" {
			countries[ip.Country] = true
		}
	}

	if len(countries) > 1 {
		return "geographic-load-balancing"
	}

	isps := make(map[string]bool)
	for _, ip := range ips {
		if ip.ISP != "" {
			isps[ip.ISP] = true
		}
	}

	if len(isps) > 1 {
		return "multi-homing"
	}

	asns := make(map[string]bool)
	for _, ip := range ips {
		if ip.ASN != "" {
			asns[ip.ASN] = true
		}
	}

	if len(asns) > 1 {
		return "failover-redundancy"
	}

	return "dns-round-robin"
}

func (r *Resolver) checkWildcard(host string, result *DNSResolutionResult) {
	testHost := fmt.Sprintf("wildcard-test-%d.%s", time.Now().Unix(), host)

	testRecords, err := r.queryDNS(testHost, dns.TypeA)
	if err == nil && len(testRecords) > 0 {
		result.Wildcard = true
	}
}

func (r *Resolver) isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	return true
}

func (r *Resolver) detectHostingProvider(result *DNSResolutionResult) string {
	hostingProviders := map[string][]string{
		"AWS": {
			"amazonaws.com",
		},
		"Google Cloud": {
			"googleusercontent.com",
			"googleapis.com",
		},
		"Azure": {
			"azurewebsites.net",
			"cloudapp.net",
		},
		"DigitalOcean": {
			"digitalocean.com",
		},
		"Heroku": {
			"herokuapp.com",
		},
		"Vercel": {
			"vercel.app",
		},
		"Netlify": {
			"netlify.app",
		},
		"Webflow": {
			"webflow.com",
		},
		"Firebase": {
			"firebaseapp.com",
			"web.app",
		},
		"Hostinger": {
			"hostinger.com",
		},
		"Hostgator": {
			"hostgator.com",
		},
		"Bluehost": {
			"bluehost.com",
		},
		"GoDaddy": {
			"godaddy.com",
		},
		"Namecheap": {
			"namecheap.com",
		},
		"DreamHost": {
			"dreamhost.com",
		},
		"SiteGround": {
			"siteground.com",
		},
		"Github Pages": {
			"github.io",
		},
		"Cloudflare": {
			"cloudflare.com",
		},
		"Short.io": {
			"short.io",
		},
		"KingHost": {
			"kinghost.com.br",
		},
		"WP Engine": {
			"wpengine.com",
		},
		"Kinsta": {
			"kinsta.com",
		},
		"Flywheel": {
			"getflywheel.com",
		},
		"Pantheon": {
			"pantheon.io",
		},
		"Platform.sh": {
			"platform.sh",
		},
		"Compilr": {
			"compilr.com",
		},
		"Surge": {
			"surge.sh",
		},
		"Readme.io": {
			"readme.io",
		},
		"GitLab Pages": {
			"gitlab.io",
		},
		"InMotion Hosting": {
			"inmotionhosting.com",
		},
		"Site5": {
			"site5.com",
		},
		"Cloudflare Pages": {
			"pages.dev",
		},
	}

	if cnameRecords, exists := result.Records["CNAME"]; exists {
		for _, record := range cnameRecords {
			for provider, patterns := range hostingProviders {
				for _, pattern := range patterns {
					if strings.Contains(strings.ToLower(record.Value), pattern) {
						return provider
					}
				}
			}
		}
	}

	return ""
}

func (r *Resolver) checkTakeover(host string, result *DNSResolutionResult) {
	if takeoverInfo, err := r.takeoverChecker.Check(host, result.Records); err == nil && takeoverInfo.Risk {
		result.TakeoverRisk = true
		result.TakeoverDetails = takeoverInfo.Details
	}
}
