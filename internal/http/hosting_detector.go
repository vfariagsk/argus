package http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type HostingInfo struct {
	Provider    string  `json:"provider"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Website     string  `json:"website"`
	Type        string  `json:"type"` // "cloud", "shared", "cdn", "vps", "managed"
}

type HostingDetector struct {
	patterns map[string][]HostingPattern
}

type HostingPattern struct {
	Pattern     string         `json:"pattern"`
	Regex       *regexp.Regexp `json:"-"`
	Confidence  float64        `json:"confidence"`
	Description string         `json:"description"`
	Type        string         `json:"type"`
}

func NewHostingDetector() *HostingDetector {
	detector := &HostingDetector{
		patterns: make(map[string][]HostingPattern),
	}
	detector.initPatterns()
	return detector
}

func (hd *HostingDetector) Detect(ip string, resp *http.Response, dnsRecords map[string][]string) []HostingInfo {
	var results []HostingInfo

	headerResults := hd.detectByHeaders(resp.Header)
	results = append(results, headerResults...)

	dnsResults := hd.detectByDNS(dnsRecords)
	results = append(results, dnsResults...)

	return hd.deduplicateAndSort(results)
}

func (hd *HostingDetector) detectByHeaders(headers http.Header) []HostingInfo {
	var results []HostingInfo

	importantHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-Hosted-By",
		"X-Served-By",
		"X-Backend-Server",
		"X-Forwarded-Server",
		"X-Real-Server",
		"CF-Ray",              // Cloudflare
		"X-Amz-Cf-Id",         // AWS CloudFront
		"X-Vercel-Id",         // Vercel
		"X-Netlify-Version",   // Netlify
		"X-GitHub-Request-Id", // GitHub Pages
		"X-GitLab-Request-Id", // GitLab Pages
		"X-Heroku-Request-Id", // Heroku
		"X-Azure-Ref",         // Azure
		"X-Google-Backend",    // Google Cloud
	}

	for _, headerName := range importantHeaders {
		if value := headers.Get(headerName); value != "" {
			headerResults := hd.matchPatterns(value, headerName)
			results = append(results, headerResults...)
		}
	}

	return results
}

func (hd *HostingDetector) detectByDNS(dnsRecords map[string][]string) []HostingInfo {
	var results []HostingInfo

	if cnames, exists := dnsRecords["CNAME"]; exists {
		for _, cname := range cnames {
			cnameResults := hd.matchPatterns(cname, "CNAME")
			results = append(results, cnameResults...)
		}
	}

	if txts, exists := dnsRecords["TXT"]; exists {
		for _, txt := range txts {
			txtResults := hd.matchPatterns(txt, "TXT")
			results = append(results, txtResults...)
		}
	}

	return results
}

func (hd *HostingDetector) matchPatterns(value, source string) []HostingInfo {
	var results []HostingInfo

	for provider, patterns := range hd.patterns {
		for _, pattern := range patterns {
			if hd.shouldApplyPattern(pattern, source) && pattern.Regex.MatchString(value) {
				hostingInfo := HostingInfo{
					Provider:    provider,
					Confidence:  pattern.Confidence,
					Description: fmt.Sprintf("%s (detected via %s)", pattern.Description, source),
					Type:        pattern.Type,
				}
				results = append(results, hostingInfo)
			}
		}
	}

	return results
}

func (hd *HostingDetector) shouldApplyPattern(pattern HostingPattern, source string) bool {
	sourcePatterns := map[string][]string{
		"headers": {"headers", "server", "x-powered-by", "x-aspnet-version", "x-generator"},
		"dns":     {"cname", "txt", "dns"},
		"ip":      {"ip", "forwarded"},
		"body":    {"body", "content"},
	}

	if patterns, exists := sourcePatterns[source]; exists {
		for _, p := range patterns {
			if strings.Contains(strings.ToLower(pattern.Description), p) {
				return true
			}
		}
	}

	return true
}

func (hd *HostingDetector) deduplicateAndSort(results []HostingInfo) []HostingInfo {
	seen := make(map[string]bool)
	var unique []HostingInfo

	for _, result := range results {
		key := fmt.Sprintf("%s-%s", result.Provider, result.Type)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, result)
		}
	}

	for i := 0; i < len(unique)-1; i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[i].Confidence < unique[j].Confidence {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}

	return unique
}

func (hd *HostingDetector) initPatterns() {
	// Firebase Hosting
	hd.patterns["Firebase Hosting"] = []HostingPattern{
		{Pattern: `firebaseapp\.com`, Confidence: 0.95, Description: "Firebase hosting domain (DNS)", Type: "cloud"},
		{Pattern: `firebase\.googleapis\.com`, Confidence: 0.9, Description: "Firebase APIs (DNS)", Type: "cloud"},
		{Pattern: `firebase`, Confidence: 0.8, Description: "Firebase platform (headers)", Type: "cloud"},
	}

	// Vercel
	hd.patterns["Vercel"] = []HostingPattern{
		{Pattern: `vercel\.app`, Confidence: 0.95, Description: "Vercel hosting domain (DNS)", Type: "cloud"},
		{Pattern: `vercel\.com`, Confidence: 0.9, Description: "Vercel domain (DNS)", Type: "cloud"},
		{Pattern: `vercel`, Confidence: 0.8, Description: "Vercel platform (headers)", Type: "cloud"},
	}

	// Netlify
	hd.patterns["Netlify"] = []HostingPattern{
		{Pattern: `netlify\.app`, Confidence: 0.95, Description: "Netlify hosting domain (DNS)", Type: "cloud"},
		{Pattern: `netlify\.com`, Confidence: 0.9, Description: "Netlify domain (DNS)", Type: "cloud"},
		{Pattern: `netlify`, Confidence: 0.8, Description: "Netlify platform (headers)", Type: "cloud"},
	}

	// GitHub Pages
	hd.patterns["GitHub Pages"] = []HostingPattern{
		{Pattern: `github\.io`, Confidence: 0.95, Description: "GitHub Pages domain (DNS)", Type: "cloud"},
		{Pattern: `github\.com`, Confidence: 0.8, Description: "GitHub domain (DNS)", Type: "cloud"},
		{Pattern: `github`, Confidence: 0.7, Description: "GitHub platform (headers)", Type: "cloud"},
	}

	// GitLab Pages
	hd.patterns["GitLab Pages"] = []HostingPattern{
		{Pattern: `gitlab\.io`, Confidence: 0.95, Description: "GitLab Pages domain (DNS)", Type: "cloud"},
		{Pattern: `gitlab\.com`, Confidence: 0.8, Description: "GitLab domain (DNS)", Type: "cloud"},
		{Pattern: `gitlab`, Confidence: 0.7, Description: "GitLab platform (headers)", Type: "cloud"},
	}

	// Heroku
	hd.patterns["Heroku"] = []HostingPattern{
		{Pattern: `herokuapp\.com`, Confidence: 0.95, Description: "Heroku hosting domain (DNS)", Type: "cloud"},
		{Pattern: `heroku\.com`, Confidence: 0.9, Description: "Heroku domain (DNS)", Type: "cloud"},
		{Pattern: `heroku`, Confidence: 0.8, Description: "Heroku platform (headers)", Type: "cloud"},
	}

	// AWS S3
	hd.patterns["AWS S3"] = []HostingPattern{
		{Pattern: `s3\.amazonaws\.com`, Confidence: 0.95, Description: "AWS S3 domain (DNS)", Type: "cloud"},
		{Pattern: `s3-`, Confidence: 0.8, Description: "AWS S3 bucket (DNS)", Type: "cloud"},
		{Pattern: `amazonaws\.com`, Confidence: 0.7, Description: "AWS domain (DNS)", Type: "cloud"},
	}

	// AWS CloudFront
	hd.patterns["AWS CloudFront"] = []HostingPattern{
		{Pattern: `cloudfront\.net`, Confidence: 0.95, Description: "AWS CloudFront domain (DNS)", Type: "cloud"},
		{Pattern: `cloudfront`, Confidence: 0.8, Description: "AWS CloudFront (headers)", Type: "cloud"},
	}

	// AWS ELB
	hd.patterns["AWS ELB"] = []HostingPattern{
		{Pattern: `elb\.amazonaws\.com`, Confidence: 0.95, Description: "AWS ELB domain (DNS)", Type: "cloud"},
		{Pattern: `elb`, Confidence: 0.8, Description: "AWS ELB (headers)", Type: "cloud"},
	}

	// Google Cloud
	hd.patterns["Google Cloud"] = []HostingPattern{
		{Pattern: `googleusercontent\.com`, Confidence: 0.95, Description: "Google Cloud domain (DNS)", Type: "cloud"},
		{Pattern: `googleapis\.com`, Confidence: 0.9, Description: "Google APIs (DNS)", Type: "cloud"},
		{Pattern: `google\.com`, Confidence: 0.7, Description: "Google domain (DNS)", Type: "cloud"},
	}

	// Azure
	hd.patterns["Azure"] = []HostingPattern{
		{Pattern: `azurewebsites\.net`, Confidence: 0.95, Description: "Azure Web Apps (DNS)", Type: "cloud"},
		{Pattern: `cloudapp\.net`, Confidence: 0.9, Description: "Azure Cloud Services (DNS)", Type: "cloud"},
		{Pattern: `azure\.com`, Confidence: 0.8, Description: "Azure domain (DNS)", Type: "cloud"},
	}

	// DigitalOcean
	hd.patterns["DigitalOcean"] = []HostingPattern{
		{Pattern: `digitalocean\.com`, Confidence: 0.95, Description: "DigitalOcean domain (DNS)", Type: "cloud"},
		{Pattern: `digitalocean`, Confidence: 0.8, Description: "DigitalOcean platform (headers)", Type: "cloud"},
	}

	// Cloudflare
	hd.patterns["Cloudflare"] = []HostingPattern{
		{Pattern: `cloudflare\.com`, Confidence: 0.95, Description: "Cloudflare domain (DNS)", Type: "cdn"},
		{Pattern: `cloudflare`, Confidence: 0.8, Description: "Cloudflare platform (headers)", Type: "cdn"},
	}

	// HostGator
	hd.patterns["HostGator"] = []HostingPattern{
		{Pattern: `hostgator\.com`, Confidence: 0.95, Description: "HostGator domain (DNS)", Type: "shared"},
		{Pattern: `hostgator`, Confidence: 0.8, Description: "HostGator platform (headers)", Type: "shared"},
	}

	// Hostinger
	hd.patterns["Hostinger"] = []HostingPattern{
		{Pattern: `hostinger\.com`, Confidence: 0.95, Description: "Hostinger domain (DNS)", Type: "shared"},
		{Pattern: `hostinger`, Confidence: 0.8, Description: "Hostinger platform (headers)", Type: "shared"},
	}

	// Bluehost
	hd.patterns["Bluehost"] = []HostingPattern{
		{Pattern: `bluehost\.com`, Confidence: 0.95, Description: "Bluehost domain (DNS)", Type: "shared"},
		{Pattern: `bluehost`, Confidence: 0.8, Description: "Bluehost platform (headers)", Type: "shared"},
	}

	// GoDaddy
	hd.patterns["GoDaddy"] = []HostingPattern{
		{Pattern: `godaddy\.com`, Confidence: 0.95, Description: "GoDaddy domain (DNS)", Type: "shared"},
		{Pattern: `godaddy`, Confidence: 0.8, Description: "GoDaddy platform (headers)", Type: "shared"},
	}

	// Namecheap
	hd.patterns["Namecheap"] = []HostingPattern{
		{Pattern: `namecheap\.com`, Confidence: 0.95, Description: "Namecheap domain (DNS)", Type: "shared"},
		{Pattern: `namecheap`, Confidence: 0.8, Description: "Namecheap platform", Type: "shared"},
	}

	// DreamHost
	hd.patterns["DreamHost"] = []HostingPattern{
		{Pattern: `dreamhost\.com`, Confidence: 0.95, Description: "DreamHost domain", Type: "shared"},
		{Pattern: `dreamhost`, Confidence: 0.8, Description: "DreamHost platform", Type: "shared"},
	}

	// SiteGround
	hd.patterns["SiteGround"] = []HostingPattern{
		{Pattern: `siteground\.com`, Confidence: 0.95, Description: "SiteGround domain", Type: "shared"},
		{Pattern: `siteground`, Confidence: 0.8, Description: "SiteGround platform", Type: "shared"},
	}

	// InMotion
	hd.patterns["InMotion"] = []HostingPattern{
		{Pattern: `inmotionhosting\.com`, Confidence: 0.95, Description: "InMotion domain", Type: "shared"},
		{Pattern: `inmotion`, Confidence: 0.8, Description: "InMotion platform", Type: "shared"},
	}

	// A2 Hosting
	hd.patterns["A2 Hosting"] = []HostingPattern{
		{Pattern: `a2hosting\.com`, Confidence: 0.95, Description: "A2 Hosting domain", Type: "shared"},
		{Pattern: `a2hosting`, Confidence: 0.8, Description: "A2 Hosting platform", Type: "shared"},
	}

	// GreenGeeks
	hd.patterns["GreenGeeks"] = []HostingPattern{
		{Pattern: `greengeeks\.com`, Confidence: 0.95, Description: "GreenGeeks domain", Type: "shared"},
		{Pattern: `greengeeks`, Confidence: 0.8, Description: "GreenGeeks platform", Type: "shared"},
	}

	// WP Engine
	hd.patterns["WP Engine"] = []HostingPattern{
		{Pattern: `wpengine\.com`, Confidence: 0.95, Description: "WP Engine domain", Type: "managed"},
		{Pattern: `wpengine`, Confidence: 0.8, Description: "WP Engine platform", Type: "managed"},
	}

	// Kinsta
	hd.patterns["Kinsta"] = []HostingPattern{
		{Pattern: `kinsta\.com`, Confidence: 0.95, Description: "Kinsta domain", Type: "managed"},
		{Pattern: `kinsta`, Confidence: 0.8, Description: "Kinsta platform", Type: "managed"},
	}

	// Flywheel
	hd.patterns["Flywheel"] = []HostingPattern{
		{Pattern: `getflywheel\.com`, Confidence: 0.95, Description: "Flywheel domain", Type: "managed"},
		{Pattern: `flywheel`, Confidence: 0.8, Description: "Flywheel platform", Type: "managed"},
	}

	// Pantheon
	hd.patterns["Pantheon"] = []HostingPattern{
		{Pattern: `pantheon\.io`, Confidence: 0.95, Description: "Pantheon domain", Type: "managed"},
		{Pattern: `pantheon`, Confidence: 0.8, Description: "Pantheon platform", Type: "managed"},
	}

	// Platform.sh
	hd.patterns["Platform.sh"] = []HostingPattern{
		{Pattern: `platform\.sh`, Confidence: 0.95, Description: "Platform.sh domain", Type: "managed"},
		{Pattern: `platformsh`, Confidence: 0.8, Description: "Platform.sh platform", Type: "managed"},
	}

	// Compilar regex patterns
	for provider, patterns := range hd.patterns {
		for i := range patterns {
			hd.patterns[provider][i].Regex = regexp.MustCompile(hd.patterns[provider][i].Pattern)
		}
	}
}
