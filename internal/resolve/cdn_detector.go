package resolve

import (
	"net/http"
	"strings"
)

type CDNDetector struct {
	providers map[string]CDNProvider
}

func NewCDNDetector() *CDNDetector {
	detector := &CDNDetector{
		providers: make(map[string]CDNProvider),
	}

	detector.initProviders()
	return detector
}

func (cd *CDNDetector) Detect(ip string) string {
	for providerName, provider := range cd.providers {
		for _, pattern := range provider.Patterns {
			if strings.Contains(ip, pattern) {
				return providerName
			}
		}
	}

	return ""
}

func (cd *CDNDetector) DetectByHeaders(headers http.Header) string {
	for providerName, provider := range cd.providers {
		for _, header := range provider.Headers {
			if headers.Get(header) != "" {
				return providerName
			}
		}
	}

	return ""
}

func (cd *CDNDetector) DetectByCNAME(cname string) string {
	cname = strings.ToLower(cname)

	for providerName, provider := range cd.providers {
		for _, pattern := range provider.Patterns {
			if strings.Contains(cname, pattern) {
				return providerName
			}
		}
	}

	return ""
}

func (cd *CDNDetector) initProviders() {
	cd.providers = map[string]CDNProvider{
		"Cloudflare": {
			Name: "Cloudflare",
			Patterns: []string{
				"cloudflare.com",
				"cloudflare",
				"cf-",
			},
			Headers: []string{
				"CF-RAY",
				"CF-Cache-Status",
				"CF-Request-ID",
			},
		},
		"Akamai": {
			Name: "Akamai",
			Patterns: []string{
				"akamai.net",
				"akamaihd.net",
				"akamaized.net",
				"akamai",
			},
			Headers: []string{
				"X-Akamai-Transform",
				"X-Akamai-Origin-Hop",
			},
		},
		"Fastly": {
			Name: "Fastly",
			Patterns: []string{
				"fastly.net",
				"fastly",
			},
			Headers: []string{
				"X-Fastly",
				"Fastly-Client-IP",
			},
		},
		"Amazon CloudFront": {
			Name: "Amazon CloudFront",
			Patterns: []string{
				"cloudfront.net",
				"cloudfront",
			},
			Headers: []string{
				"X-Amz-Cf-Id",
				"X-Amz-Cf-Pop",
			},
		},
		"Google Cloud CDN": {
			Name: "Google Cloud CDN",
			Patterns: []string{
				"googleusercontent.com",
				"googleapis.com",
				"gstatic.com",
			},
			Headers: []string{
				"X-Cloud-Trace-Context",
			},
		},
		"Azure CDN": {
			Name: "Azure CDN",
			Patterns: []string{
				"azureedge.net",
				"azure",
			},
			Headers: []string{
				"X-Azure-Ref",
			},
		},
		"Bunny CDN": {
			Name: "Bunny CDN",
			Patterns: []string{
				"b-cdn.net",
				"bunnycdn",
			},
			Headers: []string{
				"X-Bunny-Cache",
			},
		},
		"StackPath": {
			Name: "StackPath",
			Patterns: []string{
				"stackpathdns.com",
				"stackpath",
			},
			Headers: []string{
				"X-SP-Cache",
			},
		},
		"KeyCDN": {
			Name: "KeyCDN",
			Patterns: []string{
				"kxcdn.com",
				"keycdn",
			},
			Headers: []string{
				"X-Cache",
			},
		},
		"CDN77": {
			Name: "CDN77",
			Patterns: []string{
				"cdn77.org",
				"cdn77",
			},
			Headers: []string{
				"X-CDN77-Country",
			},
		},
		"Limelight": {
			Name: "Limelight",
			Patterns: []string{
				"llnwd.net",
				"limelight",
			},
			Headers: []string{
				"X-Limelight-Edge",
			},
		},
		"MaxCDN": {
			Name: "MaxCDN",
			Patterns: []string{
				"netdna-cdn.com",
				"maxcdn",
			},
			Headers: []string{
				"X-Cache",
			},
		},
		"Incapsula": {
			Name: "Incapsula",
			Patterns: []string{
				"incapdns.net",
				"incapsula",
			},
			Headers: []string{
				"X-Iinfo",
				"X-Cdn",
			},
		},
		"Imperva": {
			Name: "Imperva",
			Patterns: []string{
				"imperva.com",
				"imperva",
			},
			Headers: []string{
				"X-Iinfo",
			},
		},
		"CloudFlare Enterprise": {
			Name: "CloudFlare Enterprise",
			Patterns: []string{
				"cloudflare.com",
				"cloudflare",
			},
			Headers: []string{
				"CF-Enterprise",
			},
		},
		"EdgeCast": {
			Name: "EdgeCast",
			Patterns: []string{
				"edgecastcdn.net",
				"edgecast",
			},
			Headers: []string{
				"X-EC",
			},
		},
		"Level 3": {
			Name: "Level 3",
			Patterns: []string{
				"level3.net",
				"level3",
			},
			Headers: []string{
				"X-Level3",
			},
		},
		"CacheFly": {
			Name: "CacheFly",
			Patterns: []string{
				"cachefly.net",
				"cachefly",
			},
			Headers: []string{
				"X-Cache",
			},
		},
		"Highwinds": {
			Name: "Highwinds",
			Patterns: []string{
				"hwcdn.net",
				"highwinds",
			},
			Headers: []string{
				"X-HW",
			},
		},
		"CDNetworks": {
			Name: "CDNetworks",
			Patterns: []string{
				"cdngc.net",
				"cdnetworks",
			},
			Headers: []string{
				"X-CDN",
			},
		},
		"ChinaCache": {
			Name: "ChinaCache",
			Patterns: []string{
				"chinacache.com",
				"chinacache",
			},
			Headers: []string{
				"X-Cache",
			},
		},
		"Alibaba Cloud CDN": {
			Name: "Alibaba Cloud CDN",
			Patterns: []string{
				"alicdn.com",
				"alibaba",
			},
			Headers: []string{
				"X-Cache",
			},
		},
		"Tencent Cloud CDN": {
			Name: "Tencent Cloud CDN",
			Patterns: []string{
				"qcloud.com",
				"tencent",
			},
			Headers: []string{
				"X-Cache",
			},
		},
	}
}
