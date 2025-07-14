package http

import (
	"net/http"
	"strings"
)

type HeaderAnalyzer struct{}

func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

func (ha *HeaderAnalyzer) AnalyzeHeaders(headers http.Header, httpInfo *HTTPInfo) {
	for key, values := range headers {
		if len(values) > 0 {
			httpInfo.Headers[key] = values[0]
		}
	}

	httpInfo.SecurityHeaders.ContentSecurityPolicy = headers.Get("Content-Security-Policy")
	httpInfo.SecurityHeaders.XFrameOptions = headers.Get("X-Frame-Options")
	httpInfo.SecurityHeaders.XContentTypeOptions = headers.Get("X-Content-Type-Options")
	httpInfo.SecurityHeaders.XSSProtection = headers.Get("X-XSS-Protection")
	httpInfo.SecurityHeaders.StrictTransportSecurity = headers.Get("Strict-Transport-Security")
	httpInfo.SecurityHeaders.ReferrerPolicy = headers.Get("Referrer-Policy")
	httpInfo.SecurityHeaders.PermissionsPolicy = headers.Get("Permissions-Policy")
	httpInfo.SecurityHeaders.CrossOriginEmbedderPolicy = headers.Get("Cross-Origin-Embedder-Policy")
	httpInfo.SecurityHeaders.CrossOriginOpenerPolicy = headers.Get("Cross-Origin-Opener-Policy")
	httpInfo.SecurityHeaders.CrossOriginResourcePolicy = headers.Get("Cross-Origin-Resource-Policy")

	httpInfo.WAF = ha.detectWAF(headers)
	httpInfo.CDN = ha.detectCDN(headers)
	httpInfo.CloudProvider = ha.detectCloudProvider(headers)

	dnsInfo := ha.extractDNSFromHeaders(headers)
	if len(dnsInfo) > 0 {
		for key, values := range dnsInfo {
			httpInfo.Headers[key] = strings.Join(values, ", ")
		}
	}
}

func (ha *HeaderAnalyzer) detectWAF(headers http.Header) string {
	wafSignatures := map[string][]string{
		"Cloudflare": {
			"cf-ray", "cf-cache-status", "cf-request-id", "cf-visitor",
			"server", "x-powered-by",
		},
		"AWS WAF": {
			"x-amzn-waf", "x-amz-cf-id", "x-amz-cf-pop",
		},
		"Imperva": {
			"x-iinfo", "x-cdn", "incap_ses", "visid_incap",
		},
		"Akamai": {
			"x-akamai-transformed", "x-akamai-origin-hop",
		},
		"Fastly": {
			"x-fastly", "x-cache", "x-cache-hits",
		},
		"F5 BIG-IP": {
			"x-wa-info", "x-asg", "x-aws-waf",
		},
		"Barracuda": {
			"barra_counter_session", "barra_counter_id",
		},
		"Citrix NetScaler": {
			"ns-cache", "ns-route", "ns-timing",
		},
		"Palo Alto": {
			"x-pan-http", "x-pan-request-id",
		},
		"Fortinet": {
			"x-fortinet", "x-fortigate",
		},
	}

	for waf, signatures := range wafSignatures {
		for _, sig := range signatures {
			if headers.Get(sig) != "" {
				return waf
			}
		}
	}

	return ""
}

func (ha *HeaderAnalyzer) detectCDN(headers http.Header) string {
	cdnSignatures := map[string][]string{
		"Cloudflare": {
			"cf-ray", "cf-cache-status", "cf-request-id",
		},
		"Akamai": {
			"x-akamai-transformed", "x-akamai-origin-hop",
		},
		"Fastly": {
			"x-fastly", "x-cache", "x-cache-hits",
		},
		"Amazon CloudFront": {
			"x-amz-cf-id", "x-amz-cf-pop", "x-cache",
		},
		"Google Cloud CDN": {
			"x-goog-generation", "x-goog-metageneration",
		},
		"Azure CDN": {
			"x-azure-ref", "x-azure-ref-originshield",
		},
		"Bunny CDN": {
			"x-bunnycdn", "x-bunnycdn-cache",
		},
		"KeyCDN": {
			"x-cdn", "x-cache-status",
		},
	}

	for cdn, signatures := range cdnSignatures {
		for _, sig := range signatures {
			if headers.Get(sig) != "" {
				return cdn
			}
		}
	}

	return ""
}

func (ha *HeaderAnalyzer) detectCloudProvider(headers http.Header) string {
	cloudSignatures := map[string][]string{
		"AWS": {
			"x-amz-cf-id", "x-amz-cf-pop", "x-amz-id-2",
			"x-amz-request-id", "x-amz-version-id", "x-lambda-id",
		},
		"Google Cloud": {
			"x-goog-generation", "x-goog-metageneration",
			"x-goog-storage-class", "x-goog-hash",
		},
		"Azure": {
			"x-azure-ref", "x-azure-ref-originshield",
			"x-ms-version", "x-ms-request-id",
		},
		"DigitalOcean": {
			"x-do-orig-status", "x-do-orig-size",
		},
		"Heroku": {
			"x-request-id", "x-runtime", "x-powered-by",
		},
		"Vercel": {
			"x-vercel-cache", "x-vercel-id",
		},
		"Netlify": {
			"x-nf-request-id", "x-nf-cache-status",
		},
	}

	for provider, signatures := range cloudSignatures {
		for _, sig := range signatures {
			if headers.Get(sig) != "" {
				return provider
			}
		}
	}

	return ""
}

func (ha *HeaderAnalyzer) extractDNSFromHeaders(headers http.Header) map[string][]string {
	dnsInfo := make(map[string][]string)

	dnsHeaders := []string{
		"x-dns-prefetch-control",
		"x-forwarded-host",
		"x-host",
		"x-original-host",
		"x-real-ip",
		"x-forwarded-for",
		"x-forwarded-proto",
		"x-forwarded-server",
		"x-forwarded-port",
	}

	for _, header := range dnsHeaders {
		if value := headers.Get(header); value != "" {
			dnsInfo[header] = []string{value}
		}
	}

	return dnsInfo
}
