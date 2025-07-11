package http

import (
	"time"
)

type HTTPInfo struct {
	URL             string            `json:"url"`
	Status          int               `json:"status"`
	StatusText      string            `json:"status_text"`
	Headers         map[string]string `json:"headers"`
	BodyLength      int               `json:"body_length"`
	Title           string            `json:"title"`
	FaviconHash     string            `json:"favicon_hash"`
	Technologies    []Technology      `json:"technologies"`
	Hosting         *HostingInfo      `json:"hosting"`
	RedirectChain   []RedirectInfo    `json:"redirect_chain"`
	Traceroute      []HopInfo         `json:"traceroute"`
	ResponseTime    time.Duration     `json:"response_time"`
	ContentType     string            `json:"content_type"`
	Server          string            `json:"server"`
	PoweredBy       string            `json:"powered_by"`
	SecurityHeaders SecurityHeaders   `json:"security_headers"`
	Cookies         []CookieInfo      `json:"cookies"`
	RobotsTxt       string            `json:"robots_txt"`
	Sitemap         string            `json:"sitemap"`
	WAF             string            `json:"waf"`
	CDN             string            `json:"cdn"`
	CloudProvider   string            `json:"cloud_provider"`
	Framework       string            `json:"framework"`
	Language        string            `json:"language"`
	Database        string            `json:"database"`
	OS              string            `json:"os"`
	Errors          []string          `json:"errors"`
	IsLive          bool              `json:"is_live"`
	IsRedirect      bool              `json:"is_redirect"`
	IsError         bool              `json:"is_error"`
	IsTimeout       bool              `json:"is_timeout"`
}

type Technology struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Category    string  `json:"category"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Website     string  `json:"website"`
}

type RedirectInfo struct {
	URL          string            `json:"url"`
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	ResponseTime time.Duration     `json:"response_time"`
	Location     string            `json:"location"`
}

type HopInfo struct {
	Hop         int     `json:"hop"`
	IP          string  `json:"ip"`
	Hostname    string  `json:"hostname"`
	RTT         float64 `json:"rtt_ms"`
	TTL         int     `json:"ttl"`
	IsReachable bool    `json:"is_reachable"`
	ASN         string  `json:"asn"`
	Country     string  `json:"country"`
	ISP         string  `json:"isp"`
}

type SecurityHeaders struct {
	ContentSecurityPolicy     string `json:"content_security_policy"`
	XFrameOptions             string `json:"x_frame_options"`
	XContentTypeOptions       string `json:"x_content_type_options"`
	XSSProtection             string `json:"xss_protection"`
	StrictTransportSecurity   string `json:"strict_transport_security"`
	ReferrerPolicy            string `json:"referrer_policy"`
	PermissionsPolicy         string `json:"permissions_policy"`
	CrossOriginEmbedderPolicy string `json:"cross_origin_embedder_policy"`
	CrossOriginOpenerPolicy   string `json:"cross_origin_opener_policy"`
	CrossOriginResourcePolicy string `json:"cross_origin_resource_policy"`
}

type CookieInfo struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
}

type HTTPConfig struct {
	Timeout          time.Duration     `json:"timeout"`
	Threads          int               `json:"threads"`
	UserAgent        string            `json:"user_agent"`
	FollowRedirects  bool              `json:"follow_redirects"`
	MaxRedirects     int               `json:"max_redirects"`
	EnableTraceroute bool              `json:"enable_traceroute"`
	EnableTechDetect bool              `json:"enable_tech_detect"`
	EnableFavicon    bool              `json:"enable_favicon"`
	EnableRobotsTxt  bool              `json:"enable_robots_txt"`
	EnableSitemap    bool              `json:"enable_sitemap"`
	VerifySSL        bool              `json:"verify_ssl"`
	Headers          map[string]string `json:"headers"`
	Proxy            string            `json:"proxy"`
}

func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:          10 * time.Second,
		Threads:          50,
		UserAgent:        "Argus/1.0 (Security Scanner)",
		FollowRedirects:  true,
		MaxRedirects:     10,
		EnableTraceroute: true,
		EnableTechDetect: true,
		EnableFavicon:    true,
		EnableRobotsTxt:  true,
		EnableSitemap:    true,
		VerifySSL:        false,
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
		},
	}
}

type TechnologyCategory string

const (
	CategoryWebServer   TechnologyCategory = "web_server"
	CategoryFramework   TechnologyCategory = "framework"
	CategoryLanguage    TechnologyCategory = "language"
	CategoryDatabase    TechnologyCategory = "database"
	CategoryCMS         TechnologyCategory = "cms"
	CategoryCDN         TechnologyCategory = "cdn"
	CategoryWAF         TechnologyCategory = "waf"
	CategoryOS          TechnologyCategory = "os"
	CategoryCloud       TechnologyCategory = "cloud"
	CategoryAnalytics   TechnologyCategory = "analytics"
	CategoryAdvertising TechnologyCategory = "advertising"
	CategoryMonitoring  TechnologyCategory = "monitoring"
	CategorySecurity    TechnologyCategory = "security"
	CategoryJavaScript  TechnologyCategory = "javascript"
	CategoryCSS         TechnologyCategory = "css"
	CategoryFont        TechnologyCategory = "font"
	CategoryOther       TechnologyCategory = "other"
)
