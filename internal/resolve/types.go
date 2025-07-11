package resolve

import (
	"crypto/x509"
	"time"
)

type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type IPInfo struct {
	IP            string            `json:"ip"`
	Type          string            `json:"type"` // A, AAAA
	Country       string            `json:"country,omitempty"`
	City          string            `json:"city,omitempty"`
	ISP           string            `json:"isp,omitempty"`
	ASN           string            `json:"asn,omitempty"`
	ASName        string            `json:"as_name,omitempty"`
	Lat           float64           `json:"lat,omitempty"`
	Long          float64           `json:"long,omitempty"`
	IsPublic      bool              `json:"is_public"`
	IsCDN         bool              `json:"is_cdn"`
	CDNProvider   string            `json:"cdn_provider,omitempty"`
	IsCloud       bool              `json:"is_cloud"`
	CloudProvider string            `json:"cloud_provider,omitempty"`
	Hosting       string            `json:"hosting,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type TLSInfo struct {
	Enabled            bool      `json:"enabled"`
	Version            string    `json:"version,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	Subject            string    `json:"subject,omitempty"`
	ValidFrom          time.Time `json:"valid_from,omitempty"`
	ValidTo            time.Time `json:"valid_to,omitempty"`
	SelfSigned         bool      `json:"self_signed"`
	Expired            bool      `json:"expired"`
	Mismatch           bool      `json:"mismatch"`
	SANs               []string  `json:"sans,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	KeySize            int       `json:"key_size,omitempty"`
	KeyType            string    `json:"key_type,omitempty"`
	Errors             []string  `json:"errors,omitempty"`

	SupportedVersions []string `json:"supported_versions,omitempty"`
	SupportedCiphers  []string `json:"supported_ciphers,omitempty"`
	PreferredCipher   string   `json:"preferred_cipher,omitempty"`
	SupportedCurves   []string `json:"supported_curves,omitempty"`
	PreferredCurve    string   `json:"preferred_curve,omitempty"`

	WeakCiphers        []string `json:"weak_ciphers,omitempty"`
	DeprecatedVersions []string `json:"deprecated_versions,omitempty"`

	SecurityHeaders map[string]string `json:"security_headers,omitempty"`

	CertificateChain []string `json:"certificate_chain,omitempty"`
	OCSPStapling     bool     `json:"ocsp_stapling"`
	HSTS             bool     `json:"hsts"`
	HPKP             bool     `json:"hpkp"`

	RiskScore   int      `json:"risk_score,omitempty"`
	RiskFactors []string `json:"risk_factors,omitempty"`
}

type LoadBalancerInfo struct {
	Detected    bool     `json:"detected"`
	Type        string   `json:"type,omitempty"` // round-robin, geo, etc.
	IPs         []string `json:"ips,omitempty"`
	Provider    string   `json:"provider,omitempty"`
	HealthCheck bool     `json:"health_check"`
}

type DNSResolutionResult struct {
	Host            string                 `json:"host"`
	Resolved        bool                   `json:"resolved"`
	Records         map[string][]DNSRecord `json:"records"`
	IPs             []IPInfo               `json:"ips"`
	TLS             TLSInfo                `json:"tls"`
	LoadBalancer    LoadBalancerInfo       `json:"load_balancer"`
	TakeoverRisk    bool                   `json:"takeover_risk"`
	TakeoverDetails string                 `json:"takeover_details,omitempty"`
	Wildcard        bool                   `json:"wildcard"`
	Parked          bool                   `json:"parked"`
	ResolvedAt      time.Time              `json:"resolved_at"`
	Errors          []string               `json:"errors,omitempty"`
}

type DNSConfig struct {
	Timeout             time.Duration `json:"timeout"`
	Threads             int           `json:"threads"`
	EnableTLS           bool          `json:"enable_tls"`
	EnableGeoIP         bool          `json:"enable_geoip"`
	EnableCDNDetection  bool          `json:"enable_cdn_detection"`
	EnableTakeoverCheck bool          `json:"enable_takeover_check"`
	EnableWildcardCheck bool          `json:"enable_wildcard_check"`
	UserAgent           string        `json:"user_agent"`
	Nameservers         []string      `json:"nameservers"`
	IPGeoLocationKey    string        `json:"ip_geo_location_key"`
}

func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		Timeout:             10 * time.Second,
		Threads:             50,
		EnableTLS:           true,
		EnableGeoIP:         true,
		EnableCDNDetection:  true,
		EnableTakeoverCheck: true,
		EnableWildcardCheck: true,
		UserAgent:           "Argus/1.0 (Cybersecurity)",
		Nameservers:         []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"},
	}
}

type Certificate struct {
	Raw                []byte
	Certificate        *x509.Certificate
	Chain              []*x509.Certificate
	Verified           bool
	VerificationErrors []error
}

type CDNProvider struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	Headers  []string `json:"headers,omitempty"`
	IPRanges []string `json:"ip_ranges,omitempty"`
}

type CloudProvider struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	IPRanges []string `json:"ip_ranges,omitempty"`
	Headers  []string `json:"headers,omitempty"`
}

type TakeoverPattern struct {
	Provider    string `json:"provider"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}
