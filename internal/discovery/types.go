package discovery

import (
	"os"
	"time"
)

type Subdomain struct {
	Host         string            `json:"host"`
	Source       string            `json:"source"`
	DiscoveredAt time.Time         `json:"discovered_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type DiscoveryResult struct {
	Domain     string        `json:"domain"`
	Subdomains []Subdomain   `json:"subdomains"`
	Total      int           `json:"total"`
	Duration   time.Duration `json:"duration"`
	Errors     []string      `json:"errors,omitempty"`
}

type DiscoveryConfig struct {
	Domain            string        `json:"domain"`
	Threads           int           `json:"threads"`
	Timeout           time.Duration `json:"timeout"`
	WordlistPath      string        `json:"wordlist_path"`
	EnableCTLogs      bool          `json:"enable_ct_logs"`
	EnableBruteForce  bool          `json:"enable_brute_force"`
	EnableAPIs        bool          `json:"enable_apis"`
	EnablePassive     bool          `json:"enable_passive"`
	UserAgent         string        `json:"user_agent"`
	DNSDumpsterAPIKey string        `json:"-"`
	RapidAPIKey       string        `json:"-"`
}

type DiscoveryMethod interface {
	Name() string
	Discover(domain string, config DiscoveryConfig) ([]Subdomain, error)
}

type CTLogEntry struct {
	DomainName string `json:"domain_name"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

type PassiveSource struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"api_key,omitempty"`
}

func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		Threads:           50,
		Timeout:           10 * time.Second,
		WordlistPath:      "assets/common_subs.txt",
		EnableCTLogs:      true,
		EnableBruteForce:  true,
		EnableAPIs:        true,
		EnablePassive:     true,
		UserAgent:         "Argus/1.0 (Cybersecurity)",
		DNSDumpsterAPIKey: os.Getenv("DNS_DUMPSTER_API_KEY"),
		RapidAPIKey:       os.Getenv("RAPID_API_KEY"),
	}
}
