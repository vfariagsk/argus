package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CTLogsDiscovery struct {
	client *http.Client
}

func NewCTLogsDiscovery(timeout time.Duration) *CTLogsDiscovery {
	return &CTLogsDiscovery{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (ct *CTLogsDiscovery) Name() string {
	return "Certificate Transparency Logs"
}

func (ct *CTLogsDiscovery) Discover(domain string, config DiscoveryConfig) ([]Subdomain, error) {
	var subdomains []Subdomain

	ctResults, err := ct.queryCrtShWithRetry(domain, config.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query failed: %w", err)
	}

	censysResults, err := ct.queryCensysWithRetry(domain, config.UserAgent)
	if err != nil {
		fmt.Printf("Warning: Censys query failed: %v\n", err)
	}

	seen := make(map[string]bool)

	for _, sub := range ctResults {
		if !seen[sub.Host] {
			subdomains = append(subdomains, sub)
			seen[sub.Host] = true
		}
	}

	for _, sub := range censysResults {
		if !seen[sub.Host] {
			subdomains = append(subdomains, sub)
			seen[sub.Host] = true
		}
	}

	return subdomains, nil
}

func (ct *CTLogsDiscovery) queryCrtShWithRetry(domain string, userAgent string) ([]Subdomain, error) {
	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		results, err := ct.queryCrtSh(domain, userAgent)
		if err == nil {
			return results, nil
		}

		if attempt == maxRetries {
			return nil, fmt.Errorf("crt.sh query failed after %d attempts: %w", maxRetries+1, err)
		}

		delay := baseDelay * time.Duration(1<<attempt)
		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
		totalDelay := delay + jitter

		fmt.Printf("Retrying crt.sh query in %v (attempt %d/%d): %v\n", totalDelay, attempt+1, maxRetries, err)
		time.Sleep(totalDelay)
	}

	return nil, fmt.Errorf("unexpected error in retry loop")
}

func (ct *CTLogsDiscovery) queryCensysWithRetry(domain string, userAgent string) ([]Subdomain, error) {
	maxRetries := 3
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		results, err := ct.queryCensys(domain, userAgent)
		if err == nil {
			return results, nil
		}

		if attempt == maxRetries {
			return nil, fmt.Errorf("censys query failed after %d attempts: %w", maxRetries+1, err)
		}

		delay := baseDelay * time.Duration(1<<attempt)
		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
		totalDelay := delay + jitter

		fmt.Printf("Retrying censys query in %v (attempt %d/%d)\n", totalDelay, attempt+1, maxRetries)
		time.Sleep(totalDelay)
	}

	return nil, fmt.Errorf("unexpected error in retry loop")
}

func (ct *CTLogsDiscovery) queryCrtSh(domain string, userAgent string) ([]Subdomain, error) {
	baseURL := "https://crt.sh/"
	params := url.Values{}
	params.Add("q", "%."+domain)
	params.Add("output", "json")

	req, err := http.NewRequest("GET", baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := ct.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
		Issuer    string `json:"issuer_name"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	var subdomains []Subdomain
	seen := make(map[string]bool)

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || name == domain {
				continue
			}

			if strings.HasSuffix(name, "."+domain) || name == domain {
				if !seen[name] {
					subdomains = append(subdomains, Subdomain{
						Host:         name,
						Source:       "crt.sh",
						DiscoveredAt: time.Now(),
						Metadata: map[string]string{
							"issuer":     entry.Issuer,
							"not_before": entry.NotBefore,
							"not_after":  entry.NotAfter,
						},
					})
					seen[name] = true
				}
			}
		}
	}

	return subdomains, nil
}

func (ct *CTLogsDiscovery) queryCensys(domain string, userAgent string) ([]Subdomain, error) {
	apiURL := fmt.Sprintf("https://search.censys.io/api/v2/certificates/search?q=%s", url.QueryEscape(domain))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := ct.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return []Subdomain{}, nil
}
