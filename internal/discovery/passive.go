package discovery

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/tidwall/gjson"
)

// PassiveDiscovery implementa descoberta via APIs passivas
type PassiveDiscovery struct {
	client *http.Client
}

// NewPassiveDiscovery cria uma nova instância do PassiveDiscovery
func NewPassiveDiscovery(timeout time.Duration) *PassiveDiscovery {
	return &PassiveDiscovery{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name retorna o nome do método
func (pd *PassiveDiscovery) Name() string {
	return "Passive Reconnaissance"
}

func (pd *PassiveDiscovery) Discover(domain string, config DiscoveryConfig) ([]Subdomain, error) {
	var allSubdomains []Subdomain
	seen := make(map[string]bool)

	if dnsResults, err := pd.queryDNSDumpster(domain, config.DNSDumpsterAPIKey, config.UserAgent); err == nil {
		for _, sub := range dnsResults {
			if !seen[sub.Host] {
				allSubdomains = append(allSubdomains, sub)
				seen[sub.Host] = true
			}
		}
	} else {
		fmt.Printf("Warning: DNSDumpster query failed: %v\n", err)
	}

	if rapidResults, err := pd.queryRapidDNS(domain, config.RapidAPIKey, config.UserAgent); err == nil {
		for _, sub := range rapidResults {
			if !seen[sub.Host] {
				allSubdomains = append(allSubdomains, sub)
				seen[sub.Host] = true
			}
		}
	} else {
		fmt.Printf("Warning: RapidDNS query failed: %v\n", err)
	}

	if htResults, err := pd.queryHackerTarget(domain, config.UserAgent); err == nil {
		for _, sub := range htResults {
			if !seen[sub.Host] {
				allSubdomains = append(allSubdomains, sub)
				seen[sub.Host] = true
			}
		}
	} else {
		fmt.Printf("Warning: HackerTarget query failed: %v\n", err)
	}

	// ThreatCrowd
	if tcResults, err := pd.queryThreatCrowd(domain, config.UserAgent); err == nil {
		for _, sub := range tcResults {
			if !seen[sub.Host] {
				allSubdomains = append(allSubdomains, sub)
				seen[sub.Host] = true
			}
		}
	} else {
		fmt.Printf("Warning: ThreatCrowd query failed: %v\n", err)
	}

	return allSubdomains, nil
}

func (pd *PassiveDiscovery) queryDNSDumpster(domain string, apiKey string, userAgent string) ([]Subdomain, error) {
	apiURL := fmt.Sprintf("https://api.dnsdumpster.com/domain/%s", domain)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-API-Key", apiKey)

	resp, err := pd.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	var subdomains []Subdomain
	subdomainRegex := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(domain))

	doc.Find("td").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		matches := subdomainRegex.FindAllString(text, -1)
		for _, match := range matches {
			subdomains = append(subdomains, Subdomain{
				Host:         match,
				Source:       "dnsdumpster",
				DiscoveredAt: time.Now(),
			})
		}
	})

	return subdomains, nil
}

func (pd *PassiveDiscovery) queryRapidDNS(domain string, apiKey string, userAgent string) ([]Subdomain, error) {
	apiURL := fmt.Sprintf("https://rapiddns.p.rapidapi.com/rapiddns?name=%s", url.QueryEscape(domain))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-RapidAPI-Key", apiKey)

	resp, err := pd.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := gjson.Parse(string(body))
	var subdomains []Subdomain

	result.Get("subdomains").ForEach(func(key, value gjson.Result) bool {
		subdomain := value.Get("subdomain").String()
		if subdomain != "" {
			subdomains = append(subdomains, Subdomain{
				Host:         subdomain,
				Source:       "rapiddns",
				DiscoveredAt: time.Now(),
				Metadata: map[string]string{
					"ip": value.Get("ip").String(),
				},
			})
		}
		return true
	})

	return subdomains, nil
}

func (pd *PassiveDiscovery) queryHackerTarget(domain string, userAgent string) ([]Subdomain, error) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := pd.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	var subdomains []Subdomain

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "API count exceeded") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			subdomain := strings.TrimSpace(parts[0])
			if subdomain != "" {
				subdomains = append(subdomains, Subdomain{
					Host:         subdomain,
					Source:       "hackertarget",
					DiscoveredAt: time.Now(),
					Metadata: map[string]string{
						"ip": func() string {
							if len(parts) >= 2 {
								return strings.TrimSpace(parts[1])
							}
							return ""
						}(),
					},
				})
			}
		}
	}

	return subdomains, nil
}

func (pd *PassiveDiscovery) queryThreatCrowd(domain string, userAgent string) ([]Subdomain, error) {
	apiURL := fmt.Sprintf("https://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", url.QueryEscape(domain))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := pd.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := gjson.Parse(string(body))
	var subdomains []Subdomain

	result.Get("subdomains").ForEach(func(key, value gjson.Result) bool {
		subdomain := value.String()
		if subdomain != "" {
			subdomains = append(subdomains, Subdomain{
				Host:         subdomain,
				Source:       "threatcrowd",
				DiscoveredAt: time.Now(),
			})
		}
		return true
	})

	return subdomains, nil
}
