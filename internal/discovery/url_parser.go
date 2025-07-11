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
)

type URLParserDiscovery struct {
	client *http.Client
}

func NewURLParserDiscovery(timeout time.Duration) *URLParserDiscovery {
	return &URLParserDiscovery{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (up *URLParserDiscovery) Name() string {
	return "URL Parsing"
}

func (up *URLParserDiscovery) Discover(domain string, config DiscoveryConfig) ([]Subdomain, error) {
	var allSubdomains []Subdomain
	seen := make(map[string]bool)

	baseURLs := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("http://%s", domain),
	}

	for _, baseURL := range baseURLs {
		if robotsResults, err := up.parseRobotsTxt(baseURL, domain, config.UserAgent); err == nil {
			for _, sub := range robotsResults {
				if !seen[sub.Host] {
					allSubdomains = append(allSubdomains, sub)
					seen[sub.Host] = true
				}
			}
		}

		if sitemapResults, err := up.parseSitemap(baseURL, domain, config.UserAgent); err == nil {
			for _, sub := range sitemapResults {
				if !seen[sub.Host] {
					allSubdomains = append(allSubdomains, sub)
					seen[sub.Host] = true
				}
			}
		}

		if jsResults, err := up.parseJavaScript(baseURL, domain, config.UserAgent); err == nil {
			for _, sub := range jsResults {
				if !seen[sub.Host] {
					allSubdomains = append(allSubdomains, sub)
					seen[sub.Host] = true
				}
			}
		}

		if htmlResults, err := up.parseHTML(baseURL, domain, config.UserAgent); err == nil {
			for _, sub := range htmlResults {
				if !seen[sub.Host] {
					allSubdomains = append(allSubdomains, sub)
					seen[sub.Host] = true
				}
			}
		}
	}

	return allSubdomains, nil
}

func (up *URLParserDiscovery) parseRobotsTxt(baseURL, domain string, userAgent string) ([]Subdomain, error) {
	robotsURL := fmt.Sprintf("%s/robots.txt", baseURL)

	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := up.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("robots.txt not found or accessible")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return up.extractSubdomainsFromText(string(body), domain, "robots.txt"), nil
}

func (up *URLParserDiscovery) parseSitemap(baseURL, domain string, userAgent string) ([]Subdomain, error) {
	sitemapURL := fmt.Sprintf("%s/sitemap.xml", baseURL)

	req, err := http.NewRequest("GET", sitemapURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := up.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sitemap.xml not found or accessible")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return up.extractSubdomainsFromText(string(body), domain, "sitemap.xml"), nil
}

func (up *URLParserDiscovery) parseJavaScript(baseURL, domain string, userAgent string) ([]Subdomain, error) {
	jsPaths := []string{
		"/js/",
		"/assets/js/",
		"/static/js/",
		"/scripts/",
		"/assets/",
		"/static/",
	}

	var allSubdomains []Subdomain

	for _, path := range jsPaths {
		jsURL := fmt.Sprintf("%s%s", baseURL, path)

		req, err := http.NewRequest("GET", jsURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", userAgent)

		resp, err := up.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			subdomains := up.extractSubdomainsFromText(string(body), domain, "javascript")
			allSubdomains = append(allSubdomains, subdomains...)
		}
	}

	return allSubdomains, nil
}

func (up *URLParserDiscovery) parseHTML(baseURL, domain string, userAgent string) ([]Subdomain, error) {
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := up.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("main page not accessible")
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	var subdomains []Subdomain

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if subdomain := up.extractSubdomainFromURL(href, domain); subdomain != "" {
				subdomains = append(subdomains, Subdomain{
					Host:         subdomain,
					Source:       "html_links",
					DiscoveredAt: time.Now(),
				})
			}
		}
	})

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			if subdomain := up.extractSubdomainFromURL(src, domain); subdomain != "" {
				subdomains = append(subdomains, Subdomain{
					Host:         subdomain,
					Source:       "html_scripts",
					DiscoveredAt: time.Now(),
				})
			}
		}
	})

	doc.Find("img[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			if subdomain := up.extractSubdomainFromURL(src, domain); subdomain != "" {
				subdomains = append(subdomains, Subdomain{
					Host:         subdomain,
					Source:       "html_images",
					DiscoveredAt: time.Now(),
				})
			}
		}
	})

	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if subdomain := up.extractSubdomainFromURL(href, domain); subdomain != "" {
				subdomains = append(subdomains, Subdomain{
					Host:         subdomain,
					Source:       "html_css",
					DiscoveredAt: time.Now(),
				})
			}
		}
	})

	return subdomains, nil
}

func (up *URLParserDiscovery) extractSubdomainsFromText(text, domain, source string) []Subdomain {
	var subdomains []Subdomain
	seen := make(map[string]bool)

	urlRegex := regexp.MustCompile(`https?://([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(domain))
	matches := urlRegex.FindAllString(text, -1)

	for _, match := range matches {
		if subdomain := up.extractSubdomainFromURL(match, domain); subdomain != "" && !seen[subdomain] {
			subdomains = append(subdomains, Subdomain{
				Host:         subdomain,
				Source:       source,
				DiscoveredAt: time.Now(),
			})
			seen[subdomain] = true
		}
	}

	subdomainRegex := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(domain))
	subMatches := subdomainRegex.FindAllString(text, -1)

	for _, match := range subMatches {
		if !seen[match] {
			subdomains = append(subdomains, Subdomain{
				Host:         match,
				Source:       source,
				DiscoveredAt: time.Now(),
			})
			seen[match] = true
		}
	}

	return subdomains
}

func (up *URLParserDiscovery) extractSubdomainFromURL(urlStr, domain string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	host := parsedURL.Hostname()
	if host == "" {
		return ""
	}

	if strings.HasSuffix(host, "."+domain) || host == domain {
		return host
	}

	return ""
}
