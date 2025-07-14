package http

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type ContentExtractor struct {
	config HTTPConfig
	client *http.Client
}

func NewContentExtractor(config HTTPConfig) *ContentExtractor {
	return &ContentExtractor{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (ce *ContentExtractor) ExtractTitle(body []byte, httpInfo *HTTPInfo) {
	bodyStr := string(body)

	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(bodyStr)

	if len(matches) >= 2 {
		title := strings.TrimSpace(matches[1])
		httpInfo.Title = title
	}
}

func (ce *ContentExtractor) ExtractFavicon(baseURL string, httpInfo *HTTPInfo) {
	if !ce.config.EnableFavicon {
		return
	}

	faviconPaths := []string{
		"/favicon.ico",
		"/favicon.png",
		"/favicon.jpg",
		"/favicon.gif",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	for _, path := range faviconPaths {
		faviconURL := base.Scheme + "://" + base.Host + path
		if hash := ce.getFaviconHash(faviconURL); hash != "" {
			httpInfo.FaviconHash = hash
			break
		}
	}
}

func (ce *ContentExtractor) getFaviconHash(faviconURL string) string {
	resp, err := ce.client.Get(faviconURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	if len(body) == 0 {
		return ""
	}

	hash := md5.Sum(body)
	return fmt.Sprintf("%x", hash)
}

func (ce *ContentExtractor) FetchRobotsTxt(baseURL string, httpInfo *HTTPInfo) {
	if !ce.config.EnableRobotsTxt {
		return
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"

	resp, err := ce.client.Get(robotsURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			httpInfo.RobotsTxt = string(body)
		}
	}
}

func (ce *ContentExtractor) FetchSitemap(baseURL string, httpInfo *HTTPInfo) {
	if !ce.config.EnableSitemap {
		return
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	sitemapPaths := []string{
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/sitemap.txt",
	}

	for _, path := range sitemapPaths {
		sitemapURL := base.Scheme + "://" + base.Host + path
		resp, err := ce.client.Get(sitemapURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				httpInfo.Sitemap = string(body)
				break
			}
		}
	}
}
