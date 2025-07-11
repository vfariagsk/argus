package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type Scanner struct {
	config          HTTPConfig
	client          *http.Client
	techDetector    *TechnologyDetector
	hostingDetector *HostingDetector
	tracerouter     *Tracerouter
}

func NewScanner(config HTTPConfig) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.VerifySSL,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: -1,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		},
	}

	return &Scanner{
		config:          config,
		client:          client,
		techDetector:    NewTechnologyDetector(),
		hostingDetector: NewHostingDetector(),
		tracerouter:     NewTracerouter(),
	}
}

func (s *Scanner) ScanURL(ip, targetURL string) (*HTTPInfo, error) {
	startTime := time.Now()

	httpInfo := &HTTPInfo{
		URL:     targetURL,
		Headers: make(map[string]string),
		Errors:  []string{},
	}

	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	resp, err := s.makeRequest(targetURL)
	if err != nil {
		httpInfo.Errors = append(httpInfo.Errors, fmt.Sprintf("Request failed: %v", err))
		httpInfo.IsTimeout = strings.Contains(err.Error(), "timeout")
		return httpInfo, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpInfo.Errors = append(httpInfo.Errors, fmt.Sprintf("Failed to read body: %v", err))
	} else {
		httpInfo.BodyLength = len(body)
	}

	httpInfo.Status = resp.StatusCode
	httpInfo.StatusText = resp.Status
	httpInfo.ResponseTime = time.Since(startTime)
	httpInfo.ContentType = resp.Header.Get("Content-Type")
	httpInfo.Server = resp.Header.Get("Server")
	httpInfo.PoweredBy = resp.Header.Get("X-Powered-By")
	httpInfo.IsLive = true
	httpInfo.IsRedirect = resp.StatusCode >= 300 && resp.StatusCode < 400
	httpInfo.IsError = resp.StatusCode >= 400

	s.analyzeHeaders(resp.Header, httpInfo)
	s.analyzeCookies(resp.Cookies(), httpInfo)

	if len(body) > 0 {
		s.extractTitle(body, httpInfo)
		if s.config.EnableFavicon {
			s.extractFavicon(targetURL, httpInfo)
		}
	}

	if s.config.EnableTechDetect {
		s.detectTechnologies(resp, body, httpInfo)
	}

	s.detectHosting(ip, resp, httpInfo)

	if s.config.EnableTraceroute {
		if u, err := url.Parse(targetURL); err == nil {
			if traceroute, err := s.tracerouter.Trace(u.Host); err == nil {
				httpInfo.Traceroute = traceroute
			}
		}
	}

	if s.config.EnableRobotsTxt {
		s.fetchRobotsTxt(targetURL, httpInfo)
	}
	if s.config.EnableSitemap {
		s.fetchSitemap(targetURL, httpInfo)
	}

	return httpInfo, nil
}

func (s *Scanner) ScanURLs(addresses []struct {
	IP  string
	URL string
}) ([]*HTTPInfo, error) {
	results := make([]*HTTPInfo, len(addresses))
	errors := make([]error, len(addresses))

	workerCount := s.config.Threads
	if workerCount <= 0 {
		workerCount = 10
	}

	jobs := make(chan int, len(addresses))
	done := make(chan bool, len(addresses))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jobIndex := range jobs {
				address := addresses[jobIndex]
				result, err := s.ScanURL(address.IP, address.URL)
				results[jobIndex] = result
				errors[jobIndex] = err
				done <- true
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range addresses {
			jobs <- i
		}
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	for i := 0; i < len(addresses); i++ {
		<-done
	}

	return results, nil
}

func (s *Scanner) makeRequest(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}

	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}

	return s.client.Do(req)
}

func (s *Scanner) analyzeHeaders(headers http.Header, httpInfo *HTTPInfo) {
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

	httpInfo.WAF = s.detectWAF(headers)
	httpInfo.CDN = s.detectCDN(headers)

	httpInfo.CloudProvider = s.detectCloudProvider(headers)
}

func (s *Scanner) analyzeCookies(cookies []*http.Cookie, httpInfo *HTTPInfo) {
	for _, cookie := range cookies {
		cookieInfo := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: s.sameSiteToString(cookie.SameSite),
		}
		httpInfo.Cookies = append(httpInfo.Cookies, cookieInfo)
	}
}

func (s *Scanner) extractTitle(body []byte, httpInfo *HTTPInfo) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	var title string
	var extractTitle func(*html.Node)
	extractTitle = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil {
				title = n.FirstChild.Data
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractTitle(c)
		}
	}
	extractTitle(doc)

	httpInfo.Title = strings.TrimSpace(title)
}

func (s *Scanner) extractFavicon(baseURL string, httpInfo *HTTPInfo) {
	faviconPaths := []string{
		"/favicon.ico",
		"/favicon.png",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
	}

	for _, path := range faviconPaths {
		faviconURL := baseURL + path
		if hash := s.getFaviconHash(faviconURL); hash != "" {
			httpInfo.FaviconHash = hash
			break
		}
	}
}

func (s *Scanner) getFaviconHash(faviconURL string) string {
	resp, err := s.client.Get(faviconURL)
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

	return fmt.Sprintf("%x", len(body))
}

func (s *Scanner) detectWAF(headers http.Header) string {
	wafSignatures := map[string][]string{
		"Cloudflare": {
			"cf-ray",
			"cf-cache-status",
			"cf-request-id",
		},
		"AWS WAF": {
			"x-amz-cf-pop",
			"x-amz-cf-id",
		},
		"Imperva": {
			"incap_ses",
			"visid_incap",
		},
		"F5 BIG-IP": {
			"x-wa-info",
			"x-asg",
		},
		"Akamai": {
			"x-akamai-transformed",
			"x-akamai-ssl",
		},
		"Fastly": {
			"x-fastly",
			"x-cache-hits",
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

func (s *Scanner) detectCDN(headers http.Header) string {
	cdnSignatures := map[string][]string{
		"Cloudflare": {"cf-ray", "cf-cache-status"},
		"Akamai":     {"x-akamai-transformed", "x-akamai-ssl"},
		"Fastly":     {"x-fastly", "x-cache-hits"},
		"CloudFront": {"x-amz-cf-pop", "x-amz-cf-id"},
		"MaxCDN":     {"x-cdn", "x-cdn-pop"},
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

func (s *Scanner) detectCloudProvider(headers http.Header) string {
	cloudSignatures := map[string][]string{
		"AWS": {
			"x-amz-cf-pop",
			"x-amz-cf-id",
			"x-amz-id-2",
		},
		"Google Cloud": {
			"x-goog-generation",
			"x-goog-metageneration",
		},
		"Azure": {
			"x-ms-version",
			"x-ms-request-id",
		},
	}

	for cloud, signatures := range cloudSignatures {
		for _, sig := range signatures {
			if headers.Get(sig) != "" {
				return cloud
			}
		}
	}

	return ""
}

func (s *Scanner) detectTechnologies(resp *http.Response, body []byte, httpInfo *HTTPInfo) {
	technologies := s.techDetector.Detect(resp, body)
	httpInfo.Technologies = technologies

	for _, tech := range technologies {
		switch tech.Category {
		case string(CategoryFramework):
			httpInfo.Framework = tech.Name
		case string(CategoryLanguage):
			httpInfo.Language = tech.Name
		case string(CategoryDatabase):
			httpInfo.Database = tech.Name
		case string(CategoryOS):
			httpInfo.OS = tech.Name
		}
	}
}

func (s *Scanner) fetchRobotsTxt(baseURL string, httpInfo *HTTPInfo) {
	robotsURL := baseURL + "/robots.txt"
	resp, err := s.client.Get(robotsURL)
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

func (s *Scanner) fetchSitemap(baseURL string, httpInfo *HTTPInfo) {
	sitemapURLs := []string{
		baseURL + "/sitemap.xml",
		baseURL + "/sitemap_index.xml",
		baseURL + "/sitemap.txt",
	}

	for _, sitemapURL := range sitemapURLs {
		resp, err := s.client.Get(sitemapURL)
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

func (s *Scanner) detectHosting(ip string, resp *http.Response, httpInfo *HTTPInfo) {
	dnsRecords := s.extractDNSFromHeaders(resp.Header)

	hostingInfo := s.hostingDetector.Detect(ip, resp, dnsRecords)

	if len(hostingInfo) > 0 {
		hosting := hostingInfo[0]
		httpInfo.Hosting = &HostingInfo{
			Provider:    hosting.Provider,
			Confidence:  hosting.Confidence,
			Description: hosting.Description,
			Website:     hosting.Website,
			Type:        hosting.Type,
		}
	}
}

func (s *Scanner) extractDNSFromHeaders(headers http.Header) map[string][]string {
	dnsRecords := make(map[string][]string)

	// Extrair informações de DNS de headers específicos
	if server := headers.Get("Server"); server != "" {
		dnsRecords["TXT"] = append(dnsRecords["TXT"], server)
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		dnsRecords["TXT"] = append(dnsRecords["TXT"], poweredBy)
	}

	if hostedBy := headers.Get("X-Hosted-By"); hostedBy != "" {
		dnsRecords["TXT"] = append(dnsRecords["TXT"], hostedBy)
	}

	if servedBy := headers.Get("X-Served-By"); servedBy != "" {
		dnsRecords["TXT"] = append(dnsRecords["TXT"], servedBy)
	}

	// Extrair CNAME de headers específicos
	if cfRay := headers.Get("CF-Ray"); cfRay != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "cloudflare.com")
	}

	if vercelId := headers.Get("X-Vercel-Id"); vercelId != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "vercel.app")
	}

	if netlifyVersion := headers.Get("X-Netlify-Version"); netlifyVersion != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "netlify.app")
	}

	if githubRequestId := headers.Get("X-GitHub-Request-Id"); githubRequestId != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "github.io")
	}

	if gitlabRequestId := headers.Get("X-GitLab-Request-Id"); gitlabRequestId != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "gitlab.io")
	}

	if herokuRequestId := headers.Get("X-Heroku-Request-Id"); herokuRequestId != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "herokuapp.com")
	}

	if azureRef := headers.Get("X-Azure-Ref"); azureRef != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "azurewebsites.net")
	}

	if googleBackend := headers.Get("X-Google-Backend"); googleBackend != "" {
		dnsRecords["CNAME"] = append(dnsRecords["CNAME"], "googleusercontent.com")
	}

	return dnsRecords
}

func (s *Scanner) sameSiteToString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}
