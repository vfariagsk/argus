package http

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	config           HTTPConfig
	client           *http.Client
	techDetector     *TechnologyDetector
	hostingDetector  *HostingDetector
	tracerouter      *Tracerouter
	securityAnalyzer *SecurityAnalyzer
	contentAnalyzer  *ContentAnalyzer
	behaviorAnalyzer *BehaviorAnalyzer
	headerAnalyzer   *HeaderAnalyzer
	cookieAnalyzer   *CookieAnalyzer
	contentExtractor *ContentExtractor
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
		config:           config,
		client:           client,
		techDetector:     NewTechnologyDetector(),
		hostingDetector:  NewHostingDetector(),
		tracerouter:      NewTracerouter(),
		securityAnalyzer: NewSecurityAnalyzer(),
		contentAnalyzer:  NewContentAnalyzer(),
		behaviorAnalyzer: NewBehaviorAnalyzer(config),
		headerAnalyzer:   NewHeaderAnalyzer(),
		cookieAnalyzer:   NewCookieAnalyzer(),
		contentExtractor: NewContentExtractor(config),
	}
}

func (s *Scanner) ScanURL(ip, targetURL string) (*HTTPInfo, error) {
	startTime := time.Now()

	httpInfo := &HTTPInfo{
		URL:               targetURL,
		Headers:           make(map[string]string),
		Errors:            []string{},
		Traceroute:        []HopInfo{},
		Technologies:      []Technology{},
		RedirectChain:     []RedirectInfo{},
		Cookies:           []CookieInfo{},
		SensitiveFiles:    []SensitiveFile{},
		AdminPanels:       []AdminPanel{},
		LoginPortals:      []LoginPortal{},
		DebugEndpoints:    []DebugEndpoint{},
		StagingIndicators: []string{},
		OpenRedirects:     []OpenRedirect{},
		SecurityIssues:    []SecurityIssue{},
		RiskFactors:       []string{},
		AnomalousBehavior: []AnomalousBehavior{},
		SupportedMethods:  []string{},
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

	var bodyBytes []byte

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			resp.Body.Close()
			httpInfo.Errors = append(httpInfo.Errors, fmt.Sprintf("Failed to read body: %v", gzErr))
			return httpInfo, nil
		}
		defer gzReader.Close()
		bodyBytes, err = io.ReadAll(gzReader)
		if err != nil {
			httpInfo.Errors = append(httpInfo.Errors, fmt.Sprintf("Failed to read gzipped body: %v", err))
			return httpInfo, nil
		}
	default:
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			httpInfo.Errors = append(httpInfo.Errors, fmt.Sprintf("Failed to read body: %v", err))
			return httpInfo, nil
		}
	}
	defer resp.Body.Close()

	httpInfo.BodyLength = len(bodyBytes)

	httpInfo.Status = resp.StatusCode
	httpInfo.StatusText = resp.Status
	httpInfo.ResponseTime = time.Since(startTime)
	httpInfo.ContentType = resp.Header.Get("Content-Type")
	httpInfo.Server = resp.Header.Get("Server")
	httpInfo.PoweredBy = resp.Header.Get("X-Powered-By")
	httpInfo.IsLive = true
	httpInfo.IsRedirect = resp.StatusCode >= 300 && resp.StatusCode < 400
	httpInfo.IsError = resp.StatusCode >= 400

	s.headerAnalyzer.AnalyzeHeaders(resp.Header, httpInfo)
	s.cookieAnalyzer.AnalyzeCookies(resp.Cookies(), httpInfo)

	if len(bodyBytes) > 0 {
		s.contentExtractor.ExtractTitle(bodyBytes, httpInfo)
		s.contentExtractor.ExtractFavicon(targetURL, httpInfo)
	}

	if s.config.EnableTechDetect {
		s.detectTechnologies(resp, bodyBytes, httpInfo)
	}

	s.detectHosting(ip, resp, httpInfo)

	if s.config.EnableTraceroute {
		if u, err := url.Parse(targetURL); err == nil {
			if traceroute, err := s.tracerouter.Trace(u.Host); err == nil {
				httpInfo.Traceroute = traceroute
			}
		}
	}

	s.contentExtractor.FetchRobotsTxt(targetURL, httpInfo)
	s.contentExtractor.FetchSitemap(targetURL, httpInfo)

	s.securityAnalyzer.AnalyzeSecurityIssues(httpInfo)
	s.contentAnalyzer.DetectAdminLoginDebugByContent(resp, bodyBytes, httpInfo)
	s.behaviorAnalyzer.DetectAnomalousBehavior(resp, bodyBytes, httpInfo)

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

	return s.client.Do(req)
}

func (s *Scanner) detectTechnologies(resp *http.Response, body []byte, httpInfo *HTTPInfo) {
	technologies := s.techDetector.Detect(resp, body)
	httpInfo.Technologies = technologies
}

func (s *Scanner) detectHosting(ip string, resp *http.Response, httpInfo *HTTPInfo) {
	dnsRecords := s.headerAnalyzer.extractDNSFromHeaders(resp.Header)
	hostingInfo := s.hostingDetector.Detect(ip, resp, dnsRecords)

	if len(hostingInfo) > 0 {
		httpInfo.Hosting = &hostingInfo[0]
	}
}
