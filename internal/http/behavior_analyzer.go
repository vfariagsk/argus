package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type BehaviorAnalyzer struct {
	config HTTPConfig
}

func NewBehaviorAnalyzer(config HTTPConfig) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		config: config,
	}
}
func (ba *BehaviorAnalyzer) DetectAnomalousBehavior(resp *http.Response, body []byte, httpInfo *HTTPInfo) {
	anomalies := []AnomalousBehavior{}

	httpInfo.RedirectChainLength = len(httpInfo.RedirectChain)
	if httpInfo.RedirectChainLength > 5 {
		anomalies = append(anomalies, AnomalousBehavior{
			Type:        "Redirect Chain Loop",
			Description: "Excessive redirect chain detected",
			Risk:        "medium",
			Details:     fmt.Sprintf("Chain length: %d", httpInfo.RedirectChainLength),
		})
	}

	supportedMethods := ba.detectDangerousMethods(httpInfo)
	httpInfo.SupportedMethods = supportedMethods
	if len(supportedMethods) > 0 {
		anomalies = append(anomalies, AnomalousBehavior{
			Type:        "Dangerous HTTP Methods",
			Description: "Server supports potentially dangerous HTTP methods",
			Risk:        "high",
			Details:     fmt.Sprintf("Methods: %s", strings.Join(supportedMethods, ", ")),
		})
	}

	redirectParams := []string{"redirect", "next", "to", "url", "target", "return", "goto"}
	query := resp.Request.URL.Query()

	for _, param := range redirectParams {
		if value := query.Get(param); value != "" {
			decodedValue, _ := url.QueryUnescape(value)
			if strings.HasPrefix(decodedValue, "//") || strings.HasPrefix(decodedValue, "http") {
				anomalies = append(anomalies, AnomalousBehavior{
					Type:        "Unvalidated Redirect Parameter",
					Description: "Redirect parameter may redirect externally",
					Risk:        "high",
					Details:     fmt.Sprintf("Parameter: %s, Value: %s", param, decodedValue),
				})
			}
		}
	}

	httpInfo.OpenRedirects = ba.detectOpenRedirectByResponse(resp)
	httpInfo.AnomalousBehavior = anomalies
}

func (ba *BehaviorAnalyzer) detectDangerousMethods(httpInfo *HTTPInfo) []string {
	dangerousMethods := []string{"PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"}
	supportedMethods := []string{}

	client := &http.Client{
		Timeout: ba.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, method := range dangerousMethods {
		wg.Add(1)
		go func(method string) {
			defer wg.Done()

			req, err := http.NewRequest(method, httpInfo.URL, strings.NewReader("{}"))
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", ba.config.UserAgent)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			fmt.Println(method, resp.StatusCode)
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				mu.Lock()
				supportedMethods = append(supportedMethods, method)
				mu.Unlock()
			}
		}(method)
	}

	wg.Wait()
	return supportedMethods
}

func (ba *BehaviorAnalyzer) detectOpenRedirectByResponse(resp *http.Response) []OpenRedirect {
	openRedirects := []OpenRedirect{}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			decodedLoc, _ := url.QueryUnescape(loc)

			if strings.HasPrefix(decodedLoc, "//") {
				openRedirects = append(openRedirects, OpenRedirect{
					Parameter: "Location header",
					Value:     decodedLoc,
					Risk:      "high",
				})
				return openRedirects
			}

			targetURL, err := url.Parse(decodedLoc)
			if err != nil {
				return openRedirects
			}

			requestHost := resp.Request.URL.Hostname()

			if targetURL.IsAbs() {
				if !strings.Contains(targetURL.Hostname(), requestHost) {
					openRedirects = append(openRedirects, OpenRedirect{
						Parameter: "Location header",
						Value:     decodedLoc,
						Risk:      "high",
					})
				}
			} else {
				if strings.HasPrefix(targetURL.Path, "/admin") ||
					strings.HasPrefix(targetURL.Path, "/dashboard") ||
					strings.HasPrefix(targetURL.Path, "/cpanel") {
					openRedirects = append(openRedirects, OpenRedirect{
						Parameter: "Location header (internal)",
						Value:     decodedLoc,
						Risk:      "medium",
					})
				}

				if strings.HasPrefix(targetURL.Path, "//") {
					openRedirects = append(openRedirects, OpenRedirect{
						Parameter: "Location header (ambiguous)",
						Value:     decodedLoc,
						Risk:      "high",
					})
				}
			}
		}
	}

	return openRedirects
}
