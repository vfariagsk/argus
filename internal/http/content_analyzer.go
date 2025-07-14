package http

import (
	"net/http"
	"regexp"
	"strings"
)

type ContentAnalyzer struct{}

func NewContentAnalyzer() *ContentAnalyzer {
	return &ContentAnalyzer{}
}

func (ca *ContentAnalyzer) DetectAdminLoginDebugByContent(resp *http.Response, body []byte, httpInfo *HTTPInfo) {
	urlPath := strings.ToLower(resp.Request.URL.Path)
	title := strings.ToLower(httpInfo.Title)
	bodyStr := strings.ToLower(string(body))

	isLoginForm := ca.containsLoginForm(bodyStr)
	isAdminURL := strings.Contains(urlPath, "/admin") || strings.Contains(urlPath, "/dashboard") || strings.Contains(urlPath, "/cpanel")
	isLoginURL := strings.Contains(urlPath, "/login") || strings.Contains(urlPath, "/auth") || strings.Contains(urlPath, "/signin")

	if isLoginForm || isLoginURL || ca.containsLoginKeywords(title, bodyStr) {
		httpInfo.LoginPortals = append(httpInfo.LoginPortals, LoginPortal{
			Path:        resp.Request.URL.Path,
			Title:       httpInfo.Title,
			Description: "Login portal detected based on combined signals (input fields, URL patterns, or keywords).",
			Risk:        "medium",
		})
	}

	if isAdminURL || ca.containsAdminKeywords(title, bodyStr) {
		httpInfo.AdminPanels = append(httpInfo.AdminPanels, AdminPanel{
			Path:        resp.Request.URL.Path,
			Title:       httpInfo.Title,
			Description: "Admin panel detected based on URL pattern, title, or content.",
			Risk:        "medium",
		})
	}

	ca.detectDebugEndpoints(resp, title, bodyStr, httpInfo)
}

func (ca *ContentAnalyzer) containsLoginForm(body string) bool {
	inputPasswordRegex := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*['"]?password['"]?`)
	loginButtonRegex := regexp.MustCompile(`(?i)<(button|input)[^>]*(login|sign[\s-]?in|entrar)[^>]*>`)
	return inputPasswordRegex.MatchString(body) || loginButtonRegex.MatchString(body)
}

func (ca *ContentAnalyzer) containsLoginKeywords(title, body string) bool {
	keywords := []string{"login", "sign in", "sign-in", "signin", "authentication", "acesso restrito", "entrar"}
	for _, kw := range keywords {
		if strings.Contains(title, kw) || strings.Contains(body, kw) {
			return true
		}
	}
	return false
}

func (ca *ContentAnalyzer) containsAdminKeywords(title, body string) bool {
	keywords := []string{"admin", "admin panel", "administrator", "painel de controle", "painel administrativo", "cpanel", "backend"}
	for _, kw := range keywords {
		if strings.Contains(title, kw) || strings.Contains(body, kw) {
			return true
		}
	}
	return false
}

func (ca *ContentAnalyzer) detectDebugEndpoints(resp *http.Response, title, body string, httpInfo *HTTPInfo) {
	debugIndicators := []string{
		"debug", "phpinfo", "php info", "debug mode", "development", "staging", "homolog",
		"error_reporting", "display_errors", "database connection", "stack trace", "exception",
		"var_dump", "print_r", "var_export",
	}

	for _, indicator := range debugIndicators {
		if strings.Contains(title, indicator) || strings.Contains(body, indicator) {
			httpInfo.DebugEndpoints = append(httpInfo.DebugEndpoints, DebugEndpoint{
				Path:        resp.Request.URL.Path,
				Status:      resp.StatusCode,
				Description: "Potential debug endpoint detected by content or title.",
				Risk:        "high",
			})
			break
		}
	}

	for name, value := range resp.Header {
		if strings.Contains(strings.ToLower(name), "debug") || strings.Contains(strings.ToLower(strings.Join(value, " ")), "debug") {
			httpInfo.DebugEndpoints = append(httpInfo.DebugEndpoints, DebugEndpoint{
				Path:        resp.Request.URL.Path,
				Status:      resp.StatusCode,
				Description: "Debug information exposed in HTTP headers.",
				Risk:        "high",
			})
			break
		}
	}
}
