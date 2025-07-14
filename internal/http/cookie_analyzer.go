package http

import (
	"net/http"
)

type CookieAnalyzer struct{}

func NewCookieAnalyzer() *CookieAnalyzer {
	return &CookieAnalyzer{}
}

func (ca *CookieAnalyzer) AnalyzeCookies(cookies []*http.Cookie, httpInfo *HTTPInfo) {
	for _, cookie := range cookies {
		cookieInfo := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: ca.sameSiteToString(cookie.SameSite),
		}
		httpInfo.Cookies = append(httpInfo.Cookies, cookieInfo)
	}
}

func (ca *CookieAnalyzer) sameSiteToString(sameSite http.SameSite) string {
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
		return ""
	}
}
