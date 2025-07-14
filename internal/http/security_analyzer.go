package http

import (
	"strings"
)

type SecurityAnalyzer struct{}

func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{}
}

func (sa *SecurityAnalyzer) AnalyzeSecurityIssues(httpInfo *HTTPInfo) {
	issues := []SecurityIssue{}
	risk := 0
	factors := []string{}

	headers := httpInfo.SecurityHeaders

	if headers.StrictTransportSecurity == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing HSTS",
			Description: "Strict-Transport-Security header is missing.",
			Risk:        "medium",
			Remediation: "Add the Strict-Transport-Security header to enforce HTTPS.",
		})
		risk += 10
		factors = append(factors, "Missing HSTS")
	} else if !strings.Contains(strings.ToLower(headers.StrictTransportSecurity), "max-age=") {
		issues = append(issues, SecurityIssue{
			Type:        "Weak HSTS",
			Description: "Strict-Transport-Security header is present but lacks 'max-age'.",
			Risk:        "low",
			Remediation: "Specify a max-age in the HSTS header.",
		})
		risk += 5
		factors = append(factors, "Weak HSTS")
	}

	if headers.ContentSecurityPolicy == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing CSP",
			Description: "Content-Security-Policy header is missing.",
			Risk:        "medium",
			Remediation: "Add a CSP header to mitigate XSS attacks.",
		})
		risk += 10
		factors = append(factors, "Missing CSP")
	} else {
		csp := strings.ToLower(headers.ContentSecurityPolicy)

		if strings.Contains(csp, "unsafe-inline") {
			issues = append(issues, SecurityIssue{
				Type:        "CSP with unsafe-inline",
				Description: "CSP contains 'unsafe-inline', allowing inline scripts.",
				Risk:        "high",
				Remediation: "Avoid using 'unsafe-inline' in CSP.",
			})
			risk += 15
			factors = append(factors, "CSP unsafe-inline")
		}
		if strings.Contains(csp, "*") && (strings.Contains(csp, "script-src") || strings.Contains(csp, "default-src")) {
			issues = append(issues, SecurityIssue{
				Type:        "CSP with wildcard",
				Description: "CSP allows scripts from any origin using wildcard (*).",
				Risk:        "high",
				Remediation: "Avoid using wildcard in CSP for script-src or default-src.",
			})
			risk += 15
			factors = append(factors, "CSP wildcard")
		}
		if !strings.Contains(csp, "script-src") {
			issues = append(issues, SecurityIssue{
				Type:        "CSP missing script-src",
				Description: "CSP is missing a script-src directive.",
				Risk:        "medium",
				Remediation: "Define script-src explicitly in CSP.",
			})
			risk += 8
			factors = append(factors, "CSP missing script-src")
		}
	}

	xfo := strings.ToLower(headers.XFrameOptions)
	if xfo == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing X-Frame-Options",
			Description: "X-Frame-Options header is missing.",
			Risk:        "low",
			Remediation: "Add the X-Frame-Options header (DENY or SAMEORIGIN).",
		})
		risk += 5
		factors = append(factors, "Missing X-Frame-Options")
	} else if xfo != "deny" && xfo != "sameorigin" {
		issues = append(issues, SecurityIssue{
			Type:        "Weak X-Frame-Options",
			Description: "X-Frame-Options header has an insecure or unknown value: " + xfo,
			Risk:        "low",
			Remediation: "Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options.",
		})
		risk += 4
		factors = append(factors, "Weak X-Frame-Options")
	}

	if strings.ToLower(headers.XContentTypeOptions) != "nosniff" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing or weak X-Content-Type-Options",
			Description: "X-Content-Type-Options should be set to 'nosniff'.",
			Risk:        "low",
			Remediation: "Set X-Content-Type-Options: nosniff.",
		})
		risk += 5
		factors = append(factors, "Missing or weak X-Content-Type-Options")
	}

	if headers.XSSProtection == "" || strings.Contains(strings.ToLower(headers.XSSProtection), "0") {
		issues = append(issues, SecurityIssue{
			Type:        "X-XSS-Protection disabled or missing",
			Description: "X-XSS-Protection is disabled or not present.",
			Risk:        "low",
			Remediation: "Set X-XSS-Protection: 1; mode=block.",
		})
		risk += 3
		factors = append(factors, "X-XSS-Protection disabled")
	}

	ref := strings.ToLower(headers.ReferrerPolicy)
	if ref == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing Referrer-Policy",
			Description: "Referrer-Policy header is missing.",
			Risk:        "low",
			Remediation: "Add Referrer-Policy: strict-origin-when-cross-origin.",
		})
		risk += 2
		factors = append(factors, "Missing Referrer-Policy")
	} else if strings.Contains(ref, "unsafe-url") {
		issues = append(issues, SecurityIssue{
			Type:        "Permissive Referrer-Policy",
			Description: "Referrer-Policy set to 'unsafe-url'.",
			Risk:        "medium",
			Remediation: "Use a stricter policy such as no-referrer or strict-origin.",
		})
		risk += 8
		factors = append(factors, "Permissive Referrer-Policy")
	}

	if headers.PermissionsPolicy == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing Permissions-Policy",
			Description: "Permissions-Policy header is missing.",
			Risk:        "low",
			Remediation: "Add Permissions-Policy to restrict browser features.",
		})
		risk += 2
		factors = append(factors, "Missing Permissions-Policy")
	}

	if headers.CrossOriginEmbedderPolicy == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing Cross-Origin-Embedder-Policy",
			Description: "Cross-Origin-Embedder-Policy header is missing.",
			Risk:        "low",
			Remediation: "Add Cross-Origin-Embedder-Policy: require-corp.",
		})
		risk += 2
		factors = append(factors, "Missing COEP")
	}

	if headers.CrossOriginOpenerPolicy == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing Cross-Origin-Opener-Policy",
			Description: "Cross-Origin-Opener-Policy header is missing.",
			Risk:        "low",
			Remediation: "Add Cross-Origin-Opener-Policy: same-origin.",
		})
		risk += 2
		factors = append(factors, "Missing COOP")
	}

	if headers.CrossOriginResourcePolicy == "" {
		issues = append(issues, SecurityIssue{
			Type:        "Missing Cross-Origin-Resource-Policy",
			Description: "Cross-Origin-Resource-Policy header is missing.",
			Risk:        "low",
			Remediation: "Add Cross-Origin-Resource-Policy: same-origin.",
		})
		risk += 2
		factors = append(factors, "Missing CORP")
	}

	httpInfo.SecurityIssues = issues
	httpInfo.RiskScore += risk
	httpInfo.RiskFactors = append(httpInfo.RiskFactors, factors...)
}
