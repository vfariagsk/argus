package resolve

import (
	"fmt"
	"strings"
)

type TakeoverInfo struct {
	Risk    bool   `json:"risk"`
	Details string `json:"details"`
}

type TakeoverChecker struct {
	patterns []TakeoverPattern
}

func NewTakeoverChecker() *TakeoverChecker {
	checker := &TakeoverChecker{}
	checker.initPatterns()
	return checker
}

func (tc *TakeoverChecker) Check(host string, records map[string][]DNSRecord) (*TakeoverInfo, error) {
	info := &TakeoverInfo{
		Risk:    false,
		Details: "",
	}

	if cnameRecords, exists := records["CNAME"]; exists {
		for _, record := range cnameRecords {
			for _, pattern := range tc.patterns {
				if strings.Contains(record.Value, pattern.Pattern) {
					info.Risk = true
					info.Details = fmt.Sprintf("CNAME points to %s (%s)", pattern.Provider, pattern.Description)
					return info, nil
				}
			}
		}
	}

	return info, nil
}

func (tc *TakeoverChecker) initPatterns() {
	tc.patterns = []TakeoverPattern{
		{
			Provider:    "GitHub Pages",
			Pattern:     "github.io",
			Description: "GitHub Pages service",
			Risk:        "medium",
		},
		{
			Provider:    "Heroku",
			Pattern:     "herokuapp.com",
			Description: "Heroku application",
			Risk:        "high",
		},
		{
			Provider:    "Vercel",
			Pattern:     "vercel.app",
			Description: "Vercel deployment",
			Risk:        "high",
		},
		{
			Provider:    "Netlify",
			Pattern:     "netlify.app",
			Description: "Netlify site",
			Risk:        "high",
		},
		{
			Provider:    "AWS S3",
			Pattern:     "s3.amazonaws.com",
			Description: "AWS S3 bucket",
			Risk:        "high",
		},
		{
			Provider:    "AWS CloudFront",
			Pattern:     "cloudfront.net",
			Description: "AWS CloudFront distribution",
			Risk:        "medium",
		},
		{
			Provider:    "Google Cloud Storage",
			Pattern:     "storage.googleapis.com",
			Description: "Google Cloud Storage bucket",
			Risk:        "high",
		},
		{
			Provider:    "Azure Blob Storage",
			Pattern:     "blob.core.windows.net",
			Description: "Azure Blob Storage",
			Risk:        "high",
		},
		{
			Provider:    "DigitalOcean Spaces",
			Pattern:     "digitaloceanspaces.com",
			Description: "DigitalOcean Spaces",
			Risk:        "high",
		},
		{
			Provider:    "Firebase Hosting",
			Pattern:     "web.app",
			Description: "Firebase hosting service",
			Risk:        "high",
		},
		{
			Provider:    "Surge",
			Pattern:     "surge.sh",
			Description: "Surge.sh hosting",
			Risk:        "high",
		},
		{
			Provider:    "Readme.io",
			Pattern:     "readme.io",
			Description: "Readme.io documentation",
			Risk:        "medium",
		},
		{
			Provider:    "Help Scout",
			Pattern:     "helpscoutdocs.com",
			Description: "Help Scout documentation",
			Risk:        "medium",
		},
		{
			Provider:    "Canny",
			Pattern:     "canny.io",
			Description: "Canny feedback platform",
			Risk:        "medium",
		},
		{
			Provider:    "Intercom",
			Pattern:     "intercom.io",
			Description: "Intercom customer messaging",
			Risk:        "medium",
		},
		{
			Provider:    "Zendesk",
			Pattern:     "zendesk.com",
			Description: "Zendesk support",
			Risk:        "medium",
		},
		{
			Provider:    "StatusPage",
			Pattern:     "statuspage.io",
			Description: "StatusPage status",
			Risk:        "medium",
		},
		{
			Provider:    "UptimeRobot",
			Pattern:     "uptimerobot.com",
			Description: "UptimeRobot monitoring",
			Risk:        "medium",
		},
		{
			Provider:    "Pingdom",
			Pattern:     "pingdom.com",
			Description: "Pingdom monitoring",
			Risk:        "medium",
		},
		{
			Provider:    "Tumblr",
			Pattern:     "tumblr.com",
			Description: "Tumblr blog",
			Risk:        "low",
		},
		{
			Provider:    "WordPress",
			Pattern:     "wordpress.com",
			Description: "WordPress blog",
			Risk:        "low",
		},
		{
			Provider:    "Shopify",
			Pattern:     "myshopify.com",
			Description: "Shopify store",
			Risk:        "medium",
		},
		{
			Provider:    "Squarespace",
			Pattern:     "squarespace.com",
			Description: "Squarespace site",
			Risk:        "medium",
		},
		{
			Provider:    "Wix",
			Pattern:     "wix.com",
			Description: "Wix site",
			Risk:        "medium",
		},
		{
			Provider:    "Weebly",
			Pattern:     "weebly.com",
			Description: "Weebly site",
			Risk:        "medium",
		},
	}
}
