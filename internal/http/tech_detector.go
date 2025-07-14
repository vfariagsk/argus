package http

import (
	"net/http"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type TechnologyDetector struct {
	client *wappalyzer.Wappalyze
}

func NewTechnologyDetector() *TechnologyDetector {
	client, err := wappalyzer.New()
	if err != nil {
		return &TechnologyDetector{
			client: nil,
		}
	}
	return &TechnologyDetector{
		client: client,
	}
}

func (td *TechnologyDetector) Detect(resp *http.Response, body []byte) []Technology {
	var technologies []Technology

	if td.client == nil {
		return technologies
	}

	headers := make(map[string][]string)
	for key, values := range resp.Header {
		headers[key] = values
	}

	detectedApps := td.client.FingerprintWithInfo(headers, body)

	for appName, appInfo := range detectedApps {
		category := td.getCategoryFromWappalyzer(appInfo.Categories)

		tech := Technology{
			Name:        appName,
			Category:    category,
			Confidence:  0.8,
			Description: appInfo.Description,
			Website:     appInfo.Website,
		}
		technologies = append(technologies, tech)
	}

	return technologies
}

func (td *TechnologyDetector) getCategoryFromWappalyzer(categories []string) string {
	if len(categories) == 0 {
		return string(CategoryOther)
	}

	categoryMap := map[string]string{
		"CMS":                    string(CategoryCMS),
		"Frameworks":             string(CategoryFramework),
		"Web servers":            string(CategoryWebServer),
		"Programming languages":  string(CategoryProgramming),
		"JavaScript libraries":   string(CategoryJavaScript),
		"JavaScript frameworks":  string(CategoryJavaScript),
		"JavaScript utilities":   string(CategoryJavaScript),
		"JavaScript graphics":    string(CategoryJavaScript),
		"JavaScript analytics":   string(CategoryJavaScript),
		"JavaScript advertising": string(CategoryJavaScript),
		"JavaScript development": string(CategoryJavaScript),
		"JavaScript other":       string(CategoryJavaScript),
		"CSS frameworks":         string(CategoryCSS),
		"CSS preprocessors":      string(CategoryCSS),
		"CSS utilities":          string(CategoryCSS),
		"CSS other":              string(CategoryCSS),
		"Font scripts":           string(CategoryFont),
		"Font icons":             string(CategoryFont),
		"Font other":             string(CategoryFont),
		"Databases":              string(CategoryDatabase),
		"CDN":                    string(CategoryCDN),
		"WAF":                    string(CategoryWAF),
		"Operating systems":      string(CategoryOS),
		"Cloud":                  string(CategoryCloud),
		"Analytics":              string(CategoryAnalytics),
		"Advertising":            string(CategoryAdvertising),
		"Monitoring":             string(CategoryMonitoring),
		"Security":               string(CategorySecurity),
		"Other":                  string(CategoryOther),
	}

	if category, exists := categoryMap[categories[0]]; exists {
		return category
	}

	return string(CategoryOther)
}
