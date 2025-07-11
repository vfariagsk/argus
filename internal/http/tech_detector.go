package http

import (
	"net/http"
	"regexp"
	"strings"
)

type TechnologyDetector struct {
	signatures map[string][]TechSignature
}

type TechSignature struct {
	Pattern     string         `json:"pattern"`
	Regex       *regexp.Regexp `json:"-"`
	Confidence  float64        `json:"confidence"`
	Version     string         `json:"version"`
	Description string         `json:"description"`
}

func NewTechnologyDetector() *TechnologyDetector {
	detector := &TechnologyDetector{
		signatures: make(map[string][]TechSignature),
	}
	detector.initSignatures()
	return detector
}

func (td *TechnologyDetector) Detect(resp *http.Response, body []byte) []Technology {
	var technologies []Technology
	bodyStr := string(body)

	for tech, signatures := range td.signatures {
		for _, sig := range signatures {
			if sig.Regex != nil {
				if matches := sig.Regex.FindStringSubmatch(bodyStr); len(matches) > 1 {
					version := sig.Version
					if len(matches) > 1 {
						version = matches[1]
					}

					tech := Technology{
						Name:        tech,
						Version:     version,
						Category:    td.getCategory(tech),
						Confidence:  sig.Confidence,
						Description: sig.Description,
						Website:     td.getWebsite(tech),
					}
					technologies = append(technologies, tech)
					break
				}
			}
		}
	}

	td.detectByHeaders(resp.Header, &technologies)

	return technologies
}

func (td *TechnologyDetector) detectByHeaders(headers http.Header, technologies *[]Technology) {
	if server := headers.Get("Server"); server != "" {
		td.detectServer(server, technologies)
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		td.detectPoweredBy(poweredBy, technologies)
	}

	if aspNetVersion := headers.Get("X-AspNet-Version"); aspNetVersion != "" {
		tech := Technology{
			Name:        "ASP.NET",
			Version:     aspNetVersion,
			Category:    string(CategoryFramework),
			Confidence:  0.9,
			Description: "Microsoft ASP.NET Framework",
			Website:     "https://dotnet.microsoft.com/",
		}
		*technologies = append(*technologies, tech)
	}

	if runtime := headers.Get("X-Runtime"); runtime != "" {
		tech := Technology{
			Name:        "Ruby on Rails",
			Version:     "",
			Category:    string(CategoryFramework),
			Confidence:  0.8,
			Description: "Ruby on Rails web framework",
			Website:     "https://rubyonrails.org/",
		}
		*technologies = append(*technologies, tech)
	}
}

func (td *TechnologyDetector) detectServer(server string, technologies *[]Technology) {
	serverLower := strings.ToLower(server)

	if strings.Contains(serverLower, "nginx") {
		tech := Technology{
			Name:        "Nginx",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Nginx web server",
			Website:     "https://nginx.org/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "apache") {
		tech := Technology{
			Name:        "Apache",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Apache HTTP Server",
			Website:     "https://httpd.apache.org/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "iis") {
		tech := Technology{
			Name:        "IIS",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Microsoft Internet Information Services",
			Website:     "https://www.iis.net/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "gunicorn") {
		tech := Technology{
			Name:        "Gunicorn",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Gunicorn WSGI HTTP Server",
			Website:     "https://gunicorn.org/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "uwsgi") {
		tech := Technology{
			Name:        "uWSGI",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "uWSGI application server",
			Website:     "https://uwsgi-docs.readthedocs.io/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "caddy") {
		tech := Technology{
			Name:        "Caddy",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Caddy web server",
			Website:     "https://caddyserver.com/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "lighttpd") {
		tech := Technology{
			Name:        "Lighttpd",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "Lighttpd web server",
			Website:     "https://www.lighttpd.net/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(serverLower, "openresty") {
		tech := Technology{
			Name:        "OpenResty",
			Version:     td.extractVersion(server),
			Category:    string(CategoryWebServer),
			Confidence:  0.9,
			Description: "OpenResty web platform",
			Website:     "https://openresty.org/",
		}
		*technologies = append(*technologies, tech)
	}
}

func (td *TechnologyDetector) detectPoweredBy(poweredBy string, technologies *[]Technology) {
	poweredByLower := strings.ToLower(poweredBy)

	if strings.Contains(poweredByLower, "php") {
		tech := Technology{
			Name:        "PHP",
			Version:     td.extractVersion(poweredBy),
			Category:    string(CategoryLanguage),
			Confidence:  0.9,
			Description: "PHP scripting language",
			Website:     "https://www.php.net/",
		}
		*technologies = append(*technologies, tech)
	} else if strings.Contains(poweredByLower, "asp.net") {
		tech := Technology{
			Name:        "ASP.NET",
			Version:     td.extractVersion(poweredBy),
			Category:    string(CategoryFramework),
			Confidence:  0.9,
			Description: "Microsoft ASP.NET Framework",
			Website:     "https://dotnet.microsoft.com/",
		}
		*technologies = append(*technologies, tech)
	}
}

func (td *TechnologyDetector) extractVersion(s string) string {
	re := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	if matches := re.FindStringSubmatch(s); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (td *TechnologyDetector) getCategory(tech string) string {
	techLower := strings.ToLower(tech)

	switch {
	case strings.Contains(techLower, "nginx"), strings.Contains(techLower, "apache"), strings.Contains(techLower, "iis"):
		return string(CategoryWebServer)
	case strings.Contains(techLower, "react"), strings.Contains(techLower, "angular"), strings.Contains(techLower, "vue"):
		return string(CategoryJavaScript)
	case strings.Contains(techLower, "wordpress"), strings.Contains(techLower, "drupal"), strings.Contains(techLower, "joomla"):
		return string(CategoryCMS)
	case strings.Contains(techLower, "mysql"), strings.Contains(techLower, "postgresql"), strings.Contains(techLower, "mongodb"):
		return string(CategoryDatabase)
	default:
		return string(CategoryOther)
	}
}

func (td *TechnologyDetector) getWebsite(tech string) string {
	websites := map[string]string{
		"WordPress":          "https://wordpress.org/",
		"Firebase":           "https://firebase.google.com/",
		"Gunicorn":           "https://gunicorn.org/",
		"uWSGI":              "https://uwsgi-docs.readthedocs.io/",
		"Caddy":              "https://caddyserver.com/",
		"Lighttpd":           "https://www.lighttpd.net/",
		"OpenResty":          "https://openresty.org/",
		"React":              "https://reactjs.org/",
		"Angular":            "https://angular.io/",
		"Vue.js":             "https://vuejs.org/",
		"Bootstrap":          "https://getbootstrap.com/",
		"jQuery":             "https://jquery.com/",
		"Node.js":            "https://nodejs.org/",
		"Express.js":         "https://expressjs.com/",
		"Laravel":            "https://laravel.com/",
		"Django":             "https://www.djangoproject.com/",
		"Flask":              "https://flask.palletsprojects.com/",
		"Ruby on Rails":      "https://rubyonrails.org/",
		"ASP.NET":            "https://dotnet.microsoft.com/",
		"Spring Boot":        "https://spring.io/projects/spring-boot",
		"FastAPI":            "https://fastapi.tiangolo.com/",
		"Next.js":            "https://nextjs.org/",
		"Nuxt.js":            "https://nuxtjs.org/",
		"Gatsby":             "https://www.gatsbyjs.com/",
		"Strapi":             "https://strapi.io/",
		"Ghost":              "https://ghost.org/",
		"Drupal":             "https://www.drupal.org/",
		"Joomla":             "https://www.joomla.org/",
		"Magento":            "https://magento.com/",
		"Shopify":            "https://www.shopify.com/",
		"WooCommerce":        "https://woocommerce.com/",
		"PrestaShop":         "https://www.prestashop.com/",
		"OpenCart":           "https://www.opencart.com/",
		"BigCommerce":        "https://www.bigcommerce.com/",
		"Salesforce":         "https://www.salesforce.com/",
		"HubSpot":            "https://www.hubspot.com/",
		"Mailchimp":          "https://mailchimp.com/",
		"Google Analytics":   "https://analytics.google.com/",
		"Google Tag Manager": "https://tagmanager.google.com/",
		"Facebook Pixel":     "https://developers.facebook.com/docs/facebook-pixel/",
		"Hotjar":             "https://www.hotjar.com/",
		"Mixpanel":           "https://mixpanel.com/",
		"Segment":            "https://segment.com/",
		"Amplitude":          "https://amplitude.com/",
		"Sentry":             "https://sentry.io/",
		"LogRocket":          "https://logrocket.com/",
		"Bugsnag":            "https://www.bugsnag.com/",
		"Rollbar":            "https://rollbar.com/",
		"DataDog":            "https://www.datadoghq.com/",
		"New Relic":          "https://newrelic.com/",
		"AppDynamics":        "https://www.appdynamics.com/",
		"Dynatrace":          "https://www.dynatrace.com/",
		"Pingdom":            "https://www.pingdom.com/",
		"UptimeRobot":        "https://uptimerobot.com/",
		"StatusPage":         "https://www.statuspage.io/",
		"Intercom":           "https://www.intercom.com/",
		"Drift":              "https://www.drift.com/",
		"Zendesk":            "https://www.zendesk.com/",
		"Freshdesk":          "https://freshdesk.com/",
		"Help Scout":         "https://www.helpscout.com/",
		"Canny":              "https://canny.io/",
		"UserVoice":          "https://www.uservoice.com/",
		"Typeform":           "https://www.typeform.com/",
		"SurveyMonkey":       "https://www.surveymonkey.com/",
		"Google Forms":       "https://forms.google.com/",
		"Microsoft Forms":    "https://forms.office.com/",
		"Calendly":           "https://calendly.com/",
		"Acuity Scheduling":  "https://acuityscheduling.com/",
		"Stripe":             "https://stripe.com/",
		"PayPal":             "https://www.paypal.com/",
		"Square":             "https://square.com/",
		"Braintree":          "https://www.braintreepayments.com/",
		"Adyen":              "https://www.adyen.com/",
		"Klarna":             "https://www.klarna.com/",
		"Afterpay":           "https://www.afterpay.com/",
		"Affirm":             "https://www.affirm.com/",
		"Splitit":            "https://www.splitit.com/",
		"QuadPay":            "https://www.quadpay.com/",
		"Sezzle":             "https://sezzle.com/",
		"Zip":                "https://zip.co/",
		"Laybuy":             "https://www.laybuy.com/",
		"Humm":               "https://www.shophumm.com/",
		"Openpay":            "https://www.openpay.com.au/",
		"LatitudePay":        "https://www.latitudepay.com/",
		"Scalapay":           "https://www.scalapay.com/",
		"Clearpay":           "https://www.clearpay.co.uk/",
		"PHP":                "https://www.php.net/",
		"Python":             "https://www.python.org/",
		"Java":               "https://www.java.com/",
		"Go":                 "https://golang.org/",
		"Rust":               "https://www.rust-lang.org/",
		"Elixir":             "https://elixir-lang.org/",
		"Clojure":            "https://clojure.org/",
		"Scala":              "https://www.scala-lang.org/",
		"Kotlin":             "https://kotlinlang.org/",
		"Swift":              "https://swift.org/",
		"TypeScript":         "https://www.typescriptlang.org/",
		"JavaScript":         "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
		"HTML5":              "https://developer.mozilla.org/en-US/docs/Web/HTML",
		"CSS3":               "https://developer.mozilla.org/en-US/docs/Web/CSS",
		"Webpack":            "https://webpack.js.org/",
		"Babel":              "https://babeljs.io/",
		"ESLint":             "https://eslint.org/",
		"Prettier":           "https://prettier.io/",
		"Jest":               "https://jestjs.io/",
		"Mocha":              "https://mochajs.org/",
		"Chai":               "https://www.chaijs.com/",
		"Sinon":              "https://sinonjs.org/",
		"Karma":              "https://karma-runner.github.io/",
		"Protractor":         "https://www.protractortest.org/",
		"Cypress":            "https://www.cypress.io/",
		"Selenium":           "https://www.selenium.dev/",
		"Puppeteer":          "https://pptr.dev/",
		"Playwright":         "https://playwright.dev/",
		"Nightwatch":         "https://nightwatchjs.org/",
		"TestCafe":           "https://devexpress.github.io/testcafe/",
		"WebdriverIO":        "https://webdriver.io/",
		"Appium":             "http://appium.io/",
		"Detox":              "https://github.com/wix/Detox",
		"XCUITest":           "https://developer.apple.com/xcode/ui-testing/",
		"Espresso":           "https://developer.android.com/training/testing/espresso",
		"UI Automator":       "https://developer.android.com/training/testing/ui-automator",
		"Calabash":           "https://calaba.sh/",
		"Frank":              "https://www.testingwithfrank.com/",
		"KIF":                "https://github.com/kif-framework/KIF",
		"Earl Grey":          "https://github.com/google/EarlGrey",
		"Robotium":           "https://github.com/RobotiumTech/robotium",
		"Monkey":             "https://developer.android.com/studio/test/monkey",
		"UIAutomation":       "https://developer.apple.com/documentation/xcode/user-interface-testing",
		"XCTest":             "https://developer.apple.com/documentation/xctest",
		"JUnit":              "https://junit.org/",
		"TestNG":             "https://testng.org/",
		"NUnit":              "https://nunit.org/",
		"MSTest":             "https://docs.microsoft.com/en-us/dotnet/core/testing/unit-testing-with-mstest",
		"xUnit":              "https://xunit.net/",
		"PHPUnit":            "https://phpunit.de/",
		"PyTest":             "https://pytest.org/",
		"Unittest":           "https://docs.python.org/3/library/unittest.html",
		"RSpec":              "https://rspec.info/",
		"Minitest":           "https://github.com/seattlerb/minitest",
		"Jasmine":            "https://jasmine.github.io/",
	}

	if website, exists := websites[tech]; exists {
		return website
	}
	return ""
}

func (td *TechnologyDetector) initSignatures() {
	// WordPress
	td.signatures["WordPress"] = []TechSignature{
		{Pattern: `wp-content`, Confidence: 0.8, Description: "WordPress content directory"},
		{Pattern: `wp-includes`, Confidence: 0.8, Description: "WordPress includes directory"},
		{Pattern: `wp-admin`, Confidence: 0.9, Description: "WordPress admin directory"},
		{Pattern: `wp-json`, Confidence: 0.9, Description: "WordPress REST API"},
		{Pattern: `wp-version`, Confidence: 0.9, Description: "WordPress version"},
	}

	// Firebase
	td.signatures["Firebase"] = []TechSignature{
		{Pattern: `firebase`, Confidence: 0.8, Description: "Firebase platform"},
		{Pattern: `firebaseapp\.com`, Confidence: 0.9, Description: "Firebase hosting"},
		{Pattern: `firebase\.googleapis\.com`, Confidence: 0.9, Description: "Firebase APIs"},
		{Pattern: `firebase\.js`, Confidence: 0.9, Description: "Firebase JavaScript SDK"},
		{Pattern: `firebase\.io`, Confidence: 0.8, Description: "Firebase domain"},
	}

	// Gunicorn
	td.signatures["Gunicorn"] = []TechSignature{
		{Pattern: `gunicorn`, Confidence: 0.9, Description: "Gunicorn WSGI server"},
		{Pattern: `gunicorn/\d+\.\d+`, Confidence: 0.9, Description: "Gunicorn version"},
	}

	// Django
	td.signatures["Django"] = []TechSignature{
		{Pattern: `django`, Confidence: 0.8, Description: "Django framework"},
		{Pattern: `csrfmiddlewaretoken`, Confidence: 0.9, Description: "Django CSRF token"},
		{Pattern: `django\.js`, Confidence: 0.9, Description: "Django JavaScript"},
		{Pattern: `__admin__`, Confidence: 0.8, Description: "Django admin"},
	}

	// Flask
	td.signatures["Flask"] = []TechSignature{
		{Pattern: `flask`, Confidence: 0.8, Description: "Flask framework"},
		{Pattern: `werkzeug`, Confidence: 0.9, Description: "Werkzeug WSGI library"},
		{Pattern: `flask\.js`, Confidence: 0.9, Description: "Flask JavaScript"},
	}

	// Express.js
	td.signatures["Express.js"] = []TechSignature{
		{Pattern: `express`, Confidence: 0.8, Description: "Express.js framework"},
		{Pattern: `express/\d+\.\d+`, Confidence: 0.9, Description: "Express.js version"},
		{Pattern: `connect\.sid`, Confidence: 0.8, Description: "Express session"},
	}

	// Laravel
	td.signatures["Laravel"] = []TechSignature{
		{Pattern: `laravel`, Confidence: 0.8, Description: "Laravel framework"},
		{Pattern: `csrf-token`, Confidence: 0.9, Description: "Laravel CSRF token"},
		{Pattern: `laravel_session`, Confidence: 0.9, Description: "Laravel session"},
		{Pattern: `laravel\.js`, Confidence: 0.9, Description: "Laravel JavaScript"},
	}

	// Ruby on Rails
	td.signatures["Ruby on Rails"] = []TechSignature{
		{Pattern: `rails`, Confidence: 0.8, Description: "Ruby on Rails"},
		{Pattern: `_rails`, Confidence: 0.9, Description: "Rails session"},
		{Pattern: `rails/\d+\.\d+`, Confidence: 0.9, Description: "Rails version"},
	}

	// ASP.NET
	td.signatures["ASP.NET"] = []TechSignature{
		{Pattern: `asp\.net`, Confidence: 0.8, Description: "ASP.NET framework"},
		{Pattern: `__VIEWSTATE`, Confidence: 0.9, Description: "ASP.NET ViewState"},
		{Pattern: `__EVENTVALIDATION`, Confidence: 0.9, Description: "ASP.NET validation"},
		{Pattern: `\.aspx`, Confidence: 0.8, Description: "ASP.NET pages"},
	}

	// Spring Boot
	td.signatures["Spring Boot"] = []TechSignature{
		{Pattern: `spring`, Confidence: 0.8, Description: "Spring framework"},
		{Pattern: `spring-boot`, Confidence: 0.9, Description: "Spring Boot"},
		{Pattern: `spring/\d+\.\d+`, Confidence: 0.9, Description: "Spring version"},
	}

	// FastAPI
	td.signatures["FastAPI"] = []TechSignature{
		{Pattern: `fastapi`, Confidence: 0.8, Description: "FastAPI framework"},
		{Pattern: `uvicorn`, Confidence: 0.9, Description: "Uvicorn ASGI server"},
		{Pattern: `fastapi/\d+\.\d+`, Confidence: 0.9, Description: "FastAPI version"},
	}

	// Next.js
	td.signatures["Next.js"] = []TechSignature{
		{Pattern: `next`, Confidence: 0.8, Description: "Next.js framework"},
		{Pattern: `_next`, Confidence: 0.9, Description: "Next.js assets"},
		{Pattern: `next\.js`, Confidence: 0.9, Description: "Next.js JavaScript"},
	}

	// Nuxt.js
	td.signatures["Nuxt.js"] = []TechSignature{
		{Pattern: `nuxt`, Confidence: 0.8, Description: "Nuxt.js framework"},
		{Pattern: `_nuxt`, Confidence: 0.9, Description: "Nuxt.js assets"},
		{Pattern: `nuxt\.js`, Confidence: 0.9, Description: "Nuxt.js JavaScript"},
	}

	// Gatsby
	td.signatures["Gatsby"] = []TechSignature{
		{Pattern: `gatsby`, Confidence: 0.8, Description: "Gatsby framework"},
		{Pattern: `gatsby\.js`, Confidence: 0.9, Description: "Gatsby JavaScript"},
		{Pattern: `gatsby-plugin`, Confidence: 0.9, Description: "Gatsby plugin"},
	}

	// Strapi
	td.signatures["Strapi"] = []TechSignature{
		{Pattern: `strapi`, Confidence: 0.8, Description: "Strapi CMS"},
		{Pattern: `strapi\.js`, Confidence: 0.9, Description: "Strapi JavaScript"},
		{Pattern: `/admin`, Confidence: 0.8, Description: "Strapi admin"},
	}

	// Ghost
	td.signatures["Ghost"] = []TechSignature{
		{Pattern: `ghost`, Confidence: 0.8, Description: "Ghost CMS"},
		{Pattern: `ghost\.js`, Confidence: 0.9, Description: "Ghost JavaScript"},
		{Pattern: `ghost-admin`, Confidence: 0.9, Description: "Ghost admin"},
	}

	// Drupal
	td.signatures["Drupal"] = []TechSignature{
		{Pattern: `drupal`, Confidence: 0.8, Description: "Drupal CMS"},
		{Pattern: `drupal\.js`, Confidence: 0.9, Description: "Drupal JavaScript"},
		{Pattern: `Drupal\.settings`, Confidence: 0.9, Description: "Drupal settings"},
	}

	// Joomla
	td.signatures["Joomla"] = []TechSignature{
		{Pattern: `joomla`, Confidence: 0.8, Description: "Joomla CMS"},
		{Pattern: `joomla\.js`, Confidence: 0.9, Description: "Joomla JavaScript"},
		{Pattern: `Joomla!`, Confidence: 0.9, Description: "Joomla signature"},
	}

	// Magento
	td.signatures["Magento"] = []TechSignature{
		{Pattern: `magento`, Confidence: 0.8, Description: "Magento e-commerce"},
		{Pattern: `magento\.js`, Confidence: 0.9, Description: "Magento JavaScript"},
		{Pattern: `Mage\.`, Confidence: 0.9, Description: "Magento core"},
	}

	// Shopify
	td.signatures["Shopify"] = []TechSignature{
		{Pattern: `shopify`, Confidence: 0.8, Description: "Shopify e-commerce"},
		{Pattern: `shopify\.js`, Confidence: 0.9, Description: "Shopify JavaScript"},
		{Pattern: `myshopify\.com`, Confidence: 0.9, Description: "Shopify domain"},
	}

	// WooCommerce
	td.signatures["WooCommerce"] = []TechSignature{
		{Pattern: `woocommerce`, Confidence: 0.8, Description: "WooCommerce plugin"},
		{Pattern: `woocommerce\.js`, Confidence: 0.9, Description: "WooCommerce JavaScript"},
		{Pattern: `wc-`, Confidence: 0.8, Description: "WooCommerce classes"},
	}

	// PrestaShop
	td.signatures["PrestaShop"] = []TechSignature{
		{Pattern: `prestashop`, Confidence: 0.8, Description: "PrestaShop e-commerce"},
		{Pattern: `prestashop\.js`, Confidence: 0.9, Description: "PrestaShop JavaScript"},
		{Pattern: `PrestaShop`, Confidence: 0.9, Description: "PrestaShop signature"},
	}

	// OpenCart
	td.signatures["OpenCart"] = []TechSignature{
		{Pattern: `opencart`, Confidence: 0.8, Description: "OpenCart e-commerce"},
		{Pattern: `opencart\.js`, Confidence: 0.9, Description: "OpenCart JavaScript"},
		{Pattern: `OpenCart`, Confidence: 0.9, Description: "OpenCart signature"},
	}

	// BigCommerce
	td.signatures["BigCommerce"] = []TechSignature{
		{Pattern: `bigcommerce`, Confidence: 0.8, Description: "BigCommerce e-commerce"},
		{Pattern: `bigcommerce\.js`, Confidence: 0.9, Description: "BigCommerce JavaScript"},
		{Pattern: `bigcommerce\.com`, Confidence: 0.9, Description: "BigCommerce domain"},
	}

	// Salesforce
	td.signatures["Salesforce"] = []TechSignature{
		{Pattern: `salesforce`, Confidence: 0.8, Description: "Salesforce CRM"},
		{Pattern: `force\.com`, Confidence: 0.9, Description: "Salesforce domain"},
		{Pattern: `salesforce\.js`, Confidence: 0.9, Description: "Salesforce JavaScript"},
	}

	// HubSpot
	td.signatures["HubSpot"] = []TechSignature{
		{Pattern: `hubspot`, Confidence: 0.8, Description: "HubSpot marketing"},
		{Pattern: `hubspot\.com`, Confidence: 0.9, Description: "HubSpot domain"},
		{Pattern: `hubspot\.js`, Confidence: 0.9, Description: "HubSpot JavaScript"},
	}

	// Mailchimp
	td.signatures["Mailchimp"] = []TechSignature{
		{Pattern: `mailchimp`, Confidence: 0.8, Description: "Mailchimp email marketing"},
		{Pattern: `mailchimp\.com`, Confidence: 0.9, Description: "Mailchimp domain"},
		{Pattern: `mailchimp\.js`, Confidence: 0.9, Description: "Mailchimp JavaScript"},
	}

	// Google Analytics
	td.signatures["Google Analytics"] = []TechSignature{
		{Pattern: `google-analytics`, Confidence: 0.8, Description: "Google Analytics"},
		{Pattern: `gtag`, Confidence: 0.9, Description: "Google Analytics gtag"},
		{Pattern: `ga\(`, Confidence: 0.9, Description: "Google Analytics function"},
		{Pattern: `analytics\.google\.com`, Confidence: 0.9, Description: "Google Analytics domain"},
	}

	// Google Tag Manager
	td.signatures["Google Tag Manager"] = []TechSignature{
		{Pattern: `googletagmanager`, Confidence: 0.8, Description: "Google Tag Manager"},
		{Pattern: `gtm`, Confidence: 0.9, Description: "Google Tag Manager"},
		{Pattern: `googletagmanager\.com`, Confidence: 0.9, Description: "Google Tag Manager domain"},
	}

	// Facebook Pixel
	td.signatures["Facebook Pixel"] = []TechSignature{
		{Pattern: `facebook`, Confidence: 0.8, Description: "Facebook integration"},
		{Pattern: `fbq`, Confidence: 0.9, Description: "Facebook Pixel"},
		{Pattern: `facebook\.com`, Confidence: 0.9, Description: "Facebook domain"},
	}

	// Hotjar
	td.signatures["Hotjar"] = []TechSignature{
		{Pattern: `hotjar`, Confidence: 0.8, Description: "Hotjar analytics"},
		{Pattern: `hjsv`, Confidence: 0.9, Description: "Hotjar script"},
		{Pattern: `hotjar\.com`, Confidence: 0.9, Description: "Hotjar domain"},
	}

	// Mixpanel
	td.signatures["Mixpanel"] = []TechSignature{
		{Pattern: `mixpanel`, Confidence: 0.8, Description: "Mixpanel analytics"},
		{Pattern: `mixpanel\.com`, Confidence: 0.9, Description: "Mixpanel domain"},
		{Pattern: `mixpanel\.js`, Confidence: 0.9, Description: "Mixpanel JavaScript"},
	}

	// Segment
	td.signatures["Segment"] = []TechSignature{
		{Pattern: `segment`, Confidence: 0.8, Description: "Segment analytics"},
		{Pattern: `segment\.com`, Confidence: 0.9, Description: "Segment domain"},
		{Pattern: `analytics\.segment\.com`, Confidence: 0.9, Description: "Segment analytics"},
	}

	// Amplitude
	td.signatures["Amplitude"] = []TechSignature{
		{Pattern: `amplitude`, Confidence: 0.8, Description: "Amplitude analytics"},
		{Pattern: `amplitude\.com`, Confidence: 0.9, Description: "Amplitude domain"},
		{Pattern: `amplitude\.js`, Confidence: 0.9, Description: "Amplitude JavaScript"},
	}

	// Sentry
	td.signatures["Sentry"] = []TechSignature{
		{Pattern: `sentry`, Confidence: 0.8, Description: "Sentry error tracking"},
		{Pattern: `sentry\.io`, Confidence: 0.9, Description: "Sentry domain"},
		{Pattern: `sentry\.js`, Confidence: 0.9, Description: "Sentry JavaScript"},
	}

	// LogRocket
	td.signatures["LogRocket"] = []TechSignature{
		{Pattern: `logrocket`, Confidence: 0.8, Description: "LogRocket session replay"},
		{Pattern: `logrocket\.io`, Confidence: 0.9, Description: "LogRocket domain"},
		{Pattern: `logrocket\.js`, Confidence: 0.9, Description: "LogRocket JavaScript"},
	}

	// Bugsnag
	td.signatures["Bugsnag"] = []TechSignature{
		{Pattern: `bugsnag`, Confidence: 0.8, Description: "Bugsnag error tracking"},
		{Pattern: `bugsnag\.com`, Confidence: 0.9, Description: "Bugsnag domain"},
		{Pattern: `bugsnag\.js`, Confidence: 0.9, Description: "Bugsnag JavaScript"},
	}

	// Rollbar
	td.signatures["Rollbar"] = []TechSignature{
		{Pattern: `rollbar`, Confidence: 0.8, Description: "Rollbar error tracking"},
		{Pattern: `rollbar\.com`, Confidence: 0.9, Description: "Rollbar domain"},
		{Pattern: `rollbar\.js`, Confidence: 0.9, Description: "Rollbar JavaScript"},
	}

	// DataDog
	td.signatures["DataDog"] = []TechSignature{
		{Pattern: `datadog`, Confidence: 0.8, Description: "DataDog monitoring"},
		{Pattern: `datadoghq\.com`, Confidence: 0.9, Description: "DataDog domain"},
		{Pattern: `datadog\.js`, Confidence: 0.9, Description: "DataDog JavaScript"},
	}

	// New Relic
	td.signatures["New Relic"] = []TechSignature{
		{Pattern: `newrelic`, Confidence: 0.8, Description: "New Relic monitoring"},
		{Pattern: `newrelic\.com`, Confidence: 0.9, Description: "New Relic domain"},
		{Pattern: `newrelic\.js`, Confidence: 0.9, Description: "New Relic JavaScript"},
	}

	// AppDynamics
	td.signatures["AppDynamics"] = []TechSignature{
		{Pattern: `appdynamics`, Confidence: 0.8, Description: "AppDynamics monitoring"},
		{Pattern: `appdynamics\.com`, Confidence: 0.9, Description: "AppDynamics domain"},
		{Pattern: `appdynamics\.js`, Confidence: 0.9, Description: "AppDynamics JavaScript"},
	}

	// Dynatrace
	td.signatures["Dynatrace"] = []TechSignature{
		{Pattern: `dynatrace`, Confidence: 0.8, Description: "Dynatrace monitoring"},
		{Pattern: `dynatrace\.com`, Confidence: 0.9, Description: "Dynatrace domain"},
		{Pattern: `dynatrace\.js`, Confidence: 0.9, Description: "Dynatrace JavaScript"},
	}

	// Pingdom
	td.signatures["Pingdom"] = []TechSignature{
		{Pattern: `pingdom`, Confidence: 0.8, Description: "Pingdom monitoring"},
		{Pattern: `pingdom\.com`, Confidence: 0.9, Description: "Pingdom domain"},
		{Pattern: `pingdom\.js`, Confidence: 0.9, Description: "Pingdom JavaScript"},
	}

	// UptimeRobot
	td.signatures["UptimeRobot"] = []TechSignature{
		{Pattern: `uptimerobot`, Confidence: 0.8, Description: "UptimeRobot monitoring"},
		{Pattern: `uptimerobot\.com`, Confidence: 0.9, Description: "UptimeRobot domain"},
		{Pattern: `uptimerobot\.js`, Confidence: 0.9, Description: "UptimeRobot JavaScript"},
	}

	// StatusPage
	td.signatures["StatusPage"] = []TechSignature{
		{Pattern: `statuspage`, Confidence: 0.8, Description: "StatusPage status"},
		{Pattern: `statuspage\.io`, Confidence: 0.9, Description: "StatusPage domain"},
		{Pattern: `statuspage\.js`, Confidence: 0.9, Description: "StatusPage JavaScript"},
	}

	// Intercom
	td.signatures["Intercom"] = []TechSignature{
		{Pattern: `intercom`, Confidence: 0.8, Description: "Intercom chat"},
		{Pattern: `intercom\.io`, Confidence: 0.9, Description: "Intercom domain"},
		{Pattern: `intercom\.js`, Confidence: 0.9, Description: "Intercom JavaScript"},
	}

	// Drift
	td.signatures["Drift"] = []TechSignature{
		{Pattern: `drift`, Confidence: 0.8, Description: "Drift chat"},
		{Pattern: `drift\.com`, Confidence: 0.9, Description: "Drift domain"},
		{Pattern: `drift\.js`, Confidence: 0.9, Description: "Drift JavaScript"},
	}

	// Zendesk
	td.signatures["Zendesk"] = []TechSignature{
		{Pattern: `zendesk`, Confidence: 0.8, Description: "Zendesk support"},
		{Pattern: `zendesk\.com`, Confidence: 0.9, Description: "Zendesk domain"},
		{Pattern: `zendesk\.js`, Confidence: 0.9, Description: "Zendesk JavaScript"},
	}

	// Freshdesk
	td.signatures["Freshdesk"] = []TechSignature{
		{Pattern: `freshdesk`, Confidence: 0.8, Description: "Freshdesk support"},
		{Pattern: `freshdesk\.com`, Confidence: 0.9, Description: "Freshdesk domain"},
		{Pattern: `freshdesk\.js`, Confidence: 0.9, Description: "Freshdesk JavaScript"},
	}

	// Help Scout
	td.signatures["Help Scout"] = []TechSignature{
		{Pattern: `helpscout`, Confidence: 0.8, Description: "Help Scout support"},
		{Pattern: `helpscout\.com`, Confidence: 0.9, Description: "Help Scout domain"},
		{Pattern: `helpscout\.js`, Confidence: 0.9, Description: "Help Scout JavaScript"},
	}

	// Canny
	td.signatures["Canny"] = []TechSignature{
		{Pattern: `canny`, Confidence: 0.8, Description: "Canny feedback"},
		{Pattern: `canny\.io`, Confidence: 0.9, Description: "Canny domain"},
		{Pattern: `canny\.js`, Confidence: 0.9, Description: "Canny JavaScript"},
	}

	// UserVoice
	td.signatures["UserVoice"] = []TechSignature{
		{Pattern: `uservoice`, Confidence: 0.8, Description: "UserVoice feedback"},
		{Pattern: `uservoice\.com`, Confidence: 0.9, Description: "UserVoice domain"},
		{Pattern: `uservoice\.js`, Confidence: 0.9, Description: "UserVoice JavaScript"},
	}

	// Typeform
	td.signatures["Typeform"] = []TechSignature{
		{Pattern: `typeform`, Confidence: 0.8, Description: "Typeform forms"},
		{Pattern: `typeform\.com`, Confidence: 0.9, Description: "Typeform domain"},
		{Pattern: `typeform\.js`, Confidence: 0.9, Description: "Typeform JavaScript"},
	}

	// SurveyMonkey
	td.signatures["SurveyMonkey"] = []TechSignature{
		{Pattern: `surveymonkey`, Confidence: 0.8, Description: "SurveyMonkey surveys"},
		{Pattern: `surveymonkey\.com`, Confidence: 0.9, Description: "SurveyMonkey domain"},
		{Pattern: `surveymonkey\.js`, Confidence: 0.9, Description: "SurveyMonkey JavaScript"},
	}

	// Google Forms
	td.signatures["Google Forms"] = []TechSignature{
		{Pattern: `google\.com/forms`, Confidence: 0.9, Description: "Google Forms"},
		{Pattern: `docs\.google\.com/forms`, Confidence: 0.9, Description: "Google Forms domain"},
	}

	// Microsoft Forms
	td.signatures["Microsoft Forms"] = []TechSignature{
		{Pattern: `forms\.office\.com`, Confidence: 0.9, Description: "Microsoft Forms"},
		{Pattern: `forms\.microsoft\.com`, Confidence: 0.9, Description: "Microsoft Forms domain"},
	}

	// Calendly
	td.signatures["Calendly"] = []TechSignature{
		{Pattern: `calendly`, Confidence: 0.8, Description: "Calendly scheduling"},
		{Pattern: `calendly\.com`, Confidence: 0.9, Description: "Calendly domain"},
		{Pattern: `calendly\.js`, Confidence: 0.9, Description: "Calendly JavaScript"},
	}

	// Acuity Scheduling
	td.signatures["Acuity Scheduling"] = []TechSignature{
		{Pattern: `acuityscheduling`, Confidence: 0.8, Description: "Acuity Scheduling"},
		{Pattern: `acuityscheduling\.com`, Confidence: 0.9, Description: "Acuity Scheduling domain"},
		{Pattern: `acuityscheduling\.js`, Confidence: 0.9, Description: "Acuity Scheduling JavaScript"},
	}

	// Stripe
	td.signatures["Stripe"] = []TechSignature{
		{Pattern: `stripe`, Confidence: 0.8, Description: "Stripe payments"},
		{Pattern: `stripe\.com`, Confidence: 0.9, Description: "Stripe domain"},
		{Pattern: `stripe\.js`, Confidence: 0.9, Description: "Stripe JavaScript"},
	}

	// PayPal
	td.signatures["PayPal"] = []TechSignature{
		{Pattern: `paypal`, Confidence: 0.8, Description: "PayPal payments"},
		{Pattern: `paypal\.com`, Confidence: 0.9, Description: "PayPal domain"},
		{Pattern: `paypal\.js`, Confidence: 0.9, Description: "PayPal JavaScript"},
	}

	// Square
	td.signatures["Square"] = []TechSignature{
		{Pattern: `square`, Confidence: 0.8, Description: "Square payments"},
		{Pattern: `square\.com`, Confidence: 0.9, Description: "Square domain"},
		{Pattern: `square\.js`, Confidence: 0.9, Description: "Square JavaScript"},
	}

	// Braintree
	td.signatures["Braintree"] = []TechSignature{
		{Pattern: `braintree`, Confidence: 0.8, Description: "Braintree payments"},
		{Pattern: `braintreegateway\.com`, Confidence: 0.9, Description: "Braintree domain"},
		{Pattern: `braintree\.js`, Confidence: 0.9, Description: "Braintree JavaScript"},
	}

	// Adyen
	td.signatures["Adyen"] = []TechSignature{
		{Pattern: `adyen`, Confidence: 0.8, Description: "Adyen payments"},
		{Pattern: `adyen\.com`, Confidence: 0.9, Description: "Adyen domain"},
		{Pattern: `adyen\.js`, Confidence: 0.9, Description: "Adyen JavaScript"},
	}

	// Klarna
	td.signatures["Klarna"] = []TechSignature{
		{Pattern: `klarna`, Confidence: 0.8, Description: "Klarna payments"},
		{Pattern: `klarna\.com`, Confidence: 0.9, Description: "Klarna domain"},
		{Pattern: `klarna\.js`, Confidence: 0.9, Description: "Klarna JavaScript"},
	}

	// Afterpay
	td.signatures["Afterpay"] = []TechSignature{
		{Pattern: `afterpay`, Confidence: 0.8, Description: "Afterpay payments"},
		{Pattern: `afterpay\.com`, Confidence: 0.9, Description: "Afterpay domain"},
		{Pattern: `afterpay\.js`, Confidence: 0.9, Description: "Afterpay JavaScript"},
	}

	// Affirm
	td.signatures["Affirm"] = []TechSignature{
		{Pattern: `affirm`, Confidence: 0.8, Description: "Affirm payments"},
		{Pattern: `affirm\.com`, Confidence: 0.9, Description: "Affirm domain"},
		{Pattern: `affirm\.js`, Confidence: 0.9, Description: "Affirm JavaScript"},
	}

	// Splitit
	td.signatures["Splitit"] = []TechSignature{
		{Pattern: `splitit`, Confidence: 0.8, Description: "Splitit payments"},
		{Pattern: `splitit\.com`, Confidence: 0.9, Description: "Splitit domain"},
		{Pattern: `splitit\.js`, Confidence: 0.9, Description: "Splitit JavaScript"},
	}

	// QuadPay
	td.signatures["QuadPay"] = []TechSignature{
		{Pattern: `quadpay`, Confidence: 0.8, Description: "QuadPay payments"},
		{Pattern: `quadpay\.com`, Confidence: 0.9, Description: "QuadPay domain"},
		{Pattern: `quadpay\.js`, Confidence: 0.9, Description: "QuadPay JavaScript"},
	}

	// Sezzle
	td.signatures["Sezzle"] = []TechSignature{
		{Pattern: `sezzle`, Confidence: 0.8, Description: "Sezzle payments"},
		{Pattern: `sezzle\.com`, Confidence: 0.9, Description: "Sezzle domain"},
		{Pattern: `sezzle\.js`, Confidence: 0.9, Description: "Sezzle JavaScript"},
	}

	// Zip
	td.signatures["Zip"] = []TechSignature{
		{Pattern: `zip`, Confidence: 0.8, Description: "Zip payments"},
		{Pattern: `zip\.co`, Confidence: 0.9, Description: "Zip domain"},
		{Pattern: `zip\.js`, Confidence: 0.9, Description: "Zip JavaScript"},
	}

	// Laybuy
	td.signatures["Laybuy"] = []TechSignature{
		{Pattern: `laybuy`, Confidence: 0.8, Description: "Laybuy payments"},
		{Pattern: `laybuy\.com`, Confidence: 0.9, Description: "Laybuy domain"},
		{Pattern: `laybuy\.js`, Confidence: 0.9, Description: "Laybuy JavaScript"},
	}

	// Humm
	td.signatures["Humm"] = []TechSignature{
		{Pattern: `humm`, Confidence: 0.8, Description: "Humm payments"},
		{Pattern: `humm\.com`, Confidence: 0.9, Description: "Humm domain"},
		{Pattern: `humm\.js`, Confidence: 0.9, Description: "Humm JavaScript"},
	}

	// Openpay
	td.signatures["Openpay"] = []TechSignature{
		{Pattern: `openpay`, Confidence: 0.8, Description: "Openpay payments"},
		{Pattern: `openpay\.com`, Confidence: 0.9, Description: "Openpay domain"},
		{Pattern: `openpay\.js`, Confidence: 0.9, Description: "Openpay JavaScript"},
	}

	// LatitudePay
	td.signatures["LatitudePay"] = []TechSignature{
		{Pattern: `latitudepay`, Confidence: 0.8, Description: "LatitudePay payments"},
		{Pattern: `latitudepay\.com`, Confidence: 0.9, Description: "LatitudePay domain"},
		{Pattern: `latitudepay\.js`, Confidence: 0.9, Description: "LatitudePay JavaScript"},
	}

	// Scalapay
	td.signatures["Scalapay"] = []TechSignature{
		{Pattern: `scalapay`, Confidence: 0.8, Description: "Scalapay payments"},
		{Pattern: `scalapay\.com`, Confidence: 0.9, Description: "Scalapay domain"},
		{Pattern: `scalapay\.js`, Confidence: 0.9, Description: "Scalapay JavaScript"},
	}

	// Clearpay
	td.signatures["Clearpay"] = []TechSignature{
		{Pattern: `clearpay`, Confidence: 0.8, Description: "Clearpay payments"},
		{Pattern: `clearpay\.com`, Confidence: 0.9, Description: "Clearpay domain"},
		{Pattern: `clearpay\.js`, Confidence: 0.9, Description: "Clearpay JavaScript"},
	}

	// Laybuy
	td.signatures["Laybuy"] = []TechSignature{
		{Pattern: `laybuy`, Confidence: 0.8, Description: "Laybuy payments"},
		{Pattern: `laybuy\.com`, Confidence: 0.9, Description: "Laybuy domain"},
		{Pattern: `laybuy\.js`, Confidence: 0.9, Description: "Laybuy JavaScript"},
	}

	// Humm
	td.signatures["Humm"] = []TechSignature{
		{Pattern: `humm`, Confidence: 0.8, Description: "Humm payments"},
		{Pattern: `humm\.com`, Confidence: 0.9, Description: "Humm domain"},
		{Pattern: `humm\.js`, Confidence: 0.9, Description: "Humm JavaScript"},
	}

	// Openpay
	td.signatures["Openpay"] = []TechSignature{
		{Pattern: `openpay`, Confidence: 0.8, Description: "Openpay payments"},
		{Pattern: `openpay\.com`, Confidence: 0.9, Description: "Openpay domain"},
		{Pattern: `openpay\.js`, Confidence: 0.9, Description: "Openpay JavaScript"},
	}

	// LatitudePay
	td.signatures["LatitudePay"] = []TechSignature{
		{Pattern: `latitudepay`, Confidence: 0.8, Description: "LatitudePay payments"},
		{Pattern: `latitudepay\.com`, Confidence: 0.9, Description: "LatitudePay domain"},
		{Pattern: `latitudepay\.js`, Confidence: 0.9, Description: "LatitudePay JavaScript"},
	}

	// Scalapay
	td.signatures["Scalapay"] = []TechSignature{
		{Pattern: `scalapay`, Confidence: 0.8, Description: "Scalapay payments"},
		{Pattern: `scalapay\.com`, Confidence: 0.9, Description: "Scalapay domain"},
		{Pattern: `scalapay\.js`, Confidence: 0.9, Description: "Scalapay JavaScript"},
	}

	// Clearpay
	td.signatures["Clearpay"] = []TechSignature{
		{Pattern: `clearpay`, Confidence: 0.8, Description: "Clearpay payments"},
		{Pattern: `clearpay\.com`, Confidence: 0.9, Description: "Clearpay domain"},
		{Pattern: `clearpay\.js`, Confidence: 0.9, Description: "Clearpay JavaScript"},
	}

	// React
	td.signatures["React"] = []TechSignature{
		{Pattern: `react`, Confidence: 0.7, Description: "React library"},
		{Pattern: `react-dom`, Confidence: 0.8, Description: "React DOM"},
		{Pattern: `__REACT_DEVTOOLS_GLOBAL_HOOK__`, Confidence: 0.9, Description: "React DevTools"},
	}

	// Angular
	td.signatures["Angular"] = []TechSignature{
		{Pattern: `ng-app`, Confidence: 0.8, Description: "Angular app directive"},
		{Pattern: `angular`, Confidence: 0.7, Description: "Angular library"},
		{Pattern: `ng-controller`, Confidence: 0.9, Description: "Angular controller"},
	}

	// Vue.js
	td.signatures["Vue.js"] = []TechSignature{
		{Pattern: `vue`, Confidence: 0.7, Description: "Vue.js library"},
		{Pattern: `v-`, Confidence: 0.8, Description: "Vue.js directives"},
		{Pattern: `__VUE__`, Confidence: 0.9, Description: "Vue.js global"},
	}

	// Bootstrap
	td.signatures["Bootstrap"] = []TechSignature{
		{Pattern: `bootstrap`, Confidence: 0.8, Description: "Bootstrap CSS framework"},
		{Pattern: `bootstrap\.css`, Confidence: 0.9, Description: "Bootstrap CSS file"},
		{Pattern: `bootstrap\.js`, Confidence: 0.9, Description: "Bootstrap JavaScript file"},
	}

	// jQuery
	td.signatures["jQuery"] = []TechSignature{
		{Pattern: `jquery`, Confidence: 0.8, Description: "jQuery library"},
		{Pattern: `\$\(`, Confidence: 0.7, Description: "jQuery selector"},
	}

	// Node.js
	td.signatures["Node.js"] = []TechSignature{
		{Pattern: `node`, Confidence: 0.7, Description: "Node.js"},
		{Pattern: `express`, Confidence: 0.8, Description: "Express.js framework"},
	}

	// Laravel
	td.signatures["Laravel"] = []TechSignature{
		{Pattern: `laravel`, Confidence: 0.8, Description: "Laravel PHP framework"},
		{Pattern: `csrf-token`, Confidence: 0.9, Description: "Laravel CSRF token"},
	}

	// Django
	td.signatures["Django"] = []TechSignature{
		{Pattern: `django`, Confidence: 0.8, Description: "Django Python framework"},
		{Pattern: `csrfmiddlewaretoken`, Confidence: 0.9, Description: "Django CSRF token"},
	}

	// Flask
	td.signatures["Flask"] = []TechSignature{
		{Pattern: `flask`, Confidence: 0.8, Description: "Flask Python framework"},
		{Pattern: `werkzeug`, Confidence: 0.9, Description: "Werkzeug WSGI library"},
	}

	for tech, signatures := range td.signatures {
		for i, sig := range signatures {
			if sig.Pattern != "" {
				td.signatures[tech][i].Regex = regexp.MustCompile(sig.Pattern)
			}
		}
	}
}
