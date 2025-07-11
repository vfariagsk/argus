package discovery

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type BruteForceDiscovery struct {
	client *dns.Client
	config DiscoveryConfig
}

func NewBruteForceDiscovery(config DiscoveryConfig) *BruteForceDiscovery {
	return &BruteForceDiscovery{
		client: &dns.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}
}

func (bf *BruteForceDiscovery) Name() string {
	return "DNS Brute Force"
}

func (bf *BruteForceDiscovery) Discover(domain string, config DiscoveryConfig) ([]Subdomain, error) {
	words, err := bf.loadWordlist(config.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	workerCount := config.Threads
	if workerCount <= 0 {
		workerCount = 10
	}

	jobs := make(chan string, len(words))
	results := make(chan Subdomain, len(words))
	errors := make(chan error, len(words))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go bf.worker(domain, jobs, results, errors, &wg)
	}

	go func() {
		defer close(jobs)
		for _, word := range words {
			jobs <- word
		}
	}()

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	var subdomains []Subdomain
	var errorList []string

	for subdomain := range results {
		subdomains = append(subdomains, subdomain)
	}

	for err := range errors {
		if err != nil {
			errorList = append(errorList, err.Error())
		}
	}

	if len(errorList) > 0 {
		fmt.Printf("Warning: %d errors during brute force\n", len(errorList))
	}

	return subdomains, nil
}

func (bf *BruteForceDiscovery) worker(domain string, jobs <-chan string, results chan<- Subdomain, errors chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	for word := range jobs {
		subdomain := fmt.Sprintf("%s.%s", word, domain)

		exists, recordType, err := bf.checkSubdomain(subdomain)
		if err != nil {
			errors <- fmt.Errorf("error checking %s: %w", subdomain, err)
			continue
		}

		if exists {
			results <- Subdomain{
				Host:         subdomain,
				Source:       "brute_force",
				DiscoveredAt: time.Now(),
				Metadata: map[string]string{
					"record_type": recordType,
				},
			}
		}
	}
}

func (bf *BruteForceDiscovery) checkSubdomain(subdomain string) (bool, string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeA)

	resp, _, err := bf.client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return false, "", err
	}

	if len(resp.Answer) > 0 {
		return true, "A", nil
	}

	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)
	resp, _, err = bf.client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return false, "", err
	}

	if len(resp.Answer) > 0 {
		return true, "CNAME", nil
	}

	msg.SetQuestion(dns.Fqdn(subdomain), dns.TypeAAAA)
	resp, _, err = bf.client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return false, "", err
	}

	if len(resp.Answer) > 0 {
		return true, "AAAA", nil
	}

	return false, "", nil
}

func (bf *BruteForceDiscovery) loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return bf.getDefaultWordlist(), nil
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

func (bf *BruteForceDiscovery) getDefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
		"cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
		"pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "remote",
		"ftp2", "web", "ns4", "api", "secure", "mobile", "cdn", "mta", "mx", "static",
		"support", "stage", "app", "media", "help", "apps", "download", "remote", "db",
		"mysql", "oracle", "sql", "backup", "old", "new", "beta", "alpha", "staging",
		"dev2", "test2", "demo", "portal", "internal", "private", "corp", "intranet",
		"office", "exchange", "owa", "lync", "skype", "meet", "video", "voip", "phone",
		"fax", "print", "printer", "scan", "scanner", "file", "files", "share", "shares",
		"storage", "backup", "archive", "logs", "log", "monitor", "monitoring", "status",
		"health", "metrics", "stats", "statistics", "analytics", "tracking", "track",
		"ads", "ad", "banner", "banners", "promo", "promos", "offer", "offers", "deal",
		"deals", "shop", "store", "cart", "checkout", "payment", "pay", "billing",
		"invoice", "order", "orders", "account", "accounts", "user", "users", "member",
		"members", "profile", "profiles", "settings", "config", "configuration",
		"setup", "install", "installation", "update", "updates", "upgrade", "upgrades",
		"patch", "patches", "hotfix", "hotfixes", "service", "services", "api",
		"rest", "soap", "graphql", "swagger", "docs", "documentation", "help",
		"support", "ticket", "tickets", "issue", "issues", "bug", "bugs", "report",
		"reports", "feedback", "contact", "about", "team", "careers", "jobs",
		"press", "media", "news", "blog", "articles", "post", "posts", "comment",
		"comments", "forum", "forums", "board", "boards", "chat", "irc", "discord",
		"slack", "telegram", "whatsapp", "wechat", "line", "kik", "snapchat",
		"instagram", "facebook", "twitter", "linkedin", "youtube", "vimeo",
		"twitch", "reddit", "pinterest", "tumblr", "flickr", "500px", "behance",
		"dribbble", "github", "gitlab", "bitbucket", "stackoverflow", "quora",
		"medium", "dev", "hashnode", "substack", "newsletter", "mailing",
		"email", "emails", "newsletter", "newsletters", "subscribe", "unsubscribe",
		"optin", "optout", "confirm", "verification", "verify", "validate",
		"validation", "activate", "activation", "register", "registration",
		"signup", "signin", "login", "logout", "auth", "authentication",
		"authorize", "authorization", "oauth", "saml", "ldap", "ad", "active",
		"directory", "kerberos", "radius", "tacacs", "cert", "certificate",
		"ssl", "tls", "https", "http", "ftp", "sftp", "ssh", "telnet", "rdp",
		"vnc", "teamviewer", "anydesk", "zoom", "webex", "gotomeeting",
		"joinme", "skype", "hangouts", "meet", "calendar", "schedule",
		"event", "events", "booking", "reservation", "appointment",
		"meeting", "conference", "webinar", "training", "course", "class",
		"lesson", "tutorial", "guide", "manual", "handbook", "faq", "q&a",
		"knowledge", "base", "wiki", "documentation", "docs", "help",
		"support", "assistance", "service", "services", "customer",
		"client", "clients", "customer", "customers", "user", "users",
		"member", "members", "subscriber", "subscribers", "premium",
		"vip", "gold", "silver", "bronze", "basic", "standard", "pro",
		"professional", "enterprise", "business", "corporate", "commercial",
		"personal", "individual", "family", "student", "academic",
		"education", "school", "university", "college", "institute",
		"organization", "org", "company", "corporation", "inc", "llc",
		"ltd", "limited", "partnership", "associates", "group", "team",
		"department", "division", "branch", "office", "location", "site",
		"facility", "building", "headquarters", "hq", "main", "primary",
		"secondary", "backup", "replica", "mirror", "copy", "clone",
		"duplicate", "alternate", "alternative", "other", "another",
		"extra", "additional", "supplementary", "complementary",
		"related", "associated", "connected", "linked", "integrated",
		"unified", "consolidated", "merged", "combined", "joint",
		"shared", "common", "public", "private", "internal", "external",
		"inbound", "outbound", "incoming", "outgoing", "inbound",
		"outbound", "incoming", "outgoing", "inbound", "outbound",
	}
}
