package discovery

import (
	"fmt"
	"sync"
	"time"
)

type Orchestrator struct {
	methods []DiscoveryMethod
	config  DiscoveryConfig
}

func NewOrchestrator(config DiscoveryConfig) *Orchestrator {
	orchestrator := &Orchestrator{
		config: config,
	}

	if config.EnableCTLogs {
		orchestrator.methods = append(orchestrator.methods, NewCTLogsDiscovery(config.Timeout))
	}

	if config.EnableBruteForce {
		orchestrator.methods = append(orchestrator.methods, NewBruteForceDiscovery(config))
	}

	if config.EnableAPIs {
		orchestrator.methods = append(orchestrator.methods, NewPassiveDiscovery(config.Timeout))
	}

	if config.EnablePassive {
		orchestrator.methods = append(orchestrator.methods, NewURLParserDiscovery(config.Timeout))
	}

	return orchestrator
}

func (o *Orchestrator) Discover(domain string) (*DiscoveryResult, error) {
	startTime := time.Now()

	fmt.Printf("🔍 Starting subdomain discovery for: %s\n", domain)
	fmt.Printf("📋 Using %d discovery methods\n", len(o.methods))

	results := make(chan []Subdomain, len(o.methods))
	errors := make(chan error, len(o.methods))

	var wg sync.WaitGroup
	for _, method := range o.methods {
		wg.Add(1)
		go func(m DiscoveryMethod) {
			defer wg.Done()

			fmt.Printf("  🚀 Running %s...\n", m.Name())
			subdomains, err := m.Discover(domain, o.config)
			if err != nil {
				errors <- fmt.Errorf("%s failed: %w", m.Name(), err)
				return
			}

			fmt.Printf("  ✅ %s found %d subdomains\n", m.Name(), len(subdomains))
			results <- subdomains
		}(method)
	}

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	var allSubdomains []Subdomain
	var errorList []string
	seen := make(map[string]bool)

	for subdomains := range results {
		for _, subdomain := range subdomains {
			if !seen[subdomain.Host] {
				allSubdomains = append(allSubdomains, subdomain)
				seen[subdomain.Host] = true
			}
		}
	}

	for err := range errors {
		if err != nil {
			errorList = append(errorList, err.Error())
		}
	}

	duration := time.Since(startTime)

	result := &DiscoveryResult{
		Domain:     domain,
		Subdomains: allSubdomains,
		Total:      len(allSubdomains),
		Duration:   duration,
		Errors:     errorList,
	}

	fmt.Printf("\n📊 Discovery Summary:\n")
	fmt.Printf("  🎯 Domain: %s\n", result.Domain)
	fmt.Printf("  🔍 Total subdomains found: %d\n", result.Total)
	fmt.Printf("  ⏱️  Duration: %v\n", result.Duration)

	if len(result.Errors) > 0 {
		fmt.Printf("  ⚠️  Errors: %d\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("     - %s\n", err)
		}
	}

	sourceCount := make(map[string]int)
	for _, sub := range allSubdomains {
		sourceCount[sub.Source]++
	}

	fmt.Printf("  📈 By source:\n")
	for source, count := range sourceCount {
		fmt.Printf("     - %s: %d\n", source, count)
	}

	return result, nil
}

func (o *Orchestrator) GetMethodNames() []string {
	var names []string
	for _, method := range o.methods {
		names = append(names, method.Name())
	}
	return names
}

func (o *Orchestrator) GetConfig() DiscoveryConfig {
	return o.config
}

func (o *Orchestrator) SetConfig(config DiscoveryConfig) {
	o.config = config
	o.methods = nil

	if config.EnableCTLogs {
		o.methods = append(o.methods, NewCTLogsDiscovery(config.Timeout))
	}

	if config.EnableBruteForce {
		o.methods = append(o.methods, NewBruteForceDiscovery(config))
	}

	if config.EnableAPIs {
		o.methods = append(o.methods, NewPassiveDiscovery(config.Timeout))
	}

	if config.EnablePassive {
		o.methods = append(o.methods, NewURLParserDiscovery(config.Timeout))
	}
}
