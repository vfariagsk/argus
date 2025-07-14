# Argus 👁️

**Subdomain Intelligence Scanner for Red Teams & Offensive Recon**

Argus is a high-fidelity subdomain scanner and analyzer built for penetration testers, red teams, and security researchers. Unlike traditional subdomain brute-forcers, Argus combines multiple discovery methods with DNS enrichment, HTTP & TLS fingerprinting, stack inference, and vulnerability heuristics to provide actionable reconnaissance results in structured reports.

---

## 🔍 What Argus Does

### Subdomain Discovery
Argus performs multi-source subdomain enumeration using:
- **Certificate Transparency logs** (e.g. crt.sh)
- **Wordlist-based DNS bruteforce**
- **Passive reconnaissance APIs** (e.g. DNSDumpster, RapidDNS)
- **Target URL parsing** (e.g. from JavaScript, `robots.txt`, etc.)

### DNS Resolution & Fingerprinting
For each subdomain:
- Resolves **A**, **AAAA**, **CNAME**, **TXT**, and **NS** records
- Detects:
  - **CNAMEs pointing to cloud services** (AWS, Heroku, Vercel, etc.)
  - **Takeover opportunities** based on known patterns
  - **Wildcard DNS** and parked domains
  - **Public vs. private IP** allocation

### HTTP & HTTPS Fingerprinting
Argus connects to live subdomains and extracts:
- **Status code, redirect chains, traceroute, response size, cookie details**
- **Page title, detected framework markers, favicon hash**
- **Response headers** (Server, X-Powered-By, Set-Cookie, etc.)
- **Security header analysis** (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, etc.)
- **Technology stack inference** via response signatures, headers and source code patterns
- **Exposure of sensitive files** (robots.txt, .git/, .env, etc.)

### TLS/SSL Intelligence
If HTTPS is available, Argus parses:
- **Certificate subject and issuer**
- **SAN entries**
- **Signature algorithm**
- **Self-signed / expired certs**
- **Mismatch between cert and hostname**

### Stack & Vulnerability Heuristics
- **Infers web technologies** (Apache, Nginx, React, Laravel, etc.)
- Detects:
  - **Admin panels**
  - **Login portals**
  - **Debug endpoints**
  - **Dev/staging environments**
- Evaluates:
  - Missing security headers
  - Open redirects
  - Staging indicators in content

---

## 🧠 Intelligence Summary

| Feature | Description |
|--------|-------------|
| 🔎 Subdomain Discovery | CT logs, brute force, APIs |
| 🌐 DNS Resolution | A, CNAME, TXT, NS records |
| 🛰️ Infra Awareness | Cloud provider inference, takeover detection |
| 🧭 HTTP Fingerprint | Headers, title, status code, favicon |
| 🔐 TLS Scan | Cert issuer, expiry, SANs |
| 🧱 Stack Detection | Web server & tech fingerprint |
| ⚠️ Risk Analysis | Exposure heuristics & redirect logic |
| 📊 Output | JSON, Markdown, or console (or both) |

---

## 💡 Use Cases

- **Surface mapping of large orgs**
- **Bug bounty recon**
- **Automated staging/prod drift detection**
- **Finding forgotten infrastructure**
- **Fingerprinting cloud services and CDNs**

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/argus.git
cd argus

# Install
chmod +x install.sh
./install.sh
```

## 📖 Usage
### Basic Scan
```bash
argus scan example.com
```
### Output Options
```bash
argus scan example.com --output json        # JSON output
argus scan example.com --output markdown    # Markdown table
argus scan example.com --output both        # Console + JSON
``` 

### Command-Specific Workflows

#### Subdomain Discovery Only
```bash
# Discover subdomains and export to raw text
argus subs example.com --threads 100 --output-dir ./results
```

#### DNS Resolution Only
```bash
# Resolve subdomains to IPs only (no HTTP validation)
argus resolve example.com subdomains.txt --type ip --threads 50
```

#### HTTP Validation Only
```bash
# Resolve subdomains and validate HTTP/HTTPS connectivity
argus resolve example.com subdomains.txt --type url --threads 50
```

#### Full Resolution (IPs + HTTP)
```bash
# Resolve to IPs and validate HTTP/HTTPS (default)
argus resolve example.com subdomains.txt --type both --threads 50
```

#### HTTP Fingerprinting
```bash
# Perform detailed HTTP fingerprinting on resolved hosts
argus http example.com resolved_urls.txt --format json --output-dir ./results
```

### Customization Options

```bash
argus scan example.com \
  --threads 50 \
  --wordlist ./assets/common_subs.txt \
  --timeout 5s \
  --takeover-check \
  --tech-detect \
  --screenshot
```

## 📊 Example JSON Output
```json
{
  "domain": "example.com",
  "discovered_subdomains": [
    {
      "host": "staging.example.com",
      "ip": "34.229.12.11",
      "dns": {
        "a_record": "34.229.12.11",
        "cname": "example-staging.elasticbeanstalk.com",
        "provider": "AWS",
        "takeover_risk": true
      },
      "http": {
        "status": 200,
        "title": "Example API - Staging",
        "headers": {
          "server": "nginx",
          "x-powered-by": "Express"
        },
        "tech_stack": ["Node.js", "Express", "Nginx"]
      },
      "tls": {
        "issuer": "Let's Encrypt",
        "valid_from": "2024-01-01",
        "valid_to": "2024-03-31",
        "subject": "staging.example.com"
      },
      "risk_flags": [
        "CNAME takeover risk",
        "Environment indicator: staging",
        "Missing CSP and X-Frame-Options headers"
      ]
    }
  ],
  "summary": {
    "total_subdomains": 14,
    "http_responding": 9,
    "https_enabled": 6,
    "takeover_risks": 2
  }
}
```
## 📁 Project Structure
```graphql
argus/
├── cmd/                # CLI entrypoints (cobra commands)
├── internal/
│   ├── discovery/      # Subdomain enumeration logic
│   ├── dns/            # DNS resolution and analysis
│   ├── http/           # HTTP scanning, fingerprinting
│   ├── tls/            # TLS/SSL analysis
│   ├── tech/           # Tech stack and header heuristics
│   ├── risk/           # Risk detection (takeover, misconfig)
│   ├── report/         # Output formatting (json, markdown)
│   └── utils/          # Common functions
├── assets/             # Wordlists and fingerprint data
├── configs/            # Default config and thresholds
├── go.mod
└── main.go
```

## 🔧 Configuration
Use CLI flags or edit default config in configs/default.go.

Configurable:

- Concurrency
- Wordlist
- Timeout per request
- Output format
- Headers of interest
- Takeover fingerprints
- TLS check depth

## ⚠️ Disclaimer

This tool is designed for authorized security testing and research purposes only. Always ensure you have proper authorization before scanning any systems. The authors are not responsible for any misuse of this tool.

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/vfariag/peirce/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vfariag/peirce/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

**Made with ❤️ for the security community** 