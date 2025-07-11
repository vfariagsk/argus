package resolve

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type TLSAnalyzer struct {
	config DNSConfig
}

func NewTLSAnalyzer(config DNSConfig) *TLSAnalyzer {
	return &TLSAnalyzer{
		config: config,
	}
}

func (ta *TLSAnalyzer) Analyze(host string) (*TLSInfo, error) {
	tlsInfo := &TLSInfo{
		Enabled: false,
	}

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       nil,
		CurvePreferences:   nil,
	})

	if err != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites:       nil,
			CurvePreferences:   nil,
		})
	}

	if err != nil {
		tlsInfo.Errors = append(tlsInfo.Errors, fmt.Sprintf("TLS connection failed: %v", err))
		return tlsInfo, nil
	}
	defer conn.Close()

	tlsInfo.Enabled = true

	state := conn.ConnectionState()
	tlsInfo.Version = getTLSVersion(state.Version)
	tlsInfo.PreferredCipher = tls.CipherSuiteName(state.CipherSuite)

	ta.analyzeSupportedConfigurations(host, tlsInfo)
	ta.analyzeCertificate(state, host, tlsInfo)
	ta.analyzeSecurityHeaders(host, tlsInfo)
	ta.calculateRiskScore(tlsInfo)

	return tlsInfo, nil
}

func (ta *TLSAnalyzer) analyzeSupportedConfigurations(host string, tlsInfo *TLSInfo) {
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

	for _, version := range versions {
		if ta.testTLSVersion(host, version) {
			tlsInfo.SupportedVersions = append(tlsInfo.SupportedVersions, getTLSVersion(version))
		}
	}

	cipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}

	for _, cipher := range cipherSuites {
		if ta.testCipherSuite(host, cipher) {
			cipherName := tls.CipherSuiteName(cipher)
			if cipherName != "" {
				tlsInfo.SupportedCiphers = append(tlsInfo.SupportedCiphers, cipherName)
			}
		}
	}

	curves := []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.X25519,
	}

	for _, curve := range curves {
		if ta.testCurve(host, curve) {
			tlsInfo.SupportedCurves = append(tlsInfo.SupportedCurves, curve.String())
		}
	}
}

func (ta *TLSAnalyzer) analyzeCertificate(state tls.ConnectionState, host string, tlsInfo *TLSInfo) {
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.Subject = cert.Subject.CommonName
		tlsInfo.Issuer = cert.Issuer.CommonName
		tlsInfo.ValidFrom = cert.NotBefore
		tlsInfo.ValidTo = cert.NotAfter
		tlsInfo.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		tlsInfo.KeySize = getKeySize(cert.PublicKey)
		tlsInfo.KeyType = getKeyType(cert.PublicKey)

		tlsInfo.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName

		now := time.Now()
		tlsInfo.Expired = now.After(cert.NotAfter) || now.Before(cert.NotBefore)
		tlsInfo.SANs = cert.DNSNames
		tlsInfo.Mismatch = !ta.verifyHostname(cert, host)

		for _, cert := range state.PeerCertificates {
			tlsInfo.CertificateChain = append(tlsInfo.CertificateChain, cert.Subject.CommonName)
		}

		if len(state.OCSPResponse) > 0 {
			tlsInfo.OCSPStapling = true
		}

		if tlsInfo.SelfSigned {
			tlsInfo.Errors = append(tlsInfo.Errors, "Self-signed certificate")
		}
		if tlsInfo.Expired {
			tlsInfo.Errors = append(tlsInfo.Errors, "Certificate expired or not yet valid")
		}
		if tlsInfo.Mismatch {
			tlsInfo.Errors = append(tlsInfo.Errors, "Hostname mismatch")
		}
	}
}

func (ta *TLSAnalyzer) analyzeSecurityHeaders(host string, tlsInfo *TLSInfo) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", ta.config.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	tlsInfo.SecurityHeaders = make(map[string]string)

	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
		"Public-Key-Pins",
		"Public-Key-Pins-Report-Only",
	}

	for _, header := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			tlsInfo.SecurityHeaders[header] = value

			if header == "Strict-Transport-Security" {
				tlsInfo.HSTS = true
			}

			if header == "Public-Key-Pins" || header == "Public-Key-Pins-Report-Only" {
				tlsInfo.HPKP = true
			}
		}
	}
}

func (ta *TLSAnalyzer) calculateRiskScore(tlsInfo *TLSInfo) {
	score := 0
	var factors []string

	weakVersions := []string{"TLS 1.0", "TLS 1.1"}
	for _, version := range tlsInfo.SupportedVersions {
		for _, weak := range weakVersions {
			if version == weak {
				score += 20
				factors = append(factors, fmt.Sprintf("Weak TLS version: %s", version))
				tlsInfo.DeprecatedVersions = append(tlsInfo.DeprecatedVersions, version)
			}
		}
	}

	weakCiphers := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
	}

	for _, cipher := range tlsInfo.SupportedCiphers {
		for _, weak := range weakCiphers {
			if strings.Contains(cipher, weak) {
				score += 15
				factors = append(factors, fmt.Sprintf("Weak cipher: %s", cipher))
				tlsInfo.WeakCiphers = append(tlsInfo.WeakCiphers, cipher)
			}
		}
	}

	if tlsInfo.SelfSigned {
		score += 25
		factors = append(factors, "Self-signed certificate")
	}
	if tlsInfo.Expired {
		score += 30
		factors = append(factors, "Expired certificate")
	}
	if tlsInfo.Mismatch {
		score += 20
		factors = append(factors, "Hostname mismatch")
	}

	if !tlsInfo.HSTS {
		score += 10
		factors = append(factors, "Missing HSTS header")
	}
	if !tlsInfo.OCSPStapling {
		score += 5
		factors = append(factors, "No OCSP stapling")
	}

	if len(tlsInfo.SupportedVersions) > 0 {
		hasTLS13 := false
		for _, version := range tlsInfo.SupportedVersions {
			if version == "TLS 1.3" {
				hasTLS13 = true
				break
			}
		}
		if !hasTLS13 {
			score += 10
			factors = append(factors, "TLS 1.3 not supported")
		}
	}

	tlsInfo.RiskScore = score
	tlsInfo.RiskFactors = factors
}

func (ta *TLSAnalyzer) testTLSVersion(host string, version uint16) bool {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	return conn.ConnectionState().Version == version
}

func (ta *TLSAnalyzer) testCipherSuite(host string, cipher uint16) bool {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{cipher},
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	return conn.ConnectionState().CipherSuite == cipher
}

func (ta *TLSAnalyzer) testCurve(host string, curve tls.CurveID) bool {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{curve},
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func getKeySize(key interface{}) int {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

func getKeyType(key interface{}) string {
	switch key.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	default:
		return "Unknown"
	}
}

func (ta *TLSAnalyzer) verifyHostname(cert *x509.Certificate, hostname string) bool {
	if cert.Subject.CommonName == hostname {
		return true
	}

	for _, san := range cert.DNSNames {
		if san == hostname {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			wildcardDomain := strings.TrimPrefix(san, "*.")
			if strings.HasSuffix(hostname, "."+wildcardDomain) {
				return true
			}
		}
	}

	return false
}
