package resolve

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
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
	})

	if err != nil {
		tlsInfo.Errors = append(tlsInfo.Errors, fmt.Sprintf("TLS connection failed: %v", err))
		return tlsInfo, nil
	}
	defer conn.Close()

	tlsInfo.Enabled = true

	state := conn.ConnectionState()
	tlsInfo.Version = getTLSVersion(state.Version)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.Subject = cert.Subject.CommonName
		tlsInfo.Issuer = cert.Issuer.CommonName
		tlsInfo.ValidFrom = cert.NotBefore
		tlsInfo.ValidTo = cert.NotAfter
		tlsInfo.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		tlsInfo.KeySize = getKeySize(cert.PublicKey)

		tlsInfo.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName

		now := time.Now()
		tlsInfo.Expired = now.After(cert.NotAfter) || now.Before(cert.NotBefore)
		tlsInfo.SANs = cert.DNSNames
		tlsInfo.Mismatch = !ta.verifyHostname(cert, host)

		if len(state.VerifiedChains) == 0 {
			tlsInfo.Errors = append(tlsInfo.Errors, "Certificate verification failed")
		}
	}

	return tlsInfo, nil
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
