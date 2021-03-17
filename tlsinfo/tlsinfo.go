package tlsinfo

import (
	"crypto/tls"
	"fmt"
)

func TlsInfo(c *tls.Conn) string {
	tlsVer := ""
	switch c.ConnectionState().Version {
	//lint:ignore SA1019 ssl reporting
	case tls.VersionSSL30:
		tlsVer = "SSLv3"
	case tls.VersionTLS10:
		tlsVer = "TLS1.0"
	case tls.VersionTLS11:
		tlsVer = "TLS1.1"
	case tls.VersionTLS12:
		tlsVer = "TLS1.2"
	case tls.VersionTLS13:
		tlsVer = "TSL1.3"
	}
	tlsCypher := tls.CipherSuiteName(c.ConnectionState().CipherSuite)
	return fmt.Sprintf("version=%s,cypher=%s", tlsVer, tlsCypher)

}
