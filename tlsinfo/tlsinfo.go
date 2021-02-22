package tlsinfo

import (
	"crypto/tls"
	"fmt"
)

func TlsInfo(c *tls.Conn) string {
	tlsVer := ""
	switch c.ConnectionState().Version {
	case tls.VersionSSL30:
		tlsVer = "sslv3"
	case tls.VersionTLS10:
		tlsVer = "tls1.0"
	case tls.VersionTLS11:
		tlsVer = "tls1.1"
	case tls.VersionTLS12:
		tlsVer = "tls1.2"
	case tls.VersionTLS13:
		tlsVer = "tls1.3"
	}
	tlsCypher := tls.CipherSuiteName(c.ConnectionState().CipherSuite)
	return fmt.Sprintf("version=%s,cypher=%s", tlsVer, tlsCypher)

}