package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RSABITS    = 4096
	VALIDYEARS = 3
)

func GenCert(host, keyfile, certfile string) error {
	// check exisrtance of files
	keyexists := true
	_, err := os.Stat(keyfile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cannot stat %s: %v", keyfile, err)

		}
		keyexists = false
	}
	certexists := true
	_, err = os.Stat(certfile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cannot stat %s: %v", certfile, err)

		}
		certexists = false
	}

	if keyexists && certexists {
		return nil
	}
	// generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, RSABITS)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	// validity
	notBefore := time.Now()
	notAfter := notBefore.Add(VALIDYEARS * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Go Naive Mail Forwader"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.DNSNames = append(template.DNSNames, host)
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certfile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certfile, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", certfile, err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", certfile, err)
	}

	keyOut, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", keyfile, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", keyfile, err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", keyfile, err)
	}
	return nil
}
