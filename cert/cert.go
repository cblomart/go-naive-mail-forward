package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RSABITS    = 4096
	VALIDYEARS = 3
)

func FileExists(file string) (bool, error) {
	_, err := os.Stat(file)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("cannot stat %s: %v", file, err)
		}
		return false, nil
	}
	return true, nil
}

func GenCertBytes(host string, priv *rsa.PrivateKey) ([]byte, error) {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	// validity
	notBefore := time.Now()
	notAfter := notBefore.Add(VALIDYEARS * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)

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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return derBytes, nil
}

func SaveFile(file string, header string, content []byte) error {
	certOut, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", file, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: header, Bytes: content}); err != nil {
		return fmt.Errorf("failed to write data to %s: %v", file, err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %v", file, err)
	}
	return nil
}

func GenCert(host, keyfile, certfile string) error {
	// check if keyfile exists
	keyexists, err := FileExists(keyfile)
	if err != nil {
		return err
	}

	// check if certfile exists
	certexists, err := FileExists(keyfile)
	if err != nil {
		return err
	}

	// files exists
	if keyexists && certexists {
		return nil
	}

	// generate RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, RSABITS)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// generate Private key bytes
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %v", err)
	}

	// generate Certificate bytes
	derBytes, err := GenCertBytes(host, priv)
	if err != nil {
		return err
	}

	// save certidicate
	err = SaveFile(certfile, "CERTIFICATE", derBytes)
	if err != nil {
		return err
	}

	// save private key
	err = SaveFile(keyfile, "PRIVATE KEY", privBytes)
	if err != nil {
		return err
	}

	// done
	return nil
}
