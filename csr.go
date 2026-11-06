package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParseCSR reads a PEM certificate request, checks its signature (the
// sender holds the key) and the kind of the key, and returns the public key.
// Only the key is taken from a request: the names of a certificate are the
// signer's choice (IssueForKey), never the requester's.
func ParseCSR(csrPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the signature of the certificate request: %w", err)
	}
	if err := checkPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr.PublicKey, nil
}

// checkPublicKey accepts the keys the agents' TLS works with: ECDSA P-256 or
// P-384, Ed25519, and RSA of 2048 to 8192 bits.
func checkPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return fmt.Errorf("the ECDSA curve %s is not accepted (P-256 or P-384)", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < 2048 || bits > 8192 {
			return fmt.Errorf("an RSA key of %d bits is not accepted (2048 to 8192)", bits)
		}
	default:
		return fmt.Errorf("a key of the type %T is not accepted", pub)
	}
	return nil
}
