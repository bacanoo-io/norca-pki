package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func csrOf(t *testing.T, key crypto.Signer, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"server.eu.norca"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// A node keeps its key: it sends a request, the node CA signs its public key
// with the names the signer chooses (not those of the request), and the leaf
// verifies against the cluster CA through the node CA.
func TestIssueForKeyFromCSR(t *testing.T) {
	td, _ := TrustDomain("prod.norca")
	root, err := NewCA("test", 1, td)
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.IssueNodeCA("test eu Node CA", "eu", 30*day, td)
	if err != nil {
		t.Fatal(err)
	}
	inter := nodeCAOf(t, b)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, err := ParseCSR(csrOf(t, key, "evil"))
	if err != nil {
		t.Fatal(err)
	}
	spiffe, _ := SPIFFEID(td, "region", "eu", "node", "workers-1-1")
	id := ClientIdentity("eu").WithSPIFFE(spiffe)
	id.DNS = append(id.DNS, "workers-1-1.client.eu.norca")
	bundle, err := inter.IssueForKey(id, pub, 7*day)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.KeyPEM) != 0 {
		t.Fatal("a bundle for a key of the holder carries a key")
	}
	leaf := parse(t, bundle.CertPEM)
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate is not for the key of the request")
	}
	if leaf.Subject.CommonName == "evil" || strings.Contains(strings.Join(leaf.DNSNames, " "), "server.eu.norca") {
		t.Fatalf("names of the request were taken: %s %v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	if left := time.Until(leaf.NotAfter); left < 6*day || left > 7*day {
		t.Fatalf("a 7 day certificate ends in %s", left)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	ints := x509.NewCertPool()
	ints.AddCert(inter.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: ints,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the node certificate does not verify: %v", err)
	}

	// The name of a node is a subdomain of client.<region>.norca; the node CA
	// signs nothing outside it, also for a key of the holder.
	bad := ClientIdentity("eu")
	bad.DNS = append(bad.DNS, "server.eu.norca")
	badBundle, err := inter.IssueForKey(bad, pub, day)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(t, badBundle.CertPEM).Verify(x509.VerifyOptions{Roots: roots, Intermediates: ints,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("a server name signed by the node CA verifies")
	}
}

func TestParseCSRRefusals(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrOf(t, ec, "n")

	if _, err := ParseCSR([]byte("junk")); err == nil {
		t.Fatal("junk is accepted")
	}
	certLike := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
	if _, err := ParseCSR(certLike); err == nil {
		t.Fatal("a certificate block is accepted as a request")
	}

	// A request whose signature does not match: a letter of its subject
	// changed after it was signed.
	block, _ := pem.Decode(csrOf(t, ec, "subject-marker"))
	raw := append([]byte{}, block.Bytes...)
	i := strings.Index(string(raw), "subject-marker")
	if i < 0 {
		t.Fatal("the subject is not in the request")
	}
	raw[i] = 'S'
	if _, err := x509.ParseCertificateRequest(raw); err != nil {
		t.Fatalf("the changed request does not parse: %v", err)
	}
	if _, err := ParseCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})); err == nil {
		t.Fatal("a request with a broken signature is accepted")
	}

	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, err := ParseCSR(csrOf(t, p224, "n")); err == nil {
		t.Fatal("a P-224 key is accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := ParseCSR(csrOf(t, small, "n")); err == nil {
		t.Fatal("a 1024 bit RSA key is accepted")
	}
	if _, err := ParseCSR(good); err != nil {
		t.Fatalf("a good request is refused: %v", err)
	}
}
