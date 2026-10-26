package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGenerateHash(t *testing.T) {
	got := GenerateHash("hello")
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestGenerateTokenInvalidSize(t *testing.T) {
	_, err := GenerateToken(0)
	if err == nil {
		t.Fatal("expected error for invalid token size")
	}
}

func TestSymmetricEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plain := "super-secret"

	encrypted, err := EncryptSymmetric(plain, key)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	decrypted, err := DecryptSymmetric(encrypted, key)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if decrypted != plain {
		t.Fatalf("expected %s, got %s", plain, decrypted)
	}
}

func TestAsymmetricEncryptDecrypt(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateAsymmetricKeyPair(2048)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	plain := "secret-rsa"
	encrypted, err := EncryptAsymmetric(plain, publicKeyPEM)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	decrypted, err := DecryptAsymmetric(encrypted, privateKeyPEM)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if decrypted != plain {
		t.Fatalf("expected %s, got %s", plain, decrypted)
	}
}

func TestGenerateAsymmetricKeyPairInvalidSize(t *testing.T) {
	_, _, err := GenerateAsymmetricKeyPair(1024)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestValidateCertificate(t *testing.T) {
	certificatePEM, cert, err := createCertificate()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	if err := ValidateCertificate(certificatePEM, roots); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateCertificateInvalidPEM(t *testing.T) {
	err := ValidateCertificate([]byte("invalid"), nil)
	if err == nil {
		t.Fatal("expected error for invalid certificate pem")
	}
}

func createCertificate() ([]byte, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "go-libs-test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certificatePEM, certificate, nil
}

func TestAsymmetricDecryptInvalidCipherText(t *testing.T) {
	privateKeyPEM, _, err := GenerateAsymmetricKeyPair(2048)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	_, err = DecryptAsymmetric("@@invalid-base64@@", privateKeyPEM)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext")
	}
}

func TestSymmetricDecryptTamperedPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := EncryptSymmetric("secret", key)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	tampered := encrypted[:len(encrypted)-2]
	_, err = DecryptSymmetric(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
}
