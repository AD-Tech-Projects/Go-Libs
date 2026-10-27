package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

func GenerateSymmetricKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, errors.New("key size must be 16, 24, or 32 bytes")
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

func EncryptSymmetric(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(value), nil)
	encoded := append(nonce, cipherText...)
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func DecryptSymmetric(encryptedValue string, key []byte) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid encrypted payload")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func GenerateAsymmetricKeyPair(size int) ([]byte, []byte, error) {
	if size < 2048 {
		return nil, nil, errors.New("key size must be at least 2048 bits")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, nil, err
	}

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	return privatePEM, publicPEM, nil
}

func EncryptAsymmetric(value string, publicKeyPEM []byte) (string, error) {
	publicKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}

	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(value), nil)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(cipherText), nil
}

func DecryptAsymmetric(encryptedValue string, privateKeyPEM []byte) (string, error) {
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	cipherText, err := base64.RawURLEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", err
	}

	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func ValidateCertificate(certificatePEM []byte, roots *x509.CertPool) error {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return errors.New("invalid certificate pem")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
	}

	_, err = certificate.Verify(x509.VerifyOptions{Roots: roots})
	if err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	return nil
}

func parseRSAPrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func parseRSAPublicKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("invalid public key pem")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid rsa public key")
	}

	return rsaPublicKey, nil
}
