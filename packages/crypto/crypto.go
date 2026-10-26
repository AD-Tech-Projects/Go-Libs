package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var uuidPattern = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")

func GenerateHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

type TokenClaims struct {
	SubscriptionID string `json:"subscriptionId"`
	CreatedAt      string `json:"createdAt"`
	Expiration     int64  `json:"expiration"`
	ExpirationDate string `json:"expirationDate"`
}

func GenerateToken(subscriptionID string, createdAt time.Time, expiration time.Time, secret []byte) (string, error) {
	if !isValidUUID(subscriptionID) {
		return "", errors.New("invalid subscription id")
	}

	if len(secret) == 0 {
		return "", errors.New("secret must not be empty")
	}

	if !expiration.After(createdAt) {
		return "", errors.New("expiration must be after createdAt")
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	payload := TokenClaims{
		SubscriptionID: subscriptionID,
		CreatedAt:      createdAt.UTC().Format(time.RFC3339),
		Expiration:     expiration.UTC().Unix(),
		ExpirationDate: expiration.UTC().Format(time.RFC3339),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encodedHeader + "." + encodedPayload
	signature := signToken(signingInput, secret)

	return signingInput + "." + signature, nil
}

func ValidateToken(token string, secret []byte) (*TokenClaims, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSignature := signToken(signingInput, secret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, errors.New("invalid token signature")
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims TokenClaims
	if err := json.Unmarshal(payloadData, &claims); err != nil {
		return nil, err
	}

	if !isValidUUID(claims.SubscriptionID) {
		return nil, errors.New("invalid subscription id")
	}

	createdAt, err := time.Parse(time.RFC3339, claims.CreatedAt)
	if err != nil {
		return nil, errors.New("invalid createdAt")
	}

	expirationDate, err := time.Parse(time.RFC3339, claims.ExpirationDate)
	if err != nil {
		return nil, errors.New("invalid expirationDate")
	}

	if expirationDate.UTC().Unix() != claims.Expiration {
		return nil, errors.New("expiration metadata mismatch")
	}

	if claims.Expiration <= createdAt.UTC().Unix() {
		return nil, errors.New("invalid expiration")
	}

	if time.Now().UTC().Unix() > claims.Expiration {
		return nil, errors.New("token expired")
	}

	return &claims, nil
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

func signToken(value string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func isValidUUID(value string) bool {
	return uuidPattern.MatchString(value)
}
