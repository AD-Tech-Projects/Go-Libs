package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

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

	token := signingInput + "." + signature
	return token, nil
}

func ValidateToken(token string, secret []byte) (*TokenClaims, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	encodedHeader := parts[0]
	encodedPayload := parts[1]
	tokenSignature := parts[2]

	signingInput := encodedHeader + "." + encodedPayload
	expectedSignature := signToken(signingInput, secret)
	if !hmac.Equal([]byte(tokenSignature), []byte(expectedSignature)) {
		return nil, errors.New("invalid token signature")
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(encodedPayload)
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

func signToken(value string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var uuidPattern = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")

func isValidUUID(value string) bool {
	return uuidPattern.MatchString(value)
}
