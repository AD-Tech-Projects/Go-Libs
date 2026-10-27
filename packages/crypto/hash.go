package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

func GenerateHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
