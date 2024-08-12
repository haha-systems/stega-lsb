package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// VerifySignature verifies that a signature is valid for a given message.
func VerifySignature(pubKey []byte, signature []byte, message string) (bool, error) {
	parsedKey, err := x509.ParsePKCS1PublicKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("error parsing public key: %v", err)
	}

	hash := sha256.New()
	_, err = hash.Write([]byte(message))
	if err != nil {
		return false, fmt.Errorf("error hashing message: %v", err)
	}
	hashed := hash.Sum(nil)

	err = rsa.VerifyPKCS1v15(parsedKey, crypto.SHA256, hashed, signature)
	if err != nil {
		return false, err
	}

	return true, nil
}
