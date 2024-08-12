package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// SignMessage signs a message using the provided private key.
func SignMessage(privateKey *rsa.PrivateKey, message string) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(message))
	if err != nil {
		return nil, err
	}
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
