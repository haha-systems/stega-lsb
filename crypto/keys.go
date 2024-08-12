package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateKeyPair generates an RSA key pair and returns the private and public keys.
func GenerateKeyPair() (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return nil, nil
	}

	publicKey := privateKey.PublicKey
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	return privateKey, pubKeyBytes
}

// SaveKeyToFile saves a key to a file.
func SaveKeyToFile(filename string, keyBytes []byte, keyType string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	var block *pem.Block
	if keyType == "private" {
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
	} else {
		block = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: keyBytes,
		}
	}

	return pem.Encode(keyFile, block)
}
