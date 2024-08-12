package lsb

import (
	"fmt"
)

// toBinary converts a byte array to a binary string.
func toBinary(data []byte) string {
	var binaryStr string
	for _, b := range data {
		binaryStr += fmt.Sprintf("%08b", b)
	}
	return binaryStr
}

// fromBinary converts a binary string to a byte array.
func fromBinary(binaryData string) ([]byte, []byte, error) {
	if len(binaryData)%8 != 0 {
		return nil, nil, fmt.Errorf("invalid binary data")
	}

	pubKeyBytes := make([]byte, len(binaryData)/16) // Half for the public key
	sigBytes := make([]byte, len(binaryData)/16)    // Half for the signature

	for i := 0; i < len(pubKeyBytes); i++ {
		pubKeyBytes[i] = byte(fromBinaryStr(binaryData[i*8 : (i+1)*8]))
		sigBytes[i] = byte(fromBinaryStr(binaryData[(i+len(pubKeyBytes))*8 : (i+1+len(pubKeyBytes))*8]))
	}

	return pubKeyBytes, sigBytes, nil
}

// fromBinaryStr converts a binary string to a byte.
func fromBinaryStr(binaryStr string) int {
	var result int
	for i := 0; i < len(binaryStr); i++ {
		result = result<<1 | int(binaryStr[i]-'0')
	}
	return result
}
