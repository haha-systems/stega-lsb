package lsb

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
)

// EmbedData embeds the public key and signature into an image using LSB steganography.
func EmbedData(inputImage, outputImage string, pubKey, signature []byte) error {
	file, err := os.Open(inputImage)
	if err != nil {
		return err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return err
	}

	bounds := img.Bounds()
	binaryData := toBinary(pubKey) + toBinary(signature)
	dataLen := len(binaryData)
	bitIdx := 0

	newImg := image.NewRGBA(bounds)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			r, g, b = r>>8, g>>8, b>>8

			if bitIdx < dataLen {
				r = (r & 0xFE) | (uint32(binaryData[bitIdx]) - '0')
				bitIdx++
			}
			if bitIdx < dataLen {
				g = (g & 0xFE) | (uint32(binaryData[bitIdx]) - '0')
				bitIdx++
			}
			if bitIdx < dataLen {
				b = (b & 0xFE) | (uint32(binaryData[bitIdx]) - '0')
				bitIdx++
			}

			newImg.Set(x, y, color.RGBA{uint8(r), uint8(g), uint8(b), uint8(a >> 8)})
		}
	}

	outputFile, err := os.Create(outputImage)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	return png.Encode(outputFile, newImg)
}

// ExtractData extracts the public key and signature from the image.
func ExtractData(inputImage string) ([]byte, []byte, error) {
	file, err := os.Open(inputImage)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, nil, err
	}

	var binaryData string
	bounds := img.Bounds()

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			binaryData += fmt.Sprintf("%d%d%d", r&1, g&1, b&1)
		}
	}

	pubKey, signature, err := fromBinary(binaryData)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, signature, nil
}

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
