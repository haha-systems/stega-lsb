package lsb

import (
	"fmt"
	"image"
	"image/png"
	"os"
)

// ExtractData extracts the public key and signature from the image using LSB steganography.
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
