package lsb

import (
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
