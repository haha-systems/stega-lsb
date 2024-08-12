package main

import (
	"fmt"
	"os"

	"github.com/haha-systems/stega-lsb/crypto"
	"github.com/haha-systems/stega-lsb/lsb"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  encode <input_image> <output_image> <message>")
		fmt.Println("  decode <input_image>")
		return
	}

	switch os.Args[1] {
	case "encode":
		if len(os.Args) < 5 {
			fmt.Println("Usage: encode <input_image> <output_image> <message>")
			return
		}
		inputImage := os.Args[2]
		outputImage := os.Args[3]
		message := os.Args[4]

		// Generate a key pair
		privKey, pubKey := crypto.GenerateKeyPair()

		// Sign the message with the private key
		signature, err := crypto.SignMessage(privKey, message)
		if err != nil {
			fmt.Println("Error signing message:", err)
			return
		}

		// Embed the public key and signature into the image
		err = lsb.EmbedData(inputImage, outputImage, pubKey, signature)
		if err != nil {
			fmt.Println("Error embedding data:", err)
		} else {
			fmt.Println("Message encoded and image saved to", outputImage)
		}

	case "decode":
		if len(os.Args) < 3 {
			fmt.Println("Usage: decode <input_image>")
			return
		}
		inputImage := os.Args[2]

		// Extract the public key and signature
		pubKey, signature, err := lsb.ExtractData(inputImage)
		if err != nil {
			fmt.Println("Error extracting data:", err)
			return
		}

		// Verify the signature
		valid, err := crypto.VerifySignature(pubKey, signature, "Expected message")
		if err != nil {
			fmt.Println("Error verifying signature:", err)
			return
		}

		if valid {
			fmt.Println("Signature is valid. The image is authentic.")
		} else {
			fmt.Println("Signature is invalid. The image may have been tampered with.")
		}

	default:
		fmt.Println("Unknown command:", os.Args[1])
	}
}
