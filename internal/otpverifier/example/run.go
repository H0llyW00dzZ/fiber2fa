// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package main

import (
	"bufio"
	"fmt"
	"image"
	"image/color"
	"os"
	"time"

	"github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"golang.org/x/image/font/basicfont"
)

func main() {
	// Create a new TOTP verifier with the desired configuration
	verifier := otpverifier.NewTOTPVerifier(otpverifier.Config{
		Secret:       gotp.RandomSecret(16),
		Digits:       6,
		UseSignature: false,
		Period:       5,
		TimeSource:   time.Now, // Support Custom Timezone
		// Set to SHA512 as example since Some 2FA Mobile Apps might not supported (Poor Ecosystems) using Hash BLAKE2b,
		// additionaly in Apple Device (Not 2FA Mobile Apps) BLAKE2b is supported, has been tested on iPhone by using qrcode scan directly
		Hash: otpverifier.SHA512,
	})

	// Save the QR code image to a file
	issuer := "Gopher"
	accountName := "gopher@example.com"
	filename := "qrcode.png"
	size := 356      // Increased QR code size to accommodate signature or UUID
	textHeight := 50 // Increased text height for better visibility
	uuid := uuid.Must(uuid.NewRandom())

	// Create a custom QR code configuration
	qrCodeConfig := otpverifier.QRCodeConfig{
		Level:              qrcode.Medium,
		Size:               size,
		DisableBorder:      true,
		TopText:            "Scan Me",
		BottomText:         uuid.String(),
		ForegroundColor:    color.Black,
		Font:               basicfont.Face7x13,
		TopTextPosition:    image.Point{X: size / 2, Y: textHeight / 2},      // Dynamically calculated
		BottomTextPosition: image.Point{X: size / 2, Y: size + textHeight/3}, // Dynamically calculated
	}

	err := verifier.SaveQRCodeImage(issuer, accountName, filename, qrCodeConfig)
	if err != nil {
		fmt.Println("Error saving QR code image:", err)
		return
	}
	fmt.Println("QR code image saved successfully. Please scan it with your authenticator app.")

	// Wait for the user to scan the QR code and enter the token
	fmt.Print("Please enter the token from your authenticator app: ")

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		token := scanner.Text()

		// Verify the token
		valid := verifier.Verify(token, "")
		if valid {
			fmt.Println("Token is valid.")
		} else {
			fmt.Println("Token is invalid.")
		}
	}

	if scanner.Err() != nil {
		fmt.Println("Error reading token:", scanner.Err())
	}
}
