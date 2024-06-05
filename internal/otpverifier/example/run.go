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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"golang.org/x/image/font/basicfont"
)

func main() {

	// Custom time source function for Antarctica time zone
	customTimeSource := func() time.Time {
		location, _ := time.LoadLocation("Antarctica/South_Pole")
		return time.Now().UTC().In(location)
	}

	// Create a new TOTP verifier with the desired configuration
	verifier := otpverifier.NewTOTPVerifier(otpverifier.Config{
		Secret:       gotp.RandomSecret(16),
		Digits:       6,
		UseSignature: false,
		Period:       30,
		TimeSource:   customTimeSource, // Support Custom Timezone
		// Set to SHA512 as example since Some 2FA Mobile Apps might not supported (Poor Ecosystems) using Hash BLAKE2b,
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

	// Create a channel to receive OS signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("Please enter the token from your authenticator app (or type 'exit' to quit): ")

		// Use a select statement to wait for either user input or OS signal
		select {
		case <-signalChan:
			fmt.Println("Exiting...")
			return
		default:
			if scanner.Scan() {
				token := strings.TrimSpace(scanner.Text())

				if token == "exit" {
					fmt.Println("Exiting...")
					return
				}

				// Verify the token
				valid := verifier.Verify(token, "")
				if valid {
					fmt.Println("Token is valid.")
				} else {
					fmt.Println("Token is invalid.")
				}
			} else {
				// If scanner.Scan() returns false, it means there was an error or EOF
				if scanner.Err() != nil {
					fmt.Println("Error reading token:", scanner.Err())
				}
				return
			}
		}
	}
}
