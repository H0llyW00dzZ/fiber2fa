// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"fmt"
	"image"
	"image/color"
	"net/url"
	"os"

	"github.com/skip2/go-qrcode"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
)

// QRCodeConfig represents the configuration for generating QR codes.
type QRCodeConfig struct {
	Level              qrcode.RecoveryLevel
	Size               int
	ForegroundColor    color.Color
	BackgroundColor    color.Color
	DisableBorder      bool
	TopText            string
	BottomText         string
	Font               font.Face
	TopTextPosition    image.Point
	BottomTextPosition image.Point
}

// DefaultQRCodeConfig represents the default configuration for generating QR codes.
var DefaultQRCodeConfig = InitializeDefaultQRCodeConfig()

// InitializeDefaultQRCodeConfig sets up the default configuration for generating QR codes with dynamic text positions.
func InitializeDefaultQRCodeConfig() QRCodeConfig {
	size := 256      // This is the QR code size used in the default config
	textHeight := 20 // This should be set to the height of the text

	return QRCodeConfig{
		Level:              qrcode.Medium,
		Size:               size,
		ForegroundColor:    color.Black,
		BackgroundColor:    color.White,
		DisableBorder:      false,
		TopText:            "",
		BottomText:         "",
		Font:               basicfont.Face7x13,
		TopTextPosition:    image.Point{X: size / 2, Y: textHeight / 1},      // Dynamically calculated
		BottomTextPosition: image.Point{X: size / 2, Y: size + textHeight/1}, // Dynamically calculated
	}
}

// BuildQRCode generates a QR code image for the OTP configuration.
func (v *TOTPVerifier) BuildQRCode(issuer, accountName string, config QRCodeConfig) ([]byte, error) {
	// Ensure the configuration has default values where needed
	config = ensureDefaultConfig(config)

	otpURL := generateOTPURL(issuer, accountName, v.config)
	qrCodeImage, err := generateQRImage(otpURL, config)
	if err != nil {
		return nil, err
	}

	// Create a new image with space for text above and below the QR code
	newImage := prepareImageCanvas(qrCodeImage, config)

	// Draw the top and bottom text using the drawTextOnImage function
	drawTextOnImage(newImage, config.TopText, config.TopTextPosition, config.ForegroundColor, config.Font)
	drawTextOnImage(newImage, config.BottomText, config.BottomTextPosition, config.ForegroundColor, config.Font)

	return encodeImageToPNGBytes(newImage)
}

// ensureDefaultConfig checks the provided config and fills in any zero values with defaults.
func ensureDefaultConfig(config QRCodeConfig) QRCodeConfig {
	if config.Font == nil {
		config.Font = DefaultQRCodeConfig.Font
	}
	if config.ForegroundColor == nil {
		config.ForegroundColor = DefaultQRCodeConfig.ForegroundColor
	}
	if config.BackgroundColor == nil {
		config.BackgroundColor = DefaultQRCodeConfig.BackgroundColor
	}
	if config.TopTextPosition == (image.Point{}) {
		config.TopTextPosition = DefaultQRCodeConfig.TopTextPosition
	}
	if config.BottomTextPosition == (image.Point{}) {
		config.BottomTextPosition = DefaultQRCodeConfig.BottomTextPosition
	}
	return config
}

// generateOTPURL creates the URL for the QR code.
func generateOTPURL(issuer, accountName string, config Config) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d&algorithm=%s",
		url.QueryEscape(issuer), url.QueryEscape(accountName), config.Secret, url.QueryEscape(issuer),
		config.Digits, config.Period, config.Hasher.HashName)
}

// SaveQRCodeImage saves the QR code image to a file.
func (v *TOTPVerifier) SaveQRCodeImage(issuer, accountName, filename string, config QRCodeConfig) error {
	qrCodeBytes, err := v.BuildQRCode(issuer, accountName, config)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(qrCodeBytes)
	return err
}
