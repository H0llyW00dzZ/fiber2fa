// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"os"
)

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

// SaveQRCodeImage saves the QR code image to a file.
func (v *HOTPVerifier) SaveQRCodeImage(issuer, accountName, filename string, config QRCodeConfig) error {
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

// BuildQRCode generates a QR code image for the OTP configuration.
func (v *HOTPVerifier) BuildQRCode(issuer, accountName string, config QRCodeConfig) ([]byte, error) {
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
