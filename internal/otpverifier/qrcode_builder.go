// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"image"
	"os"
)

// BuildQRCode generates a QR code image for the OTP configuration.
func (v *TOTPVerifier) BuildQRCode(issuer, accountName string, config QRCodeConfig) ([]byte, error) {
	if v.config.Digits > 8 {
		panic("BuildQRCode: maximum digits are 8 for TOTP")
	}

	// Ensure the configuration has default values where needed
	config = ensureDefaultConfig(config)

	otpURL := v.GenerateOTPURL(issuer, accountName)
	qrCodeImage, err := config.GenerateQRCodeImage(otpURL)
	if err != nil {
		return nil, err
	}

	return config.encodeImageToPNGBytes(qrCodeImage.(*image.RGBA))
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
	if v.config.Digits > 8 {
		panic("BuildQRCode: maximum digits are 8 for HOTP")
	}

	// Ensure the configuration has default values where needed
	config = ensureDefaultConfig(config)

	otpURL := v.GenerateOTPURL(issuer, accountName)
	qrCodeImage, err := config.GenerateQRCodeImage(otpURL)
	if err != nil {
		return nil, err
	}

	return config.encodeImageToPNGBytes(qrCodeImage.(*image.RGBA))
}
