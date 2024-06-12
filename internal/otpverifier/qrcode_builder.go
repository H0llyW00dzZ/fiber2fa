// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"image"
	"os"
	"path/filepath"
)

// BuildQRCode generates a QR code image for the OTP configuration.
func (v *TOTPVerifier) BuildQRCode(issuer, accountName string) ([]byte, error) {
	// Check if issuer or account name is empty
	if issuer == "" {
		panic("BuildQRCode: issuer cannot be empty")
	}

	if accountName == "" {
		panic("BuildQRCode: account name cannot be empty")
	}

	if v.config.Digits > 8 {
		panic("BuildQRCode: maximum digits are 8 for TOTP")
	}

	otpURL := v.GenerateOTPURL(issuer, accountName)
	qrCodeImage, err := v.QRCodeBuilder.GenerateQRCodeImage(otpURL)

	if err != nil {
		return nil, err
	}

	return v.QRCodeBuilder.encodeImageToPNGBytes(qrCodeImage.(*image.RGBA))
}

// SaveQRCodeImage saves the QR code image to a file.
func (v *TOTPVerifier) SaveQRCodeImage(issuer, accountName, filename string) error {
	qrCodeBytes, err := v.BuildQRCode(issuer, accountName)
	if err != nil {
		return err
	}

	// Use the file path from the QRCodeConfig if provided, otherwise use the current directory
	//
	// Note: There is no explicit (e.g., strict permission) requirement for the file path,
	// so it basically depends on the use case and any specific permission requirements.
	// Also, keep in mind that if running on Windows, long file paths are not allowed by default.
	filePath := v.QRCodeBuilder.FilePath
	if filePath == "" {
		filePath = "."
	}

	// Create the full file path by joining the file path and filename
	fullPath := filepath.Join(filePath, filename)

	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(qrCodeBytes)
	return err
}

// SaveQRCodeImage saves the QR code image to a file.
func (v *HOTPVerifier) SaveQRCodeImage(issuer, accountName, filename string) error {
	qrCodeBytes, err := v.BuildQRCode(issuer, accountName)
	if err != nil {
		return err
	}

	// Use the file path from the QRCodeConfig if provided, otherwise use the current directory
	//
	// Note: There is no explicit (e.g., strict permission) requirement for the file path,
	// so it basically depends on the use case and any specific permission requirements.
	// Also, keep in mind that if running on Windows, long file paths are not allowed by default.
	filePath := v.QRCodeBuilder.FilePath
	if filePath == "" {
		filePath = "."
	}

	// Create the full file path by joining the file path and filename
	fullPath := filepath.Join(filePath, filename)

	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(qrCodeBytes)
	return err
}

// BuildQRCode generates a QR code image for the OTP configuration.
func (v *HOTPVerifier) BuildQRCode(issuer, accountName string) ([]byte, error) {
	// Check if issuer or account name is empty
	if issuer == "" {
		panic("BuildQRCode: issuer cannot be empty")
	}

	if accountName == "" {
		panic("BuildQRCode: account name cannot be empty")
	}

	if v.config.Digits > 8 {
		panic("BuildQRCode: maximum digits are 8 for HOTP")
	}

	otpURL := v.GenerateOTPURL(issuer, accountName)
	qrCodeImage, err := v.QRCodeBuilder.GenerateQRCodeImage(otpURL)

	if err != nil {
		return nil, err
	}

	return v.QRCodeBuilder.encodeImageToPNGBytes(qrCodeImage.(*image.RGBA))
}
