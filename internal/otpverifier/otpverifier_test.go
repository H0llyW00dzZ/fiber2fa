// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier_test

import (
	"bytes"
	"image/color"
	"image/png"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

func TestTOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Mock time for testing
	fakeTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	timeSource := func() time.Time {
		return fakeTime
	}

	// Create a TOTPVerifier with the mocked time source and UseSignature set to true
	config := otpverifier.Config{
		Secret:       secret,
		UseSignature: true,
		TimeSource:   timeSource,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	// Generate a token and signature using the verifier
	token, signature := verifier.GenerateToken()

	// Verify the token and signature
	isValid := verifier.Verify(token, signature)
	if !isValid {
		t.Errorf("Token and signature should be valid")
	}

	// Create a TOTPVerifier with the mocked time source and UseSignature set to false
	config.UseSignature = false
	verifier = otpverifier.NewTOTPVerifier(config)

	// Generate a token using the verifier
	token, _ = verifier.GenerateToken()

	// Verify the token
	isValid = verifier.Verify(token, "")
	if !isValid {
		t.Errorf("Token should be valid")
	}
}

func TestHOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)

	// Create an HOTPVerifier with the initial counter and UseSignature set to true
	config := otpverifier.Config{
		Secret:       secret,
		Counter:      initialCounter,
		UseSignature: true,
	}
	verifier := otpverifier.NewHOTPVerifier(config)

	// Generate a token and signature using the verifier
	token, signature := verifier.GenerateToken()

	// Verify the token and signature
	isValid := verifier.Verify(token, signature)
	if !isValid {
		t.Errorf("Token and signature should be valid")
	}

	// Increment the counter and generate a new token and signature
	initialCounter++
	config.Counter = initialCounter
	verifier = otpverifier.NewHOTPVerifier(config)
	newToken, newSignature := verifier.GenerateToken()

	// Verify the new token and signature
	isValid = verifier.Verify(newToken, newSignature)
	if !isValid {
		t.Errorf("New token and signature should be valid")
	}

	// Verify that the old token and signature are no longer valid
	isValid = verifier.Verify(token, signature)
	if isValid {
		t.Errorf("Old token and signature should not be valid anymore")
	}

	// Create an HOTPVerifier with the initial counter and UseSignature set to false
	config.UseSignature = false
	verifier = otpverifier.NewHOTPVerifier(config)

	// Generate a token using the verifier
	token, _ = verifier.GenerateToken()

	// Verify the token
	isValid = verifier.Verify(token, "")
	if !isValid {
		t.Errorf("Token should be valid")
	}
}

func TestOTPFactory(t *testing.T) {
	secret := gotp.RandomSecret(16)

	// Test creating a TOTPVerifier
	totpConfig := otpverifier.Config{
		Secret: secret,
	}
	totpVerifier := otpverifier.OTPFactory(totpConfig)
	if reflect.TypeOf(totpVerifier) != reflect.TypeOf(&otpverifier.TOTPVerifier{}) {
		t.Errorf("Expected TOTPVerifier, got %v", reflect.TypeOf(totpVerifier))
	}

	// Test creating an HOTPVerifier
	initialCounter := uint64(1337) // Set the counter to a non-zero value
	hotpConfig := otpverifier.Config{
		Secret:  secret,
		Counter: initialCounter,
	}
	hotpVerifier := otpverifier.OTPFactory(hotpConfig)
	if reflect.TypeOf(hotpVerifier) != reflect.TypeOf(&otpverifier.HOTPVerifier{}) {
		t.Errorf("Expected HOTPVerifier, got %v", reflect.TypeOf(hotpVerifier))
	}

	// Test TOTPVerifier token generation and verification
	fakeTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	timeSource := func() time.Time {
		return fakeTime
	}
	totpConfig.UseSignature = true
	totpConfig.TimeSource = timeSource
	totpVerifier = otpverifier.NewTOTPVerifier(totpConfig)
	totpToken, totpSignature := totpVerifier.GenerateToken()
	if !totpVerifier.Verify(totpToken, totpSignature) {
		t.Errorf("TOTP token and signature should be valid")
	}

	// Test HOTPVerifier token generation and verification
	hotpConfig.UseSignature = true
	hotpVerifier = otpverifier.NewHOTPVerifier(hotpConfig)
	hotpToken, hotpSignature := hotpVerifier.GenerateToken()
	if !hotpVerifier.Verify(hotpToken, hotpSignature) {
		t.Errorf("HOTP token and signature should be valid")
	}
}

func TestTOTPVerifier_BuildQRCode(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret: secret,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"

	// Create a custom QR code configuration
	qrCodeConfig := otpverifier.QRCodeConfig{
		Level:           qrcode.Medium,
		Size:            256,
		DisableBorder:   true,
		TopText:         "Scan Me",
		BottomText:      "OTP QR Code",
		ForegroundColor: color.Black,
	}

	qrCodeBytes, err := verifier.BuildQRCode(issuer, accountName, qrCodeConfig)
	if err != nil {
		t.Errorf("Failed to build QR code: %v", err)
	}

	if len(qrCodeBytes) == 0 {
		t.Errorf("QR code bytes should not be empty")
	}

	// Try decoding the QR code bytes as a PNG image
	_, err = png.Decode(bytes.NewReader(qrCodeBytes))
	if err != nil {
		t.Errorf("Failed to decode QR code as PNG: %v", err)
	}
}

func TestTOTPVerifier_SaveQRCodeImage(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret: secret,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"
	filename := "test_qrcode.png"

	err := verifier.SaveQRCodeImage(issuer, accountName, filename, otpverifier.DefaultQRCodeConfig)
	if err != nil {
		t.Errorf("Failed to save QR code image: %v", err)
	}
	defer os.Remove(filename)

	// Check if the file was created
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		t.Errorf("QR code image file was not created")
	}
}
