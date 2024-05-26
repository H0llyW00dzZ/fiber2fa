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

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA256,
		otpverifier.SHA512,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
	}

	for _, hashFunc := range hashFunctions {
		// Create a TOTPVerifier with the mocked time source, UseSignature set to true, and the specified hash function
		config := otpverifier.Config{
			Secret:       secret,
			UseSignature: true,
			TimeSource:   timeSource,
			Hasher:       otpverifier.Hashers[hashFunc],
		}
		verifier := otpverifier.NewTOTPVerifier(config)

		// Generate a token and signature using the verifier
		token, signature := verifier.GenerateToken()

		// Verify the token and signature
		isValid := verifier.Verify(token, signature)
		if !isValid {
			t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Create a TOTPVerifier with the mocked time source, UseSignature set to false, and the specified hash function
		config.UseSignature = false
		verifier = otpverifier.NewTOTPVerifier(config)

		// Generate a token using the verifier
		token, _ = verifier.GenerateToken()

		// Verify the token
		isValid = verifier.Verify(token, "")
		if !isValid {
			t.Errorf("Token should be valid (hash function: %s)", hashFunc)
		}
	}
}

func TestHOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA256,
		otpverifier.SHA512,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
	}

	for _, hashFunc := range hashFunctions {
		// Create an HOTPVerifier with the initial counter, UseSignature set to true, and the specified hash function
		config := otpverifier.Config{
			Secret:       secret,
			Counter:      initialCounter,
			UseSignature: true,
			Hasher:       otpverifier.Hashers[hashFunc],
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token and signature using the verifier
		token, signature := verifier.GenerateToken()

		// Verify the token and signature
		isValid := verifier.Verify(token, signature)
		if !isValid {
			t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Increment the counter and generate a new token and signature
		initialCounter++
		config.Counter = initialCounter
		verifier = otpverifier.NewHOTPVerifier(config)
		newToken, newSignature := verifier.GenerateToken()

		// Verify the new token and signature
		isValid = verifier.Verify(newToken, newSignature)
		if !isValid {
			t.Errorf("New token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Verify that the old token and signature are no longer valid
		isValid = verifier.Verify(token, signature)
		if isValid {
			t.Errorf("Old token and signature should not be valid anymore (hash function: %s)", hashFunc)
		}

		// Create an HOTPVerifier with the initial counter, UseSignature set to false, and the specified hash function
		config.UseSignature = false
		verifier = otpverifier.NewHOTPVerifier(config)

		// Generate a token using the verifier
		token, _ = verifier.GenerateToken()

		// Verify the token
		isValid = verifier.Verify(token, "")
		if !isValid {
			t.Errorf("Token should be valid (hash function: %s)", hashFunc)
		}
	}
}

func TestOTPFactory(t *testing.T) {
	secret := gotp.RandomSecret(16)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA256,
		otpverifier.SHA512,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
	}

	for _, hashFunc := range hashFunctions {
		// Test creating a TOTPVerifier
		totpConfig := otpverifier.Config{
			Secret: secret,
			Hasher: otpverifier.Hashers[hashFunc],
		}
		totpVerifier := otpverifier.OTPFactory(totpConfig)
		if reflect.TypeOf(totpVerifier) != reflect.TypeOf(&otpverifier.TOTPVerifier{}) {
			t.Errorf("Expected TOTPVerifier, got %v (hash function: %s)", reflect.TypeOf(totpVerifier), hashFunc)
		}

		// Test creating an HOTPVerifier
		initialCounter := uint64(1337) // Set the counter to a non-zero value
		hotpConfig := otpverifier.Config{
			Secret:  secret,
			Counter: initialCounter,
			Hasher:  otpverifier.Hashers[hashFunc],
		}
		hotpVerifier := otpverifier.OTPFactory(hotpConfig)
		if reflect.TypeOf(hotpVerifier) != reflect.TypeOf(&otpverifier.HOTPVerifier{}) {
			t.Errorf("Expected HOTPVerifier, got %v (hash function: %s)", reflect.TypeOf(hotpVerifier), hashFunc)
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
			t.Errorf("TOTP token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Test HOTPVerifier token generation and verification
		hotpConfig.UseSignature = true
		hotpVerifier = otpverifier.NewHOTPVerifier(hotpConfig)
		hotpToken, hotpSignature := hotpVerifier.GenerateToken()
		if !hotpVerifier.Verify(hotpToken, hotpSignature) {
			t.Errorf("HOTP token and signature should be valid (hash function: %s)", hashFunc)
		}
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

func TestHOTPVerifier_BuildQRCode(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:  secret,
		Counter: 1337,
	}
	verifier := otpverifier.NewHOTPVerifier(config)

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

func TestHOTPVerifier_SaveQRCodeImage(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:  secret,
		Counter: 1337,
	}
	verifier := otpverifier.NewHOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"
	filename := "test_hotp_qrcode.png"

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

func TestHOTPVerifier_VerifySyncWindow(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// An arbitrarily chosen initial counter value
	initialCounter := uint64(1337)
	// The sync window allows verification of tokens that are ahead by 2
	syncWindow := 2

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA256,
		otpverifier.SHA512,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
	}

	for _, hashFunc := range hashFunctions {
		config := otpverifier.Config{
			Secret:     secret,
			Counter:    initialCounter,
			Hasher:     otpverifier.Hashers[hashFunc],
			SyncWindow: syncWindow,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token for the current counter value
		currentToken := verifier.Hotp.At(int(initialCounter))

		// Verify this token should pass
		if !verifier.Verify(currentToken, "") {
			t.Errorf("Current token did not verify but should have (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value within the sync window
		withinWindowToken := verifier.Hotp.At(int(initialCounter) + syncWindow)

		// Verify this token should also pass
		if !verifier.Verify(withinWindowToken, "") {
			t.Errorf("Token within sync window did not verify but should have (hash function: %s)", hashFunc)
		}

		// Verify that the counter has been updated to the last verified counter + 1
		if verifier.GetCounter() != initialCounter+uint64(syncWindow)+1 {
			t.Errorf("Counter was not updated correctly after sync window verification (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value outside the sync window
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + syncWindow + 4)

		// Verify this token should fail
		if verifier.Verify(outsideWindowToken, "") {
			t.Errorf("Token outside sync window verified but should not have (hash function: %s)", hashFunc)
		}
	}
}
