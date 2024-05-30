// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"image/color"
	"image/png"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake2botp"
	"github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake3otp"
	"github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

func TestTOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		// Create a TOTPVerifier with the mocked time source, UseSignature set to true, and the specified hash function
		t.Run(fmt.Sprintf("HashFunc=%s", hashFunc), func(t *testing.T) {
			// Mock time for testing
			currentTime := time.Now()
			timeSource := func() time.Time {
				return currentTime
			}
			config := otpverifier.Config{
				Secret:       secret,
				UseSignature: true,
				TimeSource:   timeSource,
				Hash:         hashFunc,
			}
			verifier := otpverifier.NewTOTPVerifier(config)

			// Generate a token and signature using the verifier
			token, signature := verifier.GenerateTokenWithSignature()

			// Verify the token and signature (should succeed)
			isValid := verifier.Verify(token, signature)
			if !isValid {
				t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
			}

			// Attempt to verify the token again (should fail since the token has already been used)
			isValid = verifier.Verify(token, signature)
			if isValid {
				t.Errorf("Token and signature should be invalid since they have already been used (hash function: %s)", hashFunc)
			}

			// Verify with an invalid token (should fail)
			isValid = verifier.Verify("invalidToken", signature)
			if isValid {
				t.Errorf("Invalid token should not be accepted (hash function: %s)", hashFunc)
			}

			// Switch to a non-signature mode and test again
			config.UseSignature = false
			verifier = otpverifier.NewTOTPVerifier(config)
			token, _ = verifier.GenerateTokenWithSignature()

			// Verify the token without a signature (should succeed)
			isValid = verifier.Verify(token, "")
			if !isValid {
				t.Errorf("Token should be valid with UseSignature=false (hash function: %s)", hashFunc)
			}

			// Verify an invalid token without a signature (should fail)
			isValid = verifier.Verify("invalidToken", "")
			if isValid {
				t.Errorf("Invalid token should not be valid with UseSignature=false (hash function: %s)", hashFunc)
			}
		})
	}
}

func TestDefaultConfigTOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
	}

	for _, hashFunc := range hashFunctions {
		// Create a TOTPVerifier with the mocked time source, UseSignature set to true, and the specified hash function
		t.Run(fmt.Sprintf("HashFunc=%s", hashFunc), func(t *testing.T) {
			config := otpverifier.Config{
				Secret: secret,
				Hash:   hashFunc,
			}
			verifier := otpverifier.NewTOTPVerifier(config)

			// Generate a token and signature using the verifier
			token, signature := verifier.GenerateTokenWithSignature()

			// Verify the token and signature (should succeed)
			isValid := verifier.Verify(token, signature)
			if !isValid {
				t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
			}

			// Attempt to verify the token again (should fail since the token has already been used)
			isValid = verifier.Verify(token, signature)
			if isValid {
				t.Errorf("Token and signature should be invalid since they have already been used (hash function: %s)", hashFunc)
			}

			// Verify with an invalid token (should fail)
			isValid = verifier.Verify("invalidToken", signature)
			if isValid {
				t.Errorf("Invalid token should not be accepted (hash function: %s)", hashFunc)
			}

			// Switch to a non-signature mode and test again
			config.UseSignature = false
			verifier = otpverifier.NewTOTPVerifier(config)
			token, _ = verifier.GenerateTokenWithSignature()

			// Verify the token without a signature (should succeed)
			isValid = verifier.Verify(token, "")
			if !isValid {
				t.Errorf("Token should be valid with UseSignature=false (hash function: %s)", hashFunc)
			}

			// Verify an invalid token without a signature (should fail)
			isValid = verifier.Verify("invalidToken", "")
			if isValid {
				t.Errorf("Invalid token should not be valid with UseSignature=false (hash function: %s)", hashFunc)
			}
		})
	}
}

func TestTOTPVerifier_PeriodicCleanup(t *testing.T) {
	secret := gotp.RandomSecret(16)
	period := 10 // Set the token validity period to 10 seconds
	config := otpverifier.Config{
		Secret:     secret,
		Period:     period,
		SyncWindow: 1,
		Digits:     6,
		Hash:       otpverifier.SHA256,
	}

	verifier := otpverifier.NewTOTPVerifier(config)

	// Simulate used tokens
	token1 := verifier.GenerateToken()
	verifier.Verify(token1)

	// Wait for periodic cleanup to occur (less than the token validity period)
	time.Sleep(time.Duration(period*3/4) * time.Second)

	// Verify expired tokens are removed
	if len(verifier.UsedTokens) != 1 {
		t.Errorf("Expected 1 used token after periodic cleanup, but got %d", len(verifier.UsedTokens))
	}
}

func TestHOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		// Create an HOTPVerifier with the initial counter, UseSignature set to true, and the specified hash function
		config := otpverifier.Config{
			Secret:       secret,
			Counter:      initialCounter,
			UseSignature: true,
			Hash:         hashFunc,
		}
		config.Hasher = config.GetHasherByName(hashFunc) // Use the GetHasherByName method
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token and signature using the verifier
		token, signature := verifier.GenerateTokenWithSignature()

		// Verify the token and signature
		isValid := verifier.Verify(token, signature)
		if !isValid {
			t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Increment the counter and generate a new token and signature
		initialCounter++
		config.Counter = initialCounter
		verifier = otpverifier.NewHOTPVerifier(config)
		newToken, newSignature := verifier.GenerateTokenWithSignature()

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
		token = verifier.GenerateToken()

		// Verify the token
		isValid = verifier.Verify(token)
		if !isValid {
			t.Errorf("Token should be valid (hash function: %s)", hashFunc)
		}
	}
}

func TestDefaultConfigHOTPVerifier_Verify(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		// Create an HOTPVerifier with the initial counter, UseSignature set to true, and the specified hash function
		config := otpverifier.Config{
			Secret:       secret,
			UseSignature: true,
			Hash:         hashFunc,
		}
		config.Hasher = config.GetHasherByName(hashFunc) // Use the GetHasherByName method
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token and signature using the verifier
		token, signature := verifier.GenerateTokenWithSignature()

		// Verify the token and signature
		isValid := verifier.Verify(token, signature)
		if !isValid {
			t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Increment the counter and generate a new token and signature
		initialCounter++
		config.Counter = initialCounter
		verifier = otpverifier.NewHOTPVerifier(config)
		newToken, newSignature := verifier.GenerateTokenWithSignature()

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
		token, _ = verifier.GenerateTokenWithSignature()

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
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
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
		currentTime := time.Now()
		timeSource := func() time.Time {
			return currentTime
		}
		totpConfig.UseSignature = true
		totpConfig.TimeSource = timeSource
		totpVerifier = otpverifier.NewTOTPVerifier(totpConfig)
		totpToken, totpSignature := totpVerifier.GenerateTokenWithSignature()
		if !totpVerifier.Verify(totpToken, totpSignature) {
			t.Errorf("TOTP token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Test HOTPVerifier token generation and verification
		hotpConfig.UseSignature = true
		hotpVerifier = otpverifier.NewHOTPVerifier(hotpConfig)
		hotpToken, hotpSignature := hotpVerifier.GenerateTokenWithSignature()
		if !hotpVerifier.Verify(hotpToken, hotpSignature) {
			t.Errorf("HOTP token and signature should be valid (hash function: %s)", hashFunc)
		}
	}
}

func TestTOTPVerifier_BuildQRCode(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret: secret,
		Hash:   otpverifier.BLAKE2b512,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"

	// Create a custom QR code configuration
	qrCodeConfig := otpverifier.QRCodeConfig{
		Level:         qrcode.Medium,
		Size:          256,
		DisableBorder: true,
		TopText:       "Scan Me",
		BottomText:    "OTP QR Code",
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
		Hash:   otpverifier.BLAKE2b512,
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

func TestTOTPVerifier_BuildQRCodeWithCustomParams(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret: secret,
		Hash:   otpverifier.BLAKE2b512,
		CustomURITemplateParams: map[string]string{
			"foo": "bar",
		},
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"

	// Create a custom QR code configuration
	qrCodeConfig := otpverifier.QRCodeConfig{
		Level:         qrcode.Medium,
		Size:          256,
		DisableBorder: true,
		TopText:       "Scan Me",
		BottomText:    "OTP QR Code",
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

func TestHOTPVerifier_BuildQRCode(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:  secret,
		Counter: 1337,
		Hash:    otpverifier.BLAKE2b512,
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
		Hash:    otpverifier.BLAKE2b512,
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

func TestHOTPVerifier_BuildQRCodeWithCustomParams(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:  secret,
		Counter: 1337,
		Hash:    otpverifier.BLAKE2b512,
		CustomURITemplateParams: map[string]string{
			"foo": "bar",
		},
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

func TestHOTPVerifier_VerifySyncWindow(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Initialize the counter at an arbitrary value.
	// Note: This situation simulates a scenario where a user's counter is significantly ahead,
	// e.g., at 1337. If the user's counter is beyond the synchronization window,
	// their tokens will not be verified, effectively rendering the tokens useless.
	initialCounter := uint64(1337)
	// The sync window defines how many tokens ahead of the last verified one can be accepted.
	syncWindow := 1

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
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
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + syncWindow + 3)

		// Verify this token should fail
		if verifier.Verify(outsideWindowToken, "") {
			t.Errorf("Token outside sync window verified but should not have (hash function: %s)", hashFunc)
		}
	}
}

func TestHOTPVerifier_VerifySyncWindowWithSignature(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Initialize the counter at an arbitrary value.
	// Note: This situation simulates a scenario where a user's counter is significantly ahead,
	// e.g., at 1337. If the user's counter is beyond the synchronization window,
	// their tokens will not be verified, effectively rendering the tokens useless.
	initialCounter := uint64(1337)
	// The sync window defines how many tokens ahead of the last verified one can be accepted.
	syncWindow := 1
	useSignature := true

	hashFunctions := []string{
		otpverifier.SHA1,
		otpverifier.SHA224,
		otpverifier.SHA256,
		otpverifier.SHA384,
		otpverifier.SHA512,
		otpverifier.SHA512S224,
		otpverifier.SHA512S256,
		otpverifier.BLAKE2b256,
		otpverifier.BLAKE2b384,
		otpverifier.BLAKE2b512,
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		config := otpverifier.Config{
			Secret:       secret,
			Counter:      initialCounter,
			Hasher:       otpverifier.Hashers[hashFunc],
			SyncWindow:   syncWindow,
			UseSignature: useSignature,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Helper function to generate a signature for a token
		generateSignature := func(token string) string {
			key, _ := base32.StdEncoding.DecodeString(secret)
			h := hmac.New(otpverifier.Hashers[hashFunc].Digest, key)
			h.Write([]byte(token))
			return fmt.Sprintf("%x", h.Sum(nil))
		}

		// Generate a token and signature for the current counter value
		currentToken := verifier.Hotp.At(int(initialCounter))
		currentSignature := generateSignature(currentToken)

		// Verify this token and signature should pass
		if !verifier.Verify(currentToken, currentSignature) {
			t.Errorf("Current token did not verify with signature but should have (hash function: %s)", hashFunc)
		}

		// Generate a token and signature for a counter value within the sync window
		withinWindowToken := verifier.Hotp.At(int(initialCounter) + syncWindow)
		withinWindowSignature := generateSignature(withinWindowToken)

		// Verify this token and signature should also pass
		if !verifier.Verify(withinWindowToken, withinWindowSignature) {
			t.Errorf("Token within sync window did not verify with signature but should have (hash function: %s)", hashFunc)
		}

		// Verify that the counter has been updated to the last verified counter + 1
		if verifier.GetCounter() != initialCounter+uint64(syncWindow)+1 {
			t.Errorf("Counter was not updated correctly after sync window verification with signature (hash function: %s)", hashFunc)
		}

		// Generate a token and signature for a counter value outside the sync window
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + syncWindow + 3)
		outsideWindowSignature := generateSignature(outsideWindowToken)

		// Verify this token and signature should fail
		if verifier.Verify(outsideWindowToken, outsideWindowSignature) {
			t.Errorf("Token outside sync window verified with signature but should not have (hash function: %s)", hashFunc)
		}
	}
}

func TestHOTPVerifier_ResetSyncWindow(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)
	initialSyncWindow := 2
	resetSyncWindow := 0 // The new sync window value after reset

	verifier := otpverifier.NewHOTPVerifier(otpverifier.Config{
		Secret:     secret,
		Counter:    initialCounter,
		SyncWindow: initialSyncWindow,
	})

	// Generate a token for the current counter value
	currentToken := verifier.Hotp.At(int(initialCounter))

	// Verify this token should pass with the initial sync window
	if !verifier.Verify(currentToken, "") {
		t.Errorf("Token with initial sync window did not verify but should have")
	}

	// Reset the sync window to a new value
	verifier.ResetSyncWindow(resetSyncWindow)

	// Generate a token for a counter value that would have been within the initial sync window
	// but is outside the reset sync window
	outsideResetWindowToken := verifier.Hotp.At(int(initialCounter) + initialSyncWindow)

	// Verify this token should fail with the reset sync window
	if verifier.Verify(outsideResetWindowToken, "") {
		t.Errorf("Token outside reset sync window verified but should not have")
	}

	// Check if the sync window was correctly reset
	if currentSyncWindow := verifier.GetSyncWindow(); currentSyncWindow != resetSyncWindow {
		t.Errorf("Sync window was not reset correctly, got %d, want %d", currentSyncWindow, resetSyncWindow)
	}
}

func TestHOTPVerifier_ResetSyncWindowToDefault(t *testing.T) {
	secret := gotp.RandomSecret(16)
	initialCounter := uint64(1337)
	initialSyncWindow := 1
	verifier := otpverifier.NewHOTPVerifier(otpverifier.Config{
		Secret:     secret,
		Counter:    initialCounter,
		SyncWindow: initialSyncWindow,
	})

	// Reset the sync window to the default value
	verifier.ResetSyncWindow() // No argument passed, should reset to default

	// Check if the sync window was reset to the default value
	if currentSyncWindow := verifier.GetSyncWindow(); currentSyncWindow != otpverifier.DefaultConfig.SyncWindow {
		t.Errorf("Sync window was not reset to default correctly, got %d, want %d", currentSyncWindow, otpverifier.DefaultConfig.SyncWindow)
	}

	// Alternatively, test resetting to default by passing a negative value
	verifier.ResetSyncWindow(-1) // Passing a negative value, should reset to default

	// Check again if the sync window was reset to the default value
	if currentSyncWindow := verifier.GetSyncWindow(); currentSyncWindow != otpverifier.DefaultConfig.SyncWindow {
		t.Errorf("Sync window was not reset to default correctly after passing negative value, got %d, want %d", currentSyncWindow, otpverifier.DefaultConfig.SyncWindow)
	}
}

func TestGetHasherByName(t *testing.T) {
	// Create a dummy config to use its GetHasherByName method
	config := &otpverifier.Config{}

	// Test cases for supported hash functions
	tests := []struct {
		name       string
		wantDigest func() hash.Hash
	}{
		{name: otpverifier.SHA1, wantDigest: sha1.New},
		{name: otpverifier.SHA224, wantDigest: sha256.New224},
		{name: otpverifier.SHA256, wantDigest: sha256.New},
		{name: otpverifier.SHA384, wantDigest: sha512.New384},
		{name: otpverifier.SHA512, wantDigest: sha512.New},
		{name: otpverifier.SHA512S224, wantDigest: sha512.New512_224},
		{name: otpverifier.SHA512S256, wantDigest: sha512.New512_256},
		{name: otpverifier.BLAKE2b256, wantDigest: blake2botp.New256},
		{name: otpverifier.BLAKE2b384, wantDigest: blake2botp.New384},
		{name: otpverifier.BLAKE2b512, wantDigest: blake2botp.New512},
		{name: otpverifier.BLAKE3256, wantDigest: blake3otp.New256},
		{name: otpverifier.BLAKE3384, wantDigest: blake3otp.New384},
		{name: otpverifier.BLAKE3512, wantDigest: blake3otp.New512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := config.GetHasherByName(tt.name)
			if hasher == nil {
				t.Errorf("GetHasherByName() = nil, want %T", tt.wantDigest())
			}
			if reflect.TypeOf(hasher.Digest()) != reflect.TypeOf(tt.wantDigest()) {
				t.Errorf("GetHasherByName() = %T, want %T", hasher.Digest(), tt.wantDigest())
			}
		})
	}

	// Test case for unsupported hash function
	t.Run("UnsupportedHash", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("GetHasherByName() did not panic with unsupported hash function")
			} else {
				expected := "Hash function NotAHash is not supported"
				if r != expected {
					t.Errorf("GetHasherByName() panic = %v, want %v", r, expected)
				}
			}
		}()
		config.GetHasherByName("NotAHash")
	})
}

func TestTOTPVerifier_VerifyPanic(t *testing.T) {
	secret := gotp.RandomSecret(16)

	// Create a TOTPVerifier with a negative sync window
	config := otpverifier.Config{
		Secret:       secret,
		SyncWindow:   -1,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
	}

	// Create a new TOTPVerifier instance
	verifier := otpverifier.NewTOTPVerifier(config)

	// Generate a token and signature using the verifier
	token, signature := verifier.GenerateTokenWithSignature()

	// Expect a panic when calling Verify with a negative sync window
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected Verify to panic with a negative sync window, but it didn't")
		} else {
			expectedPanicMessage := "totp: SyncWindow must be greater than or equal to zero"
			if r != expectedPanicMessage {
				t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
			}
		}
	}()

	// Call Verify, which should panic
	verifier.Verify(token, signature)
}

func TestHOTPVerifier_VerifyPanic(t *testing.T) {
	secret := gotp.RandomSecret(16)

	// Create a HOTPVerifier with a negative sync window
	config := otpverifier.Config{
		Secret:     secret,
		SyncWindow: -1,
		Hash:       otpverifier.SHA256,
	}

	// Create a new HOTPVerifier instance
	verifier := otpverifier.NewHOTPVerifier(config)

	// Generate a token and signature using the verifier
	token, signature := verifier.GenerateTokenWithSignature()

	// Expect a panic when calling Verify with a negative sync window
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected Verify to panic with a negative sync window, but it didn't")
		} else {
			expectedPanicMessage := "hotp: SyncWindow must be greater than or equal to zero"
			if r != expectedPanicMessage {
				t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
			}
		}
	}()

	// Call Verify, which should panic
	verifier.Verify(token, signature)
}

func TestTOTPVerifier_VerifyMissingSignature(t *testing.T) {
	secret := gotp.RandomSecret(16)

	config := otpverifier.Config{
		Secret:       secret,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
	}

	verifier := otpverifier.NewTOTPVerifier(config)

	token, _ := verifier.GenerateTokenWithSignature()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected Verify to panic with missing signature, but it didn't")
		} else {
			expectedPanicMessage := "totp: Signature is required but not provided"
			if r != expectedPanicMessage {
				t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
			}
		}
	}()

	verifier.Verify(token)
}

func TestTOTPVerifier_VerifySignatureMismatch(t *testing.T) {
	secret := gotp.RandomSecret(16)

	config := otpverifier.Config{
		Secret:       secret,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
	}

	verifier := otpverifier.NewTOTPVerifier(config)

	token, _ := verifier.GenerateTokenWithSignature()
	invalidSignature := "invalid_signature"

	if verifier.Verify(token, invalidSignature) {
		t.Errorf("Expected Verify to return false for signature mismatch, but it returned true")
	}
}

func TestHOTPVerifier_VerifyMissingSignature(t *testing.T) {
	secret := gotp.RandomSecret(16)

	config := otpverifier.Config{
		Secret:       secret,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
	}

	verifier := otpverifier.NewHOTPVerifier(config)

	token, _ := verifier.GenerateTokenWithSignature()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected Verify to panic with missing signature, but it didn't")
		} else {
			expectedPanicMessage := "hotp: Signature is required but not provided"
			if r != expectedPanicMessage {
				t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
			}
		}
	}()

	verifier.Verify(token)
}

func TestHOTPVerifier_VerifySignatureMismatch(t *testing.T) {
	secret := gotp.RandomSecret(16)

	config := otpverifier.Config{
		Secret:       secret,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
	}

	verifier := otpverifier.NewHOTPVerifier(config)

	token, _ := verifier.GenerateTokenWithSignature()
	invalidSignature := "invalid_signature"

	if verifier.Verify(token, invalidSignature) {
		t.Errorf("Expected Verify to return false for signature mismatch, but it returned true")
	}
}
