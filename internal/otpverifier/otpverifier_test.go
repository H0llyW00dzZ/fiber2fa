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
	"fmt"
	"hash"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
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

			// Note: This is a hack hahaha. It succeeds (valid) because the verification process uses crypto/subtle for constant-time comparison.
			// Without using crypto/subtle, it can potentially lead to high vulnerability to timing attacks.
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
		otpverifier.BLAKE3256,
		otpverifier.BLAKE3384,
		otpverifier.BLAKE3512,
	}

	for _, hashFunc := range hashFunctions {
		// Create a TOTPVerifier with the mocked time source, UseSignature set to true, and the specified hash function
		t.Run(fmt.Sprintf("HashFunc=%s", hashFunc), func(t *testing.T) {
			config := otpverifier.Config{
				Secret:     secret,
				Hash:       hashFunc,
				SyncWindow: -1,
				TimeSource: nil,
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

			// Note: This is a hack hahaha. It succeeds (valid) because the verification process uses crypto/subtle for constant-time comparison.
			// Without using crypto/subtle, it can potentially lead to high vulnerability to timing attacks.
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
		Secret:          secret,
		Period:          period,
		Digits:          6,
		Hash:            otpverifier.SHA256,
		TimeSource:      otpverifier.DefaultConfig.TOTPTime,
		CleanupInterval: otpverifier.FastCleanup,
	}

	verifier := otpverifier.NewTOTPVerifier(config)

	// Simulate used tokens
	token1 := verifier.GenerateToken()
	verifier.Verify(token1)

	// Wait Assistant garbage collector for periodic cleanup to occur (less than the token validity period)
	time.Sleep(time.Duration(period*4/4) * time.Second)

	// Simulate used tokens
	token2 := verifier.GenerateToken()
	verifier.Verify(token2)

	// Verify expired tokens are removed
	var usedTokensCount int
	verifier.UsedTokens.Range(func(key, value any) bool {
		usedTokensCount++
		return true
	})

	if usedTokensCount != 1 {
		t.Errorf("Expected 1 used token after periodic cleanup, but got %d", usedTokensCount)
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
		// Note: This is a hack hahaha. It succeeds (valid) because the verification process uses crypto/subtle for constant-time comparison.
		// Without using crypto/subtle, it can potentially lead to high vulnerability to timing attacks.
		token, _ = verifier.GenerateTokenWithSignature()

		// Verify the token
		isValid = verifier.Verify(token, "")
		if !isValid {
			t.Errorf("Token should be valid (hash function: %s)", hashFunc)
		}
	}
}

func TestGenerateSecureRandomCounter(t *testing.T) {
	config := otpverifier.Config{
		Crypto: otpverifier.DefaultConfig.Crypto,
	}

	// Test case 1: maxDigits is 0
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("GenerateSecureRandomCounter did not panic with maxDigits = 0")
			}
		}()
		config.GenerateSecureRandomCounter(0)
	}()

	// Test case 2: maxDigits is negative
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("GenerateSecureRandomCounter did not panic with maxDigits = -1")
			}
		}()
		config.GenerateSecureRandomCounter(-1)
	}()

	// Test case 3: maxDigits is greater than maxSafeDigits
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("GenerateSecureRandomCounter did not panic with maxDigits = 31")
			}
		}()
		config.GenerateSecureRandomCounter(31)
	}()

	// Test case 4: maxDigits is within the safe range
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GenerateSecureRandomCounter panicked with maxDigits = 10: %v", r)
			}
		}()
		randomCounter := config.GenerateSecureRandomCounter(10)
		if randomCounter < 0 || randomCounter > 9999999999 {
			t.Errorf("GenerateSecureRandomCounter returned an invalid counter: %d", randomCounter)
		}
	}()
}

func TestHOTPVerifier_VerifyWithSecureRandomCounter(t *testing.T) {
	secret := gotp.RandomSecret(16)

	initialCounter := otpverifier.DefaultConfig.GenerateSecureRandomCounter(30)

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
			Hash:         hashFunc,
			UseSignature: true,
		}
		config.Hasher = config.GetHasherByName(hashFunc) // Use the GetHasherByName method
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token and signature using the verifier
		token, signature := verifier.GenerateTokenWithSignature()

		// Verify the token
		isValid := verifier.Verify(token, signature)
		if !isValid {
			t.Errorf("Token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Increment the counter and generate a new token and signature
		initialCounter++
		config.Counter = initialCounter
		verifier = otpverifier.NewHOTPVerifier(config)
		newToken, newSignature := verifier.GenerateTokenWithSignature()

		// Verify the new token and new signature
		isValid = verifier.Verify(newToken, newSignature)
		if !isValid {
			t.Errorf("New token and signature should be valid (hash function: %s)", hashFunc)
		}

		// Verify that the old token and old signature are no longer valid
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
			Secret:     secret,
			TimeSource: time.Now,
			Hasher:     otpverifier.Hashers[hashFunc],
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
		Secret:     secret,
		Hash:       otpverifier.BLAKE2b512,
		TimeSource: time.Now,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"

	// Create a custom QR code configuration
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:         qrcode.Medium,
		Size:          256,
		DisableBorder: true,
		TopText:       "Scan Me",
		BottomText:    "OTP QR Code",
	}

	qrCodeBytes, err := verifier.BuildQRCode(issuer, accountName)
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
		Secret:     secret,
		Hash:       otpverifier.BLAKE2b512,
		TimeSource: time.Now,
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"
	filename := "test_qrcode.png"

	// Test case 1: File path not provided (default)
	err := verifier.SaveQRCodeImage(issuer, accountName, filename)
	if err != nil {
		t.Errorf("Failed to save QR code image: %v", err)
	}
	defer os.Remove(filename)

	// Check if the file was created in the current directory
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		t.Errorf("QR code image file was not created in the current directory")
	}

	// Test case 2: File path provided
	tempDir, err := os.MkdirTemp("", "qrcode-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	qrCodeConfig := otpverifier.DefaultQRCodeConfig
	qrCodeConfig.FilePath = tempDir

	err = verifier.SaveQRCodeImage(issuer, accountName, filename)
	if err != nil {
		t.Errorf("Failed to save QR code image: %v", err)
	}

	// Check if the file was created in the temporary directory
	expectedPath := filepath.Join(tempDir, filename)
	_, err = os.Stat(expectedPath)
	if os.IsNotExist(err) {
		t.Errorf("QR code image file was not created at the expected path: %s", expectedPath)
	}
}

func TestTOTPVerifier_BuildQRCodeWithCustomParams(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:     secret,
		Hash:       otpverifier.BLAKE2b512,
		TimeSource: time.Now,
		CustomURITemplateParams: map[string]string{
			"foo": "bar",
		},
	}
	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := "TestIssuer"
	accountName := "TestAccount"

	// Create a custom QR code configuration
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:         qrcode.Medium,
		Size:          256,
		DisableBorder: true,
		TopText:       "Scan Me",
		BottomText:    "OTP QR Code",
	}

	qrCodeBytes, err := verifier.BuildQRCode(issuer, accountName)
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

func TestTOTPVerifier_BuildQRCodePanic(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret:     secret,
		Digits:     10,
		Hash:       otpverifier.SHA256,
		TimeSource: time.Now,
	}

	verifier := otpverifier.NewTOTPVerifier(config)

	issuer := ""
	accountName := ""

	// Create a custom QR code configuration
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:           qrcode.Medium,
		Size:            256,
		DisableBorder:   true,
		TopText:         "Scan Me",
		BottomText:      "OTP QR Code",
		ForegroundColor: color.Black,
	}

	// Expect a panic when calling BuildQRCode with a maximum digits
	t.Run("MaximumDigits", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with maximum digits, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: maximum digits are 8 for TOTP"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with maximum digits, which should panic
		verifier.BuildQRCode("issuer", "accountName")
	})

	// Expect a panic when calling BuildQRCode with empty issuer
	t.Run("EmptyIssuer", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with an empty issuer, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: issuer cannot be empty"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with an empty issuer, which should panic
		verifier.BuildQRCode(issuer, "accountName")
	})

	// Expect a panic when calling BuildQRCode with empty account name
	t.Run("EmptyAccountName", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with an empty account name, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: account name cannot be empty"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with an empty account name, which should panic
		verifier.BuildQRCode("issuer", accountName)
	})

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
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:           qrcode.Medium,
		Size:            256,
		DisableBorder:   true,
		TopText:         "Scan Me",
		BottomText:      "OTP QR Code",
		ForegroundColor: color.Black,
	}

	qrCodeBytes, err := verifier.BuildQRCode(issuer, accountName)
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

	// Test case 1: File path not provided (default)
	err := verifier.SaveQRCodeImage(issuer, accountName, filename)
	if err != nil {
		t.Errorf("Failed to save QR code image: %v", err)
	}
	defer os.Remove(filename)

	// Check if the file was created in the current directory
	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		t.Errorf("QR code image file was not created in the current directory")
	}

	// Test case 2: File path provided
	tempDir, err := os.MkdirTemp("", "qrcode-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	verifier.QRCodeBuilder.FilePath = tempDir

	err = verifier.SaveQRCodeImage(issuer, accountName, filename)
	if err != nil {
		t.Errorf("Failed to save QR code image: %v", err)
	}

	// Check if the file was created in the temporary directory
	expectedPath := filepath.Join(tempDir, filename)
	_, err = os.Stat(expectedPath)
	if os.IsNotExist(err) {
		t.Errorf("QR code image file was not created at the expected path: %s", expectedPath)
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
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:           qrcode.Medium,
		Size:            256,
		DisableBorder:   true,
		TopText:         "Scan Me",
		BottomText:      "OTP QR Code",
		ForegroundColor: color.Black,
	}

	qrCodeBytes, err := verifier.BuildQRCode(issuer, accountName)
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

func TestHOTPVerifier_BuildQRCodePanic(t *testing.T) {
	secret := gotp.RandomSecret(16)
	config := otpverifier.Config{
		Secret: secret,
		Digits: 10,
		Hash:   otpverifier.SHA256,
	}

	verifier := otpverifier.NewHOTPVerifier(config)

	issuer := ""
	accountName := ""

	// Create a custom QR code configuration
	verifier.QRCodeBuilder = otpverifier.QRCodeConfig{
		Level:           qrcode.Medium,
		Size:            256,
		DisableBorder:   true,
		TopText:         "Scan Me",
		BottomText:      "OTP QR Code",
		ForegroundColor: color.Black,
	}

	// Expect a panic when calling BuildQRCode with a maximum digits
	t.Run("MaximumDigits", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with maximum digits, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: maximum digits are 8 for HOTP"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with maximum digits, which should panic
		verifier.BuildQRCode("issuer", "accountName")
	})

	// Expect a panic when calling BuildQRCode with empty issuer
	t.Run("EmptyIssuer", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with an empty issuer, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: issuer cannot be empty"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with an empty issuer, which should panic
		verifier.BuildQRCode(issuer, "accountName")
	})

	// Expect a panic when calling BuildQRCode with empty account name
	t.Run("EmptyAccountName", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected BuildQRCode to panic with an empty account name, but it didn't")
			} else {
				expectedPanicMessage := "BuildQRCode: account name cannot be empty"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		// Call BuildQRCode with an empty account name, which should panic
		verifier.BuildQRCode("issuer", accountName)
	})

}

func TestHOTPVerifier_VerifySyncWindow(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Initialize the counter at an arbitrary value.
	// Note: This situation simulates a scenario where a user's counter is significantly ahead,
	// e.g., at 1337. If the user's counter is beyond the synchronization window,
	// their tokens will not be verified, effectively rendering the tokens useless.
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
		config := otpverifier.Config{
			Secret:     secret,
			Counter:    initialCounter,
			Hasher:     otpverifier.Hashers[hashFunc],
			SyncWindow: otpverifier.HighStrict,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token for the current counter value
		currentToken := verifier.Hotp.At(int(initialCounter))

		// Verify this token should pass
		if !verifier.Verify(currentToken) {
			t.Errorf("Current token did not verify but should have (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value within the sync window
		withinWindowToken := verifier.Hotp.At(int(initialCounter) + otpverifier.HighStrict)

		// Verify this token should also pass
		if !verifier.Verify(withinWindowToken) {
			t.Errorf("Token within sync window did not verify but should have (hash function: %s)", hashFunc)
		}

		// Verify that the counter has been updated to the last verified counter + 1
		if verifier.GetCounter() != initialCounter+uint64(otpverifier.HighStrict)+1 {
			t.Errorf("Counter was not updated correctly after sync window verification (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value outside the sync window
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + otpverifier.HighStrict + 3)

		// Verify this token should fail
		if verifier.Verify(outsideWindowToken) {
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
			SyncWindow:   otpverifier.HighStrict,
			UseSignature: useSignature,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Helper function to generate a signature for a token
		generateSignature := func(token string) string {
			key := config.DecodeBase32WithPadding()
			h := hmac.New(otpverifier.Hashers[hashFunc].Digest, key)
			h.Write([]byte(token))
			return fmt.Sprintf("%x", h.Sum(nil))
		}

		// Generate a token and signature for the current counter value
		currentToken, currentSignature := verifier.GenerateTokenWithSignature()

		// Verify this token and signature should pass
		if !verifier.Verify(currentToken, currentSignature) {
			t.Errorf("Current token did not verify with signature but should have (hash function: %s)", hashFunc)
		}

		// Generate a token and signature for a counter value within the sync window
		withinWindowToken, withinWindowSignature := verifier.GenerateTokenWithSignature()

		// Verify this token and signature should also pass
		if !verifier.Verify(withinWindowToken, withinWindowSignature) {
			t.Errorf("Token within sync window did not verify with signature but should have (hash function: %s)", hashFunc)
		}

		// Verify that the counter has been updated to the last verified counter + 1
		if verifier.GetCounter() != initialCounter+uint64(otpverifier.HighStrict)+1 {
			t.Errorf("Counter was not updated correctly after sync window verification with signature (hash function: %s)", hashFunc)
		}

		// Generate a token and signature for a counter value outside the sync window
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + otpverifier.HighStrict + 3)
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
	initialSyncWindow := otpverifier.MediumStrict
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
	verifier := otpverifier.NewHOTPVerifier(otpverifier.Config{
		Secret:     secret,
		Counter:    initialCounter,
		SyncWindow: otpverifier.HighStrict,
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

func TestHOTPVerifier_VerifySyncWindowMediumStrict(t *testing.T) {
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
		config := otpverifier.Config{
			Secret:     secret,
			Counter:    initialCounter,
			Hasher:     otpverifier.Hashers[hashFunc],
			SyncWindow: otpverifier.MediumStrict,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Get the actual sync window size based on the counter value
		syncWindowRange := otpverifier.SyncWindowRanges[otpverifier.MediumStrict]
		// Let's consider "syncWindowSize" is the number of attempts verifier tries after the current value of counter.
		syncWindowSize := int(initialCounter) % (syncWindowRange[1] - syncWindowRange[0] + 1)

		// Generate a token for the current counter value.
		currentToken := verifier.Hotp.At(int(verifier.GetCounter()))

		// Verify this token should pass.
		if !verifier.Verify(currentToken) {
			t.Fatalf("Expected the current counter token to verify")
		}

		// Generate a token within the sync window.
		withinWindowCounter := verifier.GetCounter() + uint64(syncWindowSize)
		withinWindowToken := verifier.Hotp.At(int(withinWindowCounter))

		// Verify this token should also pass.
		if !verifier.Verify(withinWindowToken) {
			t.Fatalf("Expected the within sync window token to verify")
		}

		// Ensure the counter has been incremented after the verification within the sync window.
		if verifier.GetCounter() != withinWindowCounter+1 {
			t.Fatalf("Expected the counter to be incremented to %d, but got %d", withinWindowCounter+1, verifier.GetCounter())
		}

		// Generate a token for a counter value outside the sync window.
		outsideWindowCounter := withinWindowCounter + 6
		outsideWindowToken := verifier.Hotp.At(int(outsideWindowCounter))

		// Verify this token should fail.
		if verifier.Verify(outsideWindowToken) {
			t.Fatalf("Expected the outside sync window token to fail verification")
		}
	}
}

func TestHOTPVerifier_VerifySyncWindowLowStrict(t *testing.T) {
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
		config := otpverifier.Config{
			Secret:     secret,
			Counter:    initialCounter,
			Hasher:     otpverifier.Hashers[hashFunc],
			SyncWindow: otpverifier.LowStrict,
		}
		verifier := otpverifier.NewHOTPVerifier(config)

		// Get the actual sync window size based on the counter value
		syncWindowRange := otpverifier.SyncWindowRanges[otpverifier.LowStrict]
		// Let's consider "syncWindowSize" as the dynamic value based on the current counter value
		syncWindowSize := int(initialCounter) % (syncWindowRange[1] - syncWindowRange[0] + 1)

		// Generate a token for the current counter value
		currentToken := verifier.GenerateToken()

		// Verify this token should pass
		if !verifier.Verify(currentToken) {
			t.Errorf("Current token did not verify but should have (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value within the sync window
		withinWindowCounter := verifier.GetCounter() + uint64(syncWindowSize)
		withinWindowToken := verifier.Hotp.At(int(withinWindowCounter))

		// This token should be valid as it is within the synchronization window
		if !verifier.Verify(withinWindowToken) {
			t.Errorf("Token within sync window did not verify but should have (hash function: %s)", hashFunc)
		}

		expectedNextCounter := withinWindowCounter + 1
		if verifier.GetCounter() != expectedNextCounter {
			t.Errorf("Counter was not set correctly; expected %d, got %d (hash function: %s)", expectedNextCounter, verifier.GetCounter(), hashFunc)
		}

		// Generate a token for a counter value just outside the sync window
		// Test the verification of a token just outside the sync window
		outsideWindowCounter := withinWindowCounter + 11 // next value after the sync window
		outsideWindowToken := verifier.Hotp.At(int(outsideWindowCounter))

		// This token should not verify
		if verifier.Verify(outsideWindowToken) {
			t.Errorf("Token outside sync window verified but should not have (hash function: %s)", hashFunc)
		}

		// Counter should not change after unsuccessful verification
		if verifier.GetCounter() != expectedNextCounter {
			t.Errorf("Counter should not change after unsuccessful verification; expected %d, got %d (hash function: %s)", expectedNextCounter, verifier.GetCounter(), hashFunc)
		}
	}
}

func TestHOTPVerifier_VerifySyncWindowWithResync(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Initialize the counter at an arbitrary value.
	// Note: This situation simulates a scenario where a user's counter is significantly ahead,
	// e.g., at 1337. If the user's counter is beyond the synchronization window,
	// their tokens will not be verified, effectively rendering the tokens useless.
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
		config := otpverifier.Config{
			Secret:            secret,
			Counter:           initialCounter,
			Hasher:            otpverifier.Hashers[hashFunc],
			SyncWindow:        otpverifier.MediumStrict,
			ResyncWindowDelay: 1 * time.Second,
		}

		verifier := otpverifier.NewHOTPVerifier(config)

		// Generate a token for the current counter value
		verifier.Hotp.At(int(initialCounter + 5))

		// Verify this token should fail
		if verifier.Verify("invalid") {
			t.Errorf("Token should be invalid since the user entering invalid token (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value within the sync window
		withinWindowToken := verifier.Hotp.At(int(initialCounter) + otpverifier.MediumStrict)

		// Verify this token should also pass
		if !verifier.Verify(withinWindowToken) {
			t.Errorf("Token within sync window did not verify but should have (hash function: %s)", hashFunc)
		}

		// Verify that the counter has been updated to the last verified counter + 1
		if verifier.GetCounter() != initialCounter+uint64(otpverifier.MediumStrict)+1 {
			t.Errorf("Counter was not updated correctly after sync window verification (hash function: %s)", hashFunc)
		}

		// Generate a token for a counter value outside the sync window
		outsideWindowToken := verifier.Hotp.At(int(initialCounter) + otpverifier.MediumStrict + 6)

		// Verify this token should fail
		if verifier.Verify(outsideWindowToken) {
			t.Errorf("Token outside sync window verified but should not have (hash function: %s)", hashFunc)
		}

		// Trigger the AdjustSyncWindow function
		verifier.AdjustSyncWindow(config.CounterMismatch)

		// Get the actual sync window size
		actualSyncWindow := verifier.GetSyncWindow()

		// Get the expected sync window range for MediumStrict
		expectedRange := otpverifier.SyncWindowRanges[otpverifier.MediumStrict]

		// Check if the actual sync window size falls within the expected range
		if actualSyncWindow < expectedRange[0] || actualSyncWindow > expectedRange[1] {
			t.Errorf("Expected sync window size to be within the range %v, but got %d", expectedRange, actualSyncWindow)
		}
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
				expected := "GetHasherByName: hash function NotAHash is not supported"
				if r != expected {
					t.Errorf("GetHasherByName() panic = %v, want %v", r, expected)
				}
			}
		}()
		config.GetHasherByName("NotAHash")
	})

	// Test case for empty hash function name
	t.Run("EmptyHash", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("GetHasherByName() did not panic with empty hash function name")
			} else {
				expected := "GetHasherByName: hash function name cannot be empty"
				if r != expected {
					t.Errorf("GetHasherByName() panic = %v, want %v", r, expected)
				}
			}
		}()
		config.GetHasherByName("")
	})
}

func TestTOTPVerifier_VerifyPanic(t *testing.T) {
	secret := gotp.RandomSecret(16)

	// Create a TOTPVerifier with a negative sync window
	config := otpverifier.Config{
		Secret:       secret,
		SyncWindow:   -1,
		UseSignature: true,
		TimeSource:   time.Now,
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
		Secret:       secret,
		SyncWindow:   -1,
		UseSignature: true,
		Hash:         otpverifier.SHA256,
		Counter:      1,
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
		TimeSource:   time.Now,
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
		TimeSource:   time.Now,
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

func TestOCRAVerifier_GenerateToken(t *testing.T) {
	// Create a new OCRAVerifier with default configuration
	config := otpverifier.DefaultConfig
	secret := gotp.RandomSecret(16)
	config.Secret = secret
	verifier := otpverifier.NewOCRAVerifier(config)

	// Define test cases
	testCases := []struct {
		challenge string
		expected  string
	}{
		{
			challenge: "OCRA-1:HOTP-SHA1-6:QN08-0-00000000",
			expected:  generateOCRA(secret, "OCRA-1:HOTP-SHA1-6:QN08-0-00000000"),
		},
		{
			challenge: "OCRA-1:HOTP-SHA256-8:QN08-1-11111111",
			expected:  generateOCRA(secret, "OCRA-1:HOTP-SHA256-8:QN08-1-11111111"),
		},
		{
			challenge: "OCRA-1:HOTP-SHA512-8:QN08-2-22222222",
			expected:  generateOCRA(secret, "OCRA-1:HOTP-SHA512-8:QN08-2-22222222"),
		},
	}

	for _, tc := range testCases {
		t.Run("Challenge="+tc.challenge, func(t *testing.T) {
			result := verifier.GenerateToken(tc.challenge)

			if result != tc.expected {
				t.Errorf("Expected token to be %s, got %s instead", tc.expected, result)
			}
		})
	}
}

func TestOCRAVerifier_Verify(t *testing.T) {
	// Create a new OCRAVerifier with default configuration
	config := otpverifier.DefaultConfig
	secret := gotp.RandomSecret(16)
	config.Secret = secret
	verifier := otpverifier.NewOCRAVerifier(config)

	// Define test cases
	testCases := []struct {
		ocraSuite string
		token     string
		expected  bool
	}{
		{
			ocraSuite: "OCRA-1:HOTP-SHA1-6",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA256-8",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA512-8",
			token:     "", // Token will be generated based on the challenge
			expected:  true,
		},
		{
			ocraSuite: "OCRA-1:HOTP-SHA1-6",
			token:     "123456",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		challenge := generateRandomChallenge(config, tc.ocraSuite)
		t.Run("Challenge="+challenge, func(t *testing.T) {
			if tc.token == "" {
				tc.token = generateOCRA(secret, challenge)
			}
			result := verifier.Verify(tc.token, challenge)
			t.Logf("Challenge: %s, Token: %s, Expected: %v, Result: %v", challenge, tc.token, tc.expected, result)

			if result != tc.expected {
				t.Errorf("Expected verification result to be %v, got %v instead", tc.expected, result)
			}
		})
	}
}

func TestOCRAVerifier_Verify_InvalidCounterAndQuestion(t *testing.T) {
	// Create a new OCRAVerifier with default configuration
	config := otpverifier.DefaultConfig
	secret := gotp.RandomSecret(16)
	config.Secret = secret
	verifier := otpverifier.NewOCRAVerifier(config)

	// Define test cases with invalid counter and question/answer
	//
	// Note: This is a better approach instead of incrementing a counter when generating a token,
	// however it requires building own 2FA apps because it won't work if trying to use the same source
	// that relies on the RFC Ancient Method.
	testCases := []struct {
		challenge string
		token     string
		expected  bool
	}{
		{
			challenge: "OCRA-1:HOTP-SHA1-6:QN08-123-InvalidQuestion",
			token:     "",
			expected:  false,
		},
		{
			challenge: "OCRA-1:HOTP-SHA1-6:QN08-1234-ValidQuestion",
			token:     "",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		// Generate a valid challenge
		validChallenge := generateRandomChallenge(config, "OCRA-1:HOTP-SHA1-6")
		t.Run("Challenge="+tc.challenge, func(t *testing.T) {
			if tc.token == "" {
				// Generate a valid token
				tc.token = generateOCRA(secret, validChallenge)
			}
			result := verifier.Verify(tc.token, tc.challenge)
			t.Logf("Challenge: %s, Token: %s, Expected: %v, Result: %v", tc.challenge, tc.token, tc.expected, result)

			if result != tc.expected {
				t.Errorf("Expected verification result to be %v, got %v instead", tc.expected, result)
			}
		})
	}
}

// generateOCRA is a helper function to generate OCRA tokens for testing purposes.
func generateOCRA(secret string, challenge string) string {
	return otpverifier.NewOCRAVerifier(
		otpverifier.Config{
			Secret: secret,
		}).GenerateToken(challenge)
}

// generateRandomChallenge generates a random challenge string with the specified OCRA suite and a random question.
//
// Note: This is a better way to generate the challenge. The counter and question/answer can be randomly generated,
// or the client must solve a math formula of the highest difficulty Solve to get the TOKEN.
func generateRandomChallenge(config otpverifier.Config, ocraSuite string) string {
	randNum1 := config.GenerateSecureRandomCounter(8)
	randNum2 := config.GenerateSecureRandomCounter(8)
	return fmt.Sprintf("%s:%s-%d-%d", ocraSuite, "QN08", randNum1, randNum2)
}

func TestOCRAVerifier_GenerateToken_Panics(t *testing.T) {
	// Create a new OCRAVerifier with default configuration
	config := otpverifier.DefaultConfig
	secret := gotp.RandomSecret(16)
	config.Secret = secret
	verifier := otpverifier.NewOCRAVerifier(config)

	// Define test cases
	testCases := []struct {
		name      string
		challenge string
	}{
		{
			name:      "InvalidChallengeFormat_MissingParts",
			challenge: "OCRA-1:HOTP-SHA1-6",
		},
		{
			name:      "InvalidChallengeFormat_MissingCounterAndQuestion",
			challenge: "OCRA-1:HOTP-SHA1-6:QN08",
		},
		{
			name:      "InvalidCounterValue",
			challenge: "OCRA-1:HOTP-SHA1-6:QN08-invalid-00000000",
		},
		{
			name:      "UnsupportedOCRASuite_MissingVersion",
			challenge: "HOTP-SHA1-6:QN08-0-00000000",
		},
		{
			name:      "UnsupportedOCRASuite_InvalidVersion",
			challenge: "OCRA-2:HOTP-SHA1-6:QN08-0-00000000",
		},
		{
			name:      "UnsupportedHashAlgorithm",
			challenge: "OCRA-1:HOTP-MD5-6:QN08-0-00000000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected panic, but no panic occurred")
				}
			}()

			verifier.GenerateToken(tc.challenge)
		})
	}
}

func TestDecodeBase32WithPadding_Crash(t *testing.T) {
	// Note: The base32 encoding of this secret is bounds into a
	// cryptographically secure pseudorandom number generator (see
	// https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).
	// Incorrect padding (e.g., extra "=", out-of-place "=") can lead to illegal base32 data.
	secret := gotp.RandomSecret(16) + "==="

	// Test case for invalid base32 input
	t.Run("Illegal_Base32_AnyText", func(t *testing.T) {
		helperFunction := otpverifier.Config{
			Secret: "ILLEGAL BASE32",
			Hash:   otpverifier.SHA256,
		}

		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected DecodeBase32WithPadding to panic with ILLEGAL BASE32, but it didn't")
			} else {
				expectedPanicMessage := "DecodeBase32WithPadding: illegal base32 data"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		helperFunction.DecodeBase32WithPadding()
	})

	// Test case for incorrect padding
	t.Run("Illegal_Base32_OutOfPadding", func(t *testing.T) {
		testOutPadding := otpverifier.Config{
			Secret: secret,
			Hash:   otpverifier.SHA512,
		}

		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected DecodeBase32WithPadding to panic with ILLEGAL BASE32, but it didn't")
			} else {
				expectedPanicMessage := "DecodeBase32WithPadding: illegal base32 data"
				if r != expectedPanicMessage {
					t.Errorf("Expected panic message: %s, but got: %s", expectedPanicMessage, r)
				}
			}
		}()

		testOutPadding.DecodeBase32WithPadding()
	})
}
