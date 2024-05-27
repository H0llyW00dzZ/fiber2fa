// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"fmt"

	"github.com/xlzd/gotp"
)

// HOTPVerifier is an HOTP verifier that implements the OTPVerifier interface.
type HOTPVerifier struct {
	config Config
	Hotp   *gotp.HOTP
}

// NewHOTPVerifier creates a new HOTPVerifier with the given configuration.
func NewHOTPVerifier(config Config) *HOTPVerifier {
	// Use default values if not provided
	if config.Digits == 0 {
		config.Digits = DefaultConfig.Digits
	}
	if config.Hasher == nil {
		config.Hasher = DefaultConfig.Hasher
	}
	if config.URITemplate == "" {
		config.URITemplate = DefaultConfig.URITemplate
	}

	hotp := gotp.NewHOTP(config.Secret, config.Digits, config.Hasher)
	return &HOTPVerifier{
		config: config,
		Hotp:   hotp,
	}
}

// Verify checks if the provided token and signature are valid for the specified counter value within the synchronization window.
//
// Note: Understanding how the "Synchronize in real-time" HOTP works requires a big brain.
func (v *HOTPVerifier) Verify(token, signature string) bool {
	for i := 0; i <= v.config.SyncWindow; i++ {
		expectedCounter := int(v.config.Counter) + i
		generatedToken := v.Hotp.At(expectedCounter)

		tokenMatch := subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
		signatureMatch := true // Assume true if not using signatures.

		if v.config.UseSignature {
			generatedSignature := v.generateSignature(generatedToken)
			signatureMatch = subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
		}

		if tokenMatch && signatureMatch {
			// Update the stored counter to the next expected value after a successful match
			v.config.Counter = uint64(expectedCounter + 1)
			return true
		}
	}

	// If no match is found within the synchronization window, authentication fails
	return false
}

// GenerateToken generates a token and signature for the current counter value.
func (v *HOTPVerifier) GenerateToken() (string, string) {
	token := v.Hotp.At(int(v.config.Counter))
	signature := ""
	if v.config.UseSignature {
		signature = v.generateSignature(token)
	}
	return token, signature
}

// generateSignature generates an HMAC signature for the given token using the secret key.
func (v *HOTPVerifier) generateSignature(token string) string {
	key, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	h := hmac.New(v.config.Hasher.Digest, key)
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SetCounter sets the counter value in the HOTPVerifier's configuration.
func (v *HOTPVerifier) SetCounter(counter uint64) {
	v.config.Counter = counter
}

// GetCounter returns the current counter value from the HOTPVerifier's configuration.
func (v *HOTPVerifier) GetCounter() uint64 {
	return v.config.Counter
}
