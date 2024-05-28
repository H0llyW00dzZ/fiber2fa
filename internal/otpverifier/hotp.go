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
	if config.Hash != "" {
		// If HashName is provided, use it to get the corresponding Hasher
		config.Hasher = config.GetHasherByName(config.Hash)
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

// Verify checks if the provided token and signature are valid for the specified counter value.
// If the 'SyncWindow' configuration is greater than 1, the method will validate the token against
// a range of counter values defined by the current counter and the sync window size. This allows
// for a degree of error tolerance in scenarios where the verifier's counter may be out of sync
// with the token generator's counter. If the 'UseSignature' configuration is set to true, the method
// also verifies the provided signature against the expected signature for the token.
// A successful verification will result in the counter being updated to the next expected value.
//
// Note: A firm grasp of the sync window concept is essential for understanding its role in the verification process.
func (v *HOTPVerifier) Verify(token, signature string) bool {
	// Check if sync window is applied
	// Note: Understanding this sync window requires skilled mathematical reasoning.
	if v.config.SyncWindow > 1 {
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

	// Default case when sync window is not applied
	generatedToken := v.Hotp.At(int(v.config.Counter))
	tokenMatch := subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
	signatureMatch := true // Assume true if not using signatures.

	if v.config.UseSignature {
		generatedSignature := v.generateSignature(generatedToken)
		signatureMatch = subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
	}

	if tokenMatch && signatureMatch {
		// Increment the counter value after successful verification
		v.config.Counter++
		return true
	}
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

// GetSyncWindow returns the current synchronization window value from the HOTPVerifier's configuration.
func (v *HOTPVerifier) GetSyncWindow() int {
	return v.config.SyncWindow
}

// ResetSyncWindow resets the synchronization window to a default or specified value.
// If no value is provided, it resets to the default value defined in DefaultConfig.
func (v *HOTPVerifier) ResetSyncWindow(newSyncWindow ...int) {
	if len(newSyncWindow) > 0 && newSyncWindow[0] >= 0 {
		// Set the sync window to the provided new value if it's non-negative.
		v.config.SyncWindow = newSyncWindow[0]
	} else {
		// Reset the sync window to the default value if no value is provided or if it's negative.
		v.config.SyncWindow = DefaultConfig.SyncWindow
	}
}

// GenerateOTPURL creates the URL for the QR code based on the provided URI template.
func (v *HOTPVerifier) GenerateOTPURL(issuer, accountName string) string {
	return v.config.generateOTPURL(issuer, accountName)
}
