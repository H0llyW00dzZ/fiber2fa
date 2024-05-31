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
//
// Note: When using HOTP, consider setting the counter to start from 1. In some 2FA apps, including mobile apps,
// when a device is registered, the counter is often initialized to 1 when generating the token (e.g., a 6-digit password)
// because by default, the counter starts at 0 and is hidden the token.
// Also note that this is still a basic mathematical implementation about counter. More advanced mathematical concepts might be implemented
// in the future, but not at this time due to the limitations of some mobile 2FA ecosystems (poor ecosystems).
func NewHOTPVerifier(config ...Config) *HOTPVerifier {
	c := DefaultConfig
	if len(config) > 0 {
		c = config[0]
	}

	// Use default values if not provided
	if c.Digits == 0 {
		c.Digits = DefaultConfig.Digits
	}
	if c.Counter == 0 {
		c.Digits = int(DefaultConfig.Counter)
	}
	if c.Hash != "" {
		// If HashName is provided, use it to get the corresponding Hasher
		c.Hasher = c.GetHasherByName(c.Hash)
	}
	if c.URITemplate == "" {
		c.URITemplate = DefaultConfig.URITemplate
	}

	// Set the synchronization window based on the strictness level
	switch c.SyncWindow {
	case MediumStrict, LowStrict:
		if r, ok := SyncWindowRanges[c.SyncWindow]; ok {
			c.SyncWindow = r[0] + int(c.Counter)%len(r)
		}
	}

	hotp := gotp.NewHOTP(c.Secret, c.Digits, c.Hasher)
	return &HOTPVerifier{
		config: c,
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
func (v *HOTPVerifier) Verify(token string, signature ...string) bool {
	if v.config.SyncWindow < 0 {
		panic("hotp: SyncWindow must be greater than or equal to zero")
	}

	// Set the synchronization window size based on the strictness level and counter value
	syncWindowSize := v.config.SyncWindow
	if r, ok := SyncWindowRanges[v.config.SyncWindow]; ok {
		syncWindowSize = r[0] + int(v.config.Counter)%len(r)
	}

	if v.config.UseSignature {
		if len(signature) == 0 {
			panic("hotp: Signature is required but not provided")
		}

		return v.verifyWithSignature(token, signature[0], syncWindowSize)
	}

	return v.verifyWithoutSignature(token, syncWindowSize)
}

// verifyWithoutSignature checks if the provided token is valid for the specified counter value without signature verification.
func (v *HOTPVerifier) verifyWithoutSignature(token string, syncWindowSize int) bool {
	// Check if sync window is applied
	// Note: Understanding this sync window requires skilled mathematical reasoning.
	if syncWindowSize > 0 {
		for i := 0; i <= syncWindowSize; i++ {
			expectedCounter := int(v.config.Counter) + i
			generatedToken := v.Hotp.At(expectedCounter)
			if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 {
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
	if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 {
		// Increment the counter value after successful verification
		v.config.Counter++
		return true
	}
	return false
}

// verifyWithSignature checks if the provided token and signature are valid for the specified counter value.
func (v *HOTPVerifier) verifyWithSignature(token, signature string, syncWindowSize int) bool {
	// Check if sync window is applied
	// Note: Understanding this sync window requires skilled mathematical reasoning.
	if syncWindowSize > 0 {
		for i := 0; i <= syncWindowSize; i++ {
			expectedCounter := int(v.config.Counter) + i
			generatedToken := v.Hotp.At(expectedCounter)
			generatedSignature := v.generateSignature(generatedToken)
			if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
				subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1 {
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
	generatedSignature := v.generateSignature(generatedToken)
	if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
		subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1 {
		// Increment the counter value after successful verification
		v.config.Counter++
		return true
	}
	return false
}

// GenerateToken generates a token for the current counter value.
func (v *HOTPVerifier) GenerateToken() string {
	return v.Hotp.At(int(v.config.Counter))
}

// GenerateTokenWithSignature generates a token and signature for the current counter value.
func (v *HOTPVerifier) GenerateTokenWithSignature() (string, string) {
	token := v.Hotp.At(int(v.config.Counter))
	signature := v.generateSignature(token)
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
