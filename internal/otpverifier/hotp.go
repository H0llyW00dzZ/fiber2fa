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
	hotp   *gotp.HOTP
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

	hotp := gotp.NewHOTP(config.Secret, config.Digits, config.Hasher)
	return &HOTPVerifier{
		config: config,
		hotp:   hotp,
	}
}

// Verify checks if the provided token and signature are valid for the specified counter value.
func (v *HOTPVerifier) Verify(token, signature string) bool {
	generatedToken := v.hotp.At(int(v.config.Counter))
	if v.config.UseSignature {
		generatedSignature := v.generateSignature(generatedToken)
		if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
			subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1 {
			// Increment the counter value after successful verification
			v.config.Counter++
			return true
		}
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 {
		// Increment the counter value after successful verification
		v.config.Counter++
		return true
	}
	return false
}

// GenerateToken generates a token and signature for the current counter value.
func (v *HOTPVerifier) GenerateToken() (string, string) {
	token := v.hotp.At(int(v.config.Counter))
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
