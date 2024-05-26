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

// TOTPVerifier is a TOTP verifier that implements the OTPVerifier interface.
type TOTPVerifier struct {
	config Config
	totp   *gotp.TOTP
}

// NewTOTPVerifier creates a new TOTPVerifier with the given configuration.
func NewTOTPVerifier(config Config) *TOTPVerifier {
	// Use default values if not provided
	if config.Digits == 0 {
		config.Digits = DefaultConfig.Digits
	}
	if config.Period == 0 {
		config.Period = DefaultConfig.Period
	}
	if config.TimeSource == nil {
		config.TimeSource = DefaultConfig.TimeSource
	}
	if config.Hasher == nil {
		config.Hasher = DefaultConfig.Hasher
	}

	totp := gotp.NewTOTP(config.Secret, config.Digits, config.Period, config.Hasher)
	return &TOTPVerifier{
		config: config,
		totp:   totp,
	}
}

// Verify checks if the provided token and signature are valid for the current time.
func (v *TOTPVerifier) Verify(token, signature string) bool {
	generatedToken := v.totp.Now()
	if v.config.UseSignature {
		generatedSignature := v.generateSignature(generatedToken)
		return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
			subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
}

// GenerateToken generates a token and signature for the current time.
func (v *TOTPVerifier) GenerateToken() (string, string) {
	token := v.totp.Now()
	signature := ""
	if v.config.UseSignature {
		signature = v.generateSignature(token)
	}
	return token, signature
}

// generateSignature generates an HMAC signature for the given token using the secret key.
func (v *TOTPVerifier) generateSignature(token string) string {
	key, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	h := hmac.New(v.config.Hasher.Digest, key)
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}
