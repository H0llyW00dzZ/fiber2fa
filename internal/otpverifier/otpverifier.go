// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/xlzd/gotp"
)

// TimeSource is a function type that returns the current time.
type TimeSource func() time.Time

// OTPVerifier is an interface that defines the behavior of an OTP verifier.
type OTPVerifier interface {
	Verify(token, signature string) bool
	GenerateToken() (string, string)
}

// Config is a struct that holds the configuration options for the OTP verifier.
type Config struct {
	Secret       string
	Counter      uint64
	UseSignature bool
	TimeSource   TimeSource
}

// TOTPVerifier is a TOTP verifier that implements the OTPVerifier interface.
type TOTPVerifier struct {
	config Config
}

// NewTOTPVerifier creates a new TOTPVerifier with the given configuration.
func NewTOTPVerifier(config Config) *TOTPVerifier {
	if config.TimeSource == nil {
		config.TimeSource = time.Now
	}
	return &TOTPVerifier{
		config: config,
	}
}

// Verify checks if the provided token and signature are valid for the current time.
func (v *TOTPVerifier) Verify(token, signature string) bool {
	totp := gotp.NewDefaultTOTP(v.config.Secret)
	generatedToken := totp.At(v.config.TimeSource().Unix())
	if v.config.UseSignature {
		generatedSignature := v.generateSignature(generatedToken)
		return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
			subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
}

// GenerateToken generates a token and signature for the current time.
func (v *TOTPVerifier) GenerateToken() (string, string) {
	totp := gotp.NewDefaultTOTP(v.config.Secret)
	token := totp.At(v.config.TimeSource().Unix())
	signature := ""
	if v.config.UseSignature {
		signature = v.generateSignature(token)
	}
	return token, signature
}

// generateSignature generates an HMAC signature for the given token using the secret key.
func (v *TOTPVerifier) generateSignature(token string) string {
	key, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// HOTPVerifier is an HOTP verifier that implements the OTPVerifier interface.
type HOTPVerifier struct {
	config Config
}

// NewHOTPVerifier creates a new HOTPVerifier with the given configuration.
func NewHOTPVerifier(config Config) *HOTPVerifier {
	return &HOTPVerifier{
		config: config,
	}
}

// Verify checks if the provided token and signature are valid for the specified counter value.
func (v *HOTPVerifier) Verify(token, signature string) bool {
	hotp := gotp.NewDefaultHOTP(v.config.Secret)
	generatedToken := hotp.At(int(v.config.Counter))
	if v.config.UseSignature {
		generatedSignature := v.generateSignature(generatedToken)
		return token == generatedToken && signature == generatedSignature
	}
	return token == generatedToken
}

// GenerateToken generates a token and signature for the current counter value.
func (v *HOTPVerifier) GenerateToken() (string, string) {
	hotp := gotp.NewDefaultHOTP(v.config.Secret)
	token := hotp.At(int(v.config.Counter))
	signature := ""
	if v.config.UseSignature {
		signature = v.generateSignature(token)
	}
	return token, signature
}

// generateSignature generates an HMAC signature for the given token using the secret key.
func (v *HOTPVerifier) generateSignature(token string) string {
	key, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// OTPFactory is a simple factory function to create an OTPVerifier.
// It takes a Config and creates the appropriate verifier based on the configuration.
func OTPFactory(config Config) OTPVerifier {
	if config.Counter != 0 {
		return NewHOTPVerifier(config)
	}
	return NewTOTPVerifier(config)
}
