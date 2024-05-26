// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"time"

	blake2botp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash"
	"github.com/xlzd/gotp"
)

const (
	// SHA1 represents the SHA-1 hash function.
	// SHA-1 produces a 160-bit (20-byte) hash value.
	// It is considered less secure compared to newer variants due to potential vulnerabilities.
	SHA1 = "SHA1"

	// SHA256 represents the SHA-256 hash function.
	// SHA-256 produces a 256-bit (32-byte) hash value.
	// It provides a higher level of security compared to SHA-1 and is recommended for newer applications.
	SHA256 = "SHA256"

	// SHA512 represents the SHA-512 hash function.
	// SHA-512 produces a 512-bit (64-byte) hash value.
	// It offers the highest level of security among the commonly used SHA variants.
	SHA512 = "SHA512"

	// BLAKE2b represents the secure BLAKE2b hash function.
	// It provides a 512-bit (64-byte) hash value.
	//
	// Note: Some 2FA Mobile Apps might not support this hash function, so it is recommended to build your own 2FA Mobile apps.
	BLAKE2b = "BLAKE2b"
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
	Digits       int
	Period       int
	UseSignature bool
	TimeSource   TimeSource
	Counter      uint64
	Hasher       *gotp.Hasher
}

// DefaultConfig represents the default configuration values.
var DefaultConfig = Config{
	Digits:       6,
	Period:       30,
	UseSignature: false,
	TimeSource:   time.Now,
	Hasher:       &gotp.Hasher{HashName: BLAKE2b, Digest: blake2botp.New512},
}

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
		return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 &&
			subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
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

// OTPFactory is a simple factory function to create an OTPVerifier.
// It takes a Config and creates the appropriate verifier based on the configuration.
func OTPFactory(config Config) OTPVerifier {
	if config.Counter != 0 {
		return NewHOTPVerifier(config)
	}
	return NewTOTPVerifier(config)
}

// Hashers is a map of supported hash functions.
var Hashers = map[string]*gotp.Hasher{
	SHA1:    {HashName: SHA1, Digest: sha1.New},
	SHA256:  {HashName: SHA256, Digest: sha256.New},
	SHA512:  {HashName: SHA512, Digest: sha512.New},
	BLAKE2b: {HashName: BLAKE2b, Digest: blake2botp.New512},
}
