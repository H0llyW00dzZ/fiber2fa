// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"image"
	"image/color"
	"net/url"
	"strings"
	"time"

	blake2botp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake2botp"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
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

	// BLAKE2b256 represents the secure BLAKE2b hash function with a 256-bit output size.
	// It provides a 256-bit (32-byte) hash value.
	//
	// Note: Some 2FA Mobile Apps might not support this hash function, so it is recommended to build your own 2FA Mobile apps.
	BLAKE2b256 = "BLAKE2b256"

	// BLAKE2b384 represents the secure BLAKE2b hash function with a 384-bit output size.
	// It provides a 384-bit (48-byte) hash value.
	//
	// Note: Some 2FA Mobile Apps might not support this hash function, so it is recommended to build your own 2FA Mobile apps.
	BLAKE2b384 = "BLAKE2b384"

	// BLAKE2b512 represents the secure BLAKE2b hash function with a 512-bit output size.
	// It provides a 512-bit (64-byte) hash value.
	//
	// Note: Some 2FA Mobile Apps might not support this hash function, so it is recommended to build your own 2FA Mobile apps.
	BLAKE2b512 = "BLAKE2b512"
)

// TimeSource is a function type that returns the current time.
type TimeSource func() time.Time

// OTPVerifier is an interface that defines the behavior of an OTP verifier.
type OTPVerifier interface {
	Verify(token, signature string) bool
	GenerateToken() (string, string)
	SetCounter(counter uint64)
	GetCounter() uint64
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
	SyncWindow   int
	URITemplate  string
}

// QRCodeConfig represents the configuration for generating QR codes.
type QRCodeConfig struct {
	Level              qrcode.RecoveryLevel
	Size               int
	ForegroundColor    color.Color
	BackgroundColor    color.Color
	DisableBorder      bool
	TopText            string
	BottomText         string
	Font               font.Face
	TopTextPosition    image.Point
	BottomTextPosition image.Point
}

// DefaultConfig represents the default configuration values.
var DefaultConfig = Config{
	Digits:       6,
	Period:       30,
	UseSignature: false,
	TimeSource:   time.Now,
	Hasher:       &gotp.Hasher{HashName: BLAKE2b512, Digest: blake2botp.New512},
	SyncWindow:   1,
	URITemplate:  "otpauth://%s/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s&counter=%d",
}

// Hashers is a map of supported hash functions.
var Hashers = map[string]*gotp.Hasher{
	SHA1:       {HashName: SHA1, Digest: sha1.New},
	SHA256:     {HashName: SHA256, Digest: sha256.New},
	SHA512:     {HashName: SHA512, Digest: sha512.New},
	BLAKE2b256: {HashName: BLAKE2b256, Digest: blake2botp.New256},
	BLAKE2b384: {HashName: BLAKE2b384, Digest: blake2botp.New384},
	BLAKE2b512: {HashName: BLAKE2b512, Digest: blake2botp.New512},
}

// DefaultQRCodeConfig represents the default configuration for generating QR codes.
var DefaultQRCodeConfig = InitializeDefaultQRCodeConfig()

// InitializeDefaultQRCodeConfig sets up the default configuration for generating QR codes with dynamic text positions.
func InitializeDefaultQRCodeConfig() QRCodeConfig {
	size := 256      // This is the QR code size used in the default config
	textHeight := 20 // This should be set to the height of the text

	return QRCodeConfig{
		Level:              qrcode.Medium,
		Size:               size,
		ForegroundColor:    color.Black,
		BackgroundColor:    color.White,
		DisableBorder:      false,
		TopText:            "",
		BottomText:         "",
		Font:               basicfont.Face7x13,
		TopTextPosition:    image.Point{X: size / 2, Y: textHeight / 1},      // Dynamically calculated
		BottomTextPosition: image.Point{X: size / 2, Y: size + textHeight/1}, // Dynamically calculated
	}
}

// ensureDefaultConfig checks the provided config and fills in any zero values with defaults.
func ensureDefaultConfig(config QRCodeConfig) QRCodeConfig {
	if config.Font == nil {
		config.Font = DefaultQRCodeConfig.Font
	}
	if config.ForegroundColor == nil {
		config.ForegroundColor = DefaultQRCodeConfig.ForegroundColor
	}
	if config.BackgroundColor == nil {
		config.BackgroundColor = DefaultQRCodeConfig.BackgroundColor
	}
	if config.TopTextPosition == (image.Point{}) {
		config.TopTextPosition = DefaultQRCodeConfig.TopTextPosition
	}
	if config.BottomTextPosition == (image.Point{}) {
		config.BottomTextPosition = DefaultQRCodeConfig.BottomTextPosition
	}
	return config
}

// generateOTPURL creates the URL for the QR code based on the provided URI template.
func generateOTPURL(issuer, accountName string, config Config) string {
	var otpType string
	if config.Counter != 0 {
		otpType = gotp.OtpTypeHotp
	} else {
		otpType = gotp.OtpTypeTotp
	}

	// Create a slice to hold the arguments for fmt.Sprintf
	args := make([]interface{}, 0) // Preallocate with a capacity of 0
	args = append(args, otpType, url.QueryEscape(issuer), url.QueryEscape(accountName))

	// Define a slice of parameter placeholders and their corresponding values
	paramPairs := []struct {
		placeholder string
		value       interface{}
	}{
		{"secret", config.Secret},
		{"issuer", url.QueryEscape(issuer)},
		{"digits", config.Digits},
		{"algorithm", config.Hasher.HashName},
		{"counter", config.Counter},
	}

	// Iterate over the parameter pairs and conditionally append parameters
	for _, pair := range paramPairs {
		if strings.Contains(config.URITemplate, "%"+pair.placeholder) {
			args = append(args, pair.value)
		}
	}

	return fmt.Sprintf(config.URITemplate, args...)
}

// OTPFactory is a simple factory function to create an OTPVerifier.
// It takes a Config and creates the appropriate verifier based on the configuration.
func OTPFactory(config Config) OTPVerifier {
	if config.Counter != 0 {
		return NewHOTPVerifier(config)
	}
	return NewTOTPVerifier(config)
}
