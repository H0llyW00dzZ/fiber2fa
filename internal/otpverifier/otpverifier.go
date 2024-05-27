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
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	// Additionally, on Apple devices (not 2FA mobile apps), BLAKE2b is supported and has been tested on iPhone by using QR code scanning directly.
	BLAKE2b256 = "BLAKE2b256"

	// BLAKE2b384 represents the secure BLAKE2b hash function with a 384-bit output size.
	// It provides a 384-bit (48-byte) hash value.
	//
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	// Additionally, on Apple devices (not 2FA mobile apps), BLAKE2b is supported and has been tested on iPhone by using QR code scanning directly.
	BLAKE2b384 = "BLAKE2b384"

	// BLAKE2b512 represents the secure BLAKE2b hash function with a 512-bit output size.
	// It provides a 512-bit (64-byte) hash value.
	//
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	// Additionally, on Apple devices (not 2FA mobile apps), BLAKE2b is supported and has been tested on iPhone by using QR code scanning directly.
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
	Hash         string
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
	SyncWindow:   1,
	URITemplate:  "otpauth://%s/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s",
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
	// Determine the OTP type based on whether a counter is used.
	otpType := gotp.OtpTypeTotp
	if config.Counter != 0 {
		otpType = gotp.OtpTypeHotp
	}

	// Parse the URI template to get a base URL object.
	// Note: It is important to use url.PathEscape for the issuer and account name
	// because the URL won't work correctly without it when scanning the QR code.
	baseURL, err := url.Parse(fmt.Sprintf(config.URITemplate, otpType, url.PathEscape(issuer), url.PathEscape(accountName)))
	if err != nil {
		// Panic is better than handling the error using fmt, log, or any other method since this is an internal error.
		panic(err)
	}

	// Prepare query parameters.
	// Note: There is a bug that cannot be fixed. It is probably a mobile 2FA issue or something weird.
	// The bug occurs when there is a space in the "issuer" field. For example, if the issuer is "Gopher Company",
	// it will be displayed as:
	// (issuer) Gopher+Company
	// (Account Name) Gopher Company:XGopher@example.com
	// The correct format should be:
	// (issuer) Gopher
	// (Account Name) Gopher Company:XGopher@example.com
	// Adding "Gopher Company:" to the account name is optional because it is the value of the issuer.
	query := baseURL.Query()
	query.Set("secret", config.Secret)
	query.Set("issuer", issuer)
	query.Set("digits", fmt.Sprint(config.Digits))
	query.Set("algorithm", config.Hasher.HashName)
	if config.Counter != 0 {
		query.Set("counter", fmt.Sprint(config.Counter))
	}

	// Re-encode the query parameters.
	baseURL.RawQuery = query.Encode()

	// Return the fully constructed URL string.
	return baseURL.String()
}

// OTPFactory is a simple factory function to create an OTPVerifier.
// It takes a Config and creates the appropriate verifier based on the configuration.
func OTPFactory(config Config) OTPVerifier {
	if config.Counter != 0 {
		return NewHOTPVerifier(config)
	}
	return NewTOTPVerifier(config)
}

// GetHasherByName returns a pointer to a gotp.Hasher based on the given hash function name.
// It panics if the hash function name is not supported or if the hash function name is empty.
func (v *Config) GetHasherByName(Hash string) *gotp.Hasher {
	hasher, exists := Hashers[Hash]
	if !exists {
		panic(fmt.Sprintf("Hash function %s is not supported", Hash))
	}
	return hasher
}
