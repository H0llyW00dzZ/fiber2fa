// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"image"
	"image/color"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	blake2botp "github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake2botp"
	"github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake3otp"
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

	// SHA224 represents the SHA-224 hash function.
	// SHA-224 produces a 224-bit (28-byte) hash value.
	// It is a truncated version of SHA-256 and provides a balance between security and performance.
	//
	// Note: Some 2FA mobile apps might not support SHA-224 due to poor ecosystem.
	SHA224 = "SHA224"

	// SHA256 represents the SHA-256 hash function.
	// SHA-256 produces a 256-bit (32-byte) hash value.
	// It provides a higher level of security compared to SHA-1 and is recommended for newer applications.
	SHA256 = "SHA256"

	// SHA384 represents the SHA-384 hash function.
	// SHA-384 produces a 384-bit (48-byte) hash value.
	// It is a truncated version of SHA-512 and provides a balance between security and performance.
	//
	// Note: Some 2FA mobile apps might not support SHA-384 due to poor ecosystem.
	SHA384 = "SHA384"

	// SHA512 represents the SHA-512 hash function.
	// SHA-512 produces a 512-bit (64-byte) hash value.
	// It offers the highest level of security among the commonly used SHA variants.
	SHA512 = "SHA512"

	// SHA512S224 represents the SHA-512/224 hash function.
	// SHA-512/224 produces a 224-bit (28-byte) hash value.
	// It is a truncated version of SHA-512 and provides a balance between security and performance.
	//
	// Note: Some 2FA mobile apps might not support SHA-512/224 due to poor ecosystem.
	SHA512S224 = "SHA512/224"

	// SHA512S256 represents the SHA-512/256 hash function.
	// SHA-512/256 produces a 256-bit (32-byte) hash value.
	// It is a truncated version of SHA-512 and provides a balance between security and performance.
	//
	// Note: Some 2FA mobile apps might not support SHA-512/256 due to poor ecosystem.
	SHA512S256 = "SHA512/256"

	// BLAKE2b256 represents the secure BLAKE2b hash function with a 256-bit output size.
	// It provides a 256-bit (32-byte) hash value.
	//
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	BLAKE2b256 = "BLAKE2b256"

	// BLAKE2b384 represents the secure BLAKE2b hash function with a 384-bit output size.
	// It provides a 384-bit (48-byte) hash value.
	//
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	BLAKE2b384 = "BLAKE2b384"

	// BLAKE2b512 represents the secure BLAKE2b hash function with a 512-bit output size.
	// It provides a 512-bit (64-byte) hash value.
	//
	// Note: Some 2FA mobile apps might not support (poor ecosystems) this hash function, so it is recommended to build your own 2FA mobile apps.
	BLAKE2b512 = "BLAKE2b512"

	// BLAKE3256 represents the secure BLAKE3 hash function with a 256-bit output size.
	// It provides a 256-bit (32-byte) hash value.
	// BLAKE3 is a modern, high-performance cryptographic hash function that is faster and more secure than SHA-3 and BLAKE2.
	//
	// Note: Some 2FA mobile apps might not support this hash function due to its relatively new adoption, so it is recommended to build your own 2FA mobile apps when using BLAKE3.
	BLAKE3256 = "BLAKE3256"

	// BLAKE3384 represents the secure BLAKE3 hash function with a 384-bit output size.
	// It provides a 384-bit (48-byte) hash value.
	// BLAKE3 is a modern, high-performance cryptographic hash function that is faster and more secure than SHA-3 and BLAKE2.
	//
	// Note: Some 2FA mobile apps might not support this hash function due to its relatively new adoption, so it is recommended to build your own 2FA mobile apps when using BLAKE3.
	BLAKE3384 = "BLAKE3384"

	// BLAKE3512 represents the secure BLAKE3 hash function with a 512-bit output size.
	// It provides a 512-bit (64-byte) hash value.
	// BLAKE3 is a modern, high-performance cryptographic hash function that is faster and more secure than SHA-3 and BLAKE2.
	//
	// Note: Some 2FA mobile apps might not support this hash function due to its relatively new adoption, so it is recommended to build your own 2FA mobile apps when using BLAKE3.
	BLAKE3512 = "BLAKE3512"
)

const (
	// NoneStrict represents no strictness for the synchronization window.
	// It has a value of 0, meaning the synchronization window size is not enforced.
	NoneStrict = iota

	// HighStrict represents the highest level of strictness for the synchronization window.
	// It has a value of 1, meaning the synchronization window size is fixed at 1.
	HighStrict

	// MediumStrict represents a medium level of strictness for the synchronization window.
	// It has a value of 2, and the actual synchronization window size is determined by the corresponding range in SyncWindowRanges.
	MediumStrict

	// LowStrict represents a low level of strictness for the synchronization window.
	// It has a value of 3, and the actual synchronization window size is determined by the corresponding range in SyncWindowRanges.
	LowStrict
)

const (
	// CounterMismatchThreshold1x represents a counter mismatch threshold of 1.
	// If the number of counter mismatches exceeds this threshold,
	// the sync window size will be adjusted to the value defined in the verifier's configuration.
	CounterMismatchThreshold1x = iota + 1

	// CounterMismatchThreshold3x represents a counter mismatch threshold of 3.
	// If the number of counter mismatches exceeds this threshold,
	// the sync window size will be adjusted to the value defined in the verifier's configuration.
	CounterMismatchThreshold3x = iota + 2

	// CounterMismatchThreshold5x represents a counter mismatch threshold of 5.
	// If the number of counter mismatches exceeds this threshold,
	// the sync window size will be adjusted to the value defined in the verifier's configuration.
	CounterMismatchThreshold5x = iota + 3
)

// SyncWindowRanges is a map that associates strictness levels with their corresponding ranges of synchronization window sizes.
// The ranges are used to dynamically calculate the actual synchronization window size based on the counter value:
//
//   - For [MediumStrict], the synchronization window size can be between 2 and 5.
//   - For [LowStrict], the synchronization window size can be between 5 and 10.
//   - The [HighStrict] level does not have a range defined in [SyncWindowRanges] because it has a fixed synchronization window size of 1.
//
// Also note that there are some considerations to keep in the mind:
//
//   - Security vs. Convenience Trade-off: Increasing the sync window size makes the system more user-friendly since it's less likely to reject valid tokens due to minor synchronization issues.
//     However, a larger window also increases the period during which an attacker can use a stolen OTP to gain unauthorized access.
var SyncWindowRanges = map[int][]int{
	MediumStrict: {2, 5},
	LowStrict:    {5, 10},
}

const (
	// FastCleanup represents the fastest cleanup interval for removing expired tokens in the TOTP verifier.
	// It is assigned a value of iota + 1, which evaluates to 1.
	// When FastCleanup is selected, the cleanup process runs every 25% of the TOTP period, providing the most frequent cleanup.
	FastCleanup = iota + 1

	// MediumCleanup represents a medium cleanup interval for removing expired tokens in the TOTP verifier.
	// It is assigned the next sequential value of iota, which evaluates to 2.
	// When MediumCleanup is selected, the cleanup process runs every 50% of the TOTP period, providing a balanced cleanup frequency.
	MediumCleanup

	// SlowCleanup represents the slowest cleanup interval for removing expired tokens in the TOTP verifier.
	// It is assigned the next sequential value of iota, which evaluates to 3.
	// When SlowCleanup is selected, the cleanup process runs every 75% of the TOTP period, providing the least frequent cleanup.
	SlowCleanup
)

// CleanupIntervals is a map that associates cleanup interval constants with their corresponding percentage of the TOTP period.
// The cleanup interval determines how frequently the cleanup process runs to remove expired tokens.
//
// The available cleanup intervals are:
//   - [FastCleanup]: The cleanup process runs every 25% of the TOTP period.
//   - [MediumCleanup]: The cleanup process runs every 50% of the TOTP period.
//   - [SlowCleanup]: The cleanup process runs every 75% of the TOTP period.
//
// Note: Choosing an appropriate cleanup interval is important to balance the need for timely removal of expired tokens
// and the overhead of running the cleanup process too frequently. The default cleanup interval is [MediumCleanup].
var CleanupIntervals = map[int]float64{
	FastCleanup:   0.25, // 25% of the TOTP period
	MediumCleanup: 0.50, // 50% of the TOTP period
	SlowCleanup:   0.75, // 75% of the TOTP period
}

// TimeSource is a function type that returns the current time.
type TimeSource func() time.Time

// OTPVerifier is an interface that defines the behavior of an OTP verifier.
type OTPVerifier interface {
	Verify(token string, signature ...string) bool
	GenerateToken() string
	GenerateTokenWithSignature() (string, string)
	SetCounter(counter uint64)
	GetCounter() uint64
	GenerateOTPURL(issuer, accountName string) string
}

// Config is a struct that holds the configuration options for the OTP verifier.
type Config struct {
	Secret                  string
	Digits                  int
	Period                  int
	UseSignature            bool
	TimeSource              TimeSource
	Counter                 uint64
	CounterMismatch         int
	Hasher                  *gotp.Hasher
	SyncWindow              int
	ResyncWindowDelay       time.Duration
	URITemplate             string
	CustomURITemplateParams map[string]string
	Hash                    string
	Crypto                  Crypto
	CleanupInterval         int
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

// Crypto is a struct that holds cryptographic configuration options.
//
// Note: This design allows for flexibility at the top level.
// For example, it can be used anywhere in this codebase without calling [crypto/rand] again (DRY).
// The Rand, Prime, and Int functions are provided as part of the Crypto struct to enable secure random number generation
// and prime number generation. These functions are used in various cryptographic operations throughout the codebase.
//
// By including them in the Crypto struct, they can be easily accessed and reused without the need to import and call [crypto/rand] multiple times.
// This promotes code reusability, maintainability, and adherence to the DRY (Don't Repeat Yourself) principle.
type Crypto struct {
	Rand  func([]byte) (int, error)
	Prime func(rand io.Reader, bits int) (*big.Int, error)
	Int   func(rand io.Reader, max *big.Int) (n *big.Int, err error)
}

// DefaultConfig represents the default configuration values.
var DefaultConfig = Config{
	Digits:                  6,
	Period:                  30,
	UseSignature:            false,
	SyncWindow:              HighStrict,
	ResyncWindowDelay:       30 * time.Minute,
	CounterMismatch:         CounterMismatchThreshold3x,
	URITemplate:             "otpauth://%s/%s:%s?secret=%s&issuer=%s&digits=%d&algorithm=%s",
	CustomURITemplateParams: nil,
	Crypto: Crypto{
		Rand:  rand.Read,
		Prime: rand.Prime,
		Int:   rand.Int,
	},
}

// Hashers is a map of supported hash functions.
//
// Note: This design allows for flexibility at the top level. For example,
// it can be used for experimental purposes, such as creating custom hashing functions (advanced use cases) related to cryptography.
var Hashers = map[string]*gotp.Hasher{
	SHA1:       {HashName: SHA1, Digest: sha1.New},
	SHA224:     {HashName: SHA224, Digest: sha256.New224},
	SHA256:     {HashName: SHA256, Digest: sha256.New},
	SHA384:     {HashName: SHA384, Digest: sha512.New384},
	SHA512:     {HashName: SHA512, Digest: sha512.New},
	SHA512S224: {HashName: SHA512S224, Digest: sha512.New512_224},
	SHA512S256: {HashName: SHA512S256, Digest: sha512.New512_256},
	BLAKE2b256: {HashName: BLAKE2b256, Digest: blake2botp.New256},
	BLAKE2b384: {HashName: BLAKE2b384, Digest: blake2botp.New384},
	BLAKE2b512: {HashName: BLAKE2b512, Digest: blake2botp.New512},
	BLAKE3256:  {HashName: BLAKE3256, Digest: blake3otp.New256},
	BLAKE3384:  {HashName: BLAKE3384, Digest: blake3otp.New384},
	BLAKE3512:  {HashName: BLAKE3512, Digest: blake3otp.New512},
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
func (v *Config) generateOTPURL(issuer, accountName string) string {
	// Determine the OTP type based on whether a counter is used.
	otpType := gotp.OtpTypeTotp
	if v.Counter != 0 {
		otpType = gotp.OtpTypeHotp
	}

	// Parse the URI template to get a base URL object.
	// Note: It is important to use url.PathEscape for the issuer and account name
	// because the URL won't work correctly without it when scanning the QR code.
	baseURL, err := url.Parse(fmt.Sprintf(v.URITemplate, otpType, url.PathEscape(issuer), url.PathEscape(accountName)))
	if err != nil {
		// Panic is better than handling the error using fmt, log, or any other method since this is an internal error.
		panic(err)
	}

	// Prepare query parameters.
	// Note: This should be fixing a weird bug related to the "issuer" field when spaces are included,
	// ensuring that "Gopher Company" is displayed correctly instead of "Gopher+Company".
	query := baseURL.Query()
	query.Set("secret", v.Secret)
	query.Set("digits", fmt.Sprint(v.Digits))
	query.Set("algorithm", v.Hasher.HashName)
	if otpType != gotp.OtpTypeTotp {
		query.Set("counter", fmt.Sprint(v.Counter))
	}
	if otpType != gotp.OtpTypeHotp {
		query.Set("period", fmt.Sprint(v.Period))
	}

	// Add custom URI Template parameters to the query if CustomURITemplateParams is not nil
	if v.CustomURITemplateParams != nil {
		for key, value := range v.CustomURITemplateParams {
			escapedKey := url.PathEscape(key)
			escapedValue := url.PathEscape(value)
			query.Set(escapedKey, escapedValue)
		}
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

// GetHasherByName returns a pointer to a [gotp.Hasher] based on the given hash function name.
// It panics if the hash function name is empty or not supported.
//
// The supported hash function names are:
//   - [SHA1]
//   - [SHA224]
//   - [SHA256]
//   - [SHA384]
//   - [SHA512]
//   - [SHA512S224]
//   - [SHA512S256]
//   - [BLAKE2b256]
//   - [BLAKE2b384]
//   - [BLAKE2b512]
//   - [BLAKE3256]
//   - [BLAKE3384]
//   - [BLAKE3512]
//
// Note: The hash function name is case-sensitive.
func (v *Config) GetHasherByName(Hash string) *gotp.Hasher {
	if Hash == "" {
		panic("GetHasherByName: hash function name cannot be empty")
	}

	hasher, exists := Hashers[Hash]
	if !exists {
		panic(fmt.Sprintf("GetHasherByName: hash function %s is not supported", Hash))
	}
	return hasher
}

// GenerateSecureRandomCounter generates a random counter number for HOTP with a specified maximum number of digits.
//
// Note: The maximum value for maxDigits is 30. Setting maxDigits to a value greater than 30 may result in integer overflow and panic.
// Also note that, there is no guarantee about digits for example when set 6 it the result can be possible 5 digits but it secure,
// the reason why there is no guarantee it requires skilled mathematical reasoning to understand about cryptography
func (v *Config) GenerateSecureRandomCounter(maxDigits int) uint64 {
	if maxDigits <= 0 {
		panic("GenerateSecureRandomCounter: maxDigits must be greater than 0")
	}

	// Check if maxDigits is within the safe range
	const maxSafeDigits = 30 // Maximum number of digits that can be safely represented in uint64
	if maxDigits > maxSafeDigits {
		panic(fmt.Sprintf("GenerateSecureRandomCounter: maxDigits must be less than or equal to %d to avoid integer overflow", maxSafeDigits))
	}

	// Calculate the maximum possible value based on the number of digits
	var max uint64 = 9*v.cryptopowpow10(maxDigits-1) + v.cryptopowpow10(maxDigits-1) - 1

	// Create a fixed-size byte array to store the random bytes
	var randomBytes [8]byte

	// Generate random bytes using the Crypto.Rand function from the Config struct
	// Note: This will continue generating random bytes and is safe. If it fails to generate random bytes, it will panic and crash.
	_, err := v.Crypto.Rand(randomBytes[:])
	if err != nil {
		panic(err)
	}

	// Convert the random bytes to a uint64 value
	var n uint64
	for i := 0; i < 8; i++ {
		n = (n << 8) | uint64(randomBytes[i])
	}

	// Ensure the generated number is within the desired range
	n = n % (max + 1)

	return n
}

// cryptopowpow10 is a helper function that calculates the power of 10 for a given exponent.
//
// Reference: https://en.wikipedia.org/wiki/Exponentiation
//
// Note: This Helper Function for SRC-Generator is secure (100% guarantee) 0-allocs
func (v *Config) cryptopowpow10(exponent int) uint64 {
	var result uint64 = 1
	for i := 0; i < exponent; i++ {
		result *= 10
	}
	return result
}

// TOTPTime returns the current time in the South Pole (see https://en.wikipedia.org/wiki/Time_in_Antarctica) time zone.
// It is used as the default time source for TOTP if no custom time source is provided (nil) and the sync window is set to -1.
//
// Note: The returned time is always expressed in UTC (Coordinated Universal Time) to avoid any ambiguity caused by local time zone offsets.
func (v *Config) TOTPTime() time.Time {
	location, _ := time.LoadLocation("Antarctica/South_Pole")
	return time.Now().In(location).UTC()
}

// DecodeBase32WithPadding decodes a base32-encoded secret, adding padding as necessary.
func (v *Config) DecodeBase32WithPadding() []byte {
	// Calculate the number of missing padding characters.
	//
	// Note: This is suitable for [gotp.RandomSecret](cryptographically secure pseudorandom)
	// Incorrect padding (e.g., extra "=", out-of-place "=") can lead to illegal base32 data
	// when using crypto pseudorandom from [gotp.RandomSecret].
	missingPadding := len(v.Secret) & 2 // Should be work, if it doesn't work then your machine is bad.

	// Add padding if necessary.
	if missingPadding != 0 {
		v.Secret = v.Secret + strings.Repeat("=", 8-missingPadding)
	}

	// Decode the base32 encoded secret.
	bytes, err := base32.StdEncoding.DecodeString(v.Secret)
	if err != nil {
		panic("DecodeBase32WithPadding: illegal base32 data")
	}

	return bytes
}

// cryptoPow10n calculates the value of 10 raised to the power of n (10ⁿ).
//
// The function uses recursive multiplication to compute the result.
// It starts with the base case of n ≤ 0, where the result is 1 (10⁰ = 1).
// For n > 0, the function recursively multiplies 10 with the result of cryptoPow10n(n-1).
//
// Example:
//
//	v.cryptoPow10n(0) = 1
//	v.cryptoPow10n(1) = 10
//	v.cryptoPow10n(2) = 10 × v.cryptoPow10n(1) = 10 × 10 = 10²
//	v.cryptoPow10n(3) = 10 × v.cryptoPow10n(2) = 10 × 10² = 10³
//
// The function returns the calculated value as an unsigned 32-bit integer [uint32].
//
// Note: The function assumes that n is non-negative. If n is negative, it will return 1 (10⁰ = 1).
//
// The purpose of this function is to calculate the appropriate modulo value based on
// the desired number of digits for both the HOTP (HMAC-based One-Time Password) and
// TOTP (Time-based One-Time Password) values. It is used in the truncation step of the
// HOTP and TOTP algorithms to ensure that the resulting values have the specified number of digits.
//
// Magic Calculator, the function computes:
//
//	10ⁿ = 10 × 10ⁿ⁻¹, for n > 0
//	10ⁿ = 1, for n ≤ 0
//
// where ⁿ denotes the exponentiation operation.
//
// Also note that most package helper functions here are related to cryptographic.
// They mostly do not rely on other packages, for example, using the standard package only for math,
// because sometimes it may not be suitable for Go (e.g., too many if statements, which is not idiomatic in Go).
// Therefore, the helper functions here are built in an advanced manner based on knowledge and expertise.
func (v *Config) cryptoPow10n(n int) uint32 {
	if n <= 0 { // should be fine now, since this written in Go which it suitable for cryptographic.
		return 1
	}
	return 10 * v.cryptoPow10n(n-1)
}
