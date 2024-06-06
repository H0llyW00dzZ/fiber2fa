// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"sync"
	"time"

	"github.com/xlzd/gotp"
)

// TOTPVerifier is a TOTP verifier that implements the OTPVerifier interface.
type TOTPVerifier struct {
	config     Config
	totp       *gotp.TOTP
	UsedTokens *sync.Map
}

// NewTOTPVerifier creates a new TOTPVerifier with the given configuration.
func NewTOTPVerifier(config ...Config) *TOTPVerifier {
	c := DefaultConfig
	if len(config) > 0 {
		c = config[0]
	}

	// Use default values if not provided
	if c.Digits == 0 {
		c.Digits = DefaultConfig.Digits
	}

	if c.Period == 0 {
		c.Period = DefaultConfig.Period
	}

	// Bound SyncWindow to TimeSource
	// Note: There is no RFC related to this, so understanding this requires skilled math and time-related knowledge
	// regarding the degree of time drift or synchronization window between the client (e.g., a user's device) and the server (where the TOTP verification takes place).
	// For example, let's say the current time step is 100 and SyncWindow is set to 1. In this case,
	// the server will accept tokens from time steps 99 (current - 1), 100 (current),
	// and 101 (current + 1). If the client's clock is running slightly behind or ahead,
	// the token generated on the client side will still be considered valid if it falls within this window.
	// It's also worth noting that the SyncWindow parameter is not part of the core TOTP algorithm but rather an extension to improve usability.
	// The RFC 6238 (TOTP specification) does not define a specific synchronization window, but it is a common practice to implement it in TOTP systems to accommodate
	// for real-world scenarios where perfect clock synchronization is not always possible (e.g, traveling (in airplane), living in antartica, ISS-NASA).
	if c.TimeSource == nil && c.SyncWindow != 0 {
		c.TimeSource = DefaultConfig.TOTPTime().UTC
		c.SyncWindow = DefaultConfig.SyncWindow
	}

	if c.Hash != "" {
		// If HashName is provided, use it to get the corresponding Hasher
		c.Hasher = c.GetHasherByName(c.Hash)
	}

	if c.URITemplate == "" {
		c.URITemplate = DefaultConfig.URITemplate
	}

	totp := gotp.NewTOTP(c.Secret, c.Digits, c.Period, c.Hasher)
	verifier := &TOTPVerifier{
		config: c,
		totp:   totp,
		// Allocates 11 to 15 allocs/op without signature (depends on the hash function), which is relatively inexpensive for this TOTP synchronization window.
		// Without implementing a synchronization window similar to HOTP, it can lead to high vulnerability.
		UsedTokens: &sync.Map{},
	}

	// Start the periodic cleanup goroutine
	// Note: This is important to minimize the memory footprint. Unlike HOTP,
	// TOTP authentication must implement a synchronization window similar to HOTP.
	// Without implementing a synchronization window similar to HOTP, it can lead to high vulnerability
	// where a used token is still considered valid when the user is entering the same token again (which was used previously).
	go verifier.startPeriodicCleanup()

	return verifier
}

// Verify checks if the provided token and signature are valid for the current time.
//
// Note: This TOTP verification using [crypto/subtle] requires careful consideration
// when setting TimeSource and Period to ensure correct usage.
func (v *TOTPVerifier) Verify(token string, signature ...string) bool {
	if v.config.SyncWindow < 0 {
		panic("totp: SyncWindow must be greater than or equal to zero")
	}

	if v.config.UseSignature {
		if len(signature) == 0 {
			panic("totp: Signature is required but not provided")
		}

		return v.verifyWithSignature(token, signature[0])
	}

	return v.verifyWithoutSignature(token)
}

// verifyWithoutSignature checks if the provided token is valid for the current time without signature verification.
func (v *TOTPVerifier) verifyWithoutSignature(token string) bool {
	currentTimestamp := v.config.TimeSource().Unix()
	currentTimeStep := currentTimestamp / int64(v.config.Period)

	// Check the SyncWindow periods before and after the current time step
	// Note: This offset SyncWindow (not a skew, wtf is skew) is not always non-negative.
	// Sometimes it can be negative (depending on the time zone) when customizing the SyncWindow (e.g., 1, 2, 3).
	// This is safe because it uses the crypto/subtle package for constant-time comparisons.
	for offset := -v.config.SyncWindow; offset <= v.config.SyncWindow; offset++ {
		expectedTimeStep := currentTimeStep + int64(offset)
		expectedTimestamp := expectedTimeStep * int64(v.config.Period)

		if _, found := v.UsedTokens.Load(expectedTimeStep); found {
			continue // Skip this step as the token has already been used
		}

		// Verify the token for this time step
		// This should be safe now because a synchronization window similar to HOTP is implemented.
		// The token will be marked as used even if there is still time remaining in the period (e.g., 30 seconds).
		// Without implementing a synchronization window similar to HOTP, this can lead to a high vulnerability
		// where a used token is still considered valid due to the period.
		generatedToken := v.totp.At(expectedTimestamp)
		if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 {
			v.UsedTokens.Store(expectedTimeStep, token) // Record the token as used
			return true
		}
	}

	return false // Token is invalid
}

// verifyWithSignature checks if the provided token and signature are valid for the current time.
func (v *TOTPVerifier) verifyWithSignature(token, signature string) bool {

	currentTimestamp := v.config.TimeSource().Unix()
	currentTimeStep := currentTimestamp / int64(v.config.Period)

	// Check the SyncWindow periods before and after the current time step
	// Note: This offset SyncWindow (not a skew, wtf is skew) is not always non-negative.
	// Sometimes it can be negative (depending on the time zone) when customizing the SyncWindow (e.g., 1, 2, 3).
	// This is safe because it uses the crypto/subtle package for constant-time comparisons.
	for offset := -v.config.SyncWindow; offset <= v.config.SyncWindow; offset++ {
		expectedTimeStep := currentTimeStep + int64(offset)
		expectedTimestamp := expectedTimeStep * int64(v.config.Period)

		if _, found := v.UsedTokens.Load(expectedTimeStep); found {
			continue // Skip this step as the token has already been used
		}

		// Verify the token for this time step
		// This should be safe now because a synchronization window similar to HOTP is implemented.
		// The token will be marked as used even if there is still time remaining in the period (e.g., 30 seconds).
		// Without implementing a synchronization window similar to HOTP, this can lead to a high vulnerability
		// where a used token is still considered valid due to the period.
		if v.totp.Verify(token, expectedTimestamp) {
			if v.config.UseSignature {
				generatedSignature := v.generateSignature(token)
				if subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) != 1 {
					return false // Signature mismatch
				}
			}

			v.UsedTokens.Store(expectedTimeStep, token) // Record the token as used
			return true
		}
	}

	return false // Token is invalid
}

// GenerateToken generates a token for the current time.
func (v *TOTPVerifier) GenerateToken() string {
	// TODO: Allow customizing the character set instead of using only numbers.
	// Although the current TOTP implementation relies on time and is secure due to the use of the [crypto/subtle] package,
	// even with the current implementation that uses numbers, it is secure, especially against brute-force attacks.
	// However, we won't implement this now because most 2FA apps in the world, especially for mobile devices,
	// still have poor ecosystems and are not modern enough to support custom character sets.
	return v.totp.Now()
}

// GenerateTokenWithSignature generates a token and signature for the current time.
func (v *TOTPVerifier) GenerateTokenWithSignature() (string, string) {
	// TODO: Allow customizing the character set instead of using only numbers.
	// Although the current TOTP implementation relies on time and is secure due to the use of the [crypto/subtle] package,
	// even with the current implementation that uses numbers, it is secure, especially against brute-force attacks.
	// However, we won't implement this now because most 2FA apps in the world, especially for mobile devices,
	// still have poor ecosystems and are not modern enough to support custom character sets.
	token := v.totp.Now()
	signature := v.generateSignature(token)
	return token, signature
}

// generateSignature generates an HMAC signature for the given token using the secret key.
func (v *TOTPVerifier) generateSignature(token string) string {
	key, _ := base32.StdEncoding.DecodeString(v.config.Secret)
	h := hmac.New(v.config.Hasher.Digest, key)
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GenerateOTPURL creates the URL for the QR code based on the provided URI template.
func (v *TOTPVerifier) GenerateOTPURL(issuer, accountName string) string {
	return v.config.generateOTPURL(issuer, accountName)
}

// startPeriodicCleanup starts a goroutine that periodically cleans up expired tokens.
func (v *TOTPVerifier) startPeriodicCleanup() {
	cleanupPeriod := time.Duration(v.config.Period/2) * time.Second
	cleanupTicker := time.NewTicker(cleanupPeriod)
	defer cleanupTicker.Stop()

	for range cleanupTicker.C {
		v.CleanUpExpiredTokens()
	}
}

// CleanUpExpiredTokens removes expired tokens from the usedTokens map.
func (v *TOTPVerifier) CleanUpExpiredTokens() {
	currentTimestamp := v.config.TimeSource().Unix()
	currentTimeStep := currentTimestamp / int64(v.config.Period)

	v.UsedTokens.Range(func(key, value any) bool {
		usedTimeStep := key.(int64)
		if usedTimeStep < currentTimeStep-int64(v.config.SyncWindow) {
			// Note: Never use "clear" on this to minimize the memory footprint, because it can lead to high vulnerability
			// where a used token is still considered valid due to the period.
			// Use "delete" to remove individual entries, which is a better way.
			v.UsedTokens.Delete(usedTimeStep)
		}
		return true
	})
}
