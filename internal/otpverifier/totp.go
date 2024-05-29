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
	UsedTokens map[int64]string
	m          sync.Mutex // Mutex to protect concurrent access to usedTokens
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
	if config.Hash != "" {
		// If HashName is provided, use it to get the corresponding Hasher
		config.Hasher = config.GetHasherByName(config.Hash)
	}
	if config.URITemplate == "" {
		config.URITemplate = DefaultConfig.URITemplate
	}

	totp := gotp.NewTOTP(config.Secret, config.Digits, config.Period, config.Hasher)
	verifier := &TOTPVerifier{
		config:     config,
		totp:       totp,
		UsedTokens: make(map[int64]string),
	}

	// Start the periodic cleanup goroutine
	go verifier.startPeriodicCleanup()

	return verifier
}

// Verify checks if the provided token and signature are valid for the current time.
//
// Note: This TOTP verification using [crypto/subtle] requires careful consideration
// when setting TimeSource and Period to ensure correct usage.
func (v *TOTPVerifier) Verify(token, signature string) bool {
	currentTimestamp := v.config.TimeSource().Unix()
	currentTimeStep := currentTimestamp / int64(v.config.Period)

	// Check the syncWindow periods before and after the current time step
	for offset := -v.config.SyncWindow; offset <= v.config.SyncWindow; offset++ {
		expectedTimeStep := currentTimeStep + int64(offset)
		expectedTimestamp := expectedTimeStep * int64(v.config.Period)

		v.m.Lock()
		if _, found := v.UsedTokens[expectedTimeStep]; found {
			v.m.Unlock()
			continue // Skip this step as the token has already been used
		}
		v.m.Unlock()

		// Verify the token for this time step
		if v.totp.Verify(token, expectedTimestamp) {
			if v.config.UseSignature {
				generatedSignature := v.generateSignature(token)
				if subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) != 1 {
					return false
				}
			}

			v.m.Lock()
			v.UsedTokens[expectedTimeStep] = token // Record the token as used
			v.m.Unlock()
			return true
		}
	}

	return false // Token is invalid
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
		if len(v.UsedTokens) > 0 {
			v.CleanUpExpiredTokens()
		}
	}
}

// CleanUpExpiredTokens removes expired tokens from the usedTokens map.
func (v *TOTPVerifier) CleanUpExpiredTokens() {
	currentTimestamp := v.config.TimeSource().Unix()
	currentTimeStep := currentTimestamp / int64(v.config.Period)

	v.m.Lock()
	defer v.m.Unlock()

	for usedTimeStep := range v.UsedTokens {
		if usedTimeStep < currentTimeStep-int64(v.config.SyncWindow) {
			delete(v.UsedTokens, usedTimeStep)
		}
	}
}
