// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"container/ring"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"sync"
	"time"

	"github.com/xlzd/gotp"
)

// HOTPVerifier is an HOTP verifier that implements the OTPVerifier interface.
type HOTPVerifier struct {
	config            Config
	Hotp              *gotp.HOTP
	recentCounters    *ring.Ring
	m                 sync.Mutex // Mutex to protect concurrent access to syncwindow
	counterMismatches int
	lastResyncTime    time.Time
	resyncInterval    time.Duration
}

// NewHOTPVerifier creates a new HOTPVerifier with the given configuration.
//
// Note: When using HOTP, consider setting the counter to start from 1. In some 2FA apps, including mobile apps,
// when a device is registered, the counter is often initialized to 1 when generating the token (e.g., a 6-digit password)
// because by default, the counter starts at 0 and is hidden the token.
// Also note that this is still a basic mathematical implementation about counter. More advanced mathematical concepts might be implemented
// in the future, but not at this time due to the limitations of some mobile 2FA ecosystems (poor ecosystems).
//
// Additionally, using [otpverifier.Config.GenerateSecureRandomCounter] is recommended instead of starting from 1.
// Let the client and server roll the counter for the sake of crypto 🎰 by using [otpverifier.Config.GenerateSecureRandomCounter].
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
		// Generate a secure random counter value if not provided
		c.Counter = c.GenerateSecureRandomCounter(c.Digits)
		c.CounterMismatch = DefaultConfig.CounterMismatch
	}
	if c.Hash != "" {
		// If HashName is provided, use it to get the corresponding Hasher
		c.Hasher = c.GetHasherByName(c.Hash)
	}
	if c.URITemplate == "" {
		c.URITemplate = DefaultConfig.URITemplate
	}

	// Initialize recentCounters to nil by default. It will only be created when necessary.
	var recentCounters *ring.Ring = nil

	// For NoneStrict, don't create a recentCounters ring at all.
	// For HighStrict and above, use a ring buffer of size 1.
	// For MediumStrict and LowStrict, use the upper bound of the range as the size.
	if c.SyncWindow > NoneStrict { // Check if SyncWindow is greater than NoneStrict
		recentCountersSize := 1 // Default size for HighStrict
		if syncRanges, ok := SyncWindowRanges[c.SyncWindow]; ok {
			recentCountersSize = syncRanges[1] // Use the upper bound of the sync range
		}

		// Create the ring with the determined size
		//
		// Note: This is a circular HMAC-based one-time password (HOTP) implementation.
		// There is no limit until the client or server stops. If neither
		// of them stops, it keeps rolling the counter for the sake of crypto 🎰
		recentCounters = ring.New(recentCountersSize)

		// This should be correct.
		if c.ResyncWindowDelay == 0 {
			c.ResyncWindowDelay = DefaultConfig.ResyncWindowDelay
		}

	}

	hotp := gotp.NewHOTP(c.Secret, c.Digits, c.Hasher)
	return &HOTPVerifier{
		config:         c,
		Hotp:           hotp,
		recentCounters: recentCounters, // Assign the ring, which may be nil or an actual ring
		resyncInterval: c.ResyncWindowDelay,
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

	// Calculate the actual synchronization window size
	syncWindowSize := v.calculateSyncWindowSize()

	if v.config.UseSignature {
		if len(signature) == 0 {
			panic("hotp: Signature is required but not provided")
		}

		return v.verifyWithSignature(token, signature[0], syncWindowSize)
	}

	return v.verifyWithoutSignature(token, syncWindowSize)
}

// calculateSyncWindowSize calculates the actual synchronization window size based on the configured sync window and any defined sync window ranges.
func (v *HOTPVerifier) calculateSyncWindowSize() int {
	// Default sync window size is the value set in the config
	syncWindowSize := v.config.SyncWindow

	// If there's a range defined for this strictness level, calculate the actual size
	if ranges, ok := SyncWindowRanges[v.config.SyncWindow]; ok {
		// Calculate the range size
		rangeSize := ranges[1] - ranges[0] + 1
		// Calculate the actual sync window size based on the counter value within the defined range
		syncWindowSize = ranges[0] + int(v.config.Counter)%rangeSize
	}

	return syncWindowSize
}

// verifyWithoutSignature checks if the provided token is valid for the specified counter value without signature verification.
func (v *HOTPVerifier) verifyWithoutSignature(token string, syncWindowSize int) bool {
	// If sync window is exactly 0, only validate the immediate next token 🏴‍☠️
	// Note: Understanding this sync window requires skilled mathematical reasoning.
	// Also note that this is still a basic implementation, and it is possible to implement another HOTP method
	// Called "Rolling Slots" similar to gambling. However, it requires building own 2FA apps since most mobile app ecosystems are poor.
	if syncWindowSize == NoneStrict {
		// Default case when sync window is not applied
		generatedToken := v.Hotp.At(int(v.config.Counter))
		if subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1 {
			// Increment the counter value after successful verification
			v.config.Counter++
			return true
		}

		return false
	}

	// Otherwise, validate within the sync window range 🏴‍☠️
	for i := 0; i <= syncWindowSize; i++ {
		expectedCounter := v.config.Counter + uint64(i)
		// Update the stored counter to the next expected value after a successful match (Congratulations)
		if v.isTokenValid(token, expectedCounter) {
			v.updateAfterVerification(expectedCounter)
			if !v.isRecentCountersContinuous() {
				v.deferResynchronization(expectedCounter)
			}
			return true
		}
	}

	return false
}

// verifyWithSignature checks if the provided token and signature are valid for the specified counter value.
func (v *HOTPVerifier) verifyWithSignature(token, signature string, syncWindowSize int) bool {
	// If sync window is exactly 0, only validate the immediate next token 🏴‍☠️
	// Note: Understanding this sync window requires skilled mathematical reasoning.
	// Also note that this is still a basic implementation, and it is possible to implement another HOTP method
	// Called "Rolling Slots" similar to gambling. However, it requires building own 2FA apps since most mobile app ecosystems are poor.
	if syncWindowSize == NoneStrict {
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

	// Otherwise, validate within the sync window range 🏴‍☠️
	for i := 0; i <= syncWindowSize; i++ {
		expectedCounter := v.config.Counter + uint64(i)
		// Update the stored counter to the next expected value after a successful match (Congratulations)
		if v.isTokenValid(token, expectedCounter) && v.isSignatureValid(token, signature) {
			v.updateAfterVerification(expectedCounter)
			if !v.isRecentCountersContinuous() {
				v.deferResynchronization(expectedCounter)
			}
			return true
		}
	}

	return false
}

// isTokenValid checks if the provided token is valid for the given counter value.
func (v *HOTPVerifier) isTokenValid(token string, counter uint64) bool {
	generatedToken := v.Hotp.At(int(counter))
	return subtle.ConstantTimeCompare([]byte(token), []byte(generatedToken)) == 1
}

// isSignatureValid checks if the provided signature is valid for the given token.
func (v *HOTPVerifier) isSignatureValid(token, signature string) bool {
	generatedSignature := v.generateSignature(token)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(generatedSignature)) == 1
}

// updateAfterVerification updates the counter and recent counters after a successful verification.
func (v *HOTPVerifier) updateAfterVerification(counter uint64) {
	v.config.Counter = counter + 1
	if v.recentCounters != nil {
		v.recentCounters.Value = counter
		v.recentCounters = v.recentCounters.Next()
	}
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

// isRecentCountersContinuous checks if the stored recent counters form a continuous sequence.
// This helps determine if automatic resynchronization is possible.
func (v *HOTPVerifier) isRecentCountersContinuous() bool {
	var (
		prevCounter  uint64
		isContinuous = true // assume true until proven otherwise
	)
	// Note: This helper function is particularly useful in cryptography-related applications, such as:
	// - One-Time Password (OTP) systems
	// - Virtual slot machines built with cryptographic principles
	// - Rotating private keys or public keys that might be used for security purposes
	// - Other cryptographic implementations that rely on continuous counter sequences
	//   not only for security purposes (literally boring cryptographic used for security purposes) but also for ensuring the integrity and consistency
	//   of the cryptographic operations at a fundamental level.
	v.recentCounters.Do(func(c any) {
		if c != nil {
			counter := c.(uint64)
			if prevCounter != 0 && counter != prevCounter+1 {
				isContinuous = false // sequence is broken
				return
			}
			prevCounter = counter
		}
	})
	return isContinuous
}

// deferResynchronization schedules an automatic resynchronization attempt after the predefined delay.
func (v *HOTPVerifier) deferResynchronization(matchedCounter uint64) {
	// TODO: Improve this to use a sync map. However, it is not important for now because the logic for HOTP is more challenging
	//       (e.g., expensive allocations) compared to TOTP. Refactoring this can be considered in the future if needed.
	go func() {
		// Check if enough time has passed since the last resynchronization
		v.m.Lock()
		if time.Since(v.lastResyncTime) < v.resyncInterval {
			v.m.Unlock()
			return
		}
		v.m.Unlock()

		// Sleep for the ResyncWindowDelay duration
		time.Sleep(v.config.ResyncWindowDelay)

		v.m.Lock()
		defer v.m.Unlock()

		// Set the server's counter to the matched counter value plus 1
		v.SetCounter(matchedCounter + 1)

		// Update the last resynchronization time
		v.lastResyncTime = time.Now()

		// Adjust the sync window
		v.AdjustSyncWindow(v.config.CounterMismatch)
	}()
}

// AdjustSyncWindow dynamically adjusts the size of the synchronization window
// based on the frequency of counter mismatches between the server and the client.
//
// Note: This is a long-term adjustment bound to real-time on Earth. For example, in the year 2024 (now), if the server's counter is far behind
// (e.g., the client has already reached a counter value of 1 billion), it may take until the year 3024 for the
// server and client to be fully synchronized again. The adjustment process is gradual and occurs over an extended period.
// This approach ensures a smooth and secure synchronization process, preventing sudden and drastic changes to the sync window size.
// It allows the system to adapt to counter mismatches while maintaining the integrity and security of the HOTP verification process.
func (v *HOTPVerifier) AdjustSyncWindow(threshold int) {
	// Increment the counter mismatch count
	v.counterMismatches++

	// Check if the counter mismatch count exceeds the selected threshold
	if v.counterMismatches > threshold {
		// Set the sync window size to the value defined in the verifier's configuration
		newSyncWindow := v.calculateSyncWindowSize()
		// Update the sync window size
		// Set the new sync window size in the verifier's configuration.
		v.config.SyncWindow = newSyncWindow

		// Reset the counter mismatch count
		// After adjusting the sync window, reset the mismatch count
		// to allow for future adjustments if needed.
		v.counterMismatches = 0
	}
}
