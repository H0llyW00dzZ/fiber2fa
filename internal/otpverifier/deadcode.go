// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

// SetCounter is a no-op for TOTPVerifier since TOTP doesn't use a counter.
func (v *TOTPVerifier) SetCounter(counter uint64) {
	// No-op for TOTP
}

// GetCounter always returns 0 for TOTPVerifier since TOTP doesn't use a counter.
func (v *TOTPVerifier) GetCounter() uint64 {
	return 0
}
