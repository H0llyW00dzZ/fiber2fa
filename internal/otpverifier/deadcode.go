// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import "image"

// SetCounter is a no-op for TOTPVerifier since TOTP doesn't use a counter.
//
// Deprecated: No-op for TOTP (deadcode)
func (v *TOTPVerifier) SetCounter(counter uint64) {
	// No-op for TOTP
}

// GetCounter always returns 0 for TOTPVerifier since TOTP doesn't use a counter.
//
// Deprecated: No-op for TOTP (deadcode)
func (v *TOTPVerifier) GetCounter() uint64 {
	return 0
}

// SetCounter is not applicable for OCRA, so it does nothing.
//
// Deprecated: No-op for OCRA (deadcode)
func (v *OCRAVerifier) SetCounter(counter uint64) {}

// GetCounter is not applicable for OCRA, so it returns 0.
//
// Deprecated: No-op for OCRA (deadcode)
func (v *OCRAVerifier) GetCounter() uint64 {
	return 0
}

// GenerateTokenWithSignature is not applicable for OCRA, so it panics.
//
// Deprecated: No-op for OCRA (deadcode)
func (v *OCRAVerifier) GenerateTokenWithSignature() (string, string) {
	panic("GenerateTokenWithSignature is not applicable for OCRA")
}

// ensureDefaultConfig checks the provided config and fills in any zero values with defaults.
//
// Deprecated: Replaced by [QRCodeBuilder]
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
