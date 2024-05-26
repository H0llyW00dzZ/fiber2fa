// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package otpverifier provides a simple and flexible way to verify and generate one-time passwords (OTPs)
// using time-based (TOTP) or counter-based (HOTP) algorithms. It supports optional signature generation
// and verification for enhanced security.
//
// The package offers an [otpverifier.OTPVerifier] interface that defines the behavior of an OTP verifier. It includes
// methods for verifying tokens and signatures and generating tokens and signatures.
//
// The package provides two implementations of the [otpverifier.OTPVerifier] interface: [otpverifier.TOTPVerifier] and [otpverifier.HOTPVerifier].
// [otpverifier.TOTPVerifier] is used for time-based OTPs, while [otpverifier.HOTPVerifier] is used for counter-based OTPs.
//
// The package also includes an [otpverifier.OTPFactory] function that creates an appropriate [otpverifier.OTPVerifier] based on the
// provided configuration. The configuration is defined using the Config struct, which holds options such
// as the secret key, counter value, signature usage, and time source.
//
// Example usage:
//
//	// Create a configuration for TOTP
//	totpConfig := otpverifier.Config{
//		Secret:       "your-secret-key",
//		UseSignature: true,
//	}
//
//	// Create a TOTP verifier using the factory function
//	totpVerifier := otpverifier.OTPFactory(totpConfig)
//
//	// Generate a token and signature
//	token, signature := totpVerifier.GenerateToken()
//
//	// Verify the token and signature
//	isValid := totpVerifier.Verify(token, signature)
//
//	// Create a configuration for HOTP
//	hotpConfig := otpverifier.Config{
//		Secret:       "your-secret-key",
//		Counter:      1000,
//		UseSignature: true,
//	}
//
//	// Create an HOTP verifier using the factory function
//	hotpVerifier := otpverifier.OTPFactory(hotpConfig)
//
//	// Generate a token and signature
//	token, signature := hotpVerifier.GenerateToken()
//
//	// Verify the token and signature
//	isValid := hotpVerifier.Verify(token, signature)
//
// The package uses the [github.com/xlzd/gotp] library for generating and verifying OTPs,
// and the [crypto/hmac], [crypto/sha256], and [github.com/H0llyW00dzZ/fiber2fa/internal/crypto/hash/blake2botp] packages for
// generating and verifying signatures using HMAC with SHA-1, SHA-256, SHA-512, and BLAKE2b.
package otpverifier
